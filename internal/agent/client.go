package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/protocol"

	commandstate "github.com/Relayward/relayward-agent/internal/command"
	"github.com/Relayward/relayward-agent/internal/config"
	"github.com/Relayward/relayward-agent/internal/eventqueue"
	"github.com/Relayward/relayward-agent/internal/identity"
	"github.com/Relayward/relayward-agent/internal/update"
)

const (
	RegistrationTokenEnv = "RELAYWARD_REGISTRATION_TOKEN"
	maxResponseBytes     = 64 << 10
	connectTimeout       = 15 * time.Second
	writeTimeout         = 10 * time.Second
)

var capabilities = []string{
	agentv1.CapabilityAgentSelfUpdate,
	agentv1.CapabilityControlCommands,
	agentv1.CapabilityControlHeartbeat,
	agentv1.CapabilityEventQueue,
}

type updateController interface {
	AwaitActivation(context.Context, string) error
	Confirm(string) (bool, error)
}

type Client struct {
	config     config.Config
	version    string
	identities *identity.Store
	commands   *commandstate.Processor
	events     *eventqueue.Store
	updates    updateController
	httpClient *http.Client
	wsDialer   *websocket.Dialer
	logger     *slog.Logger
	startedAt  time.Time
	now        func() time.Time
}

func NewClient(value config.Config, version string, logger *slog.Logger) (*Client, error) {
	return newClient(value, version, logger, nil)
}

func newClient(value config.Config, version string, logger *slog.Logger, executor commandstate.Executor) (*Client, error) {
	normalized, err := config.Normalize(value)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	tlsConfig, err := controlTLSConfig(normalized.ServerCertSHA256)
	if err != nil {
		return nil, err
	}
	commandStore, err := commandstate.OpenStore(normalized.StateDirectory)
	if err != nil {
		return nil, fmt.Errorf("open command state: %w", err)
	}
	var updates updateController
	if executor == nil {
		manager, err := update.NewManager(normalized.StateDirectory)
		if err != nil {
			return nil, fmt.Errorf("initialize Agent updates: %w", err)
		}
		updates = manager
		executor = update.NewExecutor(manager, version)
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}
	return &Client{
		config:     normalized,
		version:    version,
		identities: identity.NewStore(normalized.StateDirectory),
		commands:   commandstate.NewProcessor(commandStore, executor),
		updates:    updates,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   connectTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("center redirects are not allowed")
			},
		},
		wsDialer: &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			TLSClientConfig:  tlsConfig,
			HandshakeTimeout: connectTimeout,
		},
		logger: logger, startedAt: time.Now().UTC(), now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (client *Client) Run(ctx context.Context) error {
	current, err := client.identities.Load()
	if errors.Is(err, os.ErrNotExist) {
		token := strings.TrimSpace(os.Getenv(RegistrationTokenEnv))
		if token == "" {
			return fmt.Errorf("Agent is not registered; set %s for the first start", RegistrationTokenEnv)
		}
		current, err = client.Register(ctx, token)
		if err != nil {
			return err
		}
		_ = os.Unsetenv(RegistrationTokenEnv)
		client.logger.Info("Agent registered", "node_id", current.NodeID, "node_name", current.NodeName)
	} else if err != nil {
		return fmt.Errorf("load Agent identity: %w", err)
	}
	events, err := eventqueue.Open(eventqueue.Config{
		Path: filepath.Join(client.config.StateDirectory, "events.db"), NodeID: current.NodeID,
	})
	if err != nil {
		return fmt.Errorf("open event queue: %w", err)
	}
	client.events = events
	defer events.Close()
	uploader := &eventUploader{
		endpoint: client.httpURL("/api/v1/agent/events/" + current.NodeID), credential: current.Credential,
		httpClient: client.httpClient, queue: events,
	}
	workerContext, stopWorkers := context.WithCancel(ctx)
	workerFailure := make(chan error, 3)
	var workers sync.WaitGroup
	startWorker := func(name string, run func(context.Context) error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := run(workerContext); err != nil {
				workerFailure <- fmt.Errorf("%s: %w", name, err)
				stopWorkers()
			}
		}()
	}
	startWorker("command processor", client.commands.Run)
	startWorker("event uploader", uploader.Run)
	if client.updates != nil {
		startWorker("update activation watchdog", func(ctx context.Context) error {
			return client.updates.AwaitActivation(ctx, client.version)
		})
	}
	defer func() {
		stopWorkers()
		workers.Wait()
	}()

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		stable, sessionErr := client.runSession(workerContext, current)
		if ctx.Err() != nil {
			return nil
		}
		select {
		case err := <-workerFailure:
			return fmt.Errorf("run Agent worker: %w", err)
		default:
		}
		if errors.Is(sessionErr, commandstate.ErrConflict) {
			return fmt.Errorf("command state conflict: %w", sessionErr)
		}
		if stable {
			backoff = time.Second
		}
		delay := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))
		client.logger.Warn("control session ended", "reason", safeControlFailure(sessionErr), "retry_in", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case err := <-workerFailure:
			timer.Stop()
			return fmt.Errorf("run Agent worker: %w", err)
		case <-timer.C:
		}
		backoff *= 2
		if backoff > time.Minute {
			backoff = time.Minute
		}
	}
}

func (client *Client) Register(ctx context.Context, token string) (identity.Identity, error) {
	if err := agentv1.ValidateRegistrationToken(token); err != nil {
		return identity.Identity{}, errors.New("registration token is invalid")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return identity.Identity{}, fmt.Errorf("read hostname: %w", err)
	}
	requestValue := agentv1.RegisterRequest{
		APIVersion: agentv1.APIVersion, Token: token, AgentVersion: client.version,
		Hostname: hostname, OS: runtime.GOOS, Arch: runtime.GOARCH, Capabilities: capabilities,
	}
	if err := agentv1.ValidateRegisterRequest(requestValue); err != nil {
		return identity.Identity{}, fmt.Errorf("prepare registration: %w", err)
	}
	raw, err := json.Marshal(requestValue)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("encode registration: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.httpURL("/api/v1/agent/register"), bytes.NewReader(raw))
	if err != nil {
		return identity.Identity{}, fmt.Errorf("create registration request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("registration transport failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return identity.Identity{}, errors.New("read registration response failed")
	}
	if len(body) > maxResponseBytes {
		return identity.Identity{}, errors.New("registration response is too large")
	}
	if response.StatusCode != http.StatusCreated {
		return identity.Identity{}, fmt.Errorf("registration failed (HTTP %d)", response.StatusCode)
	}
	var registered agentv1.RegisterResponse
	if err := decodeStrict(body, &registered); err != nil {
		return identity.Identity{}, fmt.Errorf("decode registration response: %w", err)
	}
	if err := agentv1.ValidateRegisterResponse(registered); err != nil {
		return identity.Identity{}, fmt.Errorf("validate registration response: %w", err)
	}
	value := identity.Identity{
		APIVersion: registered.APIVersion, NodeID: registered.NodeID,
		NodeName: registered.NodeName, Credential: registered.Credential,
	}
	if err := client.identities.Save(value); err != nil {
		return identity.Identity{}, err
	}
	return value, nil
}

func (client *Client) runSession(ctx context.Context, current identity.Identity) (bool, error) {
	headers := http.Header{"Authorization": []string{"Bearer " + current.Credential}}
	connection, response, err := client.wsDialer.DialContext(ctx, client.websocketURL("/api/v1/agent/connect/"+current.NodeID), headers)
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
			return false, handshakeError(response.StatusCode)
		}
		return false, err
	}
	defer connection.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	connection.SetReadLimit(agentv1.MaximumMessageBytes)
	hello, err := agentv1.NewEnvelope(agentv1.MessageAgentHello, agentv1.AgentHello{
		NodeID: current.NodeID, AgentVersion: client.version, StartedAt: client.startedAt, Capabilities: capabilities,
	})
	if err != nil {
		return false, err
	}
	if err := writeEnvelope(connection, hello); err != nil {
		return false, err
	}
	if err := connection.SetReadDeadline(client.now().Add(20 * time.Second)); err != nil {
		return false, err
	}
	centerEnvelope, err := readEnvelope(connection)
	if err != nil {
		return false, err
	}
	if centerEnvelope.Type == agentv1.MessageProtocolError {
		return false, protocolFailure(centerEnvelope)
	}
	if centerEnvelope.Type != agentv1.MessageCenterHello {
		return false, errors.New("unexpected center hello")
	}
	centerHello, err := agentv1.DecodeEnvelopePayload[agentv1.CenterHello](centerEnvelope)
	if err != nil {
		return false, err
	}
	period := time.Duration(centerHello.HeartbeatIntervalSeconds) * time.Second
	client.logger.Info("control session connected", "node_id", current.NodeID, "session_id", centerHello.SessionID)

	stable := false
	nextHeartbeat := client.now()
	for {
		result, resultErr := client.commands.NextResult()
		switch {
		case resultErr == nil:
			if err := client.sendCommandResult(connection, result); err != nil {
				if ctx.Err() != nil {
					return stable, nil
				}
				return stable, err
			}
			continue
		case errors.Is(resultErr, commandstate.ErrNotFound):
		default:
			return stable, resultErr
		}
		wait := nextHeartbeat.Sub(client.now())
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return stable, nil
			case <-client.commands.Results():
				timer.Stop()
				continue
			case <-timer.C:
			}
		}
		heartbeat, err := agentv1.NewEnvelope(agentv1.MessageAgentHeartbeat, agentv1.Heartbeat{
			SessionID: centerHello.SessionID, AgentVersion: client.version, ObservedAt: client.now(),
		})
		if err != nil {
			return stable, err
		}
		if err := writeEnvelope(connection, heartbeat); err != nil {
			if ctx.Err() != nil {
				return stable, nil
			}
			return stable, err
		}
		if err := connection.SetReadDeadline(client.now().Add(3 * period)); err != nil {
			if ctx.Err() != nil {
				return stable, nil
			}
			return stable, err
		}
		ackEnvelope, err := readEnvelope(connection)
		if err != nil {
			if ctx.Err() != nil {
				return stable, nil
			}
			return stable, err
		}
		if ackEnvelope.Type == agentv1.MessageProtocolError {
			return stable, protocolFailure(ackEnvelope)
		}
		if ackEnvelope.Type != agentv1.MessageCenterHeartbeatAck || ackEnvelope.CorrelationID != heartbeat.ID {
			return stable, errors.New("heartbeat acknowledgement does not match")
		}
		ack, err := agentv1.DecodeEnvelopePayload[agentv1.HeartbeatAck](ackEnvelope)
		if err != nil || ack.MessageID != heartbeat.ID {
			return stable, errors.New("heartbeat acknowledgement does not match")
		}
		if ack.Command != nil {
			if err := client.commands.Accept(*ack.Command, client.now()); err != nil {
				return stable, fmt.Errorf("persist center command: %w", err)
			}
		}
		if client.updates != nil {
			if _, err := client.updates.Confirm(client.version); err != nil {
				return stable, fmt.Errorf("confirm Agent update health: %w", err)
			}
		}
		stable = true
		nextHeartbeat = client.now().Add(period)
	}
}

func (client *Client) sendCommandResult(connection *websocket.Conn, result agentv1.CommandResult) error {
	envelope, err := agentv1.NewCommandResultEnvelope(result)
	if err != nil {
		return err
	}
	if err := writeEnvelope(connection, envelope); err != nil {
		return err
	}
	if err := connection.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}
	ackEnvelope, err := readEnvelope(connection)
	if err != nil {
		return err
	}
	if ackEnvelope.Type == agentv1.MessageProtocolError {
		return protocolFailure(ackEnvelope)
	}
	if ackEnvelope.Type != agentv1.MessageCenterCommandResultAck || ackEnvelope.CorrelationID != envelope.ID {
		return errors.New("command result acknowledgement does not match")
	}
	ack, err := agentv1.DecodeEnvelopePayload[agentv1.CommandResultAck](ackEnvelope)
	if err != nil || ack.CommandID != result.CommandID || ack.RequestSHA256 != result.RequestSHA256 {
		return errors.New("command result acknowledgement does not match")
	}
	if err := client.commands.Acknowledge(ack, client.now()); err != nil {
		return fmt.Errorf("persist command result acknowledgement: %w", err)
	}
	return nil
}

func controlTLSConfig(pin string) (*tls.Config, error) {
	value := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin == "" {
		return value, nil
	}
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("server certificate fingerprint is invalid")
	}
	value.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("center did not present a certificate")
		}
		got := sha256.Sum256(state.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return errors.New("center certificate fingerprint does not match")
		}
		return nil
	}
	return value, nil
}

func (client *Client) httpURL(path string) string {
	return client.config.ServerURL + path
}

func (client *Client) websocketURL(path string) string {
	parsed, _ := url.Parse(client.config.ServerURL)
	if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	} else {
		parsed.Scheme = "ws"
	}
	parsed.Path = path
	return parsed.String()
}

func readEnvelope(connection *websocket.Conn) (protocol.Envelope, error) {
	messageType, raw, err := connection.ReadMessage()
	if err != nil {
		return protocol.Envelope{}, err
	}
	if messageType != websocket.TextMessage {
		return protocol.Envelope{}, errors.New("control message must be text JSON")
	}
	var value protocol.Envelope
	if err := decodeStrict(raw, &value); err != nil {
		return protocol.Envelope{}, err
	}
	if err := agentv1.ValidateEnvelope(value); err != nil {
		return protocol.Envelope{}, err
	}
	return value, nil
}

func writeEnvelope(connection *websocket.Conn, value protocol.Envelope) error {
	if err := agentv1.ValidateEnvelope(value); err != nil {
		return err
	}
	if err := connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return connection.WriteJSON(value)
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

type handshakeError int

func (value handshakeError) Error() string {
	return fmt.Sprintf("websocket handshake failed (HTTP %d)", int(value))
}

func protocolFailure(value protocol.Envelope) error {
	problem, err := agentv1.DecodeEnvelopePayload[protocol.Problem](value)
	if err != nil {
		return errors.New("control protocol failure")
	}
	return fmt.Errorf("control protocol failure (%s)", problem.Code)
}

func safeControlFailure(err error) string {
	if err == nil {
		return "control session ended"
	}
	var handshake handshakeError
	if errors.As(err, &handshake) {
		return handshake.Error()
	}
	var closeError *websocket.CloseError
	if errors.As(err, &closeError) {
		return fmt.Sprintf("websocket closed (code %d)", closeError.Code)
	}
	if strings.HasPrefix(err.Error(), "control protocol failure") {
		return err.Error()
	}
	return "control transport failure"
}
