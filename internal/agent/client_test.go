package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/protocol"

	"github.com/Relayward/relayward-agent/internal/config"
)

const (
	testRegistrationToken = "rwr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testNodeCredential    = "rwc_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	testNodeID            = "123e4567-e89b-42d3-a456-426614174000"
)

func TestClientRegistrationAndHeartbeat(t *testing.T) {
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
	ackSent := make(chan struct{})
	var ackOnce sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/register", func(writer http.ResponseWriter, request *http.Request) {
		registered, err := agentv1.DecodeRegisterRequest(request.Body)
		if err != nil {
			t.Errorf("decode registration request: %v", err)
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		if registered.Token != testRegistrationToken || registered.OS != "linux" || registered.Arch != "amd64" {
			t.Errorf("registration request = %+v", registered)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(agentv1.RegisterResponse{
			APIVersion: agentv1.APIVersion,
			NodeID:     testNodeID,
			NodeName:   "Edge one",
			Credential: testNodeCredential,
		})
	})
	mux.HandleFunc("GET /api/v1/agent/connect/{node_id}", func(writer http.ResponseWriter, request *http.Request) {
		if request.PathValue("node_id") != testNodeID || request.Header.Get("Authorization") != "Bearer "+testNodeCredential {
			t.Errorf("control authentication node = %q, authorization = %q", request.PathValue("node_id"), request.Header.Get("Authorization"))
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		connection, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer connection.Close()
		helloEnvelope, err := readEnvelope(connection)
		if err != nil {
			t.Errorf("read Agent hello: %v", err)
			return
		}
		hello, err := agentv1.DecodeEnvelopePayload[agentv1.AgentHello](helloEnvelope)
		if err != nil || helloEnvelope.Type != agentv1.MessageAgentHello || hello.NodeID != testNodeID {
			t.Errorf("Agent hello = %+v, payload = %+v, error = %v", helloEnvelope, hello, err)
			return
		}
		centerHello, err := agentv1.NewEnvelope(agentv1.MessageCenterHello, agentv1.CenterHello{
			SessionID:                "0123456789abcdef0123456789abcdef",
			HeartbeatIntervalSeconds: int(agentv1.MinimumHeartbeatInterval.Seconds()),
			ServerTime:               time.Now().UTC(),
		})
		if err != nil || writeEnvelope(connection, centerHello) != nil {
			t.Errorf("write center hello: %v", err)
			return
		}
		heartbeatEnvelope, err := readEnvelope(connection)
		if err != nil {
			t.Errorf("read heartbeat: %v", err)
			return
		}
		heartbeat, err := agentv1.DecodeEnvelopePayload[agentv1.Heartbeat](heartbeatEnvelope)
		if err != nil || heartbeatEnvelope.Type != agentv1.MessageAgentHeartbeat || heartbeat.SessionID != "0123456789abcdef0123456789abcdef" {
			t.Errorf("heartbeat = %+v, payload = %+v, error = %v", heartbeatEnvelope, heartbeat, err)
			return
		}
		ack, err := agentv1.NewEnvelope(agentv1.MessageCenterHeartbeatAck, agentv1.HeartbeatAck{
			MessageID:  heartbeatEnvelope.ID,
			ServerTime: time.Now().UTC(),
		})
		if err != nil {
			t.Errorf("create heartbeat acknowledgement: %v", err)
			return
		}
		ack.CorrelationID = heartbeatEnvelope.ID
		if err := writeEnvelope(connection, ack); err != nil {
			t.Errorf("write heartbeat acknowledgement: %v", err)
			return
		}
		ackOnce.Do(func() { close(ackSent) })
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client, err := NewClient(config.Config{
		ServerURL: server.URL, StateDirectory: filepath.Join(t.TempDir(), "state"), AllowInsecure: true,
	}, "0.1.0", logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	registered, err := client.Register(context.Background(), testRegistrationToken)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	stored, err := client.identities.Load()
	if err != nil || stored != registered {
		t.Fatalf("stored identity = %+v, error = %v", stored, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-ackSent:
			time.Sleep(100 * time.Millisecond)
			cancel()
		case <-ctx.Done():
		}
	}()
	stable, err := client.runSession(ctx, registered)
	if err != nil || !stable {
		t.Fatalf("runSession() stable = %v, error = %v", stable, err)
	}
	if strings.Contains(logOutput.String(), testRegistrationToken) || strings.Contains(logOutput.String(), testNodeCredential) {
		t.Fatalf("logs contain a credential: %s", logOutput.String())
	}
}

func TestClientRejectsInvalidRegistrationResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"api_version":"relayward.agent/v1","unknown":true}`))
	}))
	defer server.Close()
	client, err := NewClient(config.Config{
		ServerURL: server.URL, StateDirectory: filepath.Join(t.TempDir(), "state"), AllowInsecure: true,
	}, "0.1.0", nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.Register(context.Background(), testRegistrationToken); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Register() error = %v", err)
	}
}

func TestControlTLSConfigPin(t *testing.T) {
	rawCertificate := []byte("test certificate")
	digest := sha256.Sum256(rawCertificate)
	configuration, err := controlTLSConfig(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("controlTLSConfig() error = %v", err)
	}
	if configuration.MinVersion == 0 || configuration.VerifyConnection == nil {
		t.Fatalf("TLS configuration = %+v", configuration)
	}
	state := testTLSState(rawCertificate)
	if err := configuration.VerifyConnection(state); err != nil {
		t.Fatalf("VerifyConnection() matching pin error = %v", err)
	}
	state = testTLSState([]byte("different certificate"))
	if err := configuration.VerifyConnection(state); err == nil {
		t.Fatal("VerifyConnection() accepted a different certificate")
	}
}

func testTLSState(rawCertificate []byte) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: rawCertificate}}}
}

func TestSafeControlFailureDoesNotExposeDetails(t *testing.T) {
	secret := testNodeCredential
	if got := safeControlFailure(errors.New("dial failed with " + secret)); got != "control transport failure" {
		t.Fatalf("safeControlFailure() = %q", got)
	}
	problem, err := agentv1.NewEnvelope(agentv1.MessageProtocolError, protocol.Problem{
		Code: protocol.ErrorUnavailable, Message: "try later", Retryable: true,
	})
	if err != nil {
		t.Fatalf("create protocol problem: %v", err)
	}
	if got := protocolFailure(problem).Error(); got != "control protocol failure (unavailable)" {
		t.Fatalf("protocolFailure() = %q", got)
	}
}
