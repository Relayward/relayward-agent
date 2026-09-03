package networkobserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

const (
	defaultInterval = 10 * time.Minute
	requestTimeout  = 5 * time.Second
	maximumBodySize = 128

	defaultIPv4Endpoint = "https://api4.ipify.org"
	defaultIPv6Endpoint = "https://api6.ipify.org"
)

type EventSink interface {
	Enqueue(string, time.Time, any) (agentv1.Event, error)
}

type Observer struct {
	sink      EventSink
	client    *http.Client
	logger    *slog.Logger
	interval  time.Duration
	endpoints map[string]string
	now       func() time.Time
}

func New(sink EventSink, logger *slog.Logger) (*Observer, error) {
	if sink == nil {
		return nil, errors.New("public address event sink is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Observer{
		sink: sink,
		client: &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
			Timeout:   requestTimeout,
		},
		logger: logger, interval: defaultInterval,
		endpoints: map[string]string{
			agentv1.AddressFamilyIPv4: defaultIPv4Endpoint,
			agentv1.AddressFamilyIPv6: defaultIPv6Endpoint,
		},
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (observer *Observer) Run(ctx context.Context) error {
	observer.observe(ctx)
	ticker := time.NewTicker(observer.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			observer.observe(ctx)
		}
	}
}

func (observer *Observer) observe(ctx context.Context) {
	observedAt := observer.now()
	addresses := make([]agentv1.PublicAddressObservation, 0, len(observer.endpoints))
	for family, endpoint := range observer.endpoints {
		address, err := observer.query(ctx, family, endpoint)
		if err != nil {
			if ctx.Err() == nil {
				observer.logger.Warn("public address observation failed", "family", family, "error", err)
			}
			continue
		}
		addresses = append(addresses, agentv1.PublicAddressObservation{Family: family, Address: address})
	}
	if len(addresses) == 0 {
		return
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Family < addresses[j].Family })
	value := agentv1.PublicAddressesEvent{Addresses: addresses}
	if err := agentv1.ValidatePublicAddressesEvent(value); err != nil {
		observer.logger.Error("public address observation is invalid", "error", err)
		return
	}
	if _, err := observer.sink.Enqueue(agentv1.EventPublicAddresses, observedAt, value); err != nil {
		observer.logger.Warn("queue public address observation failed", "error", err)
	}
}

func (observer *Observer) query(ctx context.Context, family, endpoint string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "text/plain")
	response, err := observer.client.Do(request)
	if err != nil {
		return "", errors.New("endpoint unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("endpoint returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumBodySize+1))
	if err != nil {
		return "", errors.New("read response")
	}
	if len(raw) > maximumBodySize {
		return "", errors.New("response is too large")
	}
	value := strings.TrimSpace(string(raw))
	address, err := netip.ParseAddr(value)
	if err != nil || address.String() != value || !address.IsGlobalUnicast() || address.IsPrivate() {
		return "", errors.New("response is not a canonical public IP address")
	}
	if family == agentv1.AddressFamilyIPv4 && !address.Is4() {
		return "", errors.New("response is not IPv4")
	}
	if family == agentv1.AddressFamilyIPv6 && !address.Is6() {
		return "", errors.New("response is not IPv6")
	}
	return value, nil
}
