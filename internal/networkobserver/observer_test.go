package networkobserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

type recordedEvent struct {
	kind       string
	observedAt time.Time
	payload    agentv1.PublicAddressesEvent
}

type eventSink struct {
	mu     sync.Mutex
	events []recordedEvent
}

func (sink *eventSink) Enqueue(kind string, observedAt time.Time, payload any) (agentv1.Event, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, recordedEvent{kind: kind, observedAt: observedAt, payload: payload.(agentv1.PublicAddressesEvent)})
	return agentv1.Event{}, nil
}

func TestObserverQueuesSuccessfulAddressFamilies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v4" {
			_, _ = io.WriteString(writer, "203.0.113.10\n")
			return
		}
		_, _ = io.WriteString(writer, "2001:db8::10")
	}))
	defer server.Close()
	sink := &eventSink{}
	observer, err := New(sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	observer.client = server.Client()
	observer.endpoints = map[string]string{
		agentv1.AddressFamilyIPv4: server.URL + "/v4",
		agentv1.AddressFamilyIPv6: server.URL + "/v6",
	}
	observedAt := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	observer.now = func() time.Time { return observedAt }
	observer.observe(t.Context())
	if len(sink.events) != 1 || sink.events[0].kind != agentv1.EventPublicAddresses || !sink.events[0].observedAt.Equal(observedAt) {
		t.Fatalf("events = %+v", sink.events)
	}
	addresses := sink.events[0].payload.Addresses
	if len(addresses) != 2 || addresses[0].Family != agentv1.AddressFamilyIPv4 || addresses[1].Family != agentv1.AddressFamilyIPv6 {
		t.Fatalf("addresses = %+v", addresses)
	}
}

func TestObserverKeepsSuccessfulFamilyWhenAnotherFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v6" {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(writer, "203.0.113.10")
	}))
	defer server.Close()
	sink := &eventSink{}
	observer, _ := New(sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	observer.client = server.Client()
	observer.endpoints = map[string]string{
		agentv1.AddressFamilyIPv4: server.URL + "/v4",
		agentv1.AddressFamilyIPv6: server.URL + "/v6",
	}
	observer.observe(context.Background())
	if len(sink.events) != 1 || len(sink.events[0].payload.Addresses) != 1 || sink.events[0].payload.Addresses[0].Family != agentv1.AddressFamilyIPv4 {
		t.Fatalf("events = %+v", sink.events)
	}
}
