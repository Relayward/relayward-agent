package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"

	"github.com/Relayward/relayward-agent/internal/eventqueue"
)

func TestEventUploaderRetriesUntilMatchingAcknowledgement(t *testing.T) {
	queue, err := eventqueue.Open(eventqueue.Config{
		Path: filepath.Join(t.TempDir(), "events.db"), NodeID: testNodeID, MaxBytes: 1 << 20, MaxEvents: 10,
	})
	if err != nil {
		t.Fatalf("eventqueue.Open() error = %v", err)
	}
	defer queue.Close()
	if _, err := queue.Enqueue("system.test", time.Now().UTC(), map[string]bool{"ok": true}); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	var mu sync.Mutex
	var batches []agentv1.EventBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testNodeCredential || request.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("event upload headers = %+v", request.Header)
		}
		compressed, err := gzip.NewReader(request.Body)
		if err != nil {
			t.Errorf("gzip.NewReader() error = %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		batch, err := agentv1.DecodeEventBatch(compressed)
		_ = compressed.Close()
		if err != nil {
			t.Errorf("DecodeEventBatch() error = %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		batches = append(batches, batch)
		attempt := len(batches)
		mu.Unlock()
		if attempt == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(agentv1.EventBatchAck{
			APIVersion: agentv1.APIVersion, StreamID: batch.StreamID,
			HighestContiguousSequence: batch.LastSequence, ServerTime: time.Now().UTC(),
		})
	}))
	defer server.Close()
	uploader := &eventUploader{endpoint: server.URL, credential: testNodeCredential, httpClient: server.Client(), queue: queue}
	if hadEvents, err := uploader.uploadOnce(context.Background()); err == nil || !hadEvents {
		t.Fatalf("first uploadOnce() hadEvents = %v, error = %v", hadEvents, err)
	}
	info, _ := queue.Info()
	if info.PendingEvents != 1 {
		t.Fatalf("queue after failed upload = %+v", info)
	}
	if hadEvents, err := uploader.uploadOnce(context.Background()); err != nil || !hadEvents {
		t.Fatalf("second uploadOnce() hadEvents = %v, error = %v", hadEvents, err)
	}
	info, _ = queue.Info()
	if info.PendingEvents != 0 || info.HighestAckedSequence != 1 {
		t.Fatalf("queue after acknowledged upload = %+v", info)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 2 || batches[0].Events[0].EventID != batches[1].Events[0].EventID {
		t.Fatalf("retried batches = %+v", batches)
	}
}

func TestEventUploaderRejectsOutOfRangeAcknowledgement(t *testing.T) {
	queue, err := eventqueue.Open(eventqueue.Config{Path: filepath.Join(t.TempDir(), "events.db"), NodeID: testNodeID})
	if err != nil {
		t.Fatalf("eventqueue.Open() error = %v", err)
	}
	defer queue.Close()
	if _, err := queue.Enqueue("system.test", time.Now().UTC(), map[string]bool{"ok": true}); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		compressed, _ := gzip.NewReader(request.Body)
		batch, _ := agentv1.DecodeEventBatch(compressed)
		_ = compressed.Close()
		_ = json.NewEncoder(writer).Encode(agentv1.EventBatchAck{
			APIVersion: agentv1.APIVersion, StreamID: batch.StreamID,
			HighestContiguousSequence: batch.LastSequence + 1, ServerTime: time.Now().UTC(),
		})
	}))
	defer server.Close()
	uploader := &eventUploader{endpoint: server.URL, credential: testNodeCredential, httpClient: server.Client(), queue: queue}
	if _, err := uploader.uploadOnce(context.Background()); err == nil {
		t.Fatal("uploadOnce() accepted an out-of-range acknowledgement")
	}
	info, _ := queue.Info()
	if info.PendingEvents != 1 {
		t.Fatalf("queue after invalid acknowledgement = %+v", info)
	}
}
