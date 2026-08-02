package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"

	"github.com/Relayward/relayward-agent/internal/eventqueue"
)

const (
	eventUploadBatchBytes        = 512 << 10
	maximumEventAckResponseBytes = 64 << 10
)

type eventUploader struct {
	endpoint   string
	credential string
	httpClient *http.Client
	queue      *eventqueue.Store
}

type fatalEventUploadError struct {
	err error
}

func (failure *fatalEventUploadError) Error() string { return failure.err.Error() }
func (failure *fatalEventUploadError) Unwrap() error { return failure.err }

func (uploader *eventUploader) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		hadEvents, err := uploader.uploadOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			backoff = time.Second
			delay := time.Second
			if hadEvents {
				delay = 100 * time.Millisecond
			}
			if !uploader.wait(ctx, delay, true) {
				return nil
			}
			continue
		}
		var fatal *fatalEventUploadError
		if errors.As(err, &fatal) {
			return fatal.err
		}
		if !uploader.wait(ctx, backoff, false) {
			return nil
		}
		backoff *= 2
		if backoff > time.Minute {
			backoff = time.Minute
		}
	}
}

func (uploader *eventUploader) uploadOnce(ctx context.Context) (bool, error) {
	batch, err := uploader.queue.Batch(agentv1.MaximumEventBatchEvents, eventUploadBatchBytes)
	if errors.Is(err, eventqueue.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, &fatalEventUploadError{err: fmt.Errorf("read event queue: %w", err)}
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return true, &fatalEventUploadError{err: fmt.Errorf("encode event batch: %w", err)}
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		return true, &fatalEventUploadError{err: fmt.Errorf("initialize event compression: %w", err)}
	}
	if _, err := writer.Write(raw); err != nil {
		return true, &fatalEventUploadError{err: fmt.Errorf("compress event batch: %w", err)}
	}
	if err := writer.Close(); err != nil {
		return true, &fatalEventUploadError{err: fmt.Errorf("finish event compression: %w", err)}
	}
	if compressed.Len() > agentv1.MaximumEventBatchCompressedBytes {
		return true, &fatalEventUploadError{err: errors.New("compressed event batch exceeds protocol limit")}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, uploader.endpoint, &compressed)
	if err != nil {
		return true, &fatalEventUploadError{err: errors.New("create event upload request")}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+uploader.credential)
	request.Header.Set("Content-Encoding", "gzip")
	request.Header.Set("Content-Type", "application/json")
	response, err := uploader.httpClient.Do(request)
	if err != nil {
		return true, errors.New("event endpoint unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumEventAckResponseBytes+1))
	if err != nil {
		return true, errors.New("read event acknowledgement")
	}
	if len(body) > maximumEventAckResponseBytes {
		return true, errors.New("event acknowledgement exceeds limit")
	}
	if response.StatusCode != http.StatusOK {
		return true, fmt.Errorf("event endpoint returned HTTP %d", response.StatusCode)
	}
	ack, err := agentv1.DecodeEventBatchAck(bytes.NewReader(body))
	if err != nil {
		return true, errors.New("invalid event acknowledgement")
	}
	if ack.StreamID != batch.StreamID || ack.HighestContiguousSequence < batch.FirstSequence || ack.HighestContiguousSequence > batch.LastSequence {
		return true, errors.New("event acknowledgement is outside the uploaded batch")
	}
	if err := uploader.queue.Acknowledge(ack.StreamID, ack.HighestContiguousSequence); err != nil {
		return true, &fatalEventUploadError{err: fmt.Errorf("persist event acknowledgement: %w", err)}
	}
	return true, nil
}

func (uploader *eventUploader) wait(ctx context.Context, delay time.Duration, wakeOnEvent bool) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	if !wakeOnEvent {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	select {
	case <-ctx.Done():
		return false
	case <-uploader.queue.Notifications():
		return true
	case <-timer.C:
		return true
	}
}
