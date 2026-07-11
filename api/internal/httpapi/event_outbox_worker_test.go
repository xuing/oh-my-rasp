package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type fakeOutboxDrainer struct {
	mu         sync.Mutex
	calls      int
	batchSizes []int
	drained    int
	err        error
}

func (f *fakeOutboxDrainer) DrainEventOutbox(_ context.Context, limit int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.batchSizes = append(f.batchSizes, limit)
	return f.drained, f.err
}

func (f *fakeOutboxDrainer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestEventOutboxWorkerProcessOncePassesBatchSize(t *testing.T) {
	drainer := &fakeOutboxDrainer{drained: 4}
	worker := NewEventOutboxWorker(drainer, discardLogger(), EventOutboxWorkerOptions{BatchSize: 25})

	drained, err := worker.ProcessOnce(context.Background())
	if err != nil {
		t.Fatalf("process once: %v", err)
	}
	if drained != 4 {
		t.Fatalf("expected 4 drained events, got %d", drained)
	}
	if len(drainer.batchSizes) != 1 || drainer.batchSizes[0] != 25 {
		t.Fatalf("expected drain to use configured batch size, got %#v", drainer.batchSizes)
	}
}

func TestEventOutboxWorkerProcessOncePropagatesError(t *testing.T) {
	sentinel := errors.New("clickhouse unavailable")
	worker := NewEventOutboxWorker(&fakeOutboxDrainer{err: sentinel}, discardLogger(), EventOutboxWorkerOptions{})
	if _, err := worker.ProcessOnce(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("expected drain error to propagate, got %v", err)
	}
}

func TestEventOutboxWorkerRunTicks(t *testing.T) {
	drainer := &fakeOutboxDrainer{}
	worker := NewEventOutboxWorker(drainer, discardLogger(), EventOutboxWorkerOptions{Interval: time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for drainer.callCount() < 2 {
		select {
		case <-deadline:
			cancel()
			t.Fatalf("worker did not tick at least twice, got %d calls", drainer.callCount())
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop after context cancellation")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
}
