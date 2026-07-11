package httpapi

import (
	"context"
	"log/slog"
	"time"
)

// EventOutboxDrainer replays events that were persisted to the durable outbox
// but not yet delivered to ClickHouse analytics (for example after a transient
// ClickHouse outage during ingest). It is implemented by the postgres store.
type EventOutboxDrainer interface {
	DrainEventOutbox(ctx context.Context, limit int) (int, error)
}

type EventOutboxWorkerOptions struct {
	Interval  time.Duration
	BatchSize int
}

// EventOutboxWorker periodically drains the event ingest outbox so a single
// ClickHouse blip no longer permanently loses events from analytics. It mirrors
// the AlertDeliveryWorker tick/loop structure.
type EventOutboxWorker struct {
	drainer EventOutboxDrainer
	logger  *slog.Logger
	opts    EventOutboxWorkerOptions
}

func NewEventOutboxWorker(drainer EventOutboxDrainer, logger *slog.Logger, opts EventOutboxWorkerOptions) *EventOutboxWorker {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Interval <= 0 {
		opts.Interval = 15 * time.Second
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 200
	}
	return &EventOutboxWorker{drainer: drainer, logger: logger, opts: opts}
}

func (w *EventOutboxWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.opts.Interval)
	defer ticker.Stop()
	for {
		if drained, err := w.ProcessOnce(ctx); err != nil && ctx.Err() == nil {
			w.logger.Warn("event outbox drain failed", "error", err)
		} else if drained > 0 {
			w.logger.Info("event outbox drained", "count", drained)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ProcessOnce drains a single batch and returns the number of events delivered.
func (w *EventOutboxWorker) ProcessOnce(ctx context.Context) (int, error) {
	return w.drainer.DrainEventOutbox(ctx, w.opts.BatchSize)
}
