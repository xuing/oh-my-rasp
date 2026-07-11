package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/ohmyrasp/control-plane/internal/storage/migrations"
)

// captureAnalytics is a minimal EventAnalytics used to observe replayed events
// without a live ClickHouse instance.
type captureAnalytics struct {
	events []control.SecurityEvent
	err    error
}

func (c *captureAnalytics) IngestEvent(_ context.Context, event control.SecurityEvent) error {
	if c.err != nil {
		return c.err
	}
	c.events = append(c.events, event)
	return nil
}

func (c *captureAnalytics) IngestDependency(context.Context, control.Dependency, string) error {
	return nil
}

func (c *captureAnalytics) ListEvents(context.Context, control.SecurityEventQuery) ([]control.SecurityEvent, error) {
	return nil, nil
}

func (c *captureAnalytics) EventOverview(context.Context) (control.EventOverview, error) {
	return control.EventOverview{}, nil
}

func (c *captureAnalytics) Observability(context.Context, control.ObservabilityQuery) (control.ObservabilityReport, error) {
	return control.ObservabilityReport{}, nil
}

func TestDrainEventOutboxIntegration(t *testing.T) {
	dsn := os.Getenv("OHMYRASP_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set OHMYRASP_POSTGRES_TEST_DSN to run postgres integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	if err := migrations.Apply(ctx, db, migrations.Postgres); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := func() time.Time { return time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC) }
	store := NewStore(db, now).WithBootstrapAdmin("admin@ohmyrasp.local", "postgres-test-admin-password", "Default Admin")
	if err := store.EnsureSeedData(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Ingest with no analytics wired, so the event lands in the outbox and stays
	// undelivered (delivered_to_clickhouse_at IS NULL) — the data-loss scenario.
	event, err := store.IngestEvent(ctx, control.SecurityEvent{
		Type:          "attack",
		ApplicationID: defaultAppID,
		EnvironmentID: defaultEnvironmentID,
		Severity:      "high",
		Message:       "drain me",
	})
	if err != nil {
		t.Fatalf("ingest event: %v", err)
	}
	if count, err := store.UndeliveredEventOutboxCount(ctx); err != nil {
		t.Fatalf("undelivered count: %v", err)
	} else if count < 1 {
		t.Fatalf("expected at least one undelivered event, got %d", count)
	}

	// Now wire analytics and drain: the event must be replayed and stamped.
	capture := &captureAnalytics{}
	store.WithEventAnalytics(capture)
	drained, err := store.DrainEventOutbox(ctx, 100)
	if err != nil {
		t.Fatalf("drain outbox: %v", err)
	}
	if drained < 1 {
		t.Fatalf("expected drain to deliver at least one event, got %d", drained)
	}
	found := false
	for _, replayed := range capture.events {
		if replayed.ID == event.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected event %s to be replayed to analytics, got %#v", event.ID, capture.events)
	}
	if remaining, err := store.UndeliveredEventOutboxCount(ctx); err != nil {
		t.Fatalf("undelivered count after drain: %v", err)
	} else if remaining != 0 {
		t.Fatalf("expected no undelivered events after drain, got %d", remaining)
	}
}
