package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
)

func TestAlertDeliveryWorkerDeliversWebhookTargets(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC) }
	store := control.NewMemoryStoreWithSeed(now, control.MemorySeed{
		AdminEmail:        "admin@ohmyrasp.local",
		AdminPassword:     "change-me",
		ApplicationSecret: "app-secret",
		EnvironmentName:   "production",
		EnvironmentKind:   "production",
	})
	var received map[string]any
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST webhook, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("expected JSON content type, got %q", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode webhook payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()

	ctx := context.Background()
	rule, err := store.CreateAlertRule(ctx, "usr_admin", control.AlertRule{
		Name:      "High attack webhook",
		Enabled:   true,
		EventType: "attack",
		Severity:  "high",
		Condition: "severity == high",
		Target:    webhook.URL,
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	event, err := store.IngestEvent(ctx, control.SecurityEvent{
		Type:          "attack",
		ApplicationID: "app_default",
		EnvironmentID: "env_default",
		AgentID:       "agt_live",
		Severity:      "high",
		Message:       "blocked request",
	})
	if err != nil {
		t.Fatalf("ingest event: %v", err)
	}

	worker := NewAlertDeliveryWorker(store, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)), AlertDeliveryWorkerOptions{})
	worker.now = func() time.Time { return now().Add(time.Minute) }
	processed, err := worker.ProcessOnce(ctx)
	if err != nil {
		t.Fatalf("process alert deliveries: %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected one processed delivery, got %d", processed)
	}
	if received["alert_rule_id"] != rule.ID || received["event_id"] != event.ID || received["severity"] != "high" {
		t.Fatalf("unexpected webhook payload: %#v", received)
	}
	deliveries, err := store.ListAlertDeliveries(ctx)
	if err != nil {
		t.Fatalf("list alert deliveries: %v", err)
	}
	delivery := alertDeliveryForRule(t, deliveries, rule.ID)
	if delivery.Status != "delivered" || delivery.Attempts != 1 || delivery.DeliveredAt == nil || delivery.LastError != "" {
		t.Fatalf("expected delivered webhook delivery, got %#v", delivery)
	}
}

func TestAlertDeliveryWorkerFailsUnsupportedTargets(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC) }
	store := control.NewMemoryStoreWithSeed(now, control.MemorySeed{
		AdminEmail:        "admin@ohmyrasp.local",
		AdminPassword:     "change-me",
		ApplicationSecret: "app-secret",
		EnvironmentName:   "production",
		EnvironmentKind:   "production",
	})
	ctx := context.Background()
	rule, err := store.CreateAlertRule(ctx, "usr_admin", control.AlertRule{
		Name:      "Unsupported target",
		Enabled:   true,
		EventType: "attack",
		Severity:  "medium",
		Condition: "severity == medium",
		Target:    "webhook://security-operations",
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	if _, err := store.IngestEvent(ctx, control.SecurityEvent{
		Type:          "attack",
		ApplicationID: "app_default",
		EnvironmentID: "env_default",
		AgentID:       "agt_live",
		Severity:      "medium",
		Message:       "monitored request",
	}); err != nil {
		t.Fatalf("ingest event: %v", err)
	}

	worker := NewAlertDeliveryWorker(store, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)), AlertDeliveryWorkerOptions{})
	processed, err := worker.ProcessOnce(ctx)
	if err != nil {
		t.Fatalf("process alert deliveries: %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected one processed delivery, got %d", processed)
	}
	deliveries, err := store.ListAlertDeliveries(ctx)
	if err != nil {
		t.Fatalf("list alert deliveries: %v", err)
	}
	delivery := alertDeliveryForRule(t, deliveries, rule.ID)
	if delivery.Status != "failed" || delivery.Attempts != 1 || delivery.LastError == "" || delivery.DeliveredAt != nil {
		t.Fatalf("expected failed unsupported delivery, got %#v", delivery)
	}
}

func alertDeliveryForRule(t *testing.T, deliveries []control.AlertDelivery, ruleID string) control.AlertDelivery {
	t.Helper()
	for _, delivery := range deliveries {
		if delivery.AlertRuleID == ruleID {
			return delivery
		}
	}
	t.Fatalf("missing alert delivery for rule %s in %#v", ruleID, deliveries)
	return control.AlertDelivery{}
}
