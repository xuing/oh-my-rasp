package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
)

type AlertDeliveryWorkerOptions struct {
	Interval       time.Duration
	RequestTimeout time.Duration
	BatchSize      int
}

type AlertDeliveryWorker struct {
	store  control.Store
	logger *slog.Logger
	client *http.Client
	now    func() time.Time
	opts   AlertDeliveryWorkerOptions
}

func NewAlertDeliveryWorker(store control.Store, logger *slog.Logger, opts AlertDeliveryWorkerOptions) *AlertDeliveryWorker {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Second
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 5 * time.Second
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 50
	}
	return &AlertDeliveryWorker{
		store:  store,
		logger: logger,
		client: &http.Client{Timeout: opts.RequestTimeout},
		now:    time.Now,
		opts:   opts,
	}
}

func (w *AlertDeliveryWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.opts.Interval)
	defer ticker.Stop()
	for {
		if _, err := w.ProcessOnce(ctx); err != nil && ctx.Err() == nil {
			w.logger.Warn("alert delivery processing failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *AlertDeliveryWorker) ProcessOnce(ctx context.Context) (int, error) {
	deliveries, err := w.store.ListQueuedAlertDeliveries(ctx, w.opts.BatchSize)
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, delivery := range deliveries {
		status, lastError, deliveredAt := w.deliver(ctx, delivery)
		if _, err := w.store.RecordAlertDeliveryAttempt(ctx, delivery.ID, status, lastError, deliveredAt); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func (w *AlertDeliveryWorker) deliver(ctx context.Context, delivery control.AlertDelivery) (string, string, *time.Time) {
	target := strings.TrimSpace(delivery.Target)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" {
		return "failed", "alert target must be an http or https webhook URL", nil
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "failed", fmt.Sprintf("unsupported alert target scheme %q", parsed.Scheme), nil
	}
	if err := w.postWebhook(ctx, target, delivery); err != nil {
		return "failed", err.Error(), nil
	}
	deliveredAt := w.now().UTC()
	return "delivered", "", &deliveredAt
}

func (w *AlertDeliveryWorker) postWebhook(ctx context.Context, target string, delivery control.AlertDelivery) error {
	payload := map[string]any{
		"id":              delivery.ID,
		"alert_rule_id":   delivery.AlertRuleID,
		"alert_rule_name": delivery.AlertRuleName,
		"event_id":        delivery.EventID,
		"event_type":      delivery.EventType,
		"severity":        delivery.Severity,
		"created_at":      delivery.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "ohmyrasp-alert-delivery")
	response, err := w.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}
