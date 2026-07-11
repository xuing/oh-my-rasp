package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
)

type erroringLimiter struct{}

func (erroringLimiter) Allow(context.Context, string, int64, time.Duration) (control.RateLimitDecision, error) {
	return control.RateLimitDecision{}, errors.New("valkey unavailable")
}

type readinessStore struct {
	*control.MemoryStore
	readyErr error
}

func (r readinessStore) CheckReadiness(context.Context) error { return r.readyErr }

// Finding 1: internal errors must not leak their text to clients.
func TestWriteErrorDoesNotLeakInternalErrors(t *testing.T) {
	var logBuf bytes.Buffer
	server := NewServer(testMemoryStore(time.Now), slog.New(slog.NewTextHandler(&logBuf, nil)))

	rec := httptest.NewRecorder()
	server.writeError(rec, errors.New("pq: password authentication failed for secret_table"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for internal error, got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret_table") || strings.Contains(body, "password authentication") {
		t.Fatalf("internal error text leaked to client: %s", body)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if payload["error"] != "internal_error" || payload["message"] != "internal server error" {
		t.Fatalf("unexpected generic error body: %#v", payload)
	}
	if !strings.Contains(logBuf.String(), "secret_table") {
		t.Fatalf("expected the real internal error to be logged server-side, got %q", logBuf.String())
	}

	// Typed errors keep their descriptive message and status.
	typed := httptest.NewRecorder()
	server.writeError(typed, fmt.Errorf("%w: limit must be between 1 and 1000", control.ErrInvalid))
	if typed.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid error, got %d", typed.Code)
	}
	if !strings.Contains(typed.Body.String(), "limit must be between 1 and 1000") {
		t.Fatalf("expected typed error message to be preserved, got %s", typed.Body.String())
	}
}

// Finding 2: rate limiting must cover /metrics and daemon service routes while
// leaving liveness/readiness probes untouched.
func TestRateLimiterGuardsMetricsAndDaemonRoutes(t *testing.T) {
	handler := NewServer(testMemoryStore(time.Now), discardLogger()).
		WithRateLimiter(staticLimiter{allowed: false}, 1, time.Minute).
		Routes()

	for _, path := range []string{"/metrics", "/v1/service/dl/agent"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected %s to be rate limited, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected %s to bypass rate limiting, got %d", path, rec.Code)
		}
	}
}

// Finding 3: the login endpoint fails closed when the limiter backend errors,
// while ordinary traffic fails open.
func TestLoginFailsClosedWhenLimiterErrors(t *testing.T) {
	handler := NewServer(testMemoryStore(time.Now), discardLogger()).
		WithRateLimiter(erroringLimiter{}, 1, time.Minute).
		Routes()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@ohmyrasp.local","password":"change-me"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected login to fail closed on limiter error, got %d: %s", rec.Code, rec.Body.String())
	}

	// A non-login request must fail open (reaches the auth layer, returns 401).
	open := httptest.NewRecorder()
	handler.ServeHTTP(open, httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil))
	if open.Code == http.StatusServiceUnavailable {
		t.Fatalf("expected non-login request to fail open, got %d", open.Code)
	}
}

// Finding 3: repeated failed logins lock the account out.
func TestLoginLocksOutAfterRepeatedFailures(t *testing.T) {
	now := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	server := NewServer(testMemoryStore(func() time.Time { return now }), discardLogger())
	server.now = func() time.Time { return now }
	server.loginThrottle = newLoginThrottle(3, 15*time.Minute)
	handler := server.Routes()

	attempt := func(password string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@ohmyrasp.local","password":"`+password+`"}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 3; i++ {
		if code := attempt("wrong"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, code)
		}
	}
	if code := attempt("wrong"); code != http.StatusTooManyRequests {
		t.Fatalf("expected lockout after repeated failures, got %d", code)
	}
	// Even correct credentials are refused while locked out.
	if code := attempt("change-me"); code != http.StatusTooManyRequests {
		t.Fatalf("expected locked account to refuse valid credentials, got %d", code)
	}
}

// Finding 4: /metrics is gated behind a bearer token when configured.
func TestMetricsRequiresTokenWhenConfigured(t *testing.T) {
	handler := NewServer(testMemoryStore(time.Now), discardLogger()).
		WithMetricsToken("scrape-secret").
		Routes()

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"correct token", "Bearer scrape-secret", http.StatusOK},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", tc.token)
		}
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s: expected %d, got %d", tc.name, tc.want, rec.Code)
		}
		if tc.want == http.StatusOK && !strings.Contains(rec.Body.String(), "ohmyrasp_api_up 1") {
			t.Fatalf("%s: expected metrics body, got %s", tc.name, rec.Body.String())
		}
	}
}

// Finding 4: repeated scrapes are served from a short-lived cache.
func TestMetricsRenderCachedServesWithinTTL(t *testing.T) {
	current := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }
	store := testMemoryStore(clock)
	recorder := newMetricsRecorder()
	ctx := context.Background()

	first := recorder.renderCached(ctx, store, clock, 10*time.Second)
	if _, err := store.CreateApplication(ctx, "usr_admin", control.Application{Name: "Cache Mutator"}); err != nil {
		t.Fatalf("mutate store: %v", err)
	}
	if second := recorder.renderCached(ctx, store, clock, 10*time.Second); second != first {
		t.Fatal("expected a cached render within the TTL to ignore store mutations")
	}
	current = current.Add(11 * time.Second)
	if third := recorder.renderCached(ctx, store, clock, 10*time.Second); third == first {
		t.Fatal("expected a render after the TTL to reflect store mutations")
	}
}

// Finding 5: /readyz reflects real dependency health.
func TestReadyzReflectsDependencyHealth(t *testing.T) {
	healthy := NewServer(readinessStore{MemoryStore: testMemoryStore(time.Now)}, discardLogger()).Routes()
	rec := httptest.NewRecorder()
	healthy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ready") {
		t.Fatalf("expected healthy readiness, got %d: %s", rec.Code, rec.Body.String())
	}

	down := NewServer(readinessStore{MemoryStore: testMemoryStore(time.Now), readyErr: errors.New("postgres down")}, discardLogger()).Routes()
	rec = httptest.NewRecorder()
	down.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when a dependency is down, got %d: %s", rec.Code, rec.Body.String())
	}
}
