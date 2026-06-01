package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
)

func TestRateLimiterRejectsAPIRequests(t *testing.T) {
	server := NewServer(testMemoryStore(time.Now), slog.Default()).
		WithRateLimiter(staticLimiter{allowed: false}, 1, time.Minute)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@ohmyrasp.local","password":"change-me"}`))
	request.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(response, request)

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestRateLimiterSkipsHealthEndpoints(t *testing.T) {
	server := NewServer(testMemoryStore(time.Now), slog.Default()).
		WithRateLimiter(staticLimiter{allowed: false}, 1, time.Minute)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	server.Routes().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected health endpoint to skip rate limit, got %d", response.Code)
	}
}

type staticLimiter struct {
	allowed bool
}

func (s staticLimiter) Allow(_ context.Context, _ string, limit int64, window time.Duration) (control.RateLimitDecision, error) {
	return control.RateLimitDecision{
		Allowed:    s.allowed,
		Limit:      limit,
		Remaining:  0,
		RetryAfter: window,
	}, nil
}
