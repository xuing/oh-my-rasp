package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

const (
	loginPath = "/api/v1/auth/login"

	defaultLoginMaxFailures = 5
	defaultLoginLockout     = 15 * time.Minute

	maxLoginBodyPeek = 1 << 20 // 1 MiB
)

// loginThrottle applies a per-key (IP + account) failed-login backoff. It is an
// in-process defence that supplements the distributed rate limiter so that
// credential stuffing is throttled even when the shared limiter is unavailable.
type loginThrottle struct {
	mu          sync.Mutex
	entries     map[string]*loginThrottleEntry
	maxFailures int
	lockout     time.Duration
}

type loginThrottleEntry struct {
	failures    int
	updatedAt   time.Time
	lockedUntil time.Time
}

func newLoginThrottle(maxFailures int, lockout time.Duration) *loginThrottle {
	if maxFailures <= 0 {
		maxFailures = defaultLoginMaxFailures
	}
	if lockout <= 0 {
		lockout = defaultLoginLockout
	}
	return &loginThrottle{
		entries:     make(map[string]*loginThrottleEntry),
		maxFailures: maxFailures,
		lockout:     lockout,
	}
}

// retryAfter reports whether a login attempt for key is currently permitted. If
// the key is locked out it returns the remaining backoff duration and false.
func (t *loginThrottle) retryAfter(key string, now time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.entries[key]
	if entry == nil {
		return 0, true
	}
	if entry.lockedUntil.After(now) {
		return entry.lockedUntil.Sub(now), false
	}
	// The lock expired or the tracking window went stale; forget the key so
	// counting restarts and the map does not grow without bound.
	if !entry.lockedUntil.IsZero() || now.Sub(entry.updatedAt) > t.lockout {
		delete(t.entries, key)
	}
	return 0, true
}

func (t *loginThrottle) recordFailure(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.entries[key]
	if entry == nil || now.Sub(entry.updatedAt) > t.lockout {
		entry = &loginThrottleEntry{}
		t.entries[key] = entry
	}
	entry.updatedAt = now
	entry.failures++
	if entry.failures >= t.maxFailures {
		entry.lockedUntil = now.Add(t.lockout)
		entry.failures = 0
	}
}

func (t *loginThrottle) recordSuccess(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// throttleLogin wraps the login handler with the per-account backoff. Failed
// (401) attempts increment the counter, successful ones reset it.
func (s *Server) throttleLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.loginThrottle == nil {
			next(w, r)
			return
		}
		key := loginThrottleKey(clientIP(r), peekLoginEmail(r))
		if retry, ok := s.loginThrottle.retryAfter(key, s.clock()); !ok {
			s.writeLoginLocked(w, retry)
			return
		}
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next(wrapped, r)
		switch status := wrapped.Status(); {
		case status == http.StatusUnauthorized:
			s.loginThrottle.recordFailure(key, s.clock())
		case status >= 200 && status < 300:
			s.loginThrottle.recordSuccess(key)
		}
	}
}

func (s *Server) writeLoginLocked(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int64(retryAfter / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":       "login_locked",
		"message":     "too many failed login attempts, try again later",
		"retry_after": retryAfter.String(),
		"status":      strconv.Itoa(http.StatusTooManyRequests),
	})
}

func loginThrottleKey(ip string, email string) string {
	if email == "" {
		return "ip:" + ip
	}
	return "ip:" + ip + "|acct:" + email
}

// peekLoginEmail extracts the login account from the request body without
// consuming it: the body is restored so the downstream handler can decode it.
func peekLoginEmail(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxLoginBodyPeek))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	var payload struct {
		Email string `json:"email"`
	}
	_ = json.Unmarshal(body, &payload)
	return strings.ToLower(strings.TrimSpace(payload.Email))
}

func isLoginRequest(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == loginPath
}
