package httpapi

import (
	"testing"
	"time"
)

func TestLoginThrottleLocksAfterMaxFailures(t *testing.T) {
	base := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	throttle := newLoginThrottle(3, 15*time.Minute)
	key := loginThrottleKey("203.0.113.7", "admin@ohmyrasp.local")

	for i := 0; i < 2; i++ {
		if _, ok := throttle.retryAfter(key, base); !ok {
			t.Fatalf("attempt %d should be permitted before the limit", i)
		}
		throttle.recordFailure(key, base)
	}
	// Third failure trips the lockout.
	if _, ok := throttle.retryAfter(key, base); !ok {
		t.Fatal("third attempt should still be permitted")
	}
	throttle.recordFailure(key, base)

	retry, ok := throttle.retryAfter(key, base)
	if ok {
		t.Fatal("expected the account to be locked out after reaching max failures")
	}
	if retry <= 0 || retry > 15*time.Minute {
		t.Fatalf("unexpected retry-after duration: %s", retry)
	}

	// Still locked before the window elapses.
	if _, ok := throttle.retryAfter(key, base.Add(14*time.Minute)); ok {
		t.Fatal("expected the account to remain locked within the window")
	}
	// Unlocked once the window passes.
	if _, ok := throttle.retryAfter(key, base.Add(16*time.Minute)); !ok {
		t.Fatal("expected the account to unlock after the window elapses")
	}
}

func TestLoginThrottleSuccessResets(t *testing.T) {
	now := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	throttle := newLoginThrottle(3, time.Minute)
	key := loginThrottleKey("203.0.113.7", "admin@ohmyrasp.local")

	throttle.recordFailure(key, now)
	throttle.recordFailure(key, now)
	throttle.recordSuccess(key)

	// After a success, the failure count is cleared and a fresh set of failures
	// is required to trip the lock again.
	throttle.recordFailure(key, now)
	throttle.recordFailure(key, now)
	if _, ok := throttle.retryAfter(key, now); !ok {
		t.Fatal("expected success to reset the failure counter")
	}
}

func TestLoginThrottleKeysAreScopedPerAccountAndIP(t *testing.T) {
	if loginThrottleKey("10.0.0.1", "a@x") == loginThrottleKey("10.0.0.2", "a@x") {
		t.Fatal("expected different IPs to produce different keys")
	}
	if loginThrottleKey("10.0.0.1", "a@x") == loginThrottleKey("10.0.0.1", "b@x") {
		t.Fatal("expected different accounts to produce different keys")
	}
	if got := loginThrottleKey("10.0.0.1", ""); got != "ip:10.0.0.1" {
		t.Fatalf("expected ip-only key when account is unknown, got %q", got)
	}
}
