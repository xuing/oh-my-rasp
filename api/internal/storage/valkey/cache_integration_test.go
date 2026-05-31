package valkey

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
)

func TestCacheIntegrationValkeyWorkflow(t *testing.T) {
	addr := os.Getenv("OHMYRASP_VALKEY_TEST_ADDR")
	if addr == "" {
		t.Skip("set OHMYRASP_VALKEY_TEST_ADDR to run valkey integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cache, err := New(addr, os.Getenv("OHMYRASP_VALKEY_TEST_USERNAME"), os.Getenv("OHMYRASP_VALKEY_TEST_PASSWORD"))
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	defer cache.Close()
	if err := cache.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	suffix := time.Now().UnixNano()
	sessionHash := fmt.Sprintf("session_%d", suffix)
	user := control.User{
		ID:        "usr_cache",
		Email:     "cache@example.test",
		Name:      "Cache User",
		Roles:     []control.Role{control.RoleAdmin},
		CreatedAt: time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
	}
	if err := cache.SetSessionUser(ctx, sessionHash, user, time.Minute); err != nil {
		t.Fatalf("set session user: %v", err)
	}
	gotUser, found, err := cache.GetSessionUser(ctx, sessionHash)
	if err != nil {
		t.Fatalf("get session user: %v", err)
	}
	if !found || gotUser.ID != user.ID || gotUser.PasswordHash != "" {
		t.Fatalf("unexpected cached user found=%v user=%#v", found, gotUser)
	}
	if err := cache.DeleteSession(ctx, sessionHash); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if _, found, err := cache.GetSessionUser(ctx, sessionHash); err != nil || found {
		t.Fatalf("expected deleted session miss, found=%v err=%v", found, err)
	}

	agentID := fmt.Sprintf("agt_cache_%d", suffix)
	policy := control.PolicyVersion{
		Version: 1,
		Status:  "active",
		Rules: []control.Rule{{
			ID:     "rul_cache",
			Name:   "Cache Rule",
			Hook:   "sql",
			Action: "block",
		}},
		CanaryPercent: 100,
		CreatedAt:     time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
	}
	if err := cache.SetAgentPolicy(ctx, agentID, policy, time.Minute); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	gotPolicy, found, err := cache.GetAgentPolicy(ctx, agentID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if !found || gotPolicy.Version != policy.Version || len(gotPolicy.Rules) != 1 {
		t.Fatalf("unexpected cached policy found=%v policy=%#v", found, gotPolicy)
	}
	if err := cache.InvalidateAgentPolicies(ctx); err != nil {
		t.Fatalf("invalidate policies: %v", err)
	}
	if _, found, err := cache.GetAgentPolicy(ctx, agentID); err != nil || found {
		t.Fatalf("expected invalidated policy miss, found=%v err=%v", found, err)
	}

	rateKey := fmt.Sprintf("rate_%d", suffix)
	first, err := cache.Allow(ctx, rateKey, 2, time.Minute)
	if err != nil {
		t.Fatalf("rate first: %v", err)
	}
	second, err := cache.Allow(ctx, rateKey, 2, time.Minute)
	if err != nil {
		t.Fatalf("rate second: %v", err)
	}
	third, err := cache.Allow(ctx, rateKey, 2, time.Minute)
	if err != nil {
		t.Fatalf("rate third: %v", err)
	}
	if !first.Allowed || !second.Allowed || third.Allowed || third.Remaining != 0 {
		t.Fatalf("unexpected rate decisions: %#v %#v %#v", first, second, third)
	}
}
