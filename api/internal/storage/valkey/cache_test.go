package valkey

import "testing"

func TestCacheKeyNamespace(t *testing.T) {
	cache := &Cache{keyPrefix: keyRoot}
	if got := cache.key(sessionPrefix + "abc"); got != "ohmyrasp:session:abc" {
		t.Fatalf("default session key changed: %q", got)
	}
	if got := cache.agentPolicyKey("3", "agt_1"); got != "ohmyrasp:agent-policy:3:agt_1" {
		t.Fatalf("default policy key changed: %q", got)
	}
	if got := cache.key(policyCacheEpoch); got != "ohmyrasp:agent-policy:epoch" {
		t.Fatalf("default epoch key changed: %q", got)
	}
	if got := cache.key(rateLimitKeyPrefix + "login"); got != "ohmyrasp:ratelimit:login" {
		t.Fatalf("default rate-limit key changed: %q", got)
	}

	cache.WithKeyNamespace(" :tenant-a: ")
	if got := cache.key(policyCacheEpoch); got != "ohmyrasp:tenant-a:agent-policy:epoch" {
		t.Fatalf("namespaced epoch key: %q", got)
	}
	if got := cache.agentPolicyKey("0", "agt_1"); got != "ohmyrasp:tenant-a:agent-policy:0:agt_1" {
		t.Fatalf("namespaced policy key: %q", got)
	}

	cache.WithKeyNamespace("")
	if got := cache.key(sessionPrefix + "abc"); got != "ohmyrasp:session:abc" {
		t.Fatalf("empty namespace should restore default keys: %q", got)
	}
}
