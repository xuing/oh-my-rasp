package control

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestValidateRulesParsesSupportedExpressions(t *testing.T) {
	validation := ValidateRules([]Rule{
		{
			Name:       "Block command",
			Hook:       "command",
			Algorithm:  "command_common",
			Action:     "block",
			Severity:   "high",
			Expression: `message contains "Runtime.exec" && attributes.source == "policy-console"`,
		},
	})
	if !validation.Valid {
		t.Fatalf("expected valid rule, got %#v", validation.Errors)
	}
}

func TestDefaultPolicyRulesCoverSupportedAlgorithms(t *testing.T) {
	catalog := SupportedPolicyAlgorithmCatalog()
	rules := DefaultPolicyRules()
	validation := ValidateRules(rules)
	if !validation.Valid {
		t.Fatalf("expected default rules to validate, got %#v", validation.Errors)
	}
	expected := 0
	seen := map[string]bool{}
	for _, item := range catalog.Items {
		if len(item.Algorithms) == 0 {
			t.Fatalf("expected algorithms for hook %s", item.Hook)
		}
		expected += len(item.Algorithms)
		for _, algorithm := range item.Algorithms {
			seen[item.Hook+"|"+algorithm] = false
		}
	}
	if len(rules) != expected {
		t.Fatalf("expected %d default rules, got %d", expected, len(rules))
	}
	for _, rule := range rules {
		key := rule.Hook + "|" + rule.Algorithm
		if _, ok := seen[key]; !ok {
			t.Fatalf("unexpected default rule %#v", rule)
		}
		seen[key] = true
	}
	for key, ok := range seen {
		if !ok {
			t.Fatalf("missing default rule for %s", key)
		}
	}
}

func TestValidateRulesRejectsUnsupportedRules(t *testing.T) {
	validation := ValidateRules([]Rule{
		{Name: "Bad hook", Hook: "unknown", Action: "block", Expression: "message contains test"},
		{Name: "Bad regex", Hook: "command", Action: "block", Expression: "message matches ["},
		{Name: "Bad algorithm", Hook: "command", Algorithm: "sql_regex", Action: "block", Expression: "test"},
	})
	if validation.Valid {
		t.Fatal("expected invalid rules")
	}
	joined := strings.Join(validation.Errors, "\n")
	for _, want := range []string{"hook is not supported", "regex is invalid", "algorithm is not supported"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %q in errors: %#v", want, validation.Errors)
		}
	}
}

func TestRuleTestEvaluatesStructuredConditions(t *testing.T) {
	result := TestRule(
		Rule{
			Name:       "Command detector",
			Hook:       "command",
			Algorithm:  "command_common",
			Action:     "block",
			Expression: `message contains "Runtime.exec" && attributes.source == "policy-console"`,
		},
		SecurityEvent{
			Hook:      "command",
			Algorithm: "command_common",
			Severity:  "high",
			Message:   "java.lang.Runtime.exec invoked",
			Attributes: map[string]any{
				"source": "policy-console",
			},
		},
	)
	if !result.Matched || result.Confidence != 95 || result.Action != "block" {
		t.Fatalf("unexpected rule test result: %#v", result)
	}
}

func TestRuleTestRequiresAllConditions(t *testing.T) {
	result := TestRule(
		Rule{Hook: "command", Action: "block", Expression: `message contains "Runtime.exec" && severity == "critical"`},
		SecurityEvent{Hook: "command", Severity: "low", Message: "java.lang.Runtime.exec invoked", Attributes: map[string]any{}},
	)
	if result.Matched || result.Confidence != 0 {
		t.Fatalf("expected no match, got %#v", result)
	}
}

func TestMemoryStoreHashesPasswords(t *testing.T) {
	ctx := context.Background()
	now := func() time.Time { return time.Unix(1700000000, 0).UTC() }
	store := NewMemoryStoreWithSeed(now, MemorySeed{
		AdminEmail:    "admin@example.test",
		AdminPassword: "change-me-admin",
		AdminName:     "Default Admin",
	})

	admin := store.users["usr_admin"]
	if admin.PasswordHash == "change-me-admin" {
		t.Fatal("bootstrap admin password was stored as plaintext")
	}
	if !strings.HasPrefix(admin.PasswordHash, "$2") {
		t.Fatalf("expected bcrypt hash for bootstrap admin, got %q", admin.PasswordHash)
	}
	if _, _, err := store.Login(ctx, admin.Email, "change-me-admin"); err != nil {
		t.Fatalf("expected bootstrap admin login with original password: %v", err)
	}
	if _, _, err := store.Login(ctx, admin.Email, admin.PasswordHash); err == nil {
		t.Fatal("stored password hash should not authenticate as the plaintext password")
	}

	created, err := store.CreateUser(ctx, admin.ID, User{
		Email: "analyst@example.test",
		Name:  "Analyst",
		Roles: []Role{RoleViewer},
	}, "change-me-analyst")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if created.PasswordHash != "" {
		t.Fatalf("public user leaked password hash: %#v", created)
	}
	stored := store.users[created.ID]
	if stored.PasswordHash == "change-me-analyst" {
		t.Fatal("created user password was stored as plaintext")
	}
	if _, _, err := store.Login(ctx, created.Email, "change-me-analyst"); err != nil {
		t.Fatalf("expected created user login with original password: %v", err)
	}
	if _, _, err := store.Login(ctx, created.Email, stored.PasswordHash); err == nil {
		t.Fatal("stored password hash should not authenticate as the created user's plaintext password")
	}
}

func TestMemoryStoreApplicationSettingsAreScoped(t *testing.T) {
	ctx := context.Background()
	now := func() time.Time { return time.Unix(1700000000, 0).UTC() }
	store := NewMemoryStoreWithSeed(now, MemorySeed{})
	appB, err := store.CreateApplication(ctx, "usr_admin", Application{Name: "Second App"})
	if err != nil {
		t.Fatalf("create second app: %v", err)
	}

	updated, err := store.UpsertApplicationSetting(ctx, "usr_admin", ApplicationSetting{
		ApplicationID: "app_default",
		Key:           "protection.allowlist",
		Value: map[string]any{
			"enabled": true,
			"mode":    "enforce",
			"entries": []string{"/checkout/*"},
		},
	})
	if err != nil {
		t.Fatalf("upsert app setting: %v", err)
	}
	if updated.ApplicationID != "app_default" {
		t.Fatalf("unexpected updated scope: %#v", updated)
	}
	configA, err := store.ResolveApplicationConfig(ctx, "app_default", "env_default")
	if err != nil {
		t.Fatalf("resolve app A config: %v", err)
	}
	configB, err := store.ResolveApplicationConfig(ctx, appB.ID, "")
	if err != nil {
		t.Fatalf("resolve app B config: %v", err)
	}
	if configA.Allowlist["enabled"] != true {
		t.Fatalf("expected app A allowlist enabled, got %#v", configA.Allowlist)
	}
	if configB.Allowlist["enabled"] == true {
		t.Fatalf("app B inherited app A allowlist: %#v", configB.Allowlist)
	}

	policy, err := store.CreatePolicy(ctx, "usr_admin", PolicySet{Name: "Scoped Policy"})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	policy, err = store.AddPolicyVersion(ctx, "usr_admin", policy.ID, []Rule{{
		Name:       "SQL",
		Hook:       "sql",
		Algorithm:  "sql_userinput",
		Action:     "block",
		Severity:   "high",
		Expression: `algorithm == "sql_userinput"`,
	}})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}
	if _, err := store.RolloutPolicy(ctx, "usr_admin", policy.ID, PolicyRollout{Version: 1, CanaryPercent: 100, ApplicationID: "app_default"}); err != nil {
		t.Fatalf("roll out policy: %v", err)
	}
	agent, err := store.RegisterAgent(ctx, "app_default", store.applications["app_default"].Secret, Agent{
		EnvironmentID: "env_default",
		Hostname:      "api-1",
		Runtime:       "java",
		Version:       "1.0.0",
	})
	if err != nil {
		t.Fatalf("register agent: %v", err)
	}
	pulled, err := store.GetAgentPolicy(ctx, agent.ID)
	if err != nil {
		t.Fatalf("get agent policy: %v", err)
	}
	if pulled.Config == nil || pulled.Config.Allowlist["enabled"] != true {
		t.Fatalf("agent did not receive app-scoped config: %#v", pulled.Config)
	}
}

func TestMemoryStoreAlertRulesAreApplicationScoped(t *testing.T) {
	ctx := context.Background()
	now := func() time.Time { return time.Unix(1700000000, 0).UTC() }
	store := NewMemoryStoreWithSeed(now, MemorySeed{})
	appB, err := store.CreateApplication(ctx, "usr_admin", Application{Name: "Second App"})
	if err != nil {
		t.Fatalf("create second app: %v", err)
	}
	rule, err := store.CreateAlertRule(ctx, "usr_admin", AlertRule{
		ApplicationID: "app_default",
		Name:          "App A critical attack",
		Enabled:       true,
		EventType:     "attack",
		Severity:      "critical",
		Condition:     "severity == critical",
		Target:        "secops",
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	if rule.ApplicationID != "app_default" {
		t.Fatalf("expected app-scoped rule, got %#v", rule)
	}
	for _, event := range []SecurityEvent{
		{ID: "evt_a", Type: "attack", ApplicationID: "app_default", EnvironmentID: "env_default", AgentID: "agt_a", Severity: "critical", Message: "A"},
		{ID: "evt_b", Type: "attack", ApplicationID: appB.ID, EnvironmentID: "env_b", AgentID: "agt_b", Severity: "critical", Message: "B"},
	} {
		if _, err := store.IngestEvent(ctx, event); err != nil {
			t.Fatalf("ingest event %s: %v", event.ID, err)
		}
	}
	aDeliveries, err := store.ListAlertDeliveries(ctx, AlertDeliveryQuery{ApplicationID: "app_default"})
	if err != nil {
		t.Fatalf("list A deliveries: %v", err)
	}
	bDeliveries, err := store.ListAlertDeliveries(ctx, AlertDeliveryQuery{ApplicationID: appB.ID})
	if err != nil {
		t.Fatalf("list B deliveries: %v", err)
	}
	if got := countDeliveriesForRule(aDeliveries, rule.ID); got != 1 {
		t.Fatalf("expected one A delivery for scoped rule, got %d in %#v", got, aDeliveries)
	}
	if got := countDeliveriesForRule(bDeliveries, rule.ID); got != 0 {
		t.Fatalf("expected no B deliveries from A rule, got %d in %#v", got, bDeliveries)
	}
}

func countDeliveriesForRule(deliveries []AlertDelivery, ruleID string) int {
	var count int
	for _, delivery := range deliveries {
		if delivery.AlertRuleID == ruleID {
			count++
		}
	}
	return count
}
