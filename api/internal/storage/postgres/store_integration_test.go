package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/ohmyrasp/control-plane/internal/storage/migrations"
	vkstore "github.com/ohmyrasp/control-plane/internal/storage/valkey"
)

func TestStoreIntegrationPostgresWorkflow(t *testing.T) {
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

	now := func() time.Time { return time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC) }
	store := NewStore(db, now).WithBootstrapAdmin("admin@ohmyrasp.local", "postgres-test-admin-password", "Default Admin")
	var cache *vkstore.Cache
	if addr := os.Getenv("OHMYRASP_VALKEY_TEST_ADDR"); addr != "" {
		cache, err = vkstore.New(addr, os.Getenv("OHMYRASP_VALKEY_TEST_USERNAME"), os.Getenv("OHMYRASP_VALKEY_TEST_PASSWORD"))
		if err != nil {
			t.Fatalf("new valkey cache: %v", err)
		}
		defer cache.Close()
		store.WithSessionCache(cache).WithAgentPolicyCache(cache)
	}
	if err := store.EnsureSeedData(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	defaultSettings, err := store.ListSystemSettings(ctx)
	if err != nil {
		t.Fatalf("list default settings: %v", err)
	}
	for _, key := range []string{"agent.minimum_version", "events.retention", "protection.allowlist", "protection.hardening", "dependency.vulnerability_policy"} {
		if !containsSetting(defaultSettings, key) {
			t.Fatalf("expected seeded setting %s in %#v", key, defaultSettings)
		}
	}
	defaultAlertRules, err := store.ListAlertRules(ctx)
	if err != nil {
		t.Fatalf("list default alert rules: %v", err)
	}
	if !containsAlertRule(defaultAlertRules, "alr_critical_attack") {
		t.Fatalf("expected seeded alert rules in %#v", defaultAlertRules)
	}

	session, admin, err := store.Login(ctx, "admin@ohmyrasp.local", "postgres-test-admin-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if session.Token == "" || session.UserID != admin.ID {
		t.Fatalf("unexpected session: %#v admin=%#v", session, admin)
	}
	if _, err := store.UserForToken(ctx, session.Token); err != nil {
		t.Fatalf("user for token: %v", err)
	}
	if cache != nil {
		if cached, found, err := cache.GetSessionUser(ctx, hashSecret(session.Token)); err != nil || !found || cached.ID != admin.ID {
			t.Fatalf("expected valkey session cache hit, found=%v user=%#v err=%v", found, cached, err)
		}
	}

	suffix := time.Now().UnixNano()
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if !containsUser(users, admin.ID) {
		t.Fatalf("expected seeded admin user in %#v", users)
	}
	analyst, err := store.CreateUser(ctx, admin.ID, control.User{
		Email: fmt.Sprintf("analyst-%d@example.test", suffix),
		Name:  "Security Analyst",
		Roles: []control.Role{control.RoleSecurityEngineer},
	}, "change-me-2")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if analyst.PasswordHash != "" {
		t.Fatalf("expected public user without password hash: %#v", analyst)
	}
	analystSession, _, err := store.Login(ctx, analyst.Email, "change-me-2")
	if err != nil {
		t.Fatalf("login analyst: %v", err)
	}
	if _, err := store.UserForToken(ctx, analystSession.Token); err != nil {
		t.Fatalf("analyst token before disable: %v", err)
	}
	disabledAnalyst, err := store.UpdateUser(ctx, admin.ID, analyst.ID, control.User{
		Name:       analyst.Name,
		Roles:      []control.Role{control.RoleViewer},
		DisabledAt: &time.Time{},
	})
	if err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if disabledAnalyst.DisabledAt == nil {
		t.Fatalf("expected disabled user timestamp: %#v", disabledAnalyst)
	}
	if _, err := store.UserForToken(ctx, analystSession.Token); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("expected disabled user token to be unauthorized, got %v", err)
	}

	app, err := store.CreateApplication(ctx, admin.ID, control.Application{
		Name:        fmt.Sprintf("Payments API %d", suffix),
		Description: "PCI scoped service",
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	if app.Secret == "" {
		t.Fatal("expected one-time application secret")
	}
	env, err := store.CreateEnvironment(ctx, admin.ID, app.ID, control.Environment{Name: "staging", Kind: "staging"})
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	daemonToken, err := store.DaemonAccessToken(ctx)
	if err != nil {
		t.Fatalf("daemon token: %v", err)
	}
	if daemonToken.AccessToken == "" {
		t.Fatalf("expected daemon access token: %#v", daemonToken)
	}
	if _, err := store.GetDaemonApplication(ctx, "wrong-token", app.ID); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("expected wrong daemon app token to be unauthorized, got %v", err)
	}
	daemonApp, err := store.GetDaemonApplication(ctx, daemonToken.AccessToken, app.ID)
	if err != nil {
		t.Fatalf("get daemon application: %v", err)
	}
	if daemonApp.ApplicationID != app.ID || daemonApp.ApplicationSecret != app.Secret || daemonApp.Language != "java" {
		t.Fatalf("unexpected daemon application: %#v", daemonApp)
	}
	if _, err := store.ReportDaemonWorkloads(ctx, "wrong-token", control.DaemonWorkloadReport{
		NodeName:  fmt.Sprintf("node-%d", suffix),
		Workloads: []control.DaemonWorkloadInput{{Type: "process", PID: 4242}},
	}); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("expected wrong daemon token to be unauthorized, got %v", err)
	}
	workloads, err := store.ReportDaemonWorkloads(ctx, daemonToken.AccessToken, control.DaemonWorkloadReport{
		NodeName: fmt.Sprintf("node-%d", suffix),
		Workloads: []control.DaemonWorkloadInput{
			{Type: "process", PID: 4242, Cmdline: []string{"/usr/bin/java", "-jar", "app.jar"}},
			{Type: "container", ContainerID: fmt.Sprintf("ctr-%d", suffix), ContainerName: "payments", ImageTag: "payments:1.0.0"},
		},
	})
	if err != nil {
		t.Fatalf("report daemon workloads: %v", err)
	}
	if len(workloads) != 2 {
		t.Fatalf("expected two daemon workloads, got %#v", workloads)
	}
	bound, err := store.BindDaemonWorkload(ctx, admin.ID, workloads[0].ID, app.ID)
	if err != nil {
		t.Fatalf("bind daemon workload: %v", err)
	}
	if bound.ApplicationID != app.ID {
		t.Fatalf("expected daemon workload binding to persist, got %#v", bound)
	}
	if _, err := store.ListDaemonCommands(ctx, "wrong-token"); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("expected wrong daemon command token to be unauthorized, got %v", err)
	}
	commands, err := store.ListDaemonCommands(ctx, daemonToken.AccessToken)
	if err != nil {
		t.Fatalf("list daemon commands: %v", err)
	}
	if !containsDaemonCommandWorkload(commands, app.ID, app.Secret, workloads[0].ID) {
		t.Fatalf("expected daemon commands for bound workload, got %#v", commands)
	}
	if _, err := store.ReportDaemonInjection(ctx, "wrong-token", control.DaemonInjectionReport{WorkloadID: workloads[0].ID, Status: "injected"}); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("expected wrong daemon injection token to be unauthorized, got %v", err)
	}
	if _, err := store.ReportDaemonInjection(ctx, daemonToken.AccessToken, control.DaemonInjectionReport{WorkloadID: workloads[0].ID, Status: "failed"}); !errors.Is(err, control.ErrInvalid) {
		t.Fatalf("expected failed injection without error to be invalid, got %v", err)
	}
	injected, err := store.ReportDaemonInjection(ctx, daemonToken.AccessToken, control.DaemonInjectionReport{
		WorkloadID:    workloads[0].ID,
		Status:        "failed",
		Error:         "jattach permission denied",
		HelperID:      "helper-node-a",
		HelperVersion: "1.2.3",
		ReportedAt:    now(),
	})
	if err != nil {
		t.Fatalf("report daemon injection: %v", err)
	}
	if injected.InjectionStatus != "failed" || injected.InjectionError != "jattach permission denied" || injected.InjectionHelperID != "helper-node-a" || injected.InjectionReportedAt.IsZero() {
		t.Fatalf("unexpected daemon injection state: %#v", injected)
	}
	if _, err := store.ReportDaemonWorkloads(ctx, daemonToken.AccessToken, control.DaemonWorkloadReport{
		NodeName:  fmt.Sprintf("node-%d", suffix),
		Workloads: []control.DaemonWorkloadInput{{Type: "process", PID: 4242, Cmdline: []string{"/usr/bin/java", "-jar", "app.jar"}}},
	}); err != nil {
		t.Fatalf("re-report daemon workload: %v", err)
	}
	listedWorkloads, err := store.ListDaemonWorkloads(ctx)
	if err != nil {
		t.Fatalf("list daemon workloads: %v", err)
	}
	if !containsDaemonWorkloadBinding(listedWorkloads, workloads[0].ID, app.ID) {
		t.Fatalf("expected daemon report to preserve binding in %#v", listedWorkloads)
	}
	if !containsDaemonWorkloadInjection(listedWorkloads, workloads[0].ID, "failed") {
		t.Fatalf("expected daemon report to preserve injection state in %#v", listedWorkloads)
	}
	unbound, err := store.UnbindDaemonWorkload(ctx, admin.ID, workloads[0].ID)
	if err != nil {
		t.Fatalf("unbind daemon workload: %v", err)
	}
	if unbound.ApplicationID != "" {
		t.Fatalf("expected daemon workload to be unbound, got %#v", unbound)
	}
	if unbound.InjectionStatus != "" {
		t.Fatalf("expected unbind to clear daemon injection state, got %#v", unbound)
	}
	commands, err = store.ListDaemonCommands(ctx, daemonToken.AccessToken)
	if err != nil {
		t.Fatalf("list daemon commands after unbind: %v", err)
	}
	if containsDaemonCommandWorkload(commands, app.ID, app.Secret, workloads[0].ID) {
		t.Fatalf("expected unbound workload to be removed from daemon commands, got %#v", commands)
	}
	rotatedDaemonToken, err := store.ResetDaemonAccessToken(ctx, admin.ID)
	if err != nil {
		t.Fatalf("reset daemon token: %v", err)
	}
	if rotatedDaemonToken.AccessToken == daemonToken.AccessToken {
		t.Fatalf("expected daemon token rotation, got %#v", rotatedDaemonToken)
	}
	if _, err := store.ListDaemonCommands(ctx, daemonToken.AccessToken); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("expected old daemon command token to be unauthorized, got %v", err)
	}
	if _, err := store.ReportDaemonWorkloads(ctx, daemonToken.AccessToken, control.DaemonWorkloadReport{
		NodeName:  fmt.Sprintf("node-%d", suffix),
		Workloads: []control.DaemonWorkloadInput{{Type: "process", PID: 5000}},
	}); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("expected old daemon token to be unauthorized, got %v", err)
	}
	policy, err := store.CreatePolicy(ctx, admin.ID, control.PolicySet{Name: fmt.Sprintf("Default Web Protection %d", suffix)})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	policy, err = store.AddPolicyVersion(ctx, admin.ID, policy.ID, []control.Rule{{
		Name:       "Block SQL user input",
		Hook:       "sql",
		Algorithm:  "sql_userinput",
		Action:     "block",
		Severity:   "high",
		Expression: "' OR '1'='1",
	}})
	if err != nil {
		t.Fatalf("add policy v1: %v", err)
	}
	policy, err = store.UpdatePolicyVersionRules(ctx, admin.ID, policy.ID, 1, []control.Rule{{
		Name:        "Block SQL user input edited",
		Hook:        "sql",
		Algorithm:   "sql_userinput",
		Action:      "block",
		Severity:    "high",
		Expression:  "' OR '1'='1",
		Description: "Edited before rollout",
	}})
	if err != nil {
		t.Fatalf("update policy v1 draft: %v", err)
	}
	if len(policy.Versions) != 1 || len(policy.Versions[0].Rules) != 1 || policy.Versions[0].Rules[0].Name != "Block SQL user input edited" || policy.Versions[0].Rules[0].ID == "" {
		t.Fatalf("expected updated draft rule with generated id, got %#v", policy.Versions)
	}
	policy, err = store.AddPolicyVersion(ctx, admin.ID, policy.ID, []control.Rule{{
		Name:       "Log command execution",
		Hook:       "command",
		Algorithm:  "command_userinput",
		Action:     "log",
		Severity:   "medium",
		Expression: "sh",
	}})
	if err != nil {
		t.Fatalf("add policy v2: %v", err)
	}
	if len(policy.Versions) != 2 {
		t.Fatalf("expected two policy versions, got %#v", policy)
	}
	policy, err = store.RolloutPolicy(ctx, admin.ID, policy.ID, control.PolicyRollout{Version: 1, CanaryPercent: 25})
	if err != nil {
		t.Fatalf("rollout: %v", err)
	}
	if policy.Active == nil || policy.Active.Version != 1 || policy.Active.CanaryPercent != 25 {
		t.Fatalf("unexpected rollout active policy: %#v", policy.Active)
	}
	if _, err := store.UpdatePolicyVersionRules(ctx, admin.ID, policy.ID, 1, []control.Rule{{
		Name:       "Mutate active policy",
		Hook:       "sql",
		Action:     "block",
		Expression: "select",
	}}); !errors.Is(err, control.ErrInvalid) {
		t.Fatalf("expected active policy edit to be invalid, got %v", err)
	}
	policies, err := store.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if !containsPolicy(policies, policy.ID) {
		t.Fatalf("expected persisted policy %s in %#v", policy.ID, policies)
	}

	agent, err := store.RegisterAgent(ctx, app.ID, app.Secret, control.Agent{
		EnvironmentID: env.ID,
		Hostname:      "payments-1",
		Runtime:       "java",
		Version:       "1.0.0",
	})
	if err != nil {
		t.Fatalf("register agent: %v", err)
	}
	agent, err = store.HeartbeatAgent(ctx, agent.ID, "online")
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if agent.Status != "online" {
		t.Fatalf("expected online heartbeat, got %#v", agent)
	}
	pulled, err := store.GetAgentPolicy(ctx, agent.ID)
	if err != nil {
		t.Fatalf("pull policy: %v", err)
	}
	if pulled.Version != 1 {
		t.Fatalf("expected policy v1, got %#v", pulled)
	}
	if cache != nil {
		cached, found, err := cache.GetAgentPolicy(ctx, agent.ID)
		if err != nil || !found || cached.Version != 1 {
			t.Fatalf("expected valkey policy cache hit, found=%v policy=%#v err=%v", found, cached, err)
		}
	}
	policy, err = store.RolloutPolicy(ctx, admin.ID, policy.ID, control.PolicyRollout{Version: 2, CanaryPercent: 100})
	if err != nil {
		t.Fatalf("rollout v2: %v", err)
	}
	pulled, err = store.GetAgentPolicy(ctx, agent.ID)
	if err != nil {
		t.Fatalf("pull policy v2: %v", err)
	}
	if pulled.Version != 2 {
		t.Fatalf("expected policy v2 before rollback, got %#v", pulled)
	}
	if cache != nil {
		cached, found, err := cache.GetAgentPolicy(ctx, agent.ID)
		if err != nil || !found || cached.Version != 2 {
			t.Fatalf("expected valkey policy cache hit for v2, found=%v policy=%#v err=%v", found, cached, err)
		}
	}
	policy, err = store.RollbackPolicy(ctx, admin.ID, policy.ID)
	if err != nil {
		t.Fatalf("rollback policy: %v", err)
	}
	if policy.Active == nil || policy.Active.Version != 1 || policy.Active.CanaryPercent != 100 {
		t.Fatalf("expected rollback active policy v1, got %#v", policy.Active)
	}
	pulled, err = store.GetAgentPolicy(ctx, agent.ID)
	if err != nil {
		t.Fatalf("pull policy after rollback: %v", err)
	}
	if pulled.Version != 1 {
		t.Fatalf("expected policy v1 after rollback, got %#v", pulled)
	}
	if cache != nil {
		cached, found, err := cache.GetAgentPolicy(ctx, agent.ID)
		if err != nil || !found || cached.Version != 1 {
			t.Fatalf("expected valkey policy cache refresh after rollback, found=%v policy=%#v err=%v", found, cached, err)
		}
	}

	if _, err := store.IngestEvent(ctx, control.SecurityEvent{
		Type:          "attack",
		ApplicationID: app.ID,
		EnvironmentID: env.ID,
		AgentID:       agent.ID,
		PolicyID:      policy.ID,
		PolicyVersion: pulled.Version,
		Hook:          "sql",
		Algorithm:     "sql_userinput",
		Severity:      "critical",
		Message:       "tautology detected",
		Attributes:    map[string]any{"path": "/checkout"},
	}); err != nil {
		t.Fatalf("ingest event: %v", err)
	}
	events, err := store.ListEvents(ctx, control.SecurityEventQuery{
		Type:          "attack",
		ApplicationID: app.ID,
		AgentID:       agent.ID,
		Severity:      "critical",
		Hook:          "sql",
		PolicyID:      policy.ID,
		Limit:         1,
	})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 || events[0].AgentID != agent.ID || events[0].Severity != "critical" {
		t.Fatalf("expected filtered attack event for agent %s in %#v", agent.ID, events)
	}
	recycled, err := store.SoftDeleteEvents(ctx, admin.ID, control.EventRecycleBinRequest{IDs: []string{events[0].ID}})
	if err != nil {
		t.Fatalf("soft-delete event: %v", err)
	}
	if recycled.Count != 1 {
		t.Fatalf("expected one recycled event, got %#v", recycled)
	}
	activeAfterDelete, err := store.ListEvents(ctx, control.SecurityEventQuery{Type: "attack", ApplicationID: app.ID, Limit: 10})
	if err != nil {
		t.Fatalf("list events after recycle: %v", err)
	}
	if len(activeAfterDelete) != 0 {
		t.Fatalf("expected recycled event to leave active list, got %#v", activeAfterDelete)
	}
	recycleBin, err := store.ListEvents(ctx, control.SecurityEventQuery{Type: "attack", ApplicationID: app.ID, DeletedOnly: true, Limit: 10})
	if err != nil {
		t.Fatalf("list recycled events: %v", err)
	}
	if len(recycleBin) != 1 || recycleBin[0].DeletedAt == nil || recycleBin[0].DeletedBy != admin.ID {
		t.Fatalf("expected deleted event metadata, got %#v", recycleBin)
	}
	restored, err := store.RestoreDeletedEvents(ctx, admin.ID, control.EventRecycleBinRequest{IDs: []string{events[0].ID}})
	if err != nil {
		t.Fatalf("restore event: %v", err)
	}
	if restored.Count != 1 {
		t.Fatalf("expected one restored event, got %#v", restored)
	}
	deliveries, err := store.ListAlertDeliveries(ctx)
	if err != nil {
		t.Fatalf("list alert deliveries: %v", err)
	}
	if !containsAlertDelivery(deliveries, "alr_critical_attack") {
		t.Fatalf("expected critical attack alert delivery in %#v", deliveries)
	}
	if _, err := store.IngestDependency(ctx, control.Dependency{
		ApplicationID: app.ID,
		AgentID:       agent.ID,
		Name:          "spring-web",
		Version:       "6.2.0",
		Ecosystem:     "maven",
		PackagePath:   "org/springframework/spring-web/6.2.0/spring-web-6.2.0.jar",
		Licenses:      []string{"Apache-2.0"},
		Vulnerabilities: []control.DependencyVulnerability{{
			ID:             "CVE-2026-0001",
			Severity:       "critical",
			CVSS:           9.1,
			KnownExploited: true,
			FixedVersion:   "6.2.1",
		}},
	}); err != nil {
		t.Fatalf("ingest dependency: %v", err)
	}
	dependencies, err := store.ListDependencies(ctx, control.DependencyQuery{
		ApplicationID:         app.ID,
		AgentID:               agent.ID,
		Name:                  "spring-web",
		Ecosystem:             "maven",
		VulnerabilitySeverity: "critical",
		ObservedAfter:         now().Add(-time.Hour),
		ObservedBefore:        now().Add(time.Hour),
		Limit:                 1,
	})
	if err != nil {
		t.Fatalf("list dependencies: %v", err)
	}
	if len(dependencies) != 1 || dependencies[0].Name != "spring-web" || dependencies[0].AgentID != agent.ID || dependencies[0].PackagePath == "" || len(dependencies[0].Vulnerabilities) != 1 {
		t.Fatalf("expected filtered dependency inventory to include spring-web for agent %s, got %#v", agent.ID, dependencies)
	}
	dependencies, err = store.ListDependencies(ctx, control.DependencyQuery{
		ApplicationID:         app.ID,
		VulnerabilitySeverity: "low",
		Limit:                 1,
	})
	if err != nil {
		t.Fatalf("list dependencies by nonmatching vulnerability: %v", err)
	}
	if len(dependencies) != 0 {
		t.Fatalf("expected low severity dependency query to be empty, got %#v", dependencies)
	}
	if _, err := store.IngestBaselineFinding(ctx, control.BaselineFinding{
		ApplicationID: app.ID,
		EnvironmentID: env.ID,
		AgentID:       agent.ID,
		CheckID:       "jvm.security_manager",
		Title:         "JVM security manager disabled",
		Category:      "runtime",
		Severity:      "medium",
		Status:        "warning",
		Resource:      agent.Hostname,
		Remediation:   "Enable explicit policy controls before production rollout.",
		Attributes:    map[string]any{"runtime": "java"},
	}); err != nil {
		t.Fatalf("ingest baseline finding: %v", err)
	}
	findings, err := store.ListBaselineFindings(ctx, control.BaselineFindingQuery{
		ApplicationID:  app.ID,
		EnvironmentID:  env.ID,
		AgentID:        agent.ID,
		Severity:       "medium",
		Status:         "warning",
		Category:       "runtime",
		ObservedAfter:  now().Add(-time.Hour),
		ObservedBefore: now().Add(time.Hour),
		Limit:          1,
	})
	if err != nil {
		t.Fatalf("list baseline findings: %v", err)
	}
	if len(findings) != 1 || findings[0].CheckID != "jvm.security_manager" || findings[0].Attributes["runtime"] != "java" {
		t.Fatalf("expected filtered baseline finding for agent %s, got %#v", agent.ID, findings)
	}
	findings, err = store.ListBaselineFindings(ctx, control.BaselineFindingQuery{
		ApplicationID: app.ID,
		Status:        "failed",
		Limit:         1,
	})
	if err != nil {
		t.Fatalf("list nonmatching baseline findings: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected failed baseline query to be empty, got %#v", findings)
	}
	overview, err := store.Overview(ctx)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.ApplicationCount < 1 || overview.AgentCount < 1 || overview.EventsByType["attack"] < 1 {
		t.Fatalf("unexpected overview: %#v", overview)
	}
	audit, err := store.ListAuditLogs(ctx)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsAuditAction(audit, "policy.rollout") {
		t.Fatalf("expected policy rollout audit in %#v", audit)
	}
	for _, action := range []string{"policy.version.update", "agent.heartbeat", "event.ingest", "dependency.ingest", "baseline.ingest"} {
		if !containsAuditAction(audit, action) {
			t.Fatalf("expected %s audit in %#v", action, audit)
		}
	}
	if _, err := store.UpsertSystemSetting(ctx, admin.ID, control.SystemSetting{
		Key: "alerts.delivery",
		Value: map[string]any{
			"email_enabled": true,
			"severity":      "high",
		},
	}); err != nil {
		t.Fatalf("upsert system setting: %v", err)
	}
	settings, err := store.ListSystemSettings(ctx)
	if err != nil {
		t.Fatalf("list settings: %v", err)
	}
	if !containsSetting(settings, "alerts.delivery") {
		t.Fatalf("expected persisted setting in %#v", settings)
	}
	alertRule, err := store.CreateAlertRule(ctx, admin.ID, control.AlertRule{
		Name:        "Critical crash",
		Description: "Notify on critical crashes",
		Enabled:     true,
		EventType:   "crash",
		Severity:    "critical",
		Condition:   "severity == critical",
		Target:      "platform-operations",
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	alertRule, err = store.UpdateAlertRule(ctx, admin.ID, alertRule.ID, control.AlertRule{
		Name:        alertRule.Name,
		Description: "Disabled for maintenance",
		Enabled:     false,
		EventType:   alertRule.EventType,
		Severity:    alertRule.Severity,
		Condition:   alertRule.Condition,
		Target:      alertRule.Target,
	})
	if err != nil {
		t.Fatalf("update alert rule: %v", err)
	}
	if alertRule.Enabled {
		t.Fatalf("expected alert rule to be disabled: %#v", alertRule)
	}
	alertRules, err := store.ListAlertRules(ctx)
	if err != nil {
		t.Fatalf("list alert rules: %v", err)
	}
	if !containsAlertRule(alertRules, alertRule.ID) {
		t.Fatalf("expected persisted alert rule in %#v", alertRules)
	}

	cleanupCutoff := now().Add(time.Hour)
	previewCleanup, err := store.MaintenanceCleanup(ctx, admin.ID, control.MaintenanceCleanupRequest{
		ApplicationID:           app.ID,
		Before:                  cleanupCutoff,
		DryRun:                  true,
		IncludeEvents:           true,
		IncludeDependencies:     true,
		IncludeBaselineFindings: true,
		IncludeAlertDeliveries:  true,
	})
	if err != nil {
		t.Fatalf("preview maintenance cleanup: %v", err)
	}
	if previewCleanup.Counts["events"] == 0 || previewCleanup.Counts["dependencies"] == 0 || previewCleanup.Counts["baseline_findings"] == 0 {
		t.Fatalf("expected cleanup preview to count operational data, got %#v", previewCleanup)
	}
	if _, err := store.MaintenanceCleanup(ctx, admin.ID, control.MaintenanceCleanupRequest{
		ApplicationID:           app.ID,
		Before:                  cleanupCutoff,
		DryRun:                  false,
		IncludeEvents:           true,
		IncludeDependencies:     true,
		IncludeBaselineFindings: true,
		IncludeAlertDeliveries:  true,
	}); err == nil {
		t.Fatalf("expected destructive cleanup without confirmation to fail")
	}
	appliedCleanup, err := store.MaintenanceCleanup(ctx, admin.ID, control.MaintenanceCleanupRequest{
		ApplicationID:           app.ID,
		Before:                  cleanupCutoff,
		DryRun:                  false,
		IncludeEvents:           true,
		IncludeDependencies:     true,
		IncludeBaselineFindings: true,
		IncludeAlertDeliveries:  true,
		Confirmation:            "CLEAR_OPERATIONAL_DATA",
	})
	if err != nil {
		t.Fatalf("apply maintenance cleanup: %v", err)
	}
	if appliedCleanup.Counts["events"] != previewCleanup.Counts["events"] || appliedCleanup.Counts["dependencies"] != previewCleanup.Counts["dependencies"] {
		t.Fatalf("expected cleanup counts to match preview=%#v applied=%#v", previewCleanup, appliedCleanup)
	}
	eventsAfterCleanup, err := store.ListEvents(ctx, control.SecurityEventQuery{ApplicationID: app.ID, Limit: 10})
	if err != nil {
		t.Fatalf("list events after cleanup: %v", err)
	}
	if len(eventsAfterCleanup) != 0 {
		t.Fatalf("expected cleanup to purge application events, got %#v", eventsAfterCleanup)
	}
	audit, err = store.ListAuditLogs(ctx)
	if err != nil {
		t.Fatalf("audit after cleanup: %v", err)
	}
	if !containsAuditAction(audit, "maintenance.cleanup") {
		t.Fatalf("expected maintenance cleanup audit in %#v", audit)
	}

	reloaded := NewStore(db, now)
	apps, err := reloaded.ListApplications(ctx)
	if err != nil {
		t.Fatalf("reload applications: %v", err)
	}
	if !containsApplication(apps, app.ID) {
		t.Fatalf("expected persisted app %s in %#v", app.ID, apps)
	}
	reloadedWorkloads, err := reloaded.ListDaemonWorkloads(ctx)
	if err != nil {
		t.Fatalf("reload daemon workloads: %v", err)
	}
	if !containsDaemonWorkload(reloadedWorkloads, workloads[0].ID) {
		t.Fatalf("expected persisted daemon workload %s in %#v", workloads[0].ID, reloadedWorkloads)
	}
}

func containsEventForAgent(events []control.SecurityEvent, agentID string) bool {
	for _, event := range events {
		if event.AgentID == agentID {
			return true
		}
	}
	return false
}

func containsAuditAction(logs []control.AuditLog, action string) bool {
	for _, log := range logs {
		if log.Action == action {
			return true
		}
	}
	return false
}

func containsApplication(apps []control.Application, appID string) bool {
	for _, app := range apps {
		if app.ID == appID {
			return true
		}
	}
	return false
}

func containsUser(users []control.User, userID string) bool {
	for _, user := range users {
		if user.ID == userID {
			return true
		}
	}
	return false
}

func containsPolicy(policies []control.PolicySet, policyID string) bool {
	for _, policy := range policies {
		if policy.ID == policyID {
			return true
		}
	}
	return false
}

func containsDependency(dependencies []control.Dependency, name string) bool {
	for _, dep := range dependencies {
		if dep.Name == name {
			return true
		}
	}
	return false
}

func containsDaemonWorkload(workloads []control.DaemonWorkload, workloadID string) bool {
	for _, workload := range workloads {
		if workload.ID == workloadID {
			return true
		}
	}
	return false
}

func containsDaemonWorkloadBinding(workloads []control.DaemonWorkload, workloadID string, appID string) bool {
	for _, workload := range workloads {
		if workload.ID == workloadID && workload.ApplicationID == appID {
			return true
		}
	}
	return false
}

func containsDaemonWorkloadInjection(workloads []control.DaemonWorkload, workloadID string, status string) bool {
	for _, workload := range workloads {
		if workload.ID == workloadID && workload.InjectionStatus == status {
			return true
		}
	}
	return false
}

func containsDaemonCommandWorkload(commands []control.DaemonCommandGroup, appID string, appSecret string, workloadID string) bool {
	for _, command := range commands {
		if command.ApplicationID != appID || command.ApplicationSecret != appSecret || command.Language != "java" {
			continue
		}
		for _, workload := range command.Workloads {
			if workload.ID == workloadID {
				return true
			}
		}
	}
	return false
}

func containsSetting(settings []control.SystemSetting, key string) bool {
	for _, setting := range settings {
		if setting.Key == key {
			return true
		}
	}
	return false
}

func containsAlertRule(rules []control.AlertRule, id string) bool {
	for _, rule := range rules {
		if rule.ID == id {
			return true
		}
	}
	return false
}

func containsAlertDelivery(deliveries []control.AlertDelivery, ruleID string) bool {
	for _, delivery := range deliveries {
		if delivery.AlertRuleID == ruleID {
			return true
		}
	}
	return false
}
