package httpapi

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
)

func TestAgentRegistrationHeartbeatAndPolicyPull(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	app := client.request(t, http.MethodPost, "/api/v1/applications", token, map[string]any{
		"name":        "Payments API",
		"description": "PCI scoped service",
	})
	appID := stringValue(t, app, "id")
	appSecret := stringValue(t, app, "secret")
	appAuth := appHeaders(appID, appSecret)
	if envIDs := arrayValue(t, app, "environment_ids"); len(envIDs) != 0 {
		t.Fatalf("expected newly created application to expose an empty environment list, got %#v", envIDs)
	}

	env := client.request(t, http.MethodPost, "/api/v1/applications/"+appID+"/environments", token, map[string]any{
		"name": "staging",
		"kind": "staging",
	})
	envID := stringValue(t, env, "id")

	policy := client.request(t, http.MethodPost, "/api/v1/policies", token, map[string]any{
		"name": "Default Web Protection",
	})
	policyID := stringValue(t, policy, "id")

	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/versions", token, map[string]any{
		"rules": []map[string]any{
			{
				"name":       "Block SQL user input",
				"hook":       "sql",
				"algorithm":  "sql_userinput",
				"action":     "block",
				"severity":   "high",
				"expression": "' OR '1'='1",
			},
		},
	})
	rolledOut := client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/rollout", token, map[string]any{
		"version":        1,
		"canary_percent": 25,
	})
	active := objectValue(t, rolledOut, "active")
	if active["canary_percent"].(float64) != 25 {
		t.Fatalf("expected canary rollout to persist, got %#v", active)
	}
	policies := client.request(t, http.MethodGet, "/api/v1/policies", token, nil)
	listedPolicies := arrayValue(t, policies, "items")
	if len(listedPolicies) != 1 {
		t.Fatalf("expected one listed policy, got %#v", listedPolicies)
	}

	agent := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appAuth, map[string]any{
		"environment_id": envID,
		"hostname":       "payments-1",
		"runtime":        "java",
		"version":        "1.0.0",
	})
	agentID := stringValue(t, agent, "id")

	heartbeat := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/"+agentID+"/heartbeat", appAuth, map[string]any{
		"status": "online",
	})
	if heartbeat["status"] != "online" {
		t.Fatalf("expected online heartbeat, got %#v", heartbeat)
	}

	pulled := client.requestWithHeaders(t, http.MethodGet, "/api/v1/agents/"+agentID+"/policy", appAuth, nil)
	if pulled["version"].(float64) != 1 {
		t.Fatalf("expected policy version 1, got %#v", pulled)
	}
	rotated := client.request(t, http.MethodPost, "/api/v1/applications/"+appID+"/secret/rotate", token, nil)
	rotatedSecret := stringValue(t, rotated, "secret")
	if rotatedSecret == appSecret {
		t.Fatalf("expected rotated secret to change, got %#v", rotated)
	}
	oldSecretHeartbeat := client.raw(t, http.MethodPost, "/api/v1/agents/"+agentID+"/heartbeat", "", appAuth, map[string]any{
		"status": "offline",
	})
	if oldSecretHeartbeat.Code != http.StatusUnauthorized {
		t.Fatalf("expected old application secret to be rejected after rotation, got %d: %s", oldSecretHeartbeat.Code, oldSecretHeartbeat.Body.String())
	}
	appAuth = appHeaders(appID, rotatedSecret)
	heartbeat = client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/"+agentID+"/heartbeat", appAuth, map[string]any{
		"status": "offline",
	})
	if heartbeat["status"] != "offline" {
		t.Fatalf("expected rotated secret heartbeat to succeed, got %#v", heartbeat)
	}
	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	items := arrayValue(t, audit, "items")
	if !containsAuditAction(items, "agent.heartbeat") {
		t.Fatalf("expected agent heartbeat audit entry, got %#v", items)
	}
	if !containsAuditAction(items, "application.secret.rotate") {
		t.Fatalf("expected application secret rotation audit entry, got %#v", items)
	}
}

func TestAgentMaintenanceRemarkIgnoreAndDelete(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	app := client.request(t, http.MethodPost, "/api/v1/applications", token, map[string]any{
		"name": "Maintained API",
	})
	appID := stringValue(t, app, "id")
	appSecret := stringValue(t, app, "secret")
	appAuth := appHeaders(appID, appSecret)
	env := client.request(t, http.MethodPost, "/api/v1/applications/"+appID+"/environments", token, map[string]any{
		"name": "production",
		"kind": "production",
	})
	envID := stringValue(t, env, "id")

	agentA := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appAuth, map[string]any{
		"environment_id": envID,
		"hostname":       "maintained-a",
		"runtime":        "java",
		"version":        "1.0.0",
	})
	agentAID := stringValue(t, agentA, "id")
	agentB := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appAuth, map[string]any{
		"environment_id": envID,
		"hostname":       "maintained-b",
		"runtime":        "java",
		"version":        "1.0.1",
	})
	agentBID := stringValue(t, agentB, "id")

	remarked := client.request(t, http.MethodPut, "/api/v1/agents/"+agentAID+"/alias", token, map[string]any{
		"alias": "checkout primary",
	})
	if stringValue(t, remarked, "alias") != "checkout primary" {
		t.Fatalf("expected alias to be updated, got %#v", remarked)
	}
	ignored := client.request(t, http.MethodPost, "/api/v1/agents/"+agentAID+"/ignore", token, map[string]any{
		"ignored": true,
	})
	if stringValue(t, ignored, "ignored_at") == "" {
		t.Fatalf("expected ignored_at to be set, got %#v", ignored)
	}
	restored := client.request(t, http.MethodPost, "/api/v1/agents/"+agentAID+"/ignore", token, map[string]any{
		"ignored": false,
	})
	if _, ok := restored["ignored_at"]; ok {
		t.Fatalf("expected ignored_at to be omitted after restore, got %#v", restored)
	}

	deletedA := client.request(t, http.MethodDelete, "/api/v1/agents/"+agentAID, token, nil)
	if deletedA["count"].(float64) != 1 {
		t.Fatalf("expected single agent delete report, got %#v", deletedA)
	}
	deletedB := client.request(t, http.MethodPost, "/api/v1/agents/batch-delete", token, map[string]any{
		"ids": []string{agentBID},
	})
	if deletedB["count"].(float64) != 1 {
		t.Fatalf("expected batch agent delete report, got %#v", deletedB)
	}
	listed := client.request(t, http.MethodGet, "/api/v1/agents", token, nil)
	if containsAgentID(arrayValue(t, listed, "items"), agentAID) || containsAgentID(arrayValue(t, listed, "items"), agentBID) {
		t.Fatalf("expected deleted agents to be absent, got %#v", listed)
	}
	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	items := arrayValue(t, audit, "items")
	for _, action := range []string{"agent.alias.update", "agent.ignore.update", "agent.delete"} {
		if !containsAuditAction(items, action) {
			t.Fatalf("expected %s audit entry, got %#v", action, items)
		}
	}
}

func TestApplicationExportAndDelete(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	app := client.request(t, http.MethodPost, "/api/v1/applications", token, map[string]any{
		"name":        "Retired API",
		"description": "short lived test app",
	})
	appID := stringValue(t, app, "id")
	client.request(t, http.MethodPost, "/api/v1/applications/"+appID+"/environments", token, map[string]any{
		"name": "production",
		"kind": "production",
	})

	exported := client.request(t, http.MethodGet, "/api/v1/applications/export", token, nil)
	if !containsApplicationID(arrayValue(t, exported, "items"), appID) {
		t.Fatalf("expected export to include %s, got %#v", appID, exported)
	}

	deleted := client.raw(t, http.MethodDelete, "/api/v1/applications/"+appID, token, nil, nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("expected application delete to return 204, got %d: %s", deleted.Code, deleted.Body.String())
	}
	listed := client.request(t, http.MethodGet, "/api/v1/applications", token, nil)
	if containsApplicationID(arrayValue(t, listed, "items"), appID) {
		t.Fatalf("expected deleted application to be hidden from list, got %#v", listed)
	}
	exportedAfterDelete := client.request(t, http.MethodGet, "/api/v1/applications/export", token, nil)
	if containsApplicationID(arrayValue(t, exportedAfterDelete, "items"), appID) {
		t.Fatalf("expected deleted application to be hidden from export, got %#v", exportedAfterDelete)
	}
	missing := client.raw(t, http.MethodDelete, "/api/v1/applications/"+appID, token, nil, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("expected repeated delete to return 404, got %d: %s", missing.Code, missing.Body.String())
	}
	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	if !containsAuditAction(arrayValue(t, audit, "items"), "application.delete") {
		t.Fatalf("expected application delete audit entry, got %#v", audit)
	}
}

func TestPolicyDraftRulesCanBeUpdatedBeforeRollout(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	policy := client.request(t, http.MethodPost, "/api/v1/policies", token, map[string]any{"name": "Editable Policy"})
	policyID := stringValue(t, policy, "id")
	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/versions", token, map[string]any{
		"rules": []map[string]any{{"name": "Block SQL", "hook": "sql", "action": "block", "expression": "' OR '1'='1"}},
	})
	updated := client.request(t, http.MethodPut, "/api/v1/policies/"+policyID+"/versions/1/rules", token, map[string]any{
		"rules": []map[string]any{{"name": "Block SQL edited", "hook": "sql", "algorithm": "sql_userinput", "action": "block", "severity": "high", "expression": "' OR '1'='1"}},
	})
	versions := arrayValue(t, updated, "versions")
	if len(versions) != 1 {
		t.Fatalf("expected one policy version, got %#v", versions)
	}
	version, ok := versions[0].(map[string]any)
	if !ok {
		t.Fatalf("expected version object, got %#v", versions[0])
	}
	rules := arrayValue(t, version, "rules")
	if len(rules) != 1 {
		t.Fatalf("expected one updated rule, got %#v", rules)
	}
	rule, ok := rules[0].(map[string]any)
	if !ok || rule["name"] != "Block SQL edited" || rule["id"] == "" {
		t.Fatalf("expected edited rule with generated id, got %#v", rules[0])
	}

	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/rollout", token, map[string]any{"version": 1, "canary_percent": 100})
	blocked := client.raw(t, http.MethodPut, "/api/v1/policies/"+policyID+"/versions/1/rules", token, nil, map[string]any{
		"rules": []map[string]any{{"name": "Mutate active", "hook": "sql", "action": "block", "expression": "select"}},
	})
	if blocked.Code != http.StatusBadRequest {
		t.Fatalf("expected active policy edit to be rejected, got %d: %s", blocked.Code, blocked.Body.String())
	}
	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	if !containsAuditAction(arrayValue(t, audit, "items"), "policy.version.update") {
		t.Fatalf("expected policy version update audit entry, got %#v", audit)
	}
}

func TestPolicyAlgorithmCatalogAndRestoreDefault(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	catalog := client.request(t, http.MethodGet, "/api/v1/policies/algorithms", token, nil)
	items := arrayValue(t, catalog, "items")
	if len(items) == 0 {
		t.Fatalf("expected algorithm catalog items, got %#v", catalog)
	}
	if !containsAlgorithmCatalogItem(items, "sql", "sql_userinput") || !containsAlgorithmCatalogItem(items, "command", "command_userinput") {
		t.Fatalf("expected SQL and command algorithms in catalog, got %#v", items)
	}

	policy := client.request(t, http.MethodPost, "/api/v1/policies", token, map[string]any{"name": "Restore Defaults Policy"})
	policyID := stringValue(t, policy, "id")
	restored := client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/restore-default", token, nil)
	versions := arrayValue(t, restored, "versions")
	if len(versions) != 1 {
		t.Fatalf("expected one restored draft version, got %#v", versions)
	}
	version := objectFromAny(t, versions[0])
	if version["status"] != "draft" {
		t.Fatalf("expected restored version to stay draft, got %#v", version)
	}
	rules := arrayValue(t, version, "rules")
	if len(rules) < len(items) {
		t.Fatalf("expected restored defaults to include detector rules, got %d rules for %d catalog hooks", len(rules), len(items))
	}
	if !containsPolicyRule(rules, "sql", "sql_userinput") || !containsPolicyRule(rules, "jndi", "jndi_disable_all") {
		t.Fatalf("expected restored default detector rules, got %#v", rules)
	}

	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	if !containsAuditAction(arrayValue(t, audit, "items"), "policy.restore_default") {
		t.Fatalf("expected restore-default audit entry, got %#v", audit)
	}
}

func TestPolicyRollbackUpdatesAgentAssignmentAndPolicyPull(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	app := client.request(t, http.MethodPost, "/api/v1/applications", token, map[string]any{
		"name": "Rollback API",
	})
	appID := stringValue(t, app, "id")
	appSecret := stringValue(t, app, "secret")
	appAuth := appHeaders(appID, appSecret)
	env := client.request(t, http.MethodPost, "/api/v1/applications/"+appID+"/environments", token, map[string]any{
		"name": "production",
		"kind": "production",
	})
	envID := stringValue(t, env, "id")
	policy := client.request(t, http.MethodPost, "/api/v1/policies", token, map[string]any{"name": "Rollback Policy"})
	policyID := stringValue(t, policy, "id")
	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/versions", token, map[string]any{
		"rules": []map[string]any{{"name": "Block SQL", "hook": "sql", "action": "block", "expression": "' OR '1'='1"}},
	})
	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/versions", token, map[string]any{
		"rules": []map[string]any{{"name": "Log command", "hook": "command", "action": "log", "expression": "Runtime.exec"}},
	})
	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/rollout", token, map[string]any{"version": 1, "canary_percent": 100})

	agent := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appAuth, map[string]any{
		"environment_id": envID,
		"hostname":       "rollback-1",
		"runtime":        "java",
		"version":        "1.0.0",
	})
	agentID := stringValue(t, agent, "id")

	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/rollout", token, map[string]any{"version": 2, "canary_percent": 100})
	pulledV2 := client.requestWithHeaders(t, http.MethodGet, "/api/v1/agents/"+agentID+"/policy", appAuth, nil)
	if pulledV2["version"].(float64) != 2 {
		t.Fatalf("expected policy version 2 before rollback, got %#v", pulledV2)
	}

	rolledBack := client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/rollback", token, nil)
	active := objectValue(t, rolledBack, "active")
	if active["version"].(float64) != 1 || active["canary_percent"].(float64) != 100 {
		t.Fatalf("expected rollback to activate v1 at 100%%, got %#v", active)
	}
	pulledV1 := client.requestWithHeaders(t, http.MethodGet, "/api/v1/agents/"+agentID+"/policy", appAuth, nil)
	if pulledV1["version"].(float64) != 1 {
		t.Fatalf("expected policy version 1 after rollback, got %#v", pulledV1)
	}
	agents := client.request(t, http.MethodGet, "/api/v1/agents", token, nil)
	for _, item := range arrayValue(t, agents, "items") {
		agentItem := item.(map[string]any)
		if agentItem["id"] == agentID && agentItem["policy_version"].(float64) == 1 {
			return
		}
	}
	t.Fatalf("expected listed Agent %s to show rolled back policy version: %#v", agentID, agents)
}

func TestPolicyRolloutCanBeScopedToApplication(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	appA := client.request(t, http.MethodPost, "/api/v1/applications", token, map[string]any{"name": "Scoped Payments API"})
	appAID := stringValue(t, appA, "id")
	appASecret := stringValue(t, appA, "secret")
	appAAuth := appHeaders(appAID, appASecret)
	envA := client.request(t, http.MethodPost, "/api/v1/applications/"+appAID+"/environments", token, map[string]any{"name": "production", "kind": "production"})
	envAID := stringValue(t, envA, "id")

	appB := client.request(t, http.MethodPost, "/api/v1/applications", token, map[string]any{"name": "Scoped Admin API"})
	appBID := stringValue(t, appB, "id")
	appBSecret := stringValue(t, appB, "secret")
	appBAuth := appHeaders(appBID, appBSecret)
	envB := client.request(t, http.MethodPost, "/api/v1/applications/"+appBID+"/environments", token, map[string]any{"name": "production", "kind": "production"})
	envBID := stringValue(t, envB, "id")

	agentA := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appAAuth, map[string]any{"environment_id": envAID, "hostname": "payments-scoped-1", "runtime": "java", "version": "1.0.0"})
	agentAID := stringValue(t, agentA, "id")
	agentB := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appBAuth, map[string]any{"environment_id": envBID, "hostname": "admin-scoped-1", "runtime": "java", "version": "1.0.0"})
	agentBID := stringValue(t, agentB, "id")

	policy := client.request(t, http.MethodPost, "/api/v1/policies", token, map[string]any{"name": "Scoped Policy"})
	policyID := stringValue(t, policy, "id")
	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/versions", token, map[string]any{
		"rules": []map[string]any{{"name": "Block SQL", "hook": "sql", "action": "block", "expression": "' OR '1'='1"}},
	})
	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/rollout", token, map[string]any{"version": 1, "canary_percent": 100, "application_id": appAID})

	pulledA := client.requestWithHeaders(t, http.MethodGet, "/api/v1/agents/"+agentAID+"/policy", appAAuth, nil)
	if pulledA["version"].(float64) != 1 {
		t.Fatalf("expected scoped app Agent to pull policy v1, got %#v", pulledA)
	}
	pulledB := client.requestWithHeaders(t, http.MethodGet, "/api/v1/agents/"+agentBID+"/policy", appBAuth, nil)
	if pulledB["version"].(float64) != 0 || pulledB["status"] != "empty" {
		t.Fatalf("expected out-of-scope Agent to pull empty policy, got %#v", pulledB)
	}

	agentA2 := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appAAuth, map[string]any{"environment_id": envAID, "hostname": "payments-scoped-2", "runtime": "java", "version": "1.0.0"})
	pulledA2 := client.requestWithHeaders(t, http.MethodGet, "/api/v1/agents/"+stringValue(t, agentA2, "id")+"/policy", appAAuth, nil)
	if pulledA2["version"].(float64) != 1 {
		t.Fatalf("expected new scoped app Agent to inherit policy v1, got %#v", pulledA2)
	}
}

func TestMetricsExposeOperationalSignals(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	app := client.request(t, http.MethodPost, "/api/v1/applications", token, map[string]any{"name": "Metrics API"})
	appID := stringValue(t, app, "id")
	appSecret := stringValue(t, app, "secret")
	appAuth := appHeaders(appID, appSecret)
	env := client.request(t, http.MethodPost, "/api/v1/applications/"+appID+"/environments", token, map[string]any{"name": "prod", "kind": "production"})
	envID := stringValue(t, env, "id")
	policy := client.request(t, http.MethodPost, "/api/v1/policies", token, map[string]any{"name": "Metrics Policy"})
	policyID := stringValue(t, policy, "id")
	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/versions", token, map[string]any{
		"rules": []map[string]any{{"name": "Block SQL", "hook": "sql", "action": "block", "expression": "' OR '1'='1"}},
	})
	client.request(t, http.MethodPost, "/api/v1/policies/"+policyID+"/rollout", token, map[string]any{"version": 1, "canary_percent": 100})
	agent := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appAuth, map[string]any{
		"environment_id": envID,
		"hostname":       "metrics-1",
		"runtime":        "java",
		"version":        "1.2.3",
	})
	agentID := stringValue(t, agent, "id")
	client.requestWithHeaders(t, http.MethodGet, "/api/v1/agents/"+agentID+"/policy", appAuth, nil)
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/attack", appAuth, map[string]any{
		"application_id": appID,
		"environment_id": envID,
		"agent_id":       agentID,
		"policy_id":      policyID,
		"policy_version": 1,
		"hook":           "sql",
		"algorithm":      "sql_userinput",
		"severity":       "critical",
		"message":        "metrics SQL tautology blocked",
		"occurred_at":    "2026-05-31T00:00:00Z",
		"attributes":     map[string]any{"path": "/metrics", "latency_us": 1800},
	})

	response := client.raw(t, http.MethodGet, "/metrics", "", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("expected metrics response, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		"ohmyrasp_api_up 1",
		"ohmyrasp_agents_total 1",
		"ohmyrasp_agents_online 1",
		`ohmyrasp_agent_last_seen_timestamp_seconds{agent_id="` + agentID + `"`,
		`ohmyrasp_events_total{severity="critical",type=""} 1`,
		`ohmyrasp_last_event_ingested_timestamp_seconds{type="attack"} 1780185600`,
		`ohmyrasp_event_ingest_lag_seconds{type="attack"} `,
		`ohmyrasp_policy_pull_latency_seconds_count{status="success"} 1`,
		`ohmyrasp_hook_latency_p95_seconds{hook="sql"} 0.0018`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected metrics to contain %q, got:\n%s", expected, body)
		}
	}
}

func TestOpenAPIStrictContractRoutes(t *testing.T) {
	client := newTestClient(t)

	health := client.raw(t, http.MethodGet, "/healthz", "", nil, nil)
	if health.Code != http.StatusOK || health.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected strict health JSON response, got %d %q: %s", health.Code, health.Header().Get("Content-Type"), health.Body.String())
	}
	var healthBody map[string]any
	if err := json.Unmarshal(health.Body.Bytes(), &healthBody); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if healthBody["status"] != "ok" {
		t.Fatalf("unexpected health response: %#v", healthBody)
	}

	malformedLogin := client.rawBody(t, http.MethodPost, "/api/v1/auth/login", "", nil, `{"email":`)
	if malformedLogin.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed login JSON, got %d: %s", malformedLogin.Code, malformedLogin.Body.String())
	}
	var errorBody map[string]any
	if err := json.Unmarshal(malformedLogin.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed login error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict decode error body, got %#v", errorBody)
	}

	token := client.login(t)
	malformedPolicy := client.rawBody(t, http.MethodPost, "/api/v1/policies", token, nil, `{"name":`)
	if malformedPolicy.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed policy JSON, got %d: %s", malformedPolicy.Code, malformedPolicy.Body.String())
	}
	if err := json.Unmarshal(malformedPolicy.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed policy error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict policy decode error body, got %#v", errorBody)
	}

	malformedApplication := client.rawBody(t, http.MethodPost, "/api/v1/applications", token, nil, `{"name":`)
	if malformedApplication.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed application JSON, got %d: %s", malformedApplication.Code, malformedApplication.Body.String())
	}
	if err := json.Unmarshal(malformedApplication.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed application error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict application decode error body, got %#v", errorBody)
	}

	malformedUser := client.rawBody(t, http.MethodPost, "/api/v1/users", token, nil, `{"email":`)
	if malformedUser.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed user JSON, got %d: %s", malformedUser.Code, malformedUser.Body.String())
	}
	if err := json.Unmarshal(malformedUser.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed user error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict user decode error body, got %#v", errorBody)
	}

	malformedSetting := client.rawBody(t, http.MethodPut, "/api/v1/system-settings/alerts.delivery", token, nil, `{"value":`)
	if malformedSetting.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed setting JSON, got %d: %s", malformedSetting.Code, malformedSetting.Body.String())
	}
	if err := json.Unmarshal(malformedSetting.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed setting error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict setting decode error body, got %#v", errorBody)
	}

	malformedCleanup := client.rawBody(t, http.MethodPost, "/api/v1/maintenance/cleanup", token, nil, `{"before":`)
	if malformedCleanup.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed cleanup JSON, got %d: %s", malformedCleanup.Code, malformedCleanup.Body.String())
	}
	if err := json.Unmarshal(malformedCleanup.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed cleanup error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict cleanup decode error body, got %#v", errorBody)
	}

	malformedAlertRule := client.rawBody(t, http.MethodPost, "/api/v1/alert-rules", token, nil, `{"name":`)
	if malformedAlertRule.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed alert rule JSON, got %d: %s", malformedAlertRule.Code, malformedAlertRule.Body.String())
	}
	if err := json.Unmarshal(malformedAlertRule.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed alert rule error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict alert rule decode error body, got %#v", errorBody)
	}

	malformedEvent := client.rawBody(t, http.MethodPost, "/api/v1/events/attack", "", nil, `{"application_id":`)
	if malformedEvent.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed event JSON, got %d: %s", malformedEvent.Code, malformedEvent.Body.String())
	}
	if err := json.Unmarshal(malformedEvent.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed event error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict event decode error body, got %#v", errorBody)
	}

	malformedDependency := client.rawBody(t, http.MethodPost, "/api/v1/dependencies", "", nil, `{"application_id":`)
	if malformedDependency.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed dependency JSON, got %d: %s", malformedDependency.Code, malformedDependency.Body.String())
	}
	if err := json.Unmarshal(malformedDependency.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed dependency error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict dependency decode error body, got %#v", errorBody)
	}
	malformedBaseline := client.rawBody(t, http.MethodPost, "/api/v1/baseline-findings", "", nil, `{"application_id":`)
	if malformedBaseline.Code != http.StatusBadRequest {
		t.Fatalf("expected generated strict request decoder to reject malformed baseline JSON, got %d: %s", malformedBaseline.Code, malformedBaseline.Body.String())
	}
	if err := json.Unmarshal(malformedBaseline.Body.Bytes(), &errorBody); err != nil {
		t.Fatalf("decode malformed baseline error: %v", err)
	}
	if errorBody["error"] != "invalid_json" || !strings.Contains(errorBody["message"].(string), "can't decode JSON body") {
		t.Fatalf("expected strict baseline decode error body, got %#v", errorBody)
	}

	me := client.request(t, http.MethodGet, "/api/v1/me", token, nil)
	if objectValue(t, me, "user")["email"] != "admin@ohmyrasp.local" {
		t.Fatalf("unexpected strict me response: %#v", me)
	}
	applications := client.request(t, http.MethodGet, "/api/v1/applications", token, nil)
	if len(arrayValue(t, applications, "items")) == 0 {
		t.Fatalf("expected strict applications response to include seeded app, got %#v", applications)
	}
	overview := client.request(t, http.MethodGet, "/api/v1/analytics/overview", token, nil)
	if _, ok := overview["events_by_type"].(map[string]any); !ok {
		t.Fatalf("expected strict overview map response, got %#v", overview)
	}
	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	if len(arrayValue(t, audit, "items")) == 0 {
		t.Fatalf("expected strict audit log response after login, got %#v", audit)
	}

	unauthenticatedDependency := client.raw(t, http.MethodPost, "/api/v1/dependencies", "", nil, map[string]any{
		"application_id": "app_default",
		"name":           "blocked-lib",
	})
	if unauthenticatedDependency.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated dependency report to be rejected, got %d: %s", unauthenticatedDependency.Code, unauthenticatedDependency.Body.String())
	}
	mismatchedEvent := client.raw(t, http.MethodPost, "/api/v1/events/attack", "", appHeaders("app_default", "dev-app-secret"), map[string]any{
		"application_id": "other_app",
		"environment_id": "env_default",
		"agent_id":       "agt_missing",
		"severity":       "critical",
		"message":        "spoofed event",
	})
	if mismatchedEvent.Code != http.StatusUnauthorized {
		t.Fatalf("expected mismatched event app report to be rejected, got %d: %s", mismatchedEvent.Code, mismatchedEvent.Body.String())
	}

	dependency := client.requestWithHeaders(t, http.MethodPost, "/api/v1/dependencies", defaultAppHeaders(), map[string]any{
		"application_id": "app_default",
		"name":           "log4j-core",
		"version":        "2.17.2",
		"ecosystem":      "maven",
		"package_path":   "org/apache/logging/log4j/log4j-core/2.17.2/log4j-core-2.17.2.jar",
		"licenses":       []string{"Apache-2.0"},
		"vulnerabilities": []map[string]any{
			{
				"id":              "CVE-2021-45046",
				"severity":        "critical",
				"cvss":            9.0,
				"known_exploited": true,
				"fixed_version":   "2.17.3",
			},
		},
	})
	if dependency["name"] != "log4j-core" || dependency["application_id"] != "app_default" || dependency["package_path"] == "" {
		t.Fatalf("unexpected strict dependency ingest response: %#v", dependency)
	}
	if len(arrayValue(t, dependency, "licenses")) != 1 || len(arrayValue(t, dependency, "vulnerabilities")) != 1 {
		t.Fatalf("expected dependency metadata in response: %#v", dependency)
	}
	dependencies := client.request(t, http.MethodGet, "/api/v1/dependencies", token, nil)
	if len(arrayValue(t, dependencies, "items")) != 1 {
		t.Fatalf("expected dependency list response, got %#v", dependencies)
	}
	dependencyExport := client.request(t, http.MethodGet, "/api/v1/dependencies/export", token, nil)
	if len(arrayValue(t, dependencyExport, "items")) != 1 {
		t.Fatalf("expected dependency export response, got %#v", dependencyExport)
	}
	dependencySummary := client.request(t, http.MethodGet, "/api/v1/dependencies/summary", token, nil)
	if dependencySummary["dependency_count"].(float64) != 1 || dependencySummary["vulnerable_dependency_count"].(float64) != 1 || dependencySummary["known_exploited_count"].(float64) != 1 {
		t.Fatalf("expected dependency summary counts, got %#v", dependencySummary)
	}
	byEcosystem := objectValue(t, dependencySummary, "dependencies_by_ecosystem")
	if byEcosystem["maven"].(float64) != 1 {
		t.Fatalf("expected dependency ecosystem aggregate, got %#v", byEcosystem)
	}
	byVulnerabilitySeverity := objectValue(t, dependencySummary, "vulnerabilities_by_severity")
	if byVulnerabilitySeverity["critical"].(float64) != 1 {
		t.Fatalf("expected dependency vulnerability aggregate, got %#v", byVulnerabilitySeverity)
	}
	filteredDependencies := client.request(t, http.MethodGet, "/api/v1/dependencies?application_id=app_default&name=log4j-core&ecosystem=maven&vulnerability_severity=critical&observed_after=2026-05-30T00:00:00Z&observed_before=2026-06-01T00:00:00Z&limit=1", token, nil)
	if len(arrayValue(t, filteredDependencies, "items")) != 1 {
		t.Fatalf("expected filtered dependency list response, got %#v", filteredDependencies)
	}
	emptySeverityDependencies := client.request(t, http.MethodGet, "/api/v1/dependencies?vulnerability_severity=low", token, nil)
	if len(arrayValue(t, emptySeverityDependencies, "items")) != 0 {
		t.Fatalf("expected empty severity dependency list response, got %#v", emptySeverityDependencies)
	}
	emptyDependencies := client.request(t, http.MethodGet, "/api/v1/dependencies?ecosystem=npm", token, nil)
	if len(arrayValue(t, emptyDependencies, "items")) != 0 {
		t.Fatalf("expected empty dependency list response, got %#v", emptyDependencies)
	}
	badDependencyLimit := client.raw(t, http.MethodGet, "/api/v1/dependencies?limit=1001", token, nil, nil)
	if badDependencyLimit.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid dependency limit to be rejected, got %d: %s", badDependencyLimit.Code, badDependencyLimit.Body.String())
	}
	agent := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", defaultAppHeaders(), map[string]any{
		"environment_id": "env_default",
		"hostname":       "strict-agent-1",
		"runtime":        "java",
		"version":        "1.0.0",
	})
	agentID := stringValue(t, agent, "id")
	unauthenticatedHeartbeat := client.raw(t, http.MethodPost, "/api/v1/agents/"+agentID+"/heartbeat", "", nil, map[string]any{
		"status": "online",
	})
	if unauthenticatedHeartbeat.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated Agent heartbeat to be rejected, got %d: %s", unauthenticatedHeartbeat.Code, unauthenticatedHeartbeat.Body.String())
	}
	mismatchedPolicyPull := client.raw(t, http.MethodGet, "/api/v1/agents/"+agentID+"/policy", "", appHeaders("app_missing", "missing-secret"), nil)
	if mismatchedPolicyPull.Code != http.StatusUnauthorized {
		t.Fatalf("expected mismatched Agent policy pull to be rejected, got %d: %s", mismatchedPolicyPull.Code, mismatchedPolicyPull.Body.String())
	}
	unauthenticatedBaseline := client.raw(t, http.MethodPost, "/api/v1/baseline-findings", "", nil, map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"check_id":       "jvm.security_manager",
		"title":          "JVM security manager disabled",
		"severity":       "medium",
		"status":         "warning",
	})
	if unauthenticatedBaseline.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated baseline report to be rejected, got %d: %s", unauthenticatedBaseline.Code, unauthenticatedBaseline.Body.String())
	}
	baseline := client.requestWithHeaders(t, http.MethodPost, "/api/v1/baseline-findings", defaultAppHeaders(), map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"check_id":       "jvm.security_manager",
		"title":          "JVM security manager disabled",
		"category":       "runtime",
		"severity":       "medium",
		"status":         "warning",
		"resource":       "strict-agent-1",
		"remediation":    "Enable explicit policy controls before production rollout.",
		"attributes":     map[string]any{"runtime": "java"},
	})
	if baseline["check_id"] != "jvm.security_manager" || baseline["status"] != "warning" {
		t.Fatalf("unexpected baseline finding response: %#v", baseline)
	}
	filteredBaseline := client.request(t, http.MethodGet, "/api/v1/baseline-findings?application_id=app_default&environment_id=env_default&agent_id="+agentID+"&severity=medium&status=warning&category=runtime&limit=1", token, nil)
	if len(arrayValue(t, filteredBaseline, "items")) != 1 {
		t.Fatalf("expected filtered baseline finding response, got %#v", filteredBaseline)
	}
	emptyBaseline := client.request(t, http.MethodGet, "/api/v1/baseline-findings?status=failed", token, nil)
	if len(arrayValue(t, emptyBaseline, "items")) != 0 {
		t.Fatalf("expected empty baseline finding response, got %#v", emptyBaseline)
	}
	badBaselineStatus := client.raw(t, http.MethodGet, "/api/v1/baseline-findings?status=unknown", token, nil, nil)
	if badBaselineStatus.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid baseline status to be rejected, got %d: %s", badBaselineStatus.Code, badBaselineStatus.Body.String())
	}
	for _, eventType := range []string{"hook", "performance", "crash"} {
		client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/"+eventType, defaultAppHeaders(), map[string]any{
			"application_id": "app_default",
			"environment_id": "env_default",
			"agent_id":       agentID,
			"severity":       "low",
			"message":        eventType + " event",
			"hook":           "servlet",
		})
		events := client.request(t, http.MethodGet, "/api/v1/events/"+eventType, token, nil)
		items := arrayValue(t, events, "items")
		if len(items) != 1 || items[0].(map[string]any)["type"] != eventType {
			t.Fatalf("expected %s event list response, got %#v", eventType, events)
		}
	}
	audit = client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	if !containsAuditAction(arrayValue(t, audit, "items"), "dependency.ingest") {
		t.Fatalf("expected dependency ingest audit entry, got %#v", audit)
	}
	if !containsAuditAction(arrayValue(t, audit, "items"), "baseline.ingest") {
		t.Fatalf("expected baseline ingest audit entry, got %#v", audit)
	}
}

func TestRBACRequiresAuthenticatedUser(t *testing.T) {
	client := newTestClient(t)
	response := client.raw(t, http.MethodPost, "/api/v1/applications", "", nil, map[string]any{"name": "blocked"})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", response.Code, response.Body.String())
	}
}

func TestPermissionMatrixEnforcesHumanRoles(t *testing.T) {
	client := newTestClient(t)
	adminToken := client.login(t)

	viewer := client.request(t, http.MethodPost, "/api/v1/users", adminToken, map[string]any{
		"email":    "viewer@example.test",
		"name":     "Viewer User",
		"password": "change-me-2",
		"roles":    []string{"viewer"},
	})
	if stringValue(t, viewer, "id") == "" {
		t.Fatalf("expected viewer user: %#v", viewer)
	}
	viewerLogin := client.request(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    "viewer@example.test",
		"password": "change-me-2",
	})
	viewerToken := stringValue(t, objectValue(t, viewerLogin, "session"), "token")

	readApps := client.raw(t, http.MethodGet, "/api/v1/applications", viewerToken, nil, nil)
	if readApps.Code != http.StatusOK {
		t.Fatalf("expected viewer to read applications, got %d: %s", readApps.Code, readApps.Body.String())
	}
	writeApps := client.raw(t, http.MethodPost, "/api/v1/applications", viewerToken, nil, map[string]any{"name": "Viewer Attempt"})
	if writeApps.Code != http.StatusForbidden {
		t.Fatalf("expected viewer application write to be forbidden, got %d: %s", writeApps.Code, writeApps.Body.String())
	}
	rotateAppSecret := client.raw(t, http.MethodPost, "/api/v1/applications/app_default/secret/rotate", viewerToken, nil, nil)
	if rotateAppSecret.Code != http.StatusForbidden {
		t.Fatalf("expected viewer application secret rotation to be forbidden, got %d: %s", rotateAppSecret.Code, rotateAppSecret.Body.String())
	}

	security := client.request(t, http.MethodPost, "/api/v1/users", adminToken, map[string]any{
		"email":    "security@example.test",
		"name":     "Security User",
		"password": "change-me-3",
		"roles":    []string{"security_engineer"},
	})
	if stringValue(t, security, "id") == "" {
		t.Fatalf("expected security user: %#v", security)
	}
	securityLogin := client.request(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    "security@example.test",
		"password": "change-me-3",
	})
	securityToken := stringValue(t, objectValue(t, securityLogin, "session"), "token")

	securityWrite := client.raw(t, http.MethodPost, "/api/v1/applications", securityToken, nil, map[string]any{"name": "Security Managed App"})
	if securityWrite.Code != http.StatusCreated {
		t.Fatalf("expected security engineer to manage applications, got %d: %s", securityWrite.Code, securityWrite.Body.String())
	}
	var securityApp map[string]any
	if err := json.Unmarshal(securityWrite.Body.Bytes(), &securityApp); err != nil {
		t.Fatalf("decode security app: %v", err)
	}
	securityRotate := client.raw(t, http.MethodPost, "/api/v1/applications/"+stringValue(t, securityApp, "id")+"/secret/rotate", securityToken, nil, nil)
	if securityRotate.Code != http.StatusOK {
		t.Fatalf("expected security engineer to rotate application secret, got %d: %s", securityRotate.Code, securityRotate.Body.String())
	}
	securityUsers := client.raw(t, http.MethodGet, "/api/v1/users", securityToken, nil, nil)
	if securityUsers.Code != http.StatusForbidden {
		t.Fatalf("expected security engineer user read to be forbidden, got %d: %s", securityUsers.Code, securityUsers.Body.String())
	}
}

func TestDaemonWorkloadInventoryTokenAndBinding(t *testing.T) {
	artifactDir := t.TempDir()
	artifactBytes := agentArtifactZipFixture(t, "conf/ohmyrasp-agent.yml", "cloud.app_secret: dev-app-secret")
	if err := os.WriteFile(filepath.Join(artifactDir, "agent-java-linux-17.zip"), artifactBytes, 0o600); err != nil {
		t.Fatalf("write artifact fixture: %v", err)
	}
	client := newTestClientWithArtifactDir(t, artifactDir)
	adminToken := client.login(t)

	tokenResponse := client.request(t, http.MethodGet, "/api/v1/daemon/token", adminToken, nil)
	daemonToken := stringValue(t, tokenResponse, "access_token")

	unauthorizedApp := client.raw(t, http.MethodGet, "/api/v1/daemon/app?app_id=app_default", "", daemonHeaders("wrong-token"), nil)
	if unauthorizedApp.Code != http.StatusUnauthorized {
		t.Fatalf("expected daemon app lookup with wrong token to be rejected, got %d: %s", unauthorizedApp.Code, unauthorizedApp.Body.String())
	}
	daemonApp := client.requestWithHeaders(t, http.MethodGet, "/api/v1/daemon/app?app_id=app_default", daemonHeaders(daemonToken), nil)
	if stringValue(t, daemonApp, "application_id") != "app_default" || stringValue(t, daemonApp, "application_secret") != "dev-app-secret" || stringValue(t, daemonApp, "language") != "java" {
		t.Fatalf("unexpected daemon app lookup: %#v", daemonApp)
	}
	legacyAppResponse := client.raw(t, http.MethodGet, "/v1/service/app/get?appId=app_default", "", legacyDaemonHeaders(daemonToken), nil)
	if legacyAppResponse.Code != http.StatusOK {
		t.Fatalf("expected legacy daemon app lookup, got %d: %s", legacyAppResponse.Code, legacyAppResponse.Body.String())
	}
	var legacyApp map[string]any
	if err := json.Unmarshal(legacyAppResponse.Body.Bytes(), &legacyApp); err != nil {
		t.Fatalf("decode legacy daemon app: %v", err)
	}
	legacyAppData := objectValue(t, legacyApp, "data")
	if stringValue(t, legacyAppData, "secret") != "dev-app-secret" || stringValue(t, legacyAppData, "language") != "java" {
		t.Fatalf("unexpected legacy daemon app: %#v", legacyApp)
	}
	artifactInfo := client.requestWithHeaders(t, http.MethodGet, "/api/v1/daemon/artifacts/agent/info?app_id=app_default&language=java&system_type=linux&language_version=17", daemonHeaders(daemonToken), nil)
	artifactMD5 := stringValue(t, artifactInfo, "md5")
	if stringValue(t, artifactInfo, "content_type") != "application/zip" || stringValue(t, artifactInfo, "language") != "java" || artifactInfo["size"].(float64) <= 0 {
		t.Fatalf("unexpected daemon artifact info: %#v", artifactInfo)
	}
	download := client.raw(t, http.MethodGet, "/api/v1/daemon/artifacts/agent?app_id=app_default&language=java&system_type=linux&language_version=17", "", daemonHeaders(daemonToken), nil)
	if download.Code != http.StatusOK || download.Header().Get("Content-Type") != "application/zip" || download.Header().Get("X-OhMyRasp-Agent-MD5") != artifactMD5 {
		t.Fatalf("unexpected daemon artifact download %d headers=%#v body=%q", download.Code, download.Header(), download.Body.String())
	}
	if gotMD5 := fmt.Sprintf("%x", md5.Sum(download.Body.Bytes())); gotMD5 != artifactMD5 {
		t.Fatalf("expected downloaded artifact md5 %s, got %s", artifactMD5, gotMD5)
	}
	assertAgentArtifactZipContains(t, download.Body.Bytes(), "cloud.app_secret: dev-app-secret")
	legacyInfoResponse := client.raw(t, http.MethodGet, "/v1/service/dl/agent/info?appId=app_default&language=java&systemType=linux&languageVersion=17", "", legacyDaemonHeaders(daemonToken), nil)
	if legacyInfoResponse.Code != http.StatusOK {
		t.Fatalf("expected legacy daemon artifact info, got %d: %s", legacyInfoResponse.Code, legacyInfoResponse.Body.String())
	}
	var legacyInfo map[string]any
	if err := json.Unmarshal(legacyInfoResponse.Body.Bytes(), &legacyInfo); err != nil {
		t.Fatalf("decode legacy daemon artifact info: %v", err)
	}
	if legacyMD5 := stringValue(t, objectValue(t, legacyInfo, "data"), "md5"); legacyMD5 != artifactMD5 {
		t.Fatalf("expected legacy artifact md5 %s, got %s", artifactMD5, legacyMD5)
	}
	legacyDownload := client.raw(t, http.MethodGet, "/v1/service/dl/agent?appId=app_default&language=java&systemType=linux&languageVersion=17", "", legacyDaemonHeaders(daemonToken), nil)
	if legacyDownload.Code != http.StatusOK || fmt.Sprintf("%x", md5.Sum(legacyDownload.Body.Bytes())) != artifactMD5 {
		t.Fatalf("unexpected legacy daemon artifact download %d: headers=%#v", legacyDownload.Code, legacyDownload.Header())
	}
	catalogDir := t.TempDir()
	catalogBytes := []byte("agent package zip fixture")
	if err := os.WriteFile(filepath.Join(catalogDir, "agent-java-linux-17.zip"), catalogBytes, 0o600); err != nil {
		t.Fatalf("write artifact fixture: %v", err)
	}
	catalogClient := newTestClientWithArtifactDir(t, catalogDir)
	catalogToken := catalogClient.login(t)
	filesystemCatalog := catalogClient.request(t, http.MethodGet, "/api/v1/agent-artifacts", catalogToken, nil)
	if !filesystemCatalog["artifact_dir_configured"].(bool) || filesystemCatalog["generated_bootstrap_enabled"].(bool) {
		t.Fatalf("expected filesystem artifact catalog, got %#v", filesystemCatalog)
	}
	catalogItems := arrayValue(t, filesystemCatalog, "items")
	if len(catalogItems) != 1 {
		t.Fatalf("expected one artifact catalog item, got %#v", filesystemCatalog)
	}
	catalogItem := catalogItems[0].(map[string]any)
	if stringValue(t, catalogItem, "filename") != "agent-java-linux-17.zip" ||
		stringValue(t, catalogItem, "language") != "java" ||
		stringValue(t, catalogItem, "system_type") != "linux" ||
		stringValue(t, catalogItem, "language_version") != "17" ||
		stringValue(t, catalogItem, "md5") != fmt.Sprintf("%x", md5.Sum(catalogBytes)) {
		t.Fatalf("unexpected artifact catalog item: %#v", catalogItem)
	}
	noDirClient := newTestClient(t)
	noDirToken := noDirClient.login(t)
	noUploadDir := noDirClient.raw(t, http.MethodPost, "/api/v1/agent-artifacts", noDirToken, nil, map[string]any{
		"language":         "java",
		"system_type":      "linux",
		"language_version": "21",
		"content_base64":   base64.StdEncoding.EncodeToString(agentArtifactZipFixture(t, "README.txt", "fixture")),
	})
	if noUploadDir.Code != http.StatusBadRequest {
		t.Fatalf("expected upload without artifact dir to be rejected, got %d: %s", noUploadDir.Code, noUploadDir.Body.String())
	}
	uploadedBytes := agentArtifactZipFixture(t, "agent/ohmyrasp-java-agent.jar", "uploaded fixture")
	uploaded := catalogClient.request(t, http.MethodPost, "/api/v1/agent-artifacts", catalogToken, map[string]any{
		"filename":         "operator-upload.zip",
		"language":         "java",
		"system_type":      "linux",
		"language_version": "21",
		"content_base64":   base64.StdEncoding.EncodeToString(uploadedBytes),
	})
	if stringValue(t, uploaded, "filename") != "ohmyrasp-agent-java-linux-21.zip" ||
		stringValue(t, uploaded, "source") != "uploaded" ||
		stringValue(t, uploaded, "md5") != fmt.Sprintf("%x", md5.Sum(uploadedBytes)) {
		t.Fatalf("unexpected uploaded artifact response: %#v", uploaded)
	}
	badUpload := catalogClient.raw(t, http.MethodPost, "/api/v1/agent-artifacts", catalogToken, nil, map[string]any{
		"language":         "java",
		"system_type":      "linux",
		"language_version": "bad",
		"content_base64":   base64.StdEncoding.EncodeToString([]byte("not a zip")),
	})
	if badUpload.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid ZIP upload to be rejected, got %d: %s", badUpload.Code, badUpload.Body.String())
	}
	uploadedCatalog := catalogClient.request(t, http.MethodGet, "/api/v1/agent-artifacts", catalogToken, nil)
	if len(arrayValue(t, uploadedCatalog, "items")) != 2 {
		t.Fatalf("expected filesystem and uploaded artifacts in catalog, got %#v", uploadedCatalog)
	}
	catalogDaemonToken := stringValue(t, catalogClient.request(t, http.MethodGet, "/api/v1/daemon/token", catalogToken, nil), "access_token")
	uploadedInfo := catalogClient.requestWithHeaders(t, http.MethodGet, "/api/v1/daemon/artifacts/agent/info?app_id=app_default&language=java&system_type=linux&language_version=21", daemonHeaders(catalogDaemonToken), nil)
	if stringValue(t, uploadedInfo, "filename") != "ohmyrasp-agent-java-linux-21.zip" || stringValue(t, uploadedInfo, "md5") != stringValue(t, uploaded, "md5") {
		t.Fatalf("expected daemon artifact metadata to use uploaded artifact, got %#v", uploadedInfo)
	}
	uploadedDownload := catalogClient.raw(t, http.MethodGet, "/api/v1/daemon/artifacts/agent?app_id=app_default&language=java&system_type=linux&language_version=21", "", daemonHeaders(catalogDaemonToken), nil)
	if uploadedDownload.Code != http.StatusOK || fmt.Sprintf("%x", md5.Sum(uploadedDownload.Body.Bytes())) != stringValue(t, uploaded, "md5") {
		t.Fatalf("expected daemon download to serve uploaded artifact, got %d: %s", uploadedDownload.Code, uploadedDownload.Body.String())
	}
	artifactAudit := catalogClient.request(t, http.MethodGet, "/api/v1/audit-logs", catalogToken, nil)
	if !containsAuditAction(arrayValue(t, artifactAudit, "items"), "agent_artifact.upload") {
		t.Fatalf("expected Agent artifact upload audit entry, got %#v", artifactAudit)
	}

	unauthorizedReport := client.raw(t, http.MethodPost, "/api/v1/daemon/workloads/report", "", nil, map[string]any{
		"node_name": "node-a",
		"workloads": []map[string]any{
			{"type": "process", "pid": 4242, "cmdline": []string{"/usr/bin/java", "-jar", "app.jar"}},
		},
	})
	if unauthorizedReport.Code != http.StatusUnauthorized {
		t.Fatalf("expected daemon report without token to be rejected, got %d: %s", unauthorizedReport.Code, unauthorizedReport.Body.String())
	}

	report := client.requestWithHeaders(t, http.MethodPost, "/api/v1/daemon/workloads/report", daemonHeaders(daemonToken), map[string]any{
		"node_name": "node-a",
		"workloads": []map[string]any{
			{"type": "process", "pid": 4242, "cmdline": []string{"/usr/bin/java", "-jar", "app.jar"}},
			{"type": "container", "container_id": "ctr_abc", "container_name": "payments", "image_tag": "payments:1.0.0"},
		},
	})
	reported := arrayValue(t, report, "items")
	if len(reported) != 2 {
		t.Fatalf("expected two reported workloads, got %#v", report)
	}

	workloads := client.request(t, http.MethodGet, "/api/v1/daemon/workloads", adminToken, nil)
	items := arrayValue(t, workloads, "items")
	if len(items) != 2 {
		t.Fatalf("expected listed daemon workloads, got %#v", workloads)
	}
	var processID string
	for _, item := range items {
		workload := item.(map[string]any)
		if workload["type"] == "process" {
			processID = stringValue(t, workload, "id")
		}
	}
	if processID == "" {
		t.Fatalf("expected process workload in %#v", workloads)
	}

	bound := client.request(t, http.MethodPost, "/api/v1/daemon/workloads/"+processID+"/bind", adminToken, map[string]any{
		"application_id": "app_default",
	})
	if bound["application_id"] != "app_default" {
		t.Fatalf("expected workload to bind to app_default, got %#v", bound)
	}
	if response := client.raw(t, http.MethodGet, "/api/v1/daemon/commands", "", nil, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("expected daemon commands without token to be rejected, got %d: %s", response.Code, response.Body.String())
	}
	if response := client.raw(t, http.MethodGet, "/api/v1/daemon/commands", "", daemonHeaders("wrong-token"), nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("expected daemon commands with wrong token to be rejected, got %d: %s", response.Code, response.Body.String())
	}
	commands := client.requestWithHeaders(t, http.MethodGet, "/api/v1/daemon/commands", daemonHeaders(daemonToken), nil)
	commandItems := arrayValue(t, commands, "items")
	if len(commandItems) != 1 {
		t.Fatalf("expected one daemon command group, got %#v", commands)
	}
	command := commandItems[0].(map[string]any)
	if stringValue(t, command, "application_id") != "app_default" || stringValue(t, command, "application_secret") != "dev-app-secret" || stringValue(t, command, "language") != "java" {
		t.Fatalf("unexpected daemon command group: %#v", command)
	}
	commandWorkloads := arrayValue(t, command, "workloads")
	var foundProcess bool
	for _, item := range commandWorkloads {
		workload := item.(map[string]any)
		if stringValue(t, workload, "id") == processID {
			foundProcess = true
		}
	}
	if !foundProcess {
		t.Fatalf("expected bound process workload in daemon commands, got %#v", command)
	}
	unauthorizedInjection := client.raw(t, http.MethodPost, "/api/v1/daemon/injection-reports", "", daemonHeaders("wrong-token"), map[string]any{
		"workload_id": processID,
		"status":      "injected",
	})
	if unauthorizedInjection.Code != http.StatusUnauthorized {
		t.Fatalf("expected daemon injection report with wrong token to be rejected, got %d: %s", unauthorizedInjection.Code, unauthorizedInjection.Body.String())
	}
	invalidInjection := client.raw(t, http.MethodPost, "/api/v1/daemon/injection-reports", "", daemonHeaders(daemonToken), map[string]any{
		"workload_id": processID,
		"status":      "failed",
	})
	if invalidInjection.Code != http.StatusBadRequest {
		t.Fatalf("expected failed injection without error to be rejected, got %d: %s", invalidInjection.Code, invalidInjection.Body.String())
	}
	injection := client.requestWithHeaders(t, http.MethodPost, "/api/v1/daemon/injection-reports", daemonHeaders(daemonToken), map[string]any{
		"workload_id":    processID,
		"status":         "failed",
		"error":          "jattach permission denied",
		"helper_id":      "helper-node-a",
		"helper_version": "1.2.3",
		"reported_at":    "2026-05-31T00:00:00Z",
	})
	if stringValue(t, injection, "injection_status") != "failed" || stringValue(t, injection, "injection_error") != "jattach permission denied" || stringValue(t, injection, "injection_helper_id") != "helper-node-a" {
		t.Fatalf("unexpected daemon injection report response: %#v", injection)
	}
	workloads = client.request(t, http.MethodGet, "/api/v1/daemon/workloads", adminToken, nil)
	if !containsWorkloadInjection(arrayValue(t, workloads, "items"), processID, "failed") {
		t.Fatalf("expected listed daemon workload injection status, got %#v", workloads)
	}
	unbound := client.request(t, http.MethodPost, "/api/v1/daemon/workloads/"+processID+"/unbind", adminToken, nil)
	if _, ok := unbound["application_id"]; ok {
		t.Fatalf("expected workload to be unbound, got %#v", unbound)
	}
	if _, ok := unbound["injection_status"]; ok {
		t.Fatalf("expected unbind to clear injection status, got %#v", unbound)
	}
	commands = client.requestWithHeaders(t, http.MethodGet, "/api/v1/daemon/commands", daemonHeaders(daemonToken), nil)
	if commandItems := arrayValue(t, commands, "items"); len(commandItems) != 0 {
		t.Fatalf("expected daemon commands to clear after unbind, got %#v", commands)
	}

	rotated := client.request(t, http.MethodPost, "/api/v1/daemon/token/reset", adminToken, nil)
	rotatedToken := stringValue(t, rotated, "access_token")
	if rotatedToken == daemonToken {
		t.Fatalf("expected daemon token reset to rotate token, got %#v", rotated)
	}
	oldTokenReport := client.raw(t, http.MethodPost, "/api/v1/daemon/workloads/report", "", daemonHeaders(daemonToken), map[string]any{
		"node_name": "node-a",
		"workloads": []map[string]any{{"type": "process", "pid": 5000}},
	})
	if oldTokenReport.Code != http.StatusUnauthorized {
		t.Fatalf("expected old daemon token to be rejected, got %d: %s", oldTokenReport.Code, oldTokenReport.Body.String())
	}
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/daemon/workloads/report", daemonHeaders(rotatedToken), map[string]any{
		"node_name": "node-a",
		"workloads": []map[string]any{{"type": "process", "pid": 5000}},
	})

	viewer := client.request(t, http.MethodPost, "/api/v1/users", adminToken, map[string]any{
		"email":    "daemon-viewer@example.test",
		"name":     "Daemon Viewer",
		"password": "change-me-2",
		"roles":    []string{"viewer"},
	})
	if stringValue(t, viewer, "id") == "" {
		t.Fatalf("expected viewer user: %#v", viewer)
	}
	viewerLogin := client.request(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    "daemon-viewer@example.test",
		"password": "change-me-2",
	})
	viewerToken := stringValue(t, objectValue(t, viewerLogin, "session"), "token")
	if response := client.raw(t, http.MethodGet, "/api/v1/daemon/workloads", viewerToken, nil, nil); response.Code != http.StatusOK {
		t.Fatalf("expected viewer to read daemon workloads, got %d: %s", response.Code, response.Body.String())
	}
	if response := client.raw(t, http.MethodGet, "/api/v1/agent-artifacts", viewerToken, nil, nil); response.Code != http.StatusOK {
		t.Fatalf("expected viewer to read Agent artifact catalog, got %d: %s", response.Code, response.Body.String())
	}
	for _, attempt := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/daemon/token", nil},
		{http.MethodPost, "/api/v1/daemon/token/reset", nil},
		{http.MethodPost, "/api/v1/agent-artifacts", map[string]any{"language": "java", "system_type": "linux", "language_version": "21", "content_base64": "bad"}},
		{http.MethodPost, "/api/v1/daemon/workloads/" + processID + "/bind", map[string]any{"application_id": "app_default"}},
		{http.MethodPost, "/api/v1/daemon/workloads/" + processID + "/unbind", nil},
	} {
		response := client.raw(t, attempt.method, attempt.path, viewerToken, nil, attempt.body)
		if response.Code != http.StatusForbidden {
			t.Fatalf("expected viewer %s %s to be forbidden, got %d: %s", attempt.method, attempt.path, response.Code, response.Body.String())
		}
	}

	security := client.request(t, http.MethodPost, "/api/v1/users", adminToken, map[string]any{
		"email":    "daemon-security@example.test",
		"name":     "Daemon Security",
		"password": "change-me-3",
		"roles":    []string{"security_engineer"},
	})
	if stringValue(t, security, "id") == "" {
		t.Fatalf("expected security user: %#v", security)
	}
	securityLogin := client.request(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    "daemon-security@example.test",
		"password": "change-me-3",
	})
	securityToken := stringValue(t, objectValue(t, securityLogin, "session"), "token")
	if response := client.raw(t, http.MethodPost, "/api/v1/daemon/token/reset", securityToken, nil, nil); response.Code != http.StatusOK {
		t.Fatalf("expected security engineer to reset daemon token, got %d: %s", response.Code, response.Body.String())
	}

	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", adminToken, nil)
	auditItems := arrayValue(t, audit, "items")
	for _, action := range []string{"daemon.token.reset", "daemon.workload.bind", "daemon.workload.unbind"} {
		if !containsAuditAction(auditItems, action) {
			t.Fatalf("expected %s audit entry, got %#v", action, auditItems)
		}
	}
}

func TestAgentArtifactCatalogDisablesGeneratedBootstrapByDefault(t *testing.T) {
	client := newTestClientWithServer(t, NewServer(testMemoryStore(time.Now), slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))
	adminToken := client.login(t)

	catalog := client.request(t, http.MethodGet, "/api/v1/agent-artifacts", adminToken, nil)
	if catalog["artifact_dir_configured"].(bool) || catalog["generated_bootstrap_enabled"].(bool) {
		t.Fatalf("expected generated bootstrap to be disabled by default, got %#v", catalog)
	}

	tokenResponse := client.request(t, http.MethodGet, "/api/v1/daemon/token", adminToken, nil)
	daemonToken := stringValue(t, tokenResponse, "access_token")
	download := client.raw(t, http.MethodGet, "/api/v1/daemon/artifacts/agent?app_id=app_default&language=java&system_type=linux&language_version=17", "", daemonHeaders(daemonToken), nil)
	if download.Code != http.StatusNotFound {
		t.Fatalf("expected missing artifact without generated bootstrap, got %d: %s", download.Code, download.Body.String())
	}
}

func TestUserAdministrationRequiresAdminAndAudits(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	blocked := client.raw(t, http.MethodGet, "/api/v1/users", "", nil, nil)
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", blocked.Code, blocked.Body.String())
	}

	users := client.request(t, http.MethodGet, "/api/v1/users", token, nil)
	if len(arrayValue(t, users, "items")) == 0 {
		t.Fatalf("expected seeded admin user, got %#v", users)
	}

	created := client.request(t, http.MethodPost, "/api/v1/users", token, map[string]any{
		"email":    "analyst@example.test",
		"name":     "Security Analyst",
		"password": "change-me-2",
		"roles":    []string{"security_engineer"},
	})
	userID := stringValue(t, created, "id")
	if _, ok := created["password_hash"]; ok {
		t.Fatalf("password hash leaked in response: %#v", created)
	}

	analystToken := client.request(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    "analyst@example.test",
		"password": "change-me-2",
	})
	analystSession := objectValue(t, analystToken, "session")
	forbidden := client.raw(t, http.MethodGet, "/api/v1/users", stringValue(t, analystSession, "token"), nil, nil)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("expected security engineer user admin to be forbidden, got %d: %s", forbidden.Code, forbidden.Body.String())
	}

	selfDowngrade := client.raw(t, http.MethodPut, "/api/v1/users/usr_admin", token, nil, map[string]any{
		"name":     "Default Admin",
		"roles":    []string{"viewer"},
		"disabled": false,
	})
	if selfDowngrade.Code != http.StatusBadRequest {
		t.Fatalf("expected self admin-role removal to be rejected, got %d: %s", selfDowngrade.Code, selfDowngrade.Body.String())
	}

	updated := client.request(t, http.MethodPut, "/api/v1/users/"+userID, token, map[string]any{
		"name":     "Security Analyst",
		"roles":    []string{"viewer"},
		"disabled": true,
	})
	if updated["disabled_at"] == nil {
		t.Fatalf("expected disabled_at in updated user: %#v", updated)
	}
	filteredUsers := client.request(t, http.MethodGet, "/api/v1/users?search=analyst&role=viewer&status=disabled", token, nil)
	filteredItems := arrayValue(t, filteredUsers, "items")
	if len(filteredItems) != 1 || filteredItems[0].(map[string]any)["id"] != userID {
		t.Fatalf("expected disabled analyst user search result, got %#v", filteredUsers)
	}
	activeFilteredUsers := client.request(t, http.MethodGet, "/api/v1/users?search=analyst&status=active", token, nil)
	if items := arrayValue(t, activeFilteredUsers, "items"); len(items) != 0 {
		t.Fatalf("expected active analyst search to be empty, got %#v", activeFilteredUsers)
	}
	badRole := client.raw(t, http.MethodGet, "/api/v1/users?role=owner", token, nil, nil)
	if badRole.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid user role filter to be rejected, got %d: %s", badRole.Code, badRole.Body.String())
	}

	disabledLogin := client.raw(t, http.MethodPost, "/api/v1/auth/login", "", nil, map[string]any{
		"email":    "analyst@example.test",
		"password": "change-me-2",
	})
	if disabledLogin.Code != http.StatusUnauthorized {
		t.Fatalf("expected disabled user login to fail, got %d: %s", disabledLogin.Code, disabledLogin.Body.String())
	}

	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	items := arrayValue(t, audit, "items")
	if !containsAuditResource(items, userID) {
		t.Fatalf("expected user audit entry, got %#v", items)
	}
}

func TestPolicyValidationRejectsUnsafeRule(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	result := client.request(t, http.MethodPost, "/api/v1/policies/validate", token, map[string]any{
		"rules": []map[string]any{
			{
				"name":       "loop",
				"hook":       "request",
				"action":     "block",
				"expression": "while(true){}",
			},
		},
	})
	if result["valid"].(bool) {
		t.Fatalf("expected unsafe rule to be invalid: %#v", result)
	}
}

func TestEventAggregationAndAuditLog(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	agent := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", defaultAppHeaders(), map[string]any{
		"environment_id": "env_default",
		"hostname":       "audit-agent-1",
		"runtime":        "java",
		"version":        "1.0.0",
	})
	agentID := stringValue(t, agent, "id")
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/attack", defaultAppHeaders(), map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"hook":           "command",
		"algorithm":      "command_userinput",
		"severity":       "critical",
		"message":        "shell metacharacters detected",
		"attributes": map[string]any{
			"user_agent": "curl/8.0",
		},
	})
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/crash", defaultAppHeaders(), map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"severity":       "low",
		"message":        "agent crashed",
	})
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/error", defaultAppHeaders(), map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"hook":           "servlet",
		"severity":       "high",
		"message":        "unhandled exception captured",
		"attributes": map[string]any{
			"exception_class": "java.lang.IllegalStateException",
		},
	})

	overview := client.request(t, http.MethodGet, "/api/v1/analytics/overview", token, nil)
	if overview["event_count"].(float64) != 3 {
		t.Fatalf("expected three events, got %#v", overview)
	}
	byType := objectValue(t, overview, "events_by_type")
	if byType["attack"].(float64) != 1 || byType["crash"].(float64) != 1 || byType["error"].(float64) != 1 {
		t.Fatalf("expected attack, crash, and error aggregates, got %#v", byType)
	}
	if overview["crash_count"].(float64) != 1 {
		t.Fatalf("expected crash aggregate, got %#v", overview)
	}
	attackTrend := arrayValue(t, overview, "attack_trend")
	if len(attackTrend) != 1 || attackTrend[0].(map[string]any)["count"].(float64) != 1 {
		t.Fatalf("expected one attack trend bucket, got %#v", attackTrend)
	}
	byHook := objectValue(t, overview, "attacks_by_hook")
	if byHook["command"].(float64) != 1 {
		t.Fatalf("expected hook aggregate, got %#v", byHook)
	}
	byAlgorithm := objectValue(t, overview, "attacks_by_algorithm")
	if byAlgorithm["command_userinput"].(float64) != 1 {
		t.Fatalf("expected algorithm aggregate, got %#v", byAlgorithm)
	}
	byUserAgent := objectValue(t, overview, "attacks_by_user_agent")
	if byUserAgent["curl/8.0"].(float64) != 1 {
		t.Fatalf("expected user-agent aggregate, got %#v", byUserAgent)
	}
	filtered := client.request(t, http.MethodGet, "/api/v1/events/attack?application_id=app_default&environment_id=env_default&agent_id="+agentID+"&severity=critical&hook=command&occurred_after=2026-05-30T00:00:00Z&occurred_before=2026-06-01T00:00:00Z&limit=1", token, nil)
	filteredItems := arrayValue(t, filtered, "items")
	if len(filteredItems) != 1 {
		t.Fatalf("expected one filtered attack event, got %#v", filtered)
	}
	filteredEvent := filteredItems[0].(map[string]any)
	if filteredEvent["agent_id"] != agentID || filteredEvent["hook"] != "command" || filteredEvent["severity"] != "critical" {
		t.Fatalf("unexpected filtered event: %#v", filteredEvent)
	}
	emptyFiltered := client.request(t, http.MethodGet, "/api/v1/events/attack?severity=low", token, nil)
	if items := arrayValue(t, emptyFiltered, "items"); len(items) != 0 {
		t.Fatalf("expected low-severity filter to return no attack events, got %#v", emptyFiltered)
	}
	errorFiltered := client.request(t, http.MethodGet, "/api/v1/events/error?severity=high&hook=servlet", token, nil)
	errorItems := arrayValue(t, errorFiltered, "items")
	if len(errorItems) != 1 {
		t.Fatalf("expected one filtered error event, got %#v", errorFiltered)
	}
	errorEvent := errorItems[0].(map[string]any)
	if errorEvent["type"] != "error" || errorEvent["message"] != "unhandled exception captured" {
		t.Fatalf("unexpected error event: %#v", errorEvent)
	}
	errorAttributes := objectValue(t, errorEvent, "attributes")
	if errorAttributes["exception_class"] != "java.lang.IllegalStateException" {
		t.Fatalf("expected exception attributes, got %#v", errorAttributes)
	}
	badLimit := client.raw(t, http.MethodGet, "/api/v1/events/attack?limit=1001", token, nil, nil)
	if badLimit.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid event limit to be rejected, got %d: %s", badLimit.Code, badLimit.Body.String())
	}

	blockedDeliveries := client.raw(t, http.MethodGet, "/api/v1/alert-deliveries", "", nil, nil)
	if blockedDeliveries.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", blockedDeliveries.Code, blockedDeliveries.Body.String())
	}
	deliveries := client.request(t, http.MethodGet, "/api/v1/alert-deliveries", token, nil)
	deliveryItems := arrayValue(t, deliveries, "items")
	if len(deliveryItems) != 2 {
		t.Fatalf("expected attack and crash alert deliveries, got %#v", deliveries)
	}
	deliveryStatus := map[string]any{}
	for _, item := range deliveryItems {
		delivery := item.(map[string]any)
		deliveryStatus[delivery["alert_rule_id"].(string)] = delivery["status"]
	}
	if deliveryStatus["alr_critical_attack"] != "queued" || deliveryStatus["alr_agent_crash"] != "queued" {
		t.Fatalf("expected queued attack and crash deliveries, got %#v", deliveries)
	}

	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	items := arrayValue(t, audit, "items")
	if len(items) == 0 {
		t.Fatal("expected login audit log")
	}
	if !containsAuditAction(items, "event.ingest") {
		t.Fatalf("expected event ingest audit entry, got %#v", items)
	}
}

func TestEventRecycleBinLifecycle(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	agent := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", defaultAppHeaders(), map[string]any{
		"environment_id": "env_default",
		"hostname":       "recycle-agent-1",
		"runtime":        "java",
		"version":        "1.0.0",
	})
	agentID := stringValue(t, agent, "id")
	event := client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/attack", defaultAppHeaders(), map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"hook":           "sql",
		"severity":       "high",
		"message":        "recycle candidate",
	})
	eventID := stringValue(t, event, "id")

	viewer := client.request(t, http.MethodPost, "/api/v1/users", token, map[string]any{
		"email":    "event-viewer@example.test",
		"name":     "Event Viewer",
		"password": "change-me-2",
		"roles":    []string{"viewer"},
	})
	if stringValue(t, viewer, "id") == "" {
		t.Fatalf("expected viewer user: %#v", viewer)
	}
	viewerLogin := client.request(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    "event-viewer@example.test",
		"password": "change-me-2",
	})
	viewerToken := stringValue(t, objectValue(t, viewerLogin, "session"), "token")
	forbidden := client.raw(t, http.MethodPost, "/api/v1/events/recycle-bin/delete", viewerToken, nil, map[string]any{"ids": []string{eventID}})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("expected viewer recycle-bin mutation to be forbidden, got %d: %s", forbidden.Code, forbidden.Body.String())
	}

	deleted := client.request(t, http.MethodPost, "/api/v1/events/recycle-bin/delete", token, map[string]any{"ids": []string{eventID}})
	if deleted["count"].(float64) != 1 {
		t.Fatalf("expected one soft-deleted event, got %#v", deleted)
	}
	active := client.request(t, http.MethodGet, "/api/v1/events/attack", token, nil)
	if items := arrayValue(t, active, "items"); len(items) != 0 {
		t.Fatalf("expected soft-deleted event to leave active list, got %#v", active)
	}
	recycled := client.request(t, http.MethodGet, "/api/v1/events/recycle-bin?type=attack&application_id=app_default", token, nil)
	recycledItems := arrayValue(t, recycled, "items")
	if len(recycledItems) != 1 {
		t.Fatalf("expected deleted event in recycle bin, got %#v", recycled)
	}
	recycledEvent := recycledItems[0].(map[string]any)
	if recycledEvent["id"] != eventID || recycledEvent["deleted_at"] == nil || recycledEvent["deleted_by"] == nil {
		t.Fatalf("unexpected recycled event: %#v", recycledEvent)
	}

	restored := client.request(t, http.MethodPost, "/api/v1/events/recycle-bin/restore", token, map[string]any{"ids": []string{eventID}})
	if restored["count"].(float64) != 1 {
		t.Fatalf("expected one restored event, got %#v", restored)
	}
	active = client.request(t, http.MethodGet, "/api/v1/events/attack", token, nil)
	if items := arrayValue(t, active, "items"); len(items) != 1 {
		t.Fatalf("expected restored event in active list, got %#v", active)
	}

	client.request(t, http.MethodPost, "/api/v1/events/recycle-bin/delete", token, map[string]any{"ids": []string{eventID}})
	purged := client.request(t, http.MethodPost, "/api/v1/events/recycle-bin/purge", token, map[string]any{"ids": []string{eventID}})
	if purged["count"].(float64) != 1 {
		t.Fatalf("expected one purged event, got %#v", purged)
	}
	recycled = client.request(t, http.MethodGet, "/api/v1/events/recycle-bin?type=attack", token, nil)
	if items := arrayValue(t, recycled, "items"); len(items) != 0 {
		t.Fatalf("expected purged event to leave recycle bin, got %#v", recycled)
	}
	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	auditItems := arrayValue(t, audit, "items")
	for _, action := range []string{"event.recycle.delete", "event.recycle.restore", "event.recycle.purge"} {
		if !containsAuditAction(auditItems, action) {
			t.Fatalf("expected %s audit entry in %#v", action, auditItems)
		}
	}
}

func TestObservabilityReportRequiresViewerAccess(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	blocked := client.raw(t, http.MethodGet, "/api/v1/analytics/observability", "", nil, nil)
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", blocked.Code, blocked.Body.String())
	}

	created := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appHeaders("app_default", "dev-app-secret"), map[string]any{
		"environment_id": "env_default",
		"hostname":       "obs-host",
		"runtime":        "java",
		"version":        "1.0.0",
	})
	agentID := stringValue(t, created, "id")
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/performance", appHeaders("app_default", "dev-app-secret"), map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"policy_id":      "pol_observed",
		"policy_version": 1,
		"hook":           "sql",
		"algorithm":      "overhead_sample",
		"severity":       "low",
		"message":        "observed performance sample",
		"attributes": map[string]any{
			"cpu_overhead_pct":      1.2,
			"memory_overhead_bytes": 1024,
			"hook_latency_p95_us":   1800,
			"rule_eval_p95_us":      900,
			"latency_us":            1700,
		},
	})

	report := client.request(t, http.MethodGet, "/api/v1/analytics/observability?application_id=app_default", token, nil)
	ruleOverhead := arrayValue(t, report, "rule_overhead")
	hookLatency := arrayValue(t, report, "hook_latency")
	agentOverhead := arrayValue(t, report, "agent_overhead")
	policyPerformance := arrayValue(t, report, "policy_performance")
	if len(ruleOverhead) != 0 {
		t.Fatalf("expected no synthetic rule overhead without rollup samples, got %#v", report)
	}
	if len(hookLatency) == 0 || len(agentOverhead) == 0 || len(policyPerformance) == 0 {
		t.Fatalf("expected observability report from ingested performance event, got %#v", report)
	}
}

func TestSystemSettingsAreListedAndAudited(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	blocked := client.raw(t, http.MethodGet, "/api/v1/system-settings", "", nil, nil)
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", blocked.Code, blocked.Body.String())
	}
	blockedEdition := client.raw(t, http.MethodGet, "/api/v1/system/edition", "", nil, nil)
	if blockedEdition.Code != http.StatusUnauthorized {
		t.Fatalf("expected edition endpoint to require authentication, got %d: %s", blockedEdition.Code, blockedEdition.Body.String())
	}

	settings := client.request(t, http.MethodGet, "/api/v1/system-settings", token, nil)
	defaults := arrayValue(t, settings, "items")
	if len(defaults) == 0 {
		t.Fatalf("expected default system settings, got %#v", settings)
	}
	for _, key := range []string{"agent.minimum_version", "events.retention", "protection.allowlist", "protection.hardening", "dependency.vulnerability_policy"} {
		if !containsSettingKey(defaults, key) {
			t.Fatalf("expected default setting %s in %#v", key, settings)
		}
	}
	edition := client.request(t, http.MethodGet, "/api/v1/system/edition", token, nil)
	if edition["edition"] != "oss_self_hosted" || edition["deployment_model"] != "single_organization_self_hosted" || edition["license_required"] != false || edition["license_enforcement"] != "none" || edition["license_status"] != "not_applicable" {
		t.Fatalf("expected OSS self-hosted edition status without license enforcement, got %#v", edition)
	}

	updated := client.request(t, http.MethodPut, "/api/v1/system-settings/alerts.delivery", token, map[string]any{
		"value": map[string]any{
			"email_enabled": true,
			"severity":      "high",
		},
	})
	if updated["key"] != "alerts.delivery" {
		t.Fatalf("expected normalized setting key, got %#v", updated)
	}

	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	items := arrayValue(t, audit, "items")
	if !containsAuditResource(items, "alerts.delivery") {
		t.Fatalf("expected settings audit entry, got %#v", items)
	}
}

func TestMaintenanceCleanupCanPreviewAndPurgeOperationalData(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)
	appAuth := defaultAppHeaders()
	agent := client.requestWithHeaders(t, http.MethodPost, "/api/v1/agents/register", appAuth, map[string]any{
		"environment_id": "env_default",
		"hostname":       "maintenance-agent",
		"runtime":        "java",
		"version":        "1.0.0",
	})
	agentID := stringValue(t, agent, "id")
	oldAt := "2026-01-01T00:00:00Z"
	newAt := "2026-03-01T00:00:00Z"
	cutoff := "2026-02-01T00:00:00Z"
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/attack", appAuth, map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"severity":       "critical",
		"message":        "old critical attack",
		"occurred_at":    oldAt,
	})
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/events/attack", appAuth, map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"severity":       "high",
		"message":        "new attack",
		"occurred_at":    newAt,
	})
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/dependencies", appAuth, map[string]any{
		"application_id": "app_default",
		"agent_id":       agentID,
		"name":           "old-lib",
		"version":        "1.0.0",
		"ecosystem":      "maven",
		"observed_at":    oldAt,
	})
	client.requestWithHeaders(t, http.MethodPost, "/api/v1/baseline-findings", appAuth, map[string]any{
		"application_id": "app_default",
		"environment_id": "env_default",
		"agent_id":       agentID,
		"check_id":       "old.check",
		"title":          "Old baseline finding",
		"category":       "runtime",
		"severity":       "medium",
		"status":         "warning",
		"observed_at":    oldAt,
	})
	preview := client.request(t, http.MethodPost, "/api/v1/maintenance/cleanup", token, map[string]any{
		"application_id": "app_default",
		"before":         cutoff,
		"dry_run":        true,
	})
	if preview["dry_run"] != true {
		t.Fatalf("expected dry-run cleanup preview, got %#v", preview)
	}
	previewCounts := objectValue(t, preview, "counts")
	for key, want := range map[string]float64{"events": 1, "dependencies": 1, "baseline_findings": 1, "alert_deliveries": 0} {
		if previewCounts[key] != want {
			t.Fatalf("expected preview %s count %v, got %#v", key, want, previewCounts)
		}
	}
	blocked := client.raw(t, http.MethodPost, "/api/v1/maintenance/cleanup", token, nil, map[string]any{
		"application_id": "app_default",
		"before":         cutoff,
		"dry_run":        false,
	})
	if blocked.Code != http.StatusBadRequest {
		t.Fatalf("expected destructive cleanup without confirmation to be rejected, got %d: %s", blocked.Code, blocked.Body.String())
	}
	applied := client.request(t, http.MethodPost, "/api/v1/maintenance/cleanup", token, map[string]any{
		"application_id": "app_default",
		"before":         cutoff,
		"dry_run":        false,
		"confirmation":   "CLEAR_OPERATIONAL_DATA",
	})
	appliedCounts := objectValue(t, applied, "counts")
	if appliedCounts["events"] != float64(1) || appliedCounts["dependencies"] != float64(1) || appliedCounts["baseline_findings"] != float64(1) {
		t.Fatalf("unexpected applied cleanup counts: %#v", appliedCounts)
	}
	oldEvents := client.request(t, http.MethodGet, "/api/v1/events/attack?application_id=app_default&occurred_before="+cutoff, token, nil)
	if len(arrayValue(t, oldEvents, "items")) != 0 {
		t.Fatalf("expected old attack event to be purged, got %#v", oldEvents)
	}
	newEvents := client.request(t, http.MethodGet, "/api/v1/events/attack?application_id=app_default&occurred_after="+cutoff, token, nil)
	if len(arrayValue(t, newEvents, "items")) != 1 {
		t.Fatalf("expected new attack event to remain, got %#v", newEvents)
	}
	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	if !containsAuditAction(arrayValue(t, audit, "items"), "maintenance.cleanup") {
		t.Fatalf("expected cleanup audit entry, got %#v", audit)
	}
}

func TestAlertRulesCanBeManagedAndAudited(t *testing.T) {
	client := newTestClient(t)
	token := client.login(t)

	blocked := client.raw(t, http.MethodGet, "/api/v1/alert-rules", "", nil, nil)
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", blocked.Code, blocked.Body.String())
	}

	listed := client.request(t, http.MethodGet, "/api/v1/alert-rules", token, nil)
	defaults := arrayValue(t, listed, "items")
	if len(defaults) == 0 {
		t.Fatalf("expected default alert rules, got %#v", listed)
	}

	created := client.request(t, http.MethodPost, "/api/v1/alert-rules", token, map[string]any{
		"name":        "High attack volume",
		"description": "Notify on high attack severity",
		"enabled":     true,
		"event_type":  "attack",
		"severity":    "high",
		"condition":   "severity == high",
		"target":      "security-operations",
	})
	alertRuleID := stringValue(t, created, "id")

	updated := client.request(t, http.MethodPut, "/api/v1/alert-rules/"+alertRuleID, token, map[string]any{
		"name":        "High attack volume",
		"description": "Disabled during maintenance",
		"enabled":     false,
		"event_type":  "attack",
		"severity":    "high",
		"condition":   "severity == high",
		"target":      "security-operations",
	})
	if updated["enabled"].(bool) {
		t.Fatalf("expected updated alert rule to be disabled, got %#v", updated)
	}

	audit := client.request(t, http.MethodGet, "/api/v1/audit-logs", token, nil)
	items := arrayValue(t, audit, "items")
	if !containsAuditResource(items, alertRuleID) {
		t.Fatalf("expected alert rule audit entry, got %#v", items)
	}
}

type testClient struct {
	handler http.Handler
}

func newTestClient(t *testing.T) *testClient {
	return newTestClientWithArtifactDir(t, "")
}

func newTestClientWithArtifactDir(t *testing.T, artifactDir string) *testClient {
	t.Helper()
	now := func() time.Time { return time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC) }
	store := testMemoryStore(now)
	server := NewServer(store, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
	if artifactDir != "" {
		server.WithAgentArtifactDir(artifactDir)
	}
	return newTestClientWithServer(t, server)
}

func testMemoryStore(now func() time.Time) *control.MemoryStore {
	return control.NewMemoryStoreWithSeed(now, control.MemorySeed{
		AdminEmail:             "admin@ohmyrasp.local",
		AdminPassword:          "change-me",
		AdminName:              "Default Admin",
		ApplicationID:          "app_default",
		ApplicationName:        "Test Java Service",
		ApplicationDescription: "Test application",
		ApplicationSecret:      "dev-app-secret",
		EnvironmentID:          "env_default",
		EnvironmentName:        "production",
		EnvironmentKind:        "production",
	})
}

func newTestClientWithServer(t *testing.T, server *Server) *testClient {
	t.Helper()
	return &testClient{handler: server.Routes()}
}

func (c *testClient) login(t *testing.T) string {
	t.Helper()
	result := c.request(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    "admin@ohmyrasp.local",
		"password": "change-me",
	})
	session := objectValue(t, result, "session")
	return stringValue(t, session, "token")
}

func (c *testClient) request(t *testing.T, method string, path string, token string, body any) map[string]any {
	t.Helper()
	return c.requestWithHeaders(t, method, path, authHeaders(token), body)
}

func (c *testClient) requestWithHeaders(t *testing.T, method string, path string, headers map[string]string, body any) map[string]any {
	t.Helper()
	response := c.raw(t, method, path, "", headers, body)
	if response.Code < 200 || response.Code >= 300 {
		t.Fatalf("%s %s returned %d: %s", method, path, response.Code, response.Body.String())
	}
	if response.Body.Len() == 0 {
		return map[string]any{}
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, response.Body.String())
	}
	return result
}

func (c *testClient) raw(t *testing.T, method string, path string, token string, headers map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	request := httptest.NewRequest(method, path, &payload)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	c.handler.ServeHTTP(response, request)
	return response
}

func (c *testClient) rawBody(t *testing.T, method string, path string, token string, headers map[string]string, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	c.handler.ServeHTTP(response, request)
	return response
}

func authHeaders(token string) map[string]string {
	if token == "" {
		return nil
	}
	return map[string]string{"Authorization": "Bearer " + token}
}

func appHeaders(appID string, appSecret string) map[string]string {
	return map[string]string{
		"X-OhMyRasp-App-ID":     appID,
		"X-OhMyRasp-App-Secret": appSecret,
	}
}

func defaultAppHeaders() map[string]string {
	return appHeaders("app_default", "dev-app-secret")
}

func daemonHeaders(token string) map[string]string {
	return map[string]string{"X-OhMyRasp-Daemon-Token": token}
}

func legacyDaemonHeaders(token string) map[string]string {
	return map[string]string{"X-Auth-Token": token}
}

func assertAgentArtifactZipContains(t *testing.T, data []byte, content string) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("read agent artifact zip: %v", err)
	}
	for _, file := range reader.File {
		if file.Name != "conf/ohmyrasp-agent.yml" {
			continue
		}
		handle, err := file.Open()
		if err != nil {
			t.Fatalf("open agent artifact config: %v", err)
		}
		raw, err := io.ReadAll(handle)
		if closeErr := handle.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatalf("read agent artifact config: %v", err)
		}
		if !strings.Contains(string(raw), content) {
			t.Fatalf("expected agent artifact config to contain %q, got %q", content, string(raw))
		}
		return
	}
	t.Fatalf("expected agent artifact config file in zip")
}

func agentArtifactZipFixture(t *testing.T, name string, content string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	file, err := writer.Create(name)
	if err != nil {
		t.Fatalf("create artifact zip fixture file: %v", err)
	}
	if _, err := file.Write([]byte(content)); err != nil {
		t.Fatalf("write artifact zip fixture file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close artifact zip fixture: %v", err)
	}
	return buffer.Bytes()
}

func stringValue(t *testing.T, value map[string]any, key string) string {
	t.Helper()
	raw, ok := value[key].(string)
	if !ok || raw == "" {
		t.Fatalf("expected non-empty string %q in %#v", key, value)
	}
	return raw
}

func objectValue(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	raw, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("expected object %q in %#v", key, value)
	}
	return raw
}

func objectFromAny(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object in %#v", value)
	}
	return raw
}

func arrayValue(t *testing.T, value map[string]any, key string) []any {
	t.Helper()
	raw, ok := value[key].([]any)
	if !ok {
		t.Fatalf("expected array %q in %#v", key, value)
	}
	return raw
}

func containsAuditResource(items []any, resource string) bool {
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if ok && raw["resource"] == resource {
			return true
		}
	}
	return false
}

func containsSettingKey(items []any, key string) bool {
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if ok && raw["key"] == key {
			return true
		}
	}
	return false
}

func containsAuditAction(items []any, action string) bool {
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if ok && raw["action"] == action {
			return true
		}
	}
	return false
}

func containsAlgorithmCatalogItem(items []any, hook string, algorithm string) bool {
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if !ok || raw["hook"] != hook {
			continue
		}
		algorithms, ok := raw["algorithms"].([]any)
		if !ok {
			continue
		}
		for _, item := range algorithms {
			if item == algorithm {
				return true
			}
		}
	}
	return false
}

func containsPolicyRule(items []any, hook string, algorithm string) bool {
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if ok && raw["hook"] == hook && raw["algorithm"] == algorithm {
			return true
		}
	}
	return false
}

func containsApplicationID(items []any, id string) bool {
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if ok && raw["id"] == id {
			return true
		}
	}
	return false
}

func containsAgentID(items []any, id string) bool {
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if ok && raw["id"] == id {
			return true
		}
	}
	return false
}

func containsWorkloadInjection(items []any, workloadID string, status string) bool {
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if ok && raw["id"] == workloadID && raw["injection_status"] == status {
			return true
		}
	}
	return false
}
