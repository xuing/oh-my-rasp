package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pierrec/lz4/v4"
)

func TestLegacyDaemonCommandWebSocketLifecycle(t *testing.T) {
	client := newTestClient(t)
	adminToken := client.login(t)
	daemonToken := stringValue(t, client.request(t, http.MethodGet, "/api/v1/daemon/token", adminToken, nil), "access_token")
	server := httptest.NewServer(client.handler)
	t.Cleanup(server.Close)
	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/service/command"

	if conn, response, err := websocket.DefaultDialer.Dial(websocketURL, http.Header{"X-Auth-Token": []string{"wrong-token"}}); err == nil {
		_ = conn.Close()
		t.Fatal("expected legacy daemon websocket with wrong token to fail")
	} else if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected websocket unauthorized response, got response=%v err=%v", response, err)
	}

	conn, response, err := websocket.DefaultDialer.Dial(websocketURL, http.Header{"X-Auth-Token": []string{daemonToken}})
	if err != nil {
		t.Fatalf("connect legacy daemon websocket: status=%v err=%v", response, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	update := legacyDaemonTestUpdateProcess("legacy-node")
	if err := conn.WriteMessage(websocket.BinaryMessage, encodeLegacyDaemonTestJSON(t, update)); err != nil {
		t.Fatalf("write legacy daemon update: %v", err)
	}

	processID := legacyDaemonTestWaitForWorkloadID(t, client, adminToken, "process")
	client.request(t, http.MethodPost, "/api/v1/daemon/workloads/"+processID+"/bind", adminToken, map[string]any{"application_id": "app_default"})

	if err := conn.WriteMessage(websocket.BinaryMessage, encodeLegacyDaemonTestJSON(t, update)); err != nil {
		t.Fatalf("write legacy daemon update after bind: %v", err)
	}
	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read legacy daemon command: %v", err)
	}
	if messageType != websocket.BinaryMessage {
		t.Fatalf("expected binary command message, got %d", messageType)
	}
	command := decodeLegacyDaemonTestJSON(t, payload)
	if command["cmd"] != "InjectProcessGroup" {
		t.Fatalf("expected InjectProcessGroup command, got %#v", command)
	}
	args := command["args"].([]any)
	if len(args) != 1 {
		t.Fatalf("expected one process group, got %#v", command)
	}
	group := args[0].(map[string]any)
	if group["app_id"] != "app_default" || group["app_secret"] != "dev-app-secret" || group["language"] != "java" {
		t.Fatalf("unexpected legacy daemon process group: %#v", group)
	}
	data := group["data"].([]any)
	process := data[0].(map[string]any)
	processData := process["data"].(map[string]any)
	if process["type"] != "process" || processData["rasp_id"] != processID {
		t.Fatalf("expected command to carry bound workload id as rasp_id, got %#v", process)
	}

	injectionError := map[string]any{
		"cmd":       "NotifyInjectError",
		"node_name": "legacy-node",
		"node_ip":   "10.0.0.5",
		"args": map[string]any{
			"error":     "jattach permission denied",
			"helper_id": "helper-legacy",
			"time":      1780272000000,
			"data":      process,
		},
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, encodeLegacyDaemonTestJSON(t, injectionError)); err != nil {
		t.Fatalf("write legacy daemon injection error: %v", err)
	}
	legacyDaemonTestWaitForInjection(t, client, adminToken, processID, "failed")
}

func legacyDaemonTestUpdateProcess(nodeName string) map[string]any {
	return map[string]any{
		"cmd":       "UpdateProcess",
		"node_name": nodeName,
		"node_ip":   "10.0.0.5",
		"args": map[string]any{
			"helper_version": "1.2.3",
			"helper_id":      "helper-legacy",
			"time":           1780272000000,
			"os":             "linux",
			"tasks": []map[string]any{{
				"aggregation_id": "agg-java",
				"description":    "java -jar app.jar",
				"datas": []map[string]any{{
					"type": "process",
					"data": map[string]any{
						"pid":         4242,
						"cmdline":     []string{"/usr/bin/java", "-jar", "app.jar"},
						"description": "java -jar app.jar",
						"version":     "17",
						"start_time":  0,
						"exe":         "/usr/bin/java",
						"language":    "java",
					},
				}},
			}},
		},
	}
}

func legacyDaemonTestWorkloadID(t *testing.T, items []any, workloadType string) string {
	t.Helper()
	for _, item := range items {
		workload := item.(map[string]any)
		if workload["type"] == workloadType {
			return stringValue(t, workload, "id")
		}
	}
	t.Fatalf("missing %s workload in %#v", workloadType, items)
	return ""
}

func legacyDaemonTestWaitForWorkloadID(t *testing.T, client *testClient, adminToken string, workloadType string) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var items []any
	for time.Now().Before(deadline) {
		workloads := client.request(t, http.MethodGet, "/api/v1/daemon/workloads", adminToken, nil)
		items = arrayValue(t, workloads, "items")
		for _, item := range items {
			workload := item.(map[string]any)
			if workload["type"] == workloadType {
				return stringValue(t, workload, "id")
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return legacyDaemonTestWorkloadID(t, items, workloadType)
}

func legacyDaemonTestWaitForInjection(t *testing.T, client *testClient, adminToken string, workloadID string, status string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var workloads map[string]any
	for time.Now().Before(deadline) {
		workloads = client.request(t, http.MethodGet, "/api/v1/daemon/workloads", adminToken, nil)
		if containsWorkloadInjection(arrayValue(t, workloads, "items"), workloadID, status) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected legacy injection error to update workload status, got %#v", workloads)
}

func encodeLegacyDaemonTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal legacy daemon message: %v", err)
	}
	var compressed bytes.Buffer
	writer := lz4.NewWriter(&compressed)
	if _, err := writer.Write(raw); err != nil {
		t.Fatalf("compress legacy daemon message: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("finish legacy daemon message compression: %v", err)
	}
	return compressed.Bytes()
}

func decodeLegacyDaemonTestJSON(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	reader := lz4.NewReader(bytes.NewReader(payload))
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decompress legacy daemon message: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode legacy daemon message: %v; body=%s", err, string(raw))
	}
	return result
}
