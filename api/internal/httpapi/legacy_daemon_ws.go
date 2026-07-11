package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/pierrec/lz4/v4"
)

const maxLegacyDaemonFrameBytes = 4 * 1024 * 1024

var legacyDaemonWebsocketUpgrader = websocket.Upgrader{
	ReadBufferSize:   4096,
	WriteBufferSize:  4096,
	HandshakeTimeout: 6 * time.Second,
	CheckOrigin: func(*http.Request) bool {
		return true
	},
}

type legacyDaemonEnvelope struct {
	Cmd      string          `json:"cmd"`
	NodeName string          `json:"node_name"`
	NodeIP   string          `json:"node_ip"`
	Args     json.RawMessage `json:"args"`
}

type legacyDaemonHelperArgs struct {
	Tasks         []legacyDaemonAggregatedProcess `json:"tasks"`
	HelperVersion string                          `json:"helper_version"`
	HelperID      string                          `json:"helper_id"`
	Time          uint64                          `json:"time"`
	OS            string                          `json:"os"`
}

type legacyDaemonAggregatedProcess struct {
	AggregationID string                    `json:"aggregation_id"`
	Description   string                    `json:"description"`
	Datas         []legacyDaemonProcessData `json:"datas"`
}

type legacyDaemonProcessData struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

type legacyDaemonInjectErrorArgs struct {
	Error    string                  `json:"error"`
	Data     legacyDaemonProcessData `json:"data"`
	HelperID string                  `json:"helper_id"`
	Time     uint64                  `json:"time"`
}

type legacyRemoteCommand struct {
	Cmd  string                     `json:"cmd"`
	Args []legacyRemoteProcessGroup `json:"args"`
}

type legacyRemoteProcessGroup struct {
	ApplicationID     string                    `json:"app_id"`
	ApplicationSecret string                    `json:"app_secret,omitempty"`
	Language          string                    `json:"language,omitempty"`
	Data              []legacyDaemonProcessData `json:"data"`
}

func (s *Server) legacyDaemonCommandWebsocket(w http.ResponseWriter, r *http.Request) {
	token := daemonRequestToken(r)
	if token == "" {
		s.writeError(w, control.ErrUnauthorized)
		return
	}
	if _, err := s.store.ListDaemonCommands(r.Context(), token); err != nil {
		s.writeError(w, err)
		return
	}
	conn, err := legacyDaemonWebsocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Warn("legacy daemon websocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(maxLegacyDaemonFrameBytes)

	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		commands, err := s.handleLegacyDaemonMessage(r.Context(), token, messageType, payload)
		if err != nil {
			s.logger.Warn("legacy daemon websocket message rejected", "error", err)
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseUnsupportedData, err.Error()))
			return
		}
		if len(commands) == 0 {
			continue
		}
		response, err := encodeLegacyDaemonCommands(commands)
		if err != nil {
			s.logger.Warn("legacy daemon websocket command encoding failed", "error", err)
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "command encoding failed"))
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, response); err != nil {
			return
		}
	}
}

func (s *Server) legacyDaemonSetInject(w http.ResponseWriter, r *http.Request) {
	token := daemonRequestToken(r)
	if token == "" {
		s.writeError(w, control.ErrUnauthorized)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxLegacyDaemonFrameBytes+1))
	if err != nil {
		s.writeError(w, err)
		return
	}
	if len(payload) > maxLegacyDaemonFrameBytes {
		s.writeError(w, fmt.Errorf("%w: legacy daemon message exceeds maximum size", control.ErrInvalid))
		return
	}
	if _, err := s.handleLegacyDaemonMessage(r.Context(), token, websocket.TextMessage, payload); err != nil {
		s.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":        "success",
		"description": "ok",
		"status":      0,
	})
}

func (s *Server) handleLegacyDaemonMessage(ctx context.Context, token string, messageType int, payload []byte) ([]control.DaemonCommandGroup, error) {
	raw, err := decodeLegacyDaemonPayload(messageType, payload)
	if err != nil {
		return nil, err
	}
	var message legacyDaemonEnvelope
	if err := json.Unmarshal(raw, &message); err != nil {
		return nil, fmt.Errorf("%w: legacy daemon message must be JSON", control.ErrInvalid)
	}
	switch strings.TrimSpace(message.Cmd) {
	case "UpdateProcess", "UpdateK8S":
		report, err := legacyDaemonWorkloadReport(message)
		if err != nil {
			return nil, err
		}
		if _, err := s.store.ReportDaemonWorkloads(ctx, token, report); err != nil {
			return nil, err
		}
		return s.store.ListDaemonCommands(ctx, token)
	case "NotifyInjectError":
		report, err := legacyDaemonInjectionReport(message)
		if err != nil {
			return nil, err
		}
		if _, err := s.store.ReportDaemonInjection(ctx, token, report); err != nil {
			return nil, err
		}
		return s.store.ListDaemonCommands(ctx, token)
	default:
		return nil, fmt.Errorf("%w: unsupported legacy daemon command", control.ErrInvalid)
	}
}

func decodeLegacyDaemonPayload(messageType int, payload []byte) ([]byte, error) {
	if messageType == websocket.TextMessage || json.Valid(payload) {
		return payload, nil
	}
	if messageType != websocket.BinaryMessage {
		return nil, fmt.Errorf("%w: legacy daemon messages must be binary LZ4 JSON", control.ErrInvalid)
	}
	reader := lz4.NewReader(bytes.NewReader(payload))
	raw, err := io.ReadAll(io.LimitReader(reader, maxLegacyDaemonFrameBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: legacy daemon message must be LZ4 framed JSON", control.ErrInvalid)
	}
	if len(raw) > maxLegacyDaemonFrameBytes {
		return nil, fmt.Errorf("%w: legacy daemon message exceeds maximum size", control.ErrInvalid)
	}
	return raw, nil
}

func legacyDaemonWorkloadReport(message legacyDaemonEnvelope) (control.DaemonWorkloadReport, error) {
	args, reported, err := legacyDaemonHelperArgsAndProcesses(message.Args)
	if err != nil {
		return control.DaemonWorkloadReport{}, err
	}
	observedAt := legacyDaemonTimestamp(args.Time)
	inputs := make([]control.DaemonWorkloadInput, 0, len(reported))
	for _, process := range reported {
		input, err := legacyDaemonWorkloadInput(process, observedAt)
		if err != nil {
			return control.DaemonWorkloadReport{}, err
		}
		inputs = append(inputs, input)
	}
	return control.DaemonWorkloadReport{
		NodeName:  strings.TrimSpace(message.NodeName),
		Workloads: inputs,
	}, nil
}

func legacyDaemonHelperArgsAndProcesses(raw json.RawMessage) (legacyDaemonHelperArgs, []legacyDaemonProcessData, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return legacyDaemonHelperArgs{}, nil, fmt.Errorf("%w: legacy daemon args are required", control.ErrInvalid)
	}
	var args legacyDaemonHelperArgs
	if err := json.Unmarshal(raw, &args); err == nil && (len(args.Tasks) > 0 || args.HelperID != "" || args.HelperVersion != "") {
		return args, legacyDaemonTaskProcesses(args.Tasks), nil
	}
	var processes []legacyDaemonProcessData
	if err := json.Unmarshal(raw, &processes); err == nil {
		return legacyDaemonHelperArgs{}, processes, nil
	}
	return legacyDaemonHelperArgs{}, nil, fmt.Errorf("%w: legacy daemon process args are invalid", control.ErrInvalid)
}

func legacyDaemonTaskProcesses(tasks []legacyDaemonAggregatedProcess) []legacyDaemonProcessData {
	var processes []legacyDaemonProcessData
	for _, task := range tasks {
		processes = append(processes, task.Datas...)
	}
	return processes
}

func legacyDaemonWorkloadInput(process legacyDaemonProcessData, observedAt time.Time) (control.DaemonWorkloadInput, error) {
	processType := strings.ToLower(strings.TrimSpace(process.Type))
	switch processType {
	case "process":
		return control.DaemonWorkloadInput{
			Type:       "process",
			PID:        intValue(process.Data["pid"]),
			Cmdline:    stringSliceValue(process.Data["cmdline"]),
			ObservedAt: observedAt,
		}, nil
	case "container":
		return control.DaemonWorkloadInput{
			Type:          "container",
			ContainerID:   firstStringValue(process.Data, "container_id", "id"),
			ContainerName: firstStringValue(process.Data, "container_name", "name"),
			ImageID:       firstStringValue(process.Data, "image_id"),
			ImageTag:      firstStringValue(process.Data, "image_tag"),
			ObservedAt:    observedAt,
		}, nil
	default:
		return control.DaemonWorkloadInput{}, fmt.Errorf("%w: legacy daemon workload type must be process or container", control.ErrInvalid)
	}
}

func legacyDaemonInjectionReport(message legacyDaemonEnvelope) (control.DaemonInjectionReport, error) {
	var args legacyDaemonInjectErrorArgs
	if err := json.Unmarshal(message.Args, &args); err != nil {
		return control.DaemonInjectionReport{}, fmt.Errorf("%w: legacy daemon injection args are invalid", control.ErrInvalid)
	}
	reportedAt := legacyDaemonTimestamp(args.Time)
	input, err := legacyDaemonWorkloadInput(args.Data, reportedAt)
	if err != nil {
		return control.DaemonInjectionReport{}, err
	}
	workloadID := firstStringValue(args.Data.Data, "rasp_id", "workload_id", "id")
	if workloadID == "" {
		workloadID = control.PrepareDaemonWorkload(message.NodeName, input, time.Now().UTC()).ID
	}
	return control.DaemonInjectionReport{
		WorkloadID:    workloadID,
		Status:        "failed",
		Error:         strings.TrimSpace(args.Error),
		HelperID:      strings.TrimSpace(args.HelperID),
		ReportedAt:    reportedAt,
		HelperVersion: "",
	}, nil
}

func encodeLegacyDaemonCommands(commands []control.DaemonCommandGroup) ([]byte, error) {
	remote := legacyRemoteCommand{
		Cmd:  "InjectProcessGroup",
		Args: make([]legacyRemoteProcessGroup, 0, len(commands)),
	}
	for _, command := range commands {
		group := legacyRemoteProcessGroup{
			ApplicationID:     command.ApplicationID,
			ApplicationSecret: command.ApplicationSecret,
			Language:          daemonCommandLanguage(command.Language),
			Data:              make([]legacyDaemonProcessData, 0, len(command.Workloads)),
		}
		for _, workload := range command.Workloads {
			group.Data = append(group.Data, legacyDaemonRemoteProcessData(command.Language, workload))
		}
		remote.Args = append(remote.Args, group)
	}
	var raw bytes.Buffer
	if err := json.NewEncoder(&raw).Encode(remote); err != nil {
		return nil, err
	}
	var compressed bytes.Buffer
	writer := lz4.NewWriter(&compressed)
	if _, err := writer.Write(raw.Bytes()); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}

func legacyDaemonRemoteProcessData(language string, workload control.DaemonWorkload) legacyDaemonProcessData {
	switch workload.Type {
	case "container":
		return legacyDaemonProcessData{
			Type: "container",
			Data: map[string]any{
				"id":        workload.ContainerID,
				"name":      workload.ContainerName,
				"image_id":  workload.ImageID,
				"image_tag": workload.ImageTag,
				"created":   "",
				"status":    "",
				"ports":     []string{},
				"language":  daemonCommandLanguage(language),
				"rasp_id":   workload.ID,
			},
		}
	default:
		description := strings.Join(workload.Cmdline, " ")
		if description == "" && workload.PID != 0 {
			description = "pid:" + strconv.Itoa(workload.PID)
		}
		return legacyDaemonProcessData{
			Type: "process",
			Data: map[string]any{
				"pid":         workload.PID,
				"cmdline":     append([]string{}, workload.Cmdline...),
				"description": description,
				"version":     "",
				"start_time":  0,
				"exe":         nil,
				"language":    daemonCommandLanguage(language),
				"rasp_id":     workload.ID,
			},
		}
	}
}

func daemonCommandLanguage(language string) string {
	if value := strings.ToLower(strings.TrimSpace(language)); value != "" {
		return value
	}
	return "java"
}

func legacyDaemonTimestamp(raw uint64) time.Time {
	if raw == 0 {
		return time.Time{}
	}
	if raw > 10_000_000_000 {
		return time.UnixMilli(int64(raw)).UTC()
	}
	return time.Unix(int64(raw), 0).UTC()
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
		return parsed
	default:
		return 0
	}
}

func stringSliceValue(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string{}, typed...)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := strings.TrimSpace(fmt.Sprint(item)); value != "" {
				values = append(values, value)
			}
		}
		return values
	default:
		return nil
	}
}

func firstStringValue(values map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := values[name]; ok {
			if text := strings.TrimSpace(fmt.Sprint(value)); text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}
