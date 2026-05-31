package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/ohmyrasp/control-plane/internal/generated"
)

const maxAgentArtifactUploadBytes = 100 * 1024 * 1024

type agentArtifact struct {
	FileName        string `json:"filename"`
	ContentType     string `json:"content_type"`
	MD5             string `json:"md5"`
	Size            int64  `json:"size"`
	Language        string `json:"language"`
	SystemType      string `json:"system_type"`
	LanguageVersion string `json:"language_version"`
	data            []byte
}

func (s *Server) daemonApplication(w http.ResponseWriter, r *http.Request) {
	app, err := s.daemonApplicationFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) legacyDaemonApplication(w http.ResponseWriter, r *http.Request) {
	app, err := s.daemonApplicationFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]string{
			"secret":   app.ApplicationSecret,
			"language": app.Language,
		},
		"description": "ok",
		"status":      0,
	})
}

func (s *Server) daemonArtifactInfo(w http.ResponseWriter, r *http.Request) {
	artifact, err := s.agentArtifactFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, artifact)
}

func (s *Server) legacyDaemonArtifactInfo(w http.ResponseWriter, r *http.Request) {
	artifact, err := s.agentArtifactFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]string{
			"md5": artifact.MD5,
		},
		"description": "ok",
		"status":      0,
	})
}

func (s *Server) daemonArtifactDownload(w http.ResponseWriter, r *http.Request) {
	artifact, err := s.agentArtifactFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", artifact.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", artifact.FileName))
	w.Header().Set("X-OhMyRasp-Agent-MD5", artifact.MD5)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact.data)
}

func (s *Server) agentArtifactCatalog() (generated.AgentArtifactCatalog, error) {
	catalog := generated.AgentArtifactCatalog{
		ArtifactDirConfigured:     s.agentArtifactDir != "",
		GeneratedBootstrapEnabled: true,
		Items:                     []generated.AgentArtifactCatalogItem{},
	}
	if s.agentArtifactDir == "" {
		return catalog, nil
	}
	entries, err := os.ReadDir(s.agentArtifactDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return catalog, nil
		}
		return generated.AgentArtifactCatalog{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".zip") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return generated.AgentArtifactCatalog{}, err
		}
		path := filepath.Join(s.agentArtifactDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return generated.AgentArtifactCatalog{}, err
		}
		language, systemType, languageVersion := artifactCatalogSegments(entry.Name())
		source := "filesystem"
		if strings.HasPrefix(strings.ToLower(entry.Name()), "ohmyrasp-agent-") {
			source = "uploaded"
		}
		catalog.Items = append(catalog.Items, generated.AgentArtifactCatalogItem{
			Filename:        entry.Name(),
			ContentType:     "application/zip",
			Md5:             md5Hex(data),
			Size:            info.Size(),
			Language:        language,
			SystemType:      systemType,
			LanguageVersion: languageVersion,
			Source:          source,
			UpdatedAt:       info.ModTime().UTC(),
		})
	}
	sort.Slice(catalog.Items, func(i, j int) bool {
		return catalog.Items[i].Filename < catalog.Items[j].Filename
	})
	return catalog, nil
}

func (s *Server) uploadAgentArtifact(ctx context.Context, actorID string, input generated.AgentArtifactUpload) (generated.AgentArtifactCatalogItem, error) {
	if s.agentArtifactDir == "" {
		return generated.AgentArtifactCatalogItem{}, fmt.Errorf("%w: agent artifact directory is not configured", control.ErrInvalid)
	}
	language := normalizeArtifactSegment(string(input.Language))
	systemType := normalizeArtifactSegment(input.SystemType)
	languageVersion := normalizeArtifactSegment(input.LanguageVersion)
	if language != "java" || systemType == "" || languageVersion == "" {
		return generated.AgentArtifactCatalogItem{}, fmt.Errorf("%w: artifact language, system type, and language version are required", control.ErrInvalid)
	}
	data, err := decodeAgentArtifactContent(input.ContentBase64)
	if err != nil {
		return generated.AgentArtifactCatalogItem{}, err
	}
	if err := validateAgentArtifactZip(data); err != nil {
		return generated.AgentArtifactCatalogItem{}, err
	}
	if err := os.MkdirAll(s.agentArtifactDir, 0o750); err != nil {
		return generated.AgentArtifactCatalogItem{}, err
	}
	filename := canonicalAgentArtifactFilename(language, systemType, languageVersion)
	path := filepath.Join(s.agentArtifactDir, filename)
	if err := writeAgentArtifactFile(path, data); err != nil {
		return generated.AgentArtifactCatalogItem{}, err
	}
	updatedAt := time.Now().UTC()
	item := generated.AgentArtifactCatalogItem{
		Filename:        filename,
		ContentType:     "application/zip",
		Md5:             md5Hex(data),
		Size:            int64(len(data)),
		Language:        language,
		SystemType:      systemType,
		LanguageVersion: languageVersion,
		Source:          "uploaded",
		UpdatedAt:       updatedAt,
	}
	if err := s.store.RecordAuditLog(ctx, actorID, "agent_artifact.upload", filename, map[string]any{
		"filename":         filename,
		"md5":              item.Md5,
		"size":             item.Size,
		"language":         language,
		"system_type":      systemType,
		"language_version": languageVersion,
	}); err != nil {
		return generated.AgentArtifactCatalogItem{}, err
	}
	return item, nil
}

func (s *Server) daemonApplicationFromRequest(r *http.Request) (control.DaemonApplication, error) {
	appID := queryValue(r, "app_id", "appId")
	if appID == "" {
		return control.DaemonApplication{}, fmt.Errorf("%w: application id is required", control.ErrInvalid)
	}
	return s.store.GetDaemonApplication(r.Context(), daemonRequestToken(r), appID)
}

func (s *Server) agentArtifactFromRequest(r *http.Request) (agentArtifact, error) {
	app, err := s.daemonApplicationFromRequest(r)
	if err != nil {
		return agentArtifact{}, err
	}
	language := normalizeArtifactSegment(queryValue(r, "language"))
	if language == "" {
		language = app.Language
	}
	if language != app.Language {
		return agentArtifact{}, fmt.Errorf("%w: requested language does not match application language", control.ErrInvalid)
	}
	if language != "java" {
		return agentArtifact{}, fmt.Errorf("%w: unsupported agent language", control.ErrInvalid)
	}
	systemType := normalizeArtifactSegment(queryValue(r, "system_type", "systemType"))
	if systemType == "" {
		systemType = "linux"
	}
	languageVersion := normalizeArtifactSegment(queryValue(r, "language_version", "languageVersion"))
	if languageVersion == "" {
		languageVersion = "unknown"
	}
	data, fileName, err := s.loadAgentArtifact(app, language, systemType, languageVersion)
	if err != nil {
		return agentArtifact{}, err
	}
	return agentArtifact{
		FileName:        fileName,
		ContentType:     "application/zip",
		MD5:             md5Hex(data),
		Size:            int64(len(data)),
		Language:        language,
		SystemType:      systemType,
		LanguageVersion: languageVersion,
		data:            data,
	}, nil
}

func (s *Server) loadAgentArtifact(app control.DaemonApplication, language string, systemType string, languageVersion string) ([]byte, string, error) {
	if s.agentArtifactDir != "" {
		for _, candidate := range agentArtifactCandidates(language, systemType, languageVersion) {
			path := filepath.Join(s.agentArtifactDir, candidate)
			data, err := os.ReadFile(path)
			if err == nil {
				return data, candidate, nil
			}
			if !errors.Is(err, os.ErrNotExist) {
				return nil, "", err
			}
		}
	}
	fileName := fmt.Sprintf("ohmyrasp-agent-%s-%s-%s.zip", language, systemType, languageVersion)
	data, err := generatedAgentArtifact(app, language, systemType, languageVersion)
	return data, fileName, err
}

func generatedAgentArtifact(app control.DaemonApplication, language string, systemType string, languageVersion string) ([]byte, error) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	files := []struct {
		name    string
		content string
	}{
		{
			name:    "README.txt",
			content: "OhMyRasp generated agent bootstrap artifact.\nProvide OHMYRASP_AGENT_ARTIFACT_DIR to serve a production agent ZIP.\n",
		},
		{
			name:    "conf/ohmyrasp-agent.yml",
			content: fmt.Sprintf("cloud.backend_url: /api/v1\ncloud.app_id: %s\ncloud.app_secret: %s\nagent.language: %s\nagent.system_type: %s\nagent.language_version: %s\n", app.ApplicationID, app.ApplicationSecret, language, systemType, languageVersion),
		},
	}
	for _, entry := range files {
		header := &zip.FileHeader{
			Name:     entry.name,
			Method:   zip.Deflate,
			Modified: time.Unix(0, 0).UTC(),
		}
		file, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := file.Write([]byte(entry.content)); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func agentArtifactCandidates(language string, systemType string, languageVersion string) []string {
	return []string{
		canonicalAgentArtifactFilename(language, systemType, languageVersion),
		fmt.Sprintf("agent-%s-%s-%s.zip", language, systemType, languageVersion),
		fmt.Sprintf("agent-%s-%s.zip", language, systemType),
		fmt.Sprintf("agent-%s.zip", language),
		fmt.Sprintf("%s-%s-%s.zip", language, systemType, languageVersion),
		fmt.Sprintf("%s-%s.zip", language, systemType),
		fmt.Sprintf("%s.zip", language),
	}
}

func canonicalAgentArtifactFilename(language string, systemType string, languageVersion string) string {
	return fmt.Sprintf("ohmyrasp-agent-%s-%s-%s.zip", language, systemType, languageVersion)
}

func decodeAgentArtifactContent(raw string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if strings.HasPrefix(value, "data:") {
		if _, after, ok := strings.Cut(value, ","); ok {
			value = after
		}
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: artifact content must be base64", control.ErrInvalid)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: artifact content is required", control.ErrInvalid)
	}
	if len(data) > maxAgentArtifactUploadBytes {
		return nil, fmt.Errorf("%w: artifact content exceeds 100 MiB", control.ErrInvalid)
	}
	return data, nil
}

func validateAgentArtifactZip(data []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%w: artifact must be a valid ZIP package", control.ErrInvalid)
	}
	if len(reader.File) == 0 {
		return fmt.Errorf("%w: artifact ZIP must contain at least one file", control.ErrInvalid)
	}
	for _, file := range reader.File {
		name := strings.TrimSpace(file.Name)
		cleaned := filepath.Clean(name)
		if name == "" || filepath.IsAbs(name) || strings.HasPrefix(cleaned, "..") || strings.Contains(name, "\\") {
			return fmt.Errorf("%w: artifact ZIP contains an unsafe path", control.ErrInvalid)
		}
	}
	return nil
}

func writeAgentArtifactFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".artifact-*.zip")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func artifactCatalogSegments(filename string) (string, string, string) {
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(filename)), ".zip")
	for _, prefix := range []string{"ohmyrasp-agent-", "agent-"} {
		name = strings.TrimPrefix(name, prefix)
	}
	parts := strings.Split(name, "-")
	language := "unknown"
	systemType := "any"
	languageVersion := "any"
	if len(parts) > 0 {
		if value := normalizeArtifactSegment(parts[0]); value != "" {
			language = value
		}
	}
	if len(parts) > 1 {
		if value := normalizeArtifactSegment(parts[1]); value != "" {
			systemType = value
		}
	}
	if len(parts) > 2 {
		if value := normalizeArtifactSegment(strings.Join(parts[2:], "-")); value != "" {
			languageVersion = value
		}
	}
	return language, systemType, languageVersion
}

func queryValue(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.URL.Query().Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func daemonRequestToken(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get("X-OhMyRasp-Daemon-Token")); token != "" {
		return token
	}
	return strings.TrimSpace(r.Header.Get("X-Auth-Token"))
}

func normalizeArtifactSegment(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return ""
	}
	return value
}

func md5Hex(data []byte) string {
	sum := md5.Sum(data)
	return fmt.Sprintf("%x", sum)
}
