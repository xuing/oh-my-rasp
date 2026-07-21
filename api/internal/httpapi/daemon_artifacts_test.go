package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohmyrasp/control-plane/internal/control"
)

func TestNormalizeArtifactSegmentRejectsTraversalSyntax(t *testing.T) {
	for _, value := range []string{".", "..", "../linux", `..\\linux`, "linux/amd64", `linux\\amd64`, strings.Repeat("a", 65)} {
		if got := normalizeArtifactSegment(value); got != "" {
			t.Fatalf("normalizeArtifactSegment(%q) = %q, want empty", value, got)
		}
	}
	for _, value := range []string{"java", "linux-musl", "1.8.0", "jdk_25"} {
		if got := normalizeArtifactSegment(value); got != value {
			t.Fatalf("normalizeArtifactSegment(%q) = %q", value, got)
		}
	}
}

func TestLoadAgentArtifactCannotFollowSymlinkOutsideRoot(t *testing.T) {
	artifactDir := t.TempDir()
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "secret.zip")
	if err := os.WriteFile(outside, []byte("not an artifact"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(artifactDir, "agent-java-linux-17.zip")); err != nil {
		t.Fatalf("create escaping symlink: %v", err)
	}

	server := &Server{agentArtifactDir: artifactDir}
	data, _, err := server.loadAgentArtifact(control.DaemonApplication{}, "java", "linux", "17")
	if err == nil {
		t.Fatalf("expected escaping symlink to be rejected, got %q", data)
	}
}
