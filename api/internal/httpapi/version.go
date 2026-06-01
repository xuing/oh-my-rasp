package httpapi

import (
	"os"
	"runtime"
	"strings"

	"github.com/ohmyrasp/control-plane/internal/generated"
)

func systemVersion() generated.SystemVersion {
	return generated.SystemVersion{
		Component: "ohmyrasp-control-api",
		Version:   envOrDefault("OHMYRASP_VERSION", "dev"),
		Commit:    strings.TrimSpace(os.Getenv("OHMYRASP_COMMIT")),
		BuildTime: strings.TrimSpace(os.Getenv("OHMYRASP_BUILT_AT")),
		GoVersion: runtime.Version(),
	}
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
