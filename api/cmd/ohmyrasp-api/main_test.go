package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestBuildStoreRequiresExplicitMemoryModeWithoutPostgresDSN(t *testing.T) {
	t.Setenv("OHMYRASP_STORE", "")
	t.Setenv("OHMYRASP_POSTGRES_DSN", "")
	t.Setenv("OHMYRASP_CLICKHOUSE_DSN", "")
	t.Setenv("OHMYRASP_VALKEY_ADDR", "")
	t.Setenv("OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD", "memory-test-admin-password")

	store, limiter, cleanup, err := buildStore(context.Background(), testLogger())
	if err == nil {
		cleanup()
		t.Fatalf("expected missing postgres dsn error, got store=%T limiter=%T", store, limiter)
	}
	if !strings.Contains(err.Error(), "OHMYRASP_POSTGRES_DSN is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildStoreAllowsExplicitMemoryMode(t *testing.T) {
	t.Setenv("OHMYRASP_STORE", "memory")
	t.Setenv("OHMYRASP_POSTGRES_DSN", "")
	t.Setenv("OHMYRASP_CLICKHOUSE_DSN", "")
	t.Setenv("OHMYRASP_VALKEY_ADDR", "")
	t.Setenv("OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD", "memory-test-admin-password")

	store, limiter, cleanup, err := buildStore(context.Background(), testLogger())
	defer cleanup()
	if err != nil {
		t.Fatalf("build memory store: %v", err)
	}
	if store == nil {
		t.Fatal("expected store")
	}
	if limiter != nil {
		t.Fatalf("expected no limiter without valkey, got %T", limiter)
	}
}

func TestBuildStoreRejectsUnknownStoreMode(t *testing.T) {
	t.Setenv("OHMYRASP_STORE", "demo")
	t.Setenv("OHMYRASP_POSTGRES_DSN", "")
	t.Setenv("OHMYRASP_CLICKHOUSE_DSN", "")
	t.Setenv("OHMYRASP_VALKEY_ADDR", "")

	_, _, cleanup, err := buildStore(context.Background(), testLogger())
	defer cleanup()
	if err == nil || !strings.Contains(err.Error(), "OHMYRASP_STORE") {
		t.Fatalf("expected store mode error, got %v", err)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
}
