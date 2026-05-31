package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/ohmyrasp/control-plane/internal/httpapi"
	chstore "github.com/ohmyrasp/control-plane/internal/storage/clickhouse"
	"github.com/ohmyrasp/control-plane/internal/storage/migrations"
	pgstore "github.com/ohmyrasp/control-plane/internal/storage/postgres"
	vkstore "github.com/ohmyrasp/control-plane/internal/storage/valkey"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()
	store, limiter, cleanup, err := buildStore(startupCtx, logger)
	if err != nil {
		logger.Error("store initialization failed", "error", err)
		os.Exit(1)
	}
	defer cleanup()
	server := httpapi.NewServer(store, logger)
	server.WithAgentArtifactDir(env("OHMYRASP_AGENT_ARTIFACT_DIR", ""))
	if limiter != nil {
		server.WithRateLimiter(
			limiter,
			envInt64("OHMYRASP_RATE_LIMIT", 600),
			envDuration("OHMYRASP_RATE_LIMIT_WINDOW", time.Minute),
		)
	}

	addr := env("OHMYRASP_API_ADDR", ":8080")
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		logger.Info("ohmyrasp api listening", "addr", addr)
		errs <- httpServer.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("server shutdown failed", "error", err)
		os.Exit(1)
	}
}

func env(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func buildStore(ctx context.Context, logger *slog.Logger) (control.Store, httpapi.RateLimiter, func(), error) {
	mode := env("OHMYRASP_STORE", "")
	postgresDSN := env("OHMYRASP_POSTGRES_DSN", "")
	clickHouseDSN := env("OHMYRASP_CLICKHOUSE_DSN", "")
	valkeyAddr := env("OHMYRASP_VALKEY_ADDR", "")
	var limiter httpapi.RateLimiter
	cleanup := func() {}
	var valkeyCache *vkstore.Cache
	if valkeyAddr != "" {
		cache, err := vkstore.New(
			valkeyAddr,
			env("OHMYRASP_VALKEY_USERNAME", ""),
			env("OHMYRASP_VALKEY_PASSWORD", ""),
		)
		if err != nil {
			return nil, nil, func() {}, err
		}
		if err := cache.Ping(ctx); err != nil {
			cache.Close()
			return nil, nil, func() {}, err
		}
		valkeyCache = cache
		limiter = cache
		cleanup = func() { cache.Close() }
		logger.Info("valkey cache enabled", "addr", valkeyAddr)
	}
	if mode == "memory" || postgresDSN == "" {
		logger.Info("using in-memory store", "reason", memoryReason(mode, postgresDSN))
		return control.NewMemoryStore(time.Now), limiter, cleanup, nil
	}

	db, err := sql.Open("pgx", postgresDSN)
	if err != nil {
		cleanup()
		return nil, nil, func() {}, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		cleanup()
		return nil, nil, func() {}, err
	}
	if envBool("OHMYRASP_AUTO_MIGRATE", false) {
		logger.Info("applying postgres migrations")
		if err := migrations.Apply(ctx, db, migrations.Postgres); err != nil {
			_ = db.Close()
			cleanup()
			return nil, nil, func() {}, err
		}
	}
	previousCleanup := cleanup
	cleanup = func() {
		_ = db.Close()
		previousCleanup()
	}
	store := pgstore.NewStore(db, time.Now).WithBootstrapAdmin(
		env("OHMYRASP_BOOTSTRAP_ADMIN_EMAIL", "admin@ohmyrasp.local"),
		env("OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD", "change-me"),
		env("OHMYRASP_BOOTSTRAP_ADMIN_NAME", "Default Admin"),
	)
	if valkeyCache != nil {
		store.WithSessionCache(valkeyCache).WithAgentPolicyCache(valkeyCache)
		logger.Info("postgres store valkey caches enabled")
	}
	if clickHouseDSN != "" {
		chDB, err := sql.Open("clickhouse", clickHouseDSN)
		if err != nil {
			cleanup()
			return nil, nil, func() {}, err
		}
		chDB.SetMaxOpenConns(10)
		chDB.SetMaxIdleConns(5)
		chDB.SetConnMaxLifetime(30 * time.Minute)
		if err := chDB.PingContext(ctx); err != nil {
			_ = chDB.Close()
			cleanup()
			return nil, nil, func() {}, err
		}
		if envBool("OHMYRASP_AUTO_MIGRATE", false) {
			logger.Info("applying clickhouse migrations")
			if err := migrations.Apply(ctx, chDB, migrations.ClickHouse); err != nil {
				_ = chDB.Close()
				cleanup()
				return nil, nil, func() {}, err
			}
		}
		store.WithEventAnalytics(chstore.NewAnalytics(chDB, time.Now))
		previousCleanup := cleanup
		cleanup = func() {
			_ = chDB.Close()
			previousCleanup()
		}
		logger.Info("clickhouse analytics enabled")
	}
	if err := store.EnsureSeedData(ctx); err != nil {
		cleanup()
		return nil, nil, func() {}, err
	}
	logger.Info("using postgres store")
	return store, limiter, cleanup, nil
}

func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(name string, fallback int64) int64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func memoryReason(mode string, postgresDSN string) string {
	if mode == "memory" {
		return "explicit"
	}
	if postgresDSN == "" {
		return "missing_postgres_dsn"
	}
	return "fallback"
}
