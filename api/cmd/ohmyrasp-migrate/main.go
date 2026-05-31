package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ohmyrasp/control-plane/internal/storage/migrations"
)

func main() {
	var postgresDSN string
	var clickhouseDSN string
	var skipPostgres bool
	var skipClickHouse bool
	var timeout time.Duration

	flag.StringVar(&postgresDSN, "postgres-dsn", env("OHMYRASP_POSTGRES_DSN", ""), "PostgreSQL DSN")
	flag.StringVar(&clickhouseDSN, "clickhouse-dsn", env("OHMYRASP_CLICKHOUSE_DSN", ""), "ClickHouse DSN")
	flag.BoolVar(&skipPostgres, "skip-postgres", false, "skip PostgreSQL migrations")
	flag.BoolVar(&skipClickHouse, "skip-clickhouse", false, "skip ClickHouse migrations")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "migration timeout")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if !skipPostgres {
		if postgresDSN == "" {
			exit(errors.New("postgres DSN is required unless -skip-postgres is set"))
		}
		apply(ctx, logger, "pgx", postgresDSN, migrations.Postgres)
	}
	if !skipClickHouse {
		if clickhouseDSN == "" {
			exit(errors.New("clickhouse DSN is required unless -skip-clickhouse is set"))
		}
		apply(ctx, logger, "clickhouse", clickhouseDSN, migrations.ClickHouse)
	}
}

func apply(ctx context.Context, logger *slog.Logger, driver string, dsn string, dialect migrations.Dialect) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		exit(fmt.Errorf("open %s: %w", dialect, err))
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		exit(fmt.Errorf("ping %s: %w", dialect, err))
	}
	logger.Info("applying migrations", "dialect", dialect)
	if err := migrations.Apply(ctx, db, dialect); err != nil {
		exit(fmt.Errorf("apply %s migrations: %w", dialect, err))
	}
	logger.Info("migrations applied", "dialect", dialect)
}

func env(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func exit(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}
