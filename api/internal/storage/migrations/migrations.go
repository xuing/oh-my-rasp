package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed postgres/*.sql clickhouse/*.sql
var files embed.FS

type Dialect string

const (
	Postgres   Dialect = "postgres"
	ClickHouse Dialect = "clickhouse"
)

type Migration struct {
	Version int
	Name    string
	Path    string
	SQL     string
}

var migrationName = regexp.MustCompile(`^(\d{3})_[a-z0-9_]+\.sql$`)

func List(dialect Dialect) ([]Migration, error) {
	dir, err := directory(dialect)
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(files, dir)
	if err != nil {
		return nil, err
	}
	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matches := migrationName.FindStringSubmatch(entry.Name())
		if len(matches) != 2 {
			return nil, fmt.Errorf("invalid migration name %q", entry.Name())
		}
		version, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("parse migration version %q: %w", entry.Name(), err)
		}
		filePath := path.Join(dir, entry.Name())
		body, err := files.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		sqlText := strings.TrimSpace(string(body))
		if sqlText == "" {
			return nil, fmt.Errorf("migration %q is empty", filePath)
		}
		migrations = append(migrations, Migration{
			Version: version,
			Name:    entry.Name(),
			Path:    filePath,
			SQL:     sqlText,
		})
	}
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	for i, migration := range migrations {
		expected := i + 1
		if migration.Version != expected {
			return nil, fmt.Errorf("migration %q has version %03d, expected %03d", migration.Name, migration.Version, expected)
		}
	}
	return migrations, nil
}

func Apply(ctx context.Context, db *sql.DB, dialect Dialect) error {
	if db == nil {
		return errors.New("database is required")
	}
	migrations, err := List(dialect)
	if err != nil {
		return err
	}
	if err := ensureMigrationTable(ctx, db, dialect); err != nil {
		return err
	}
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		if applied[migration.Version] {
			continue
		}
		started := time.Now().UTC()
		if _, err := db.ExecContext(ctx, migration.SQL); err != nil {
			return fmt.Errorf("apply %s: %w", migration.Path, err)
		}
		if _, err := db.ExecContext(ctx, recordMigrationStatement(dialect), migration.Version, migration.Name, time.Now().UTC(), time.Since(started).Milliseconds()); err != nil {
			return fmt.Errorf("record %s: %w", migration.Path, err)
		}
	}
	return nil
}

func directory(dialect Dialect) (string, error) {
	switch dialect {
	case Postgres:
		return "postgres", nil
	case ClickHouse:
		return "clickhouse", nil
	default:
		return "", fmt.Errorf("unsupported migration dialect %q", dialect)
	}
}

func ensureMigrationTable(ctx context.Context, db *sql.DB, dialect Dialect) error {
	statement := `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		duration_ms BIGINT NOT NULL DEFAULT 0
	)`
	if dialect == ClickHouse {
		statement = `CREATE TABLE IF NOT EXISTS schema_migrations (
			version UInt32,
			name String,
			applied_at DateTime64(3, 'UTC'),
			duration_ms Int64
		) ENGINE = MergeTree
		ORDER BY version`
	}
	_, err := db.ExecContext(ctx, statement)
	return err
}

func appliedVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func recordMigrationStatement(dialect Dialect) string {
	if dialect == Postgres {
		return `INSERT INTO schema_migrations (version, name, applied_at, duration_ms) VALUES ($1, $2, $3, $4)`
	}
	return `INSERT INTO schema_migrations (version, name, applied_at, duration_ms) VALUES (?, ?, ?, ?)`
}
