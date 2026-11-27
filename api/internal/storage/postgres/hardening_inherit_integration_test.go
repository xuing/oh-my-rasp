package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/ohmyrasp/control-plane/internal/storage/migrations"
)

// The postgres store marks the members an environment inherits the way the memory store does, and
// keeps the marker out of the config the hosts download.
func TestHardeningInheritedMembersIntegration(t *testing.T) {
	dsn := os.Getenv("OHMYRASP_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set OHMYRASP_POSTGRES_TEST_DSN to run postgres integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	if err := migrations.Apply(ctx, db, migrations.Postgres); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	now := func() time.Time { return time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC) }
	store := NewStore(db, now).WithBootstrapAdmin("admin@ohmyrasp.local", "postgres-test-admin-password", "Default Admin")
	if err := store.EnsureSeedData(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, admin, err := store.Login(ctx, "admin@ohmyrasp.local", "postgres-test-admin-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	app, err := store.CreateApplication(ctx, admin.ID, control.Application{Name: fmt.Sprintf("Hardening inherit %d", time.Now().UnixNano())})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	env, err := store.CreateEnvironment(ctx, admin.ID, app.ID, control.Environment{Name: "staging", Kind: "staging"})
	if err != nil {
		t.Fatalf("create env: %v", err)
	}

	const hardening = "protection.hardening"
	put := func(environmentID string, value map[string]any) {
		t.Helper()
		if _, err := store.UpsertApplicationSetting(ctx, admin.ID, control.ApplicationSetting{ApplicationID: app.ID, EnvironmentID: environmentID, Key: hardening, Value: value}); err != nil {
			t.Fatalf("upsert %q %v: %v", environmentID, value, err)
		}
	}
	assertEnvironment := func(label string, value string, inherited bool) {
		t.Helper()
		settings, err := store.ListApplicationSettings(ctx, app.ID, env.ID)
		if err != nil {
			t.Fatalf("%s: list: %v", label, err)
		}
		found := false
		for _, setting := range settings {
			if setting.Key != hardening {
				continue
			}
			found = true
			if setting.Value["outside_request"] != value {
				t.Fatalf("%s: expected outside_request %q, got %#v", label, value, setting.Value)
			}
			if inherited && (len(setting.Inherited) != 1 || setting.Inherited[0] != "outside_request") {
				t.Fatalf("%s: expected outside_request inherited, got %#v", label, setting.Inherited)
			}
			if !inherited && len(setting.Inherited) != 0 {
				t.Fatalf("%s: expected nothing inherited, got %#v", label, setting.Inherited)
			}
		}
		if !found {
			t.Fatalf("%s: no %s in %#v", label, hardening, settings)
		}
		config, err := store.ResolveApplicationConfig(ctx, app.ID, env.ID)
		if err != nil {
			t.Fatalf("%s: resolve config: %v", label, err)
		}
		if config.Hardening["outside_request"] != value {
			t.Fatalf("%s: expected the agent config to carry %q, got %#v", label, value, config.Hardening)
		}
		if _, leaked := config.Hardening["inherited"]; leaked {
			t.Fatalf("%s: the inherited marker reached the agent config: %#v", label, config.Hardening)
		}
	}

	assertEnvironment("no environment row", "block", true)
	applicationSettings, err := store.ListApplicationSettings(ctx, app.ID, "")
	if err != nil {
		t.Fatalf("list application settings: %v", err)
	}
	for _, setting := range applicationSettings {
		if len(setting.Inherited) != 0 {
			t.Fatalf("an application setting inherits nothing, got %#v", setting)
		}
	}
	put("", map[string]any{"mode": "monitor", "outside_request": "log"})
	assertEnvironment("application log, no environment row", "log", true)
	put(env.ID, map[string]any{"mode": "enforce", "block_reflection_abuse": true})
	assertEnvironment("environment row without the member", "log", true)
	put(env.ID, map[string]any{"mode": "enforce", "outside_request": nil})
	assertEnvironment("environment row with null", "log", true)
	put("", map[string]any{"mode": "monitor", "outside_request": "block"})
	assertEnvironment("application switched to block", "block", true)
	put(env.ID, map[string]any{"mode": "enforce", "outside_request": "log"})
	assertEnvironment("explicit environment value", "log", false)
	put("", map[string]any{"mode": "monitor", "outside_request": "block"})
	assertEnvironment("explicit value after an application save", "log", false)
	put(env.ID, map[string]any{"mode": "enforce", "outside_request": nil})
	assertEnvironment("null after explicit", "block", true)
}
