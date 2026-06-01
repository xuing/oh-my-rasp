package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultOrganizationID = "org_default"
	defaultAdminID        = "usr_admin"
	defaultAppID          = "app_default"
	defaultEnvironmentID  = "env_default"
)

type Store struct {
	db                  *sql.DB
	now                 func() time.Time
	organizationID      string
	bootstrapAdminEmail string
	bootstrapAdminPass  string
	bootstrapAdminName  string
	sessionTTL          time.Duration
	analytics           EventAnalytics
	sessionCache        SessionCache
	agentPolicyCache    AgentPolicyCache
}

type queryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type EventAnalytics interface {
	IngestEvent(ctx context.Context, event control.SecurityEvent) error
	IngestDependency(ctx context.Context, dep control.Dependency, environmentID string) error
	ListEvents(ctx context.Context, query control.SecurityEventQuery) ([]control.SecurityEvent, error)
	EventOverview(ctx context.Context) (control.EventOverview, error)
	Observability(ctx context.Context, query control.ObservabilityQuery) (control.ObservabilityReport, error)
}

type MaintenanceAnalytics interface {
	CleanupOperationalData(ctx context.Context, request control.MaintenanceCleanupRequest) (control.MaintenanceCleanupReport, error)
}

type EventDeletionAnalytics interface {
	DeleteEvents(ctx context.Context, ids []string) error
}

type SessionCache interface {
	GetSessionUser(ctx context.Context, tokenHash string) (control.User, bool, error)
	SetSessionUser(ctx context.Context, tokenHash string, user control.User, ttl time.Duration) error
	DeleteSession(ctx context.Context, tokenHash string) error
}

type AgentPolicyCache interface {
	GetAgentPolicy(ctx context.Context, agentID string) (control.PolicyVersion, bool, error)
	SetAgentPolicy(ctx context.Context, agentID string, policy control.PolicyVersion, ttl time.Duration) error
	InvalidateAgentPolicies(ctx context.Context) error
}

func NewStore(db *sql.DB, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		db:                  db,
		now:                 now,
		organizationID:      defaultOrganizationID,
		bootstrapAdminEmail: "admin@ohmyrasp.local",
		bootstrapAdminName:  "Default Admin",
		sessionTTL:          12 * time.Hour,
	}
}

func (s *Store) WithEventAnalytics(analytics EventAnalytics) *Store {
	s.analytics = analytics
	return s
}

func (s *Store) WithSessionCache(cache SessionCache) *Store {
	s.sessionCache = cache
	return s
}

func (s *Store) WithAgentPolicyCache(cache AgentPolicyCache) *Store {
	s.agentPolicyCache = cache
	return s
}

func (s *Store) WithBootstrapAdmin(email string, password string, name string) *Store {
	if strings.TrimSpace(email) != "" {
		s.bootstrapAdminEmail = strings.TrimSpace(email)
	}
	if password != "" {
		s.bootstrapAdminPass = password
	}
	if strings.TrimSpace(name) != "" {
		s.bootstrapAdminName = strings.TrimSpace(name)
	}
	return s
}

func (s *Store) EnsureSeedData(ctx context.Context) error {
	if s.db == nil {
		return errors.New("database is required")
	}
	if s.bootstrapAdminPass == "" {
		return errors.New("bootstrap admin password is required")
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(s.bootstrapAdminPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO organizations (id, name)
		VALUES ($1, $2)
		ON CONFLICT (id) DO NOTHING
	`, s.organizationID, "Default Organization")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO users (id, organization_id, email, name, password_hash, roles)
		VALUES ($1, $2, $3, $4, $5, ARRAY['admin', 'security_engineer'])
		ON CONFLICT (email) DO NOTHING
	`, defaultAdminID, s.organizationID, s.bootstrapAdminEmail, s.bootstrapAdminName, string(passwordHash))
	if err != nil {
		return err
	}
	defaultAppSecret, err := generatedBootstrapSecret()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO applications (id, organization_id, name, description, secret_hash, secret_preview, agent_secret_value)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO NOTHING
	`, defaultAppID, s.organizationID, "Demo Java Service", "Seed application for local development", hashSecret(defaultAppSecret), secretPreview(defaultAppSecret), defaultAppSecret)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO environments (id, application_id, name, kind)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO NOTHING
	`, defaultEnvironmentID, defaultAppID, "production", "production")
	if err != nil {
		return err
	}
	for _, setting := range control.DefaultSystemSettings(s.now().UTC()) {
		body, err := json.Marshal(setting.Value)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO system_settings (key, value, updated_by, updated_at)
			VALUES ($1, $2::jsonb, $3, $4)
			ON CONFLICT (key) DO NOTHING
		`, setting.Key, string(body), defaultAdminID, setting.UpdatedAt.UTC()); err != nil {
			return err
		}
	}
	for _, alertRule := range control.DefaultAlertRules(s.now().UTC()) {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO alert_rules (
				id, organization_id, name, description, enabled, event_type, severity,
				condition, target, created_by, created_at, updated_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
			ON CONFLICT (id) DO NOTHING
		`, alertRule.ID, s.organizationID, alertRule.Name, alertRule.Description, alertRule.Enabled, alertRule.EventType, alertRule.Severity, alertRule.Condition, alertRule.Target, defaultAdminID, alertRule.CreatedAt.UTC()); err != nil {
			return err
		}
	}
	return nil
}

func generatedBootstrapSecret() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return "ohmyrasp_" + hex.EncodeToString(data[:]), nil
}

func (s *Store) Login(ctx context.Context, email string, password string) (control.Session, control.User, error) {
	user, err := s.userByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return control.Session{}, control.User{}, control.ErrUnauthorized
		}
		return control.Session{}, control.User{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return control.Session{}, control.User{}, control.ErrUnauthorized
	}
	token := "ses_" + control.NewSecret() + control.NewSecret()
	session := control.Session{
		Token:     token,
		UserID:    user.ID,
		ExpiresAt: s.now().Add(s.sessionTTL).UTC(),
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, expires_at)
		VALUES ($1, $2, $3)
	`, hashSecret(token), session.UserID, session.ExpiresAt); err != nil {
		return control.Session{}, control.User{}, err
	}
	if err := s.audit(ctx, s.db, user.ID, "auth.login", "session", map[string]any{"email": strings.ToLower(email)}); err != nil {
		return control.Session{}, control.User{}, err
	}
	if s.sessionCache != nil {
		_ = s.sessionCache.SetSessionUser(ctx, hashSecret(token), publicUser(user), session.ExpiresAt.Sub(s.now()))
	}
	return session, user, nil
}

func (s *Store) UserForToken(ctx context.Context, token string) (control.User, error) {
	tokenHash := hashSecret(token)
	if s.sessionCache != nil {
		user, found, err := s.sessionCache.GetSessionUser(ctx, tokenHash)
		if err == nil && found {
			return user, nil
		}
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.name, u.password_hash, to_json(u.roles)::text, u.created_at, u.updated_at, u.disabled_at, s.expires_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1
			AND s.revoked_at IS NULL
			AND s.expires_at > $2
			AND u.disabled_at IS NULL
	`, tokenHash, s.now().UTC())
	user, expiresAt, err := scanSessionUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return control.User{}, control.ErrUnauthorized
	}
	if err == nil && s.sessionCache != nil {
		_ = s.sessionCache.SetSessionUser(ctx, tokenHash, publicUser(user), expiresAt.Sub(s.now()))
	}
	return user, err
}

func (s *Store) ListUsers(ctx context.Context) ([]control.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, email, name, password_hash, to_json(roles)::text, created_at, updated_at, disabled_at
		FROM users
		WHERE organization_id = $1
		ORDER BY email
	`, s.organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []control.User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, publicUser(user))
	}
	return users, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, actorID string, input control.User, password string) (control.User, error) {
	user, password, err := control.PrepareUser(input, password, s.now().UTC())
	if err != nil {
		return control.User{}, err
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return control.User{}, err
	}
	user.ID = control.NewID("usr")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.User{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		INSERT INTO users (id, organization_id, email, name, password_hash, roles, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6::text[], $7, $8)
		ON CONFLICT (email) DO NOTHING
		RETURNING id, email, name, password_hash, to_json(roles)::text, created_at, updated_at, disabled_at
	`, user.ID, s.organizationID, user.Email, user.Name, string(passwordHash), rolesToPostgresArray(user.Roles), user.CreatedAt.UTC(), user.UpdatedAt.UTC())
	created, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return control.User{}, fmt.Errorf("%w: user email already exists", control.ErrInvalid)
	}
	if err != nil {
		return control.User{}, err
	}
	if err := s.audit(ctx, tx, actorID, "user.create", created.ID, map[string]any{"email": created.Email, "roles": roleStrings(created.Roles)}); err != nil {
		return control.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.User{}, err
	}
	return publicUser(created), nil
}

func (s *Store) UpdateUser(ctx context.Context, actorID string, userID string, input control.User) (control.User, error) {
	user, err := control.PrepareUserUpdate(input, s.now().UTC())
	if err != nil {
		return control.User{}, err
	}
	if actorID == userID {
		if user.DisabledAt != nil {
			return control.User{}, fmt.Errorf("%w: cannot disable your own user", control.ErrInvalid)
		}
		if !hasRole(user.Roles, control.RoleAdmin) {
			return control.User{}, fmt.Errorf("%w: cannot remove your own admin role", control.ErrInvalid)
		}
	}
	var disabledAt any
	if user.DisabledAt != nil {
		disabledAt = user.DisabledAt.UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.User{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		UPDATE users
		SET name = $3, roles = $4::text[], disabled_at = $5, updated_at = $6
		WHERE id = $1 AND organization_id = $2
		RETURNING id, email, name, password_hash, to_json(roles)::text, created_at, updated_at, disabled_at
	`, userID, s.organizationID, user.Name, rolesToPostgresArray(user.Roles), disabledAt, user.UpdatedAt.UTC())
	updated, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return control.User{}, control.ErrNotFound
	}
	if err != nil {
		return control.User{}, err
	}
	var revokedSessionHashes []string
	if updated.DisabledAt != nil {
		rows, err := tx.QueryContext(ctx, `
			SELECT token_hash
			FROM sessions
			WHERE user_id = $1 AND revoked_at IS NULL
		`, userID)
		if err != nil {
			return control.User{}, err
		}
		for rows.Next() {
			var tokenHash string
			if err := rows.Scan(&tokenHash); err != nil {
				rows.Close()
				return control.User{}, err
			}
			revokedSessionHashes = append(revokedSessionHashes, tokenHash)
		}
		if err := rows.Close(); err != nil {
			return control.User{}, err
		}
		if err := rows.Err(); err != nil {
			return control.User{}, err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE sessions
			SET revoked_at = $2
			WHERE user_id = $1 AND revoked_at IS NULL
		`, userID, s.now().UTC()); err != nil {
			return control.User{}, err
		}
	}
	if err := s.audit(ctx, tx, actorID, "user.update", updated.ID, map[string]any{"email": updated.Email, "roles": roleStrings(updated.Roles), "disabled": updated.DisabledAt != nil}); err != nil {
		return control.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.User{}, err
	}
	if s.sessionCache != nil {
		for _, tokenHash := range revokedSessionHashes {
			_ = s.sessionCache.DeleteSession(ctx, tokenHash)
		}
	}
	return publicUser(updated), nil
}

func (s *Store) ListApplications(ctx context.Context) ([]control.Application, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.description, a.created_at,
			COALESCE(a.policy_id, ''), COALESCE(a.policy_version, 0),
			COALESCE(json_agg(e.id ORDER BY e.name) FILTER (WHERE e.id IS NOT NULL), '[]')::text
		FROM applications a
		LEFT JOIN environments e ON e.application_id = a.id
		WHERE a.organization_id = $1 AND a.deleted_at IS NULL
		GROUP BY a.id
		ORDER BY a.name
	`, s.organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []control.Application
	for rows.Next() {
		var app control.Application
		var envIDs string
		if err := rows.Scan(&app.ID, &app.Name, &app.Description, &app.CreatedAt, &app.PolicyID, &app.PolicyVersion, &envIDs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(envIDs), &app.EnvironmentIDs); err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

func (s *Store) CreateApplication(ctx context.Context, actorID string, input control.Application) (control.Application, error) {
	if strings.TrimSpace(input.Name) == "" {
		return control.Application{}, fmt.Errorf("%w: application name is required", control.ErrInvalid)
	}
	app := control.Application{
		ID:             control.NewID("app"),
		Name:           strings.TrimSpace(input.Name),
		Description:    input.Description,
		Secret:         control.NewSecret(),
		CreatedAt:      s.now().UTC(),
		EnvironmentIDs: []string{},
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.Application{}, err
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO applications (id, organization_id, name, description, secret_hash, secret_preview, agent_secret_value, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
	`, app.ID, s.organizationID, app.Name, app.Description, hashSecret(app.Secret), secretPreview(app.Secret), app.Secret, app.CreatedAt); err != nil {
		return control.Application{}, mapConstraintError(err)
	}
	if err := s.audit(ctx, tx, actorID, "application.create", app.ID, map[string]any{"name": app.Name}); err != nil {
		return control.Application{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.Application{}, err
	}
	return app, nil
}

func (s *Store) RotateApplicationSecret(ctx context.Context, actorID string, appID string) (control.Application, error) {
	secret := control.NewSecret()
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.Application{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		WITH updated AS (
			UPDATE applications
			SET secret_hash = $1, secret_preview = $2, agent_secret_value = $3, updated_at = $4
			WHERE id = $5 AND organization_id = $6 AND deleted_at IS NULL
			RETURNING id, name, description, created_at,
				COALESCE(policy_id, '') AS policy_id,
				COALESCE(policy_version, 0) AS policy_version
		)
		SELECT u.id, u.name, u.description, u.created_at, u.policy_id, u.policy_version,
			COALESCE(json_agg(e.id ORDER BY e.name) FILTER (WHERE e.id IS NOT NULL), '[]')::text
		FROM updated u
		LEFT JOIN environments e ON e.application_id = u.id
		GROUP BY u.id, u.name, u.description, u.created_at, u.policy_id, u.policy_version
	`, hashSecret(secret), secretPreview(secret), secret, now, appID, s.organizationID)
	var app control.Application
	var envIDs string
	if err := row.Scan(&app.ID, &app.Name, &app.Description, &app.CreatedAt, &app.PolicyID, &app.PolicyVersion, &envIDs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return control.Application{}, control.ErrNotFound
		}
		return control.Application{}, err
	}
	if err := json.Unmarshal([]byte(envIDs), &app.EnvironmentIDs); err != nil {
		return control.Application{}, err
	}
	app.Secret = secret
	if err := s.audit(ctx, tx, actorID, "application.secret.rotate", app.ID, map[string]any{"name": app.Name}); err != nil {
		return control.Application{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.Application{}, err
	}
	return app, nil
}

func (s *Store) DeleteApplication(ctx context.Context, actorID string, appID string) error {
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var name string
	if err := tx.QueryRowContext(ctx, `
		UPDATE applications
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND organization_id = $3 AND deleted_at IS NULL
		RETURNING name
	`, now, appID, s.organizationID).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return control.ErrNotFound
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE daemon_workloads
		SET application_id = NULL, updated_at = $1
		WHERE application_id = $2
	`, now, appID); err != nil {
		return err
	}
	if err := s.audit(ctx, tx, actorID, "application.delete", appID, map[string]any{"name": name}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateEnvironment(ctx context.Context, actorID string, appID string, input control.Environment) (control.Environment, error) {
	if strings.TrimSpace(input.Name) == "" {
		return control.Environment{}, fmt.Errorf("%w: environment name is required", control.ErrInvalid)
	}
	env := control.Environment{
		ID:            control.NewID("env"),
		ApplicationID: appID,
		Name:          strings.TrimSpace(input.Name),
		Kind:          input.Kind,
		CreatedAt:     s.now().UTC(),
	}
	if env.Kind == "" {
		env.Kind = "custom"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.Environment{}, err
	}
	defer rollback(tx)
	exists, err := rowExists(ctx, tx, `SELECT 1 FROM applications WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`, appID, s.organizationID)
	if err != nil {
		return control.Environment{}, err
	}
	if !exists {
		return control.Environment{}, control.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO environments (id, application_id, name, kind, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)
	`, env.ID, env.ApplicationID, env.Name, env.Kind, env.CreatedAt); err != nil {
		return control.Environment{}, mapConstraintError(err)
	}
	if err := s.audit(ctx, tx, actorID, "environment.create", env.ID, map[string]any{"application_id": appID, "name": env.Name}); err != nil {
		return control.Environment{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.Environment{}, err
	}
	return env, nil
}

func (s *Store) DaemonAccessToken(ctx context.Context) (control.DaemonAccessToken, error) {
	return s.daemonAccessToken(ctx, s.db)
}

func (s *Store) ResetDaemonAccessToken(ctx context.Context, actorID string) (control.DaemonAccessToken, error) {
	token := control.NewSecret()
	updatedAt := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.DaemonAccessToken{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		INSERT INTO daemon_settings (id, access_token, updated_by, updated_at)
		VALUES (TRUE, $1, NULLIF($2, ''), $3)
		ON CONFLICT (id)
		DO UPDATE SET access_token = EXCLUDED.access_token, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
		RETURNING access_token, updated_at
	`, token, actorID, updatedAt)
	var result control.DaemonAccessToken
	if err := row.Scan(&result.AccessToken, &result.UpdatedAt); err != nil {
		return control.DaemonAccessToken{}, err
	}
	if err := s.audit(ctx, tx, actorID, "daemon.token.reset", "daemon", nil); err != nil {
		return control.DaemonAccessToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.DaemonAccessToken{}, err
	}
	return result, nil
}

func (s *Store) GetDaemonApplication(ctx context.Context, accessToken string, appID string) (control.DaemonApplication, error) {
	token, err := s.daemonAccessToken(ctx, s.db)
	if err != nil {
		return control.DaemonApplication{}, err
	}
	if accessToken == "" || accessToken != token.AccessToken {
		return control.DaemonApplication{}, control.ErrUnauthorized
	}
	var app control.DaemonApplication
	row := s.db.QueryRowContext(ctx, `
		SELECT id, COALESCE(agent_secret_value, '')
		FROM applications
		WHERE id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
			AND agent_secret_value IS NOT NULL
			AND agent_secret_value <> ''
	`, strings.TrimSpace(appID), s.organizationID)
	if err := row.Scan(&app.ApplicationID, &app.ApplicationSecret); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return control.DaemonApplication{}, control.ErrNotFound
		}
		return control.DaemonApplication{}, err
	}
	app.Language = "java"
	return app, nil
}

func (s *Store) ReportDaemonWorkloads(ctx context.Context, accessToken string, report control.DaemonWorkloadReport) ([]control.DaemonWorkload, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	token, err := s.daemonAccessToken(ctx, tx)
	if err != nil {
		return nil, err
	}
	if accessToken == "" || accessToken != token.AccessToken {
		return nil, control.ErrUnauthorized
	}
	now := s.now().UTC()
	workloads := make([]control.DaemonWorkload, 0, len(report.Workloads))
	for _, input := range report.Workloads {
		workload, err := control.PrepareAndValidateDaemonWorkload(report.NodeName, input, now)
		if err != nil {
			return nil, err
		}
		cmdline, err := json.Marshal(workload.Cmdline)
		if err != nil {
			return nil, err
		}
		row := tx.QueryRowContext(ctx, `
			INSERT INTO daemon_workloads (
				id, node_name, type, pid, cmdline, container_id, container_name,
				image_id, image_tag, observed_at, updated_at
			)
			VALUES ($1, $2, $3, NULLIF($4, 0), $5::jsonb, NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10, $11)
			ON CONFLICT (id)
			DO UPDATE SET
				node_name = EXCLUDED.node_name,
				type = EXCLUDED.type,
				pid = EXCLUDED.pid,
				cmdline = EXCLUDED.cmdline,
				container_id = EXCLUDED.container_id,
				container_name = EXCLUDED.container_name,
				image_id = EXCLUDED.image_id,
				image_tag = EXCLUDED.image_tag,
				observed_at = EXCLUDED.observed_at,
				updated_at = EXCLUDED.updated_at
			RETURNING id, COALESCE(application_id, ''), node_name, type, COALESCE(pid, 0), cmdline::text,
				COALESCE(container_id, ''), COALESCE(container_name, ''), COALESCE(image_id, ''), COALESCE(image_tag, ''),
				COALESCE(injection_status, ''), COALESCE(injection_error, ''), COALESCE(injection_helper_id, ''), COALESCE(injection_helper_version, ''),
				injection_reported_at, injection_status_updated_at,
				observed_at, updated_at
		`, workload.ID, workload.NodeName, workload.Type, workload.PID, string(cmdline), workload.ContainerID, workload.ContainerName, workload.ImageID, workload.ImageTag, workload.ObservedAt.UTC(), workload.UpdatedAt.UTC())
		reported, err := scanDaemonWorkload(row)
		if err != nil {
			return nil, err
		}
		workloads = append(workloads, reported)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return workloads, nil
}

func (s *Store) ListDaemonWorkloads(ctx context.Context) ([]control.DaemonWorkload, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(application_id, ''), node_name, type, COALESCE(pid, 0), cmdline::text,
			COALESCE(container_id, ''), COALESCE(container_name, ''), COALESCE(image_id, ''), COALESCE(image_tag, ''),
			COALESCE(injection_status, ''), COALESCE(injection_error, ''), COALESCE(injection_helper_id, ''), COALESCE(injection_helper_version, ''),
			injection_reported_at, injection_status_updated_at,
			observed_at, updated_at
		FROM daemon_workloads
		ORDER BY updated_at DESC, id
		LIMIT 1000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	workloads := []control.DaemonWorkload{}
	for rows.Next() {
		workload, err := scanDaemonWorkload(rows)
		if err != nil {
			return nil, err
		}
		workloads = append(workloads, workload)
	}
	return workloads, rows.Err()
}

func (s *Store) ListDaemonCommands(ctx context.Context, accessToken string) ([]control.DaemonCommandGroup, error) {
	token, err := s.daemonAccessToken(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if accessToken == "" || accessToken != token.AccessToken {
		return nil, control.ErrUnauthorized
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, COALESCE(a.agent_secret_value, ''), w.id, COALESCE(w.application_id, ''), w.node_name, w.type, COALESCE(w.pid, 0), w.cmdline::text,
			COALESCE(w.container_id, ''), COALESCE(w.container_name, ''), COALESCE(w.image_id, ''), COALESCE(w.image_tag, ''),
			COALESCE(w.injection_status, ''), COALESCE(w.injection_error, ''), COALESCE(w.injection_helper_id, ''), COALESCE(w.injection_helper_version, ''),
			w.injection_reported_at, w.injection_status_updated_at,
			w.observed_at, w.updated_at
		FROM daemon_workloads w
		JOIN applications a ON a.id = w.application_id
		WHERE a.organization_id = $1
			AND a.deleted_at IS NULL
			AND a.agent_secret_value IS NOT NULL
			AND a.agent_secret_value <> ''
		ORDER BY a.id, w.id
	`, s.organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groupByApp := map[string]*control.DaemonCommandGroup{}
	var appOrder []string
	for rows.Next() {
		var appID string
		var appSecret string
		workload, err := scanDaemonWorkloadWithPrefix(rows, &appID, &appSecret)
		if err != nil {
			return nil, err
		}
		group, ok := groupByApp[appID]
		if !ok {
			group = &control.DaemonCommandGroup{
				ApplicationID:     appID,
				ApplicationSecret: appSecret,
				Language:          "java",
				Workloads:         []control.DaemonWorkload{},
			}
			groupByApp[appID] = group
			appOrder = append(appOrder, appID)
		}
		group.Workloads = append(group.Workloads, workload)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	commands := make([]control.DaemonCommandGroup, 0, len(appOrder))
	for _, appID := range appOrder {
		commands = append(commands, *groupByApp[appID])
	}
	return commands, nil
}

func (s *Store) ReportDaemonInjection(ctx context.Context, accessToken string, input control.DaemonInjectionReport) (control.DaemonWorkload, error) {
	token, err := s.daemonAccessToken(ctx, s.db)
	if err != nil {
		return control.DaemonWorkload{}, err
	}
	if accessToken == "" || accessToken != token.AccessToken {
		return control.DaemonWorkload{}, control.ErrUnauthorized
	}
	now := s.now().UTC()
	report, err := control.PrepareDaemonInjectionReport(input, now)
	if err != nil {
		return control.DaemonWorkload{}, err
	}
	row := s.db.QueryRowContext(ctx, `
		UPDATE daemon_workloads
		SET injection_status = $2,
			injection_error = NULLIF($3, ''),
			injection_helper_id = NULLIF($4, ''),
			injection_helper_version = NULLIF($5, ''),
			injection_reported_at = $6,
			injection_status_updated_at = $7,
			updated_at = $7
		WHERE id = $1
		RETURNING id, COALESCE(application_id, ''), node_name, type, COALESCE(pid, 0), cmdline::text,
			COALESCE(container_id, ''), COALESCE(container_name, ''), COALESCE(image_id, ''), COALESCE(image_tag, ''),
			COALESCE(injection_status, ''), COALESCE(injection_error, ''), COALESCE(injection_helper_id, ''), COALESCE(injection_helper_version, ''),
			injection_reported_at, injection_status_updated_at,
			observed_at, updated_at
	`, report.WorkloadID, report.Status, report.Error, report.HelperID, report.HelperVersion, report.ReportedAt, now)
	workload, err := scanDaemonWorkload(row)
	if errors.Is(err, sql.ErrNoRows) {
		return control.DaemonWorkload{}, control.ErrNotFound
	}
	if err != nil {
		return control.DaemonWorkload{}, err
	}
	return workload, nil
}

func (s *Store) BindDaemonWorkload(ctx context.Context, actorID string, workloadID string, applicationID string) (control.DaemonWorkload, error) {
	if strings.TrimSpace(applicationID) == "" {
		return control.DaemonWorkload{}, fmt.Errorf("%w: application id is required", control.ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.DaemonWorkload{}, err
	}
	defer rollback(tx)
	exists, err := rowExists(ctx, tx, `SELECT 1 FROM applications WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`, applicationID, s.organizationID)
	if err != nil {
		return control.DaemonWorkload{}, err
	}
	if !exists {
		return control.DaemonWorkload{}, control.ErrNotFound
	}
	row := tx.QueryRowContext(ctx, `
		UPDATE daemon_workloads
		SET application_id = $2,
			injection_status = NULL,
			injection_error = NULL,
			injection_helper_id = NULL,
			injection_helper_version = NULL,
			injection_reported_at = NULL,
			injection_status_updated_at = NULL,
			updated_at = $3
		WHERE id = $1
		RETURNING id, COALESCE(application_id, ''), node_name, type, COALESCE(pid, 0), cmdline::text,
			COALESCE(container_id, ''), COALESCE(container_name, ''), COALESCE(image_id, ''), COALESCE(image_tag, ''),
			COALESCE(injection_status, ''), COALESCE(injection_error, ''), COALESCE(injection_helper_id, ''), COALESCE(injection_helper_version, ''),
			injection_reported_at, injection_status_updated_at,
			observed_at, updated_at
	`, workloadID, applicationID, s.now().UTC())
	workload, err := scanDaemonWorkload(row)
	if errors.Is(err, sql.ErrNoRows) {
		return control.DaemonWorkload{}, control.ErrNotFound
	}
	if err != nil {
		return control.DaemonWorkload{}, err
	}
	if err := s.audit(ctx, tx, actorID, "daemon.workload.bind", workloadID, map[string]any{"application_id": applicationID, "node_name": workload.NodeName, "type": workload.Type}); err != nil {
		return control.DaemonWorkload{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.DaemonWorkload{}, err
	}
	return workload, nil
}

func (s *Store) UnbindDaemonWorkload(ctx context.Context, actorID string, workloadID string) (control.DaemonWorkload, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.DaemonWorkload{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		UPDATE daemon_workloads
		SET application_id = NULL,
			injection_status = NULL,
			injection_error = NULL,
			injection_helper_id = NULL,
			injection_helper_version = NULL,
			injection_reported_at = NULL,
			injection_status_updated_at = NULL,
			updated_at = $2
		WHERE id = $1
		RETURNING id, COALESCE(application_id, ''), node_name, type, COALESCE(pid, 0), cmdline::text,
			COALESCE(container_id, ''), COALESCE(container_name, ''), COALESCE(image_id, ''), COALESCE(image_tag, ''),
			COALESCE(injection_status, ''), COALESCE(injection_error, ''), COALESCE(injection_helper_id, ''), COALESCE(injection_helper_version, ''),
			injection_reported_at, injection_status_updated_at,
			observed_at, updated_at
	`, workloadID, s.now().UTC())
	workload, err := scanDaemonWorkload(row)
	if errors.Is(err, sql.ErrNoRows) {
		return control.DaemonWorkload{}, control.ErrNotFound
	}
	if err != nil {
		return control.DaemonWorkload{}, err
	}
	if err := s.audit(ctx, tx, actorID, "daemon.workload.unbind", workloadID, map[string]any{"node_name": workload.NodeName, "type": workload.Type}); err != nil {
		return control.DaemonWorkload{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.DaemonWorkload{}, err
	}
	return workload, nil
}

func (s *Store) daemonAccessToken(ctx context.Context, q queryer) (control.DaemonAccessToken, error) {
	token := control.NewSecret()
	updatedAt := s.now().UTC()
	if _, err := q.ExecContext(ctx, `
		INSERT INTO daemon_settings (id, access_token, updated_by, updated_at)
		VALUES (TRUE, $1, 'system', $2)
		ON CONFLICT (id) DO NOTHING
	`, token, updatedAt); err != nil {
		return control.DaemonAccessToken{}, err
	}
	row := q.QueryRowContext(ctx, `SELECT access_token, updated_at FROM daemon_settings WHERE id = TRUE`)
	var result control.DaemonAccessToken
	if err := row.Scan(&result.AccessToken, &result.UpdatedAt); err != nil {
		return control.DaemonAccessToken{}, err
	}
	return result, nil
}

func (s *Store) ListAgents(ctx context.Context) ([]control.Agent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, application_id, environment_id, hostname, runtime, version, status, last_seen_at,
			COALESCE(policy_id, ''), COALESCE(policy_version, 0)
		FROM agents
		ORDER BY last_seen_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []control.Agent
	for rows.Next() {
		agent, err := scanAgentRows(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, rows.Err()
}

func (s *Store) RegisterAgent(ctx context.Context, appID string, appSecret string, input control.Agent) (control.Agent, error) {
	var storedSecretHash string
	var appPolicyID string
	var appPolicyVersion int
	if err := s.db.QueryRowContext(ctx, `
		SELECT secret_hash, COALESCE(policy_id, ''), COALESCE(policy_version, 0)
		FROM applications
		WHERE id = $1 AND deleted_at IS NULL
	`, appID).Scan(&storedSecretHash, &appPolicyID, &appPolicyVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return control.Agent{}, control.ErrUnauthorized
		}
		return control.Agent{}, err
	}
	if storedSecretHash != hashSecret(appSecret) {
		return control.Agent{}, control.ErrUnauthorized
	}
	var envPolicyID string
	var envPolicyVersion int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(policy_id, ''), COALESCE(policy_version, 0)
		FROM environments
		WHERE id = $1 AND application_id = $2
	`, input.EnvironmentID, appID).Scan(&envPolicyID, &envPolicyVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return control.Agent{}, control.ErrNotFound
		}
		return control.Agent{}, err
	}
	var orgPolicyID string
	var orgPolicyVersion int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(policy_id, ''), COALESCE(policy_version, 0)
		FROM organizations
		WHERE id = $1
	`, s.organizationID).Scan(&orgPolicyID, &orgPolicyVersion); err != nil {
		return control.Agent{}, err
	}
	agent := input
	agent.ID = control.NewID("agt")
	agent.ApplicationID = appID
	if envPolicyID != "" && envPolicyVersion > 0 {
		agent.PolicyID = envPolicyID
		agent.PolicyVersion = envPolicyVersion
	} else if appPolicyID != "" && appPolicyVersion > 0 {
		agent.PolicyID = appPolicyID
		agent.PolicyVersion = appPolicyVersion
	} else if orgPolicyID != "" && orgPolicyVersion > 0 {
		agent.PolicyID = orgPolicyID
		agent.PolicyVersion = orgPolicyVersion
	}
	agent.Status = "online"
	agent.LastSeenAt = s.now().UTC()
	if strings.TrimSpace(agent.Runtime) == "" {
		agent.Runtime = "java"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.Agent{}, err
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agents (id, application_id, environment_id, hostname, runtime, version, status, last_seen_at, policy_id, policy_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, 0), $8, $8)
	`, agent.ID, agent.ApplicationID, agent.EnvironmentID, agent.Hostname, agent.Runtime, agent.Version, agent.Status, agent.LastSeenAt, agent.PolicyID, agent.PolicyVersion); err != nil {
		return control.Agent{}, mapConstraintError(err)
	}
	if err := s.audit(ctx, tx, "agent", "agent.register", agent.ID, map[string]any{"application_id": appID, "version": agent.Version}); err != nil {
		return control.Agent{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.Agent{}, err
	}
	return agent, nil
}

func (s *Store) AuthorizeAgent(ctx context.Context, appID string, appSecret string, environmentID string, agentID string) error {
	var storedSecretHash string
	if err := s.db.QueryRowContext(ctx, `
		SELECT secret_hash
		FROM applications
		WHERE id = $1 AND deleted_at IS NULL
	`, appID).Scan(&storedSecretHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return control.ErrUnauthorized
		}
		return err
	}
	if storedSecretHash != hashSecret(appSecret) {
		return control.ErrUnauthorized
	}
	if environmentID != "" {
		exists, err := rowExists(ctx, s.db, `
			SELECT 1
			FROM environments
			WHERE id = $1 AND application_id = $2
		`, environmentID, appID)
		if err != nil {
			return err
		}
		if !exists {
			return control.ErrUnauthorized
		}
	}
	if agentID != "" {
		query := `
			SELECT 1
			FROM agents
			WHERE id = $1 AND application_id = $2
		`
		args := []any{agentID, appID}
		if environmentID != "" {
			query += ` AND environment_id = $3`
			args = append(args, environmentID)
		}
		exists, err := rowExists(ctx, s.db, query, args...)
		if err != nil {
			return err
		}
		if !exists {
			return control.ErrUnauthorized
		}
	}
	return nil
}

func (s *Store) HeartbeatAgent(ctx context.Context, agentID string, status string) (control.Agent, error) {
	if status == "" {
		status = "online"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.Agent{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		UPDATE agents
		SET status = $2, last_seen_at = $3, updated_at = $3
		WHERE id = $1
		RETURNING id, application_id, environment_id, hostname, runtime, version, status, last_seen_at,
			COALESCE(policy_id, ''), COALESCE(policy_version, 0)
	`, agentID, status, s.now().UTC())
	agent, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return control.Agent{}, control.ErrNotFound
	}
	if err != nil {
		return control.Agent{}, err
	}
	if err := s.audit(ctx, tx, agent.ID, "agent.heartbeat", agent.ID, map[string]any{"application_id": agent.ApplicationID, "status": agent.Status}); err != nil {
		return control.Agent{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.Agent{}, err
	}
	return agent, nil
}

func (s *Store) GetAgentPolicy(ctx context.Context, agentID string) (control.PolicyVersion, error) {
	if s.agentPolicyCache != nil {
		policy, found, err := s.agentPolicyCache.GetAgentPolicy(ctx, agentID)
		if err == nil && found {
			return policy, nil
		}
	}
	var policyID string
	var policyVersion int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(policy_id, ''), COALESCE(policy_version, 0)
		FROM agents
		WHERE id = $1
	`, agentID).Scan(&policyID, &policyVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return control.PolicyVersion{}, control.ErrNotFound
		}
		return control.PolicyVersion{}, err
	}
	if policyID == "" || policyVersion == 0 {
		if err := s.db.QueryRowContext(ctx, `
			SELECT COALESCE(policy_id, ''), COALESCE(policy_version, 0)
			FROM organizations
			WHERE id = $1
		`, s.organizationID).Scan(&policyID, &policyVersion); err != nil {
			return control.PolicyVersion{}, err
		}
	}
	if policyID == "" || policyVersion == 0 {
		empty := control.PolicyVersion{Version: 0, Status: "empty", Rules: []control.Rule{}}
		if s.agentPolicyCache != nil {
			_ = s.agentPolicyCache.SetAgentPolicy(ctx, agentID, empty, time.Minute)
		}
		return empty, nil
	}
	version, err := s.activePolicyVersion(ctx, policyID, policyVersion)
	if errors.Is(err, sql.ErrNoRows) {
		empty := control.PolicyVersion{Version: 0, Status: "empty", Rules: []control.Rule{}}
		if s.agentPolicyCache != nil {
			_ = s.agentPolicyCache.SetAgentPolicy(ctx, agentID, empty, time.Minute)
		}
		return empty, nil
	}
	if err == nil && s.agentPolicyCache != nil {
		_ = s.agentPolicyCache.SetAgentPolicy(ctx, agentID, version, time.Minute)
	}
	return version, err
}

func (s *Store) ListPolicies(ctx context.Context) ([]control.PolicySet, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id
		FROM policies
		WHERE organization_id = $1
		ORDER BY name
	`, s.organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	policies := make([]control.PolicySet, 0, len(ids))
	for _, id := range ids {
		policy, err := s.policyByID(ctx, s.db, id)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

func (s *Store) CreatePolicy(ctx context.Context, actorID string, input control.PolicySet) (control.PolicySet, error) {
	if strings.TrimSpace(input.Name) == "" {
		return control.PolicySet{}, fmt.Errorf("%w: policy name is required", control.ErrInvalid)
	}
	policy := control.PolicySet{
		ID:          control.NewID("pol"),
		Name:        strings.TrimSpace(input.Name),
		Description: input.Description,
		CreatedAt:   s.now().UTC(),
		Versions:    []control.PolicyVersion{},
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.PolicySet{}, err
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO policies (id, organization_id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)
	`, policy.ID, s.organizationID, policy.Name, policy.Description, policy.CreatedAt); err != nil {
		return control.PolicySet{}, mapConstraintError(err)
	}
	if err := s.audit(ctx, tx, actorID, "policy.create", policy.ID, map[string]any{"name": policy.Name}); err != nil {
		return control.PolicySet{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.PolicySet{}, err
	}
	return policy, nil
}

func (s *Store) AddPolicyVersion(ctx context.Context, actorID string, policyID string, rules []control.Rule) (control.PolicySet, error) {
	validation := control.ValidateRules(rules)
	if !validation.Valid {
		return control.PolicySet{}, fmt.Errorf("%w: %s", control.ErrInvalid, strings.Join(validation.Errors, "; "))
	}
	ensureRuleIDs(rules)
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return control.PolicySet{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.PolicySet{}, err
	}
	defer rollback(tx)
	exists, err := rowExists(ctx, tx, `SELECT 1 FROM policies WHERE id = $1 AND organization_id = $2`, policyID, s.organizationID)
	if err != nil {
		return control.PolicySet{}, err
	}
	if !exists {
		return control.PolicySet{}, control.ErrNotFound
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE policy_id = $1`, policyID).Scan(&version); err != nil {
		return control.PolicySet{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO policy_versions (policy_id, version, status, rules, canary_percent, created_by, created_at)
		VALUES ($1, $2, 'draft', $3::jsonb, 0, $4, $5)
	`, policyID, version, string(rulesJSON), nullIfEmpty(actorID), s.now().UTC()); err != nil {
		return control.PolicySet{}, err
	}
	if err := s.audit(ctx, tx, actorID, "policy.version.create", policyID, map[string]any{"version": version}); err != nil {
		return control.PolicySet{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.PolicySet{}, err
	}
	if s.agentPolicyCache != nil {
		_ = s.agentPolicyCache.InvalidateAgentPolicies(ctx)
	}
	return s.policyByID(ctx, s.db, policyID)
}

func (s *Store) UpdatePolicyVersionRules(ctx context.Context, actorID string, policyID string, version int, rules []control.Rule) (control.PolicySet, error) {
	if version <= 0 {
		return control.PolicySet{}, fmt.Errorf("%w: policy version must be positive", control.ErrInvalid)
	}
	validation := control.ValidateRules(rules)
	if !validation.Valid {
		return control.PolicySet{}, fmt.Errorf("%w: %s", control.ErrInvalid, strings.Join(validation.Errors, "; "))
	}
	ensureRuleIDs(rules)
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return control.PolicySet{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.PolicySet{}, err
	}
	defer rollback(tx)
	var status string
	err = tx.QueryRowContext(ctx, `
		SELECT pv.status
		FROM policy_versions pv
		JOIN policies p ON p.id = pv.policy_id
		WHERE pv.policy_id = $1 AND pv.version = $2 AND p.organization_id = $3
		FOR UPDATE
	`, policyID, version, s.organizationID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return control.PolicySet{}, control.ErrNotFound
	}
	if err != nil {
		return control.PolicySet{}, err
	}
	if status != "draft" {
		return control.PolicySet{}, fmt.Errorf("%w: only draft policy versions can be edited", control.ErrInvalid)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE policy_versions
		SET rules = $3::jsonb
		WHERE policy_id = $1 AND version = $2
	`, policyID, version, string(rulesJSON)); err != nil {
		return control.PolicySet{}, err
	}
	if err := s.audit(ctx, tx, actorID, "policy.version.update", policyID, map[string]any{"version": version, "rule_count": len(rules)}); err != nil {
		return control.PolicySet{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.PolicySet{}, err
	}
	return s.policyByID(ctx, s.db, policyID)
}

func ensureRuleIDs(rules []control.Rule) {
	for i := range rules {
		if rules[i].ID == "" {
			rules[i].ID = control.NewID("rul")
		}
	}
}

func (s *Store) ValidateRules(_ context.Context, rules []control.Rule) control.RuleValidation {
	return control.ValidateRules(rules)
}

func (s *Store) TestRule(_ context.Context, rule control.Rule, event control.SecurityEvent) control.RuleTestResult {
	return control.TestRule(rule, event)
}

func (s *Store) RolloutPolicy(ctx context.Context, actorID string, policyID string, rollout control.PolicyRollout) (control.PolicySet, error) {
	if rollout.CanaryPercent < 0 || rollout.CanaryPercent > 100 {
		return control.PolicySet{}, fmt.Errorf("%w: canary percent must be between 0 and 100", control.ErrInvalid)
	}
	targetStatus := "active"
	if rollout.CanaryPercent < 100 {
		targetStatus = "canary"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.PolicySet{}, err
	}
	defer rollback(tx)
	if err := s.validatePolicyRolloutScope(ctx, tx, &rollout); err != nil {
		return control.PolicySet{}, err
	}
	exists, err := rowExists(ctx, tx, `SELECT 1 FROM policy_versions WHERE policy_id = $1 AND version = $2`, policyID, rollout.Version)
	if err != nil {
		return control.PolicySet{}, err
	}
	if !exists {
		return control.PolicySet{}, control.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE policy_versions
		SET status = 'rolled_back'
		WHERE policy_id = $1 AND status IN ('active', 'canary') AND version <> $2
	`, policyID, rollout.Version); err != nil {
		return control.PolicySet{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE policy_versions
		SET status = $3, canary_percent = $4, published_at = $5
		WHERE policy_id = $1 AND version = $2
	`, policyID, rollout.Version, targetStatus, rollout.CanaryPercent, s.now().UTC()); err != nil {
		return control.PolicySet{}, err
	}
	if err := s.updatePolicyAssignmentScope(ctx, tx, policyID, rollout); err != nil {
		return control.PolicySet{}, err
	}
	if err := s.audit(ctx, tx, actorID, "policy.rollout", policyID, policyRolloutAuditDetails(rollout)); err != nil {
		return control.PolicySet{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.PolicySet{}, err
	}
	if s.agentPolicyCache != nil {
		_ = s.agentPolicyCache.InvalidateAgentPolicies(ctx)
	}
	return s.policyByID(ctx, s.db, policyID)
}

func (s *Store) validatePolicyRolloutScope(ctx context.Context, q queryer, rollout *control.PolicyRollout) error {
	if rollout.EnvironmentID != "" {
		var environmentAppID string
		err := q.QueryRowContext(ctx, `
			SELECT application_id
			FROM environments
			WHERE id = $1
		`, rollout.EnvironmentID).Scan(&environmentAppID)
		if errors.Is(err, sql.ErrNoRows) {
			return control.ErrNotFound
		}
		if err != nil {
			return err
		}
		if rollout.ApplicationID != "" && rollout.ApplicationID != environmentAppID {
			return fmt.Errorf("%w: rollout environment does not belong to application", control.ErrInvalid)
		}
		rollout.ApplicationID = environmentAppID
	}
	if rollout.ApplicationID != "" {
		exists, err := rowExists(ctx, q, `SELECT 1 FROM applications WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`, rollout.ApplicationID, s.organizationID)
		if err != nil {
			return err
		}
		if !exists {
			return control.ErrNotFound
		}
	}
	return nil
}

func (s *Store) updatePolicyAssignmentScope(ctx context.Context, tx *sql.Tx, policyID string, rollout control.PolicyRollout) error {
	now := s.now().UTC()
	if rollout.EnvironmentID != "" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE environments
			SET policy_id = $1, policy_version = $2, updated_at = $3
			WHERE id = $4
		`, policyID, rollout.Version, now, rollout.EnvironmentID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE agents
			SET policy_id = $1, policy_version = $2, updated_at = $3
			WHERE environment_id = $4
		`, policyID, rollout.Version, now, rollout.EnvironmentID)
		return err
	}
	if rollout.ApplicationID != "" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE applications
			SET policy_id = $1, policy_version = $2, updated_at = $3
			WHERE id = $4
		`, policyID, rollout.Version, now, rollout.ApplicationID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE agents
			SET policy_id = $1, policy_version = $2, updated_at = $3
			WHERE application_id = $4
		`, policyID, rollout.Version, now, rollout.ApplicationID)
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE organizations
		SET policy_id = $1, policy_version = $2
		WHERE id = $3
	`, policyID, rollout.Version, s.organizationID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE agents SET policy_id = $1, policy_version = $2, updated_at = $3
	`, policyID, rollout.Version, now)
	return err
}

func policyRolloutAuditDetails(rollout control.PolicyRollout) map[string]any {
	details := map[string]any{"version": rollout.Version, "canary_percent": rollout.CanaryPercent}
	if rollout.ApplicationID != "" {
		details["application_id"] = rollout.ApplicationID
	}
	if rollout.EnvironmentID != "" {
		details["environment_id"] = rollout.EnvironmentID
	}
	return details
}

func (s *Store) RollbackPolicy(ctx context.Context, actorID string, policyID string) (control.PolicySet, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.PolicySet{}, err
	}
	defer rollback(tx)
	var activeVersion int
	err = tx.QueryRowContext(ctx, `
		SELECT version
		FROM policy_versions
		WHERE policy_id = $1 AND status IN ('active', 'canary')
		ORDER BY published_at DESC NULLS LAST, version DESC
		LIMIT 1
	`, policyID).Scan(&activeVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return control.PolicySet{}, control.ErrNotFound
	}
	if err != nil {
		return control.PolicySet{}, err
	}
	var targetVersion int
	err = tx.QueryRowContext(ctx, `
		SELECT version
		FROM policy_versions
		WHERE policy_id = $1 AND version < $2
		ORDER BY version DESC
		LIMIT 1
	`, policyID, activeVersion).Scan(&targetVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return control.PolicySet{}, control.ErrNotFound
	}
	if err != nil {
		return control.PolicySet{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE policy_versions
		SET status = 'rolled_back'
		WHERE policy_id = $1 AND status IN ('active', 'canary')
	`, policyID); err != nil {
		return control.PolicySet{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE policy_versions
		SET status = 'active', canary_percent = 100, published_at = $3
		WHERE policy_id = $1 AND version = $2
	`, policyID, targetVersion, s.now().UTC()); err != nil {
		return control.PolicySet{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE agents SET policy_id = $1, policy_version = $2, updated_at = $3
	`, policyID, targetVersion, s.now().UTC()); err != nil {
		return control.PolicySet{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE applications
		SET policy_version = $2, updated_at = $3
		WHERE policy_id = $1
	`, policyID, targetVersion, s.now().UTC()); err != nil {
		return control.PolicySet{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE environments
		SET policy_version = $2, updated_at = $3
		WHERE policy_id = $1
	`, policyID, targetVersion, s.now().UTC()); err != nil {
		return control.PolicySet{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE organizations
		SET policy_version = $2
		WHERE policy_id = $1
	`, policyID, targetVersion); err != nil {
		return control.PolicySet{}, err
	}
	if err := s.audit(ctx, tx, actorID, "policy.rollback", policyID, map[string]any{"version": targetVersion}); err != nil {
		return control.PolicySet{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.PolicySet{}, err
	}
	if s.agentPolicyCache != nil {
		_ = s.agentPolicyCache.InvalidateAgentPolicies(ctx)
	}
	return s.policyByID(ctx, s.db, policyID)
}

func (s *Store) IngestEvent(ctx context.Context, event control.SecurityEvent) (control.SecurityEvent, error) {
	if event.Type == "" {
		return control.SecurityEvent{}, fmt.Errorf("%w: event type is required", control.ErrInvalid)
	}
	event.ID = control.NewID("evt")
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now().UTC()
	}
	attrs, err := json.Marshal(emptyMap(event.Attributes))
	if err != nil {
		return control.SecurityEvent{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.SecurityEvent{}, err
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO event_ingest_outbox (
			id, type, application_id, environment_id, agent_id, policy_id, policy_version,
			hook, algorithm, severity, message, attributes, occurred_at, ingested_at
		)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8, $9, $10, $11, $12::jsonb, $13, $14)
	`, event.ID, event.Type, event.ApplicationID, event.EnvironmentID, event.AgentID, event.PolicyID, event.PolicyVersion, event.Hook, event.Algorithm, event.Severity, event.Message, string(attrs), event.OccurredAt.UTC(), s.now().UTC()); err != nil {
		return control.SecurityEvent{}, mapConstraintError(err)
	}
	rules, err := s.listEnabledAlertRulesForEvent(ctx, tx, event.Type)
	if err != nil {
		return control.SecurityEvent{}, err
	}
	for _, rule := range rules {
		if !control.MatchAlertRule(rule, event) {
			continue
		}
		delivery := control.NewAlertDelivery(rule, event, s.now().UTC())
		delivery.ID = control.NewID("adl")
		var deliveredAt any
		if delivery.DeliveredAt != nil {
			deliveredAt = delivery.DeliveredAt.UTC()
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO alert_deliveries (
				id, organization_id, alert_rule_id, alert_rule_name, event_id, event_type,
				severity, target, status, attempts, last_error, created_at, delivered_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (alert_rule_id, event_id) DO NOTHING
			`, delivery.ID, s.organizationID, delivery.AlertRuleID, delivery.AlertRuleName, delivery.EventID, delivery.EventType, delivery.Severity, delivery.Target, delivery.Status, delivery.Attempts, delivery.LastError, delivery.CreatedAt.UTC(), deliveredAt); err != nil {
			return control.SecurityEvent{}, err
		}
	}
	if err := s.audit(ctx, tx, auditActorForAgent(event.AgentID), "event.ingest", event.ID, map[string]any{
		"application_id": event.ApplicationID,
		"environment_id": event.EnvironmentID,
		"severity":       event.Severity,
		"type":           event.Type,
	}); err != nil {
		return control.SecurityEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.SecurityEvent{}, err
	}
	if s.analytics != nil {
		if err := s.analytics.IngestEvent(ctx, event); err == nil {
			_, _ = s.db.ExecContext(ctx, `
				UPDATE event_ingest_outbox
				SET delivered_to_clickhouse_at = $2
				WHERE id = $1
			`, event.ID, s.now().UTC())
		}
	}
	return event, nil
}

func (s *Store) IngestDependency(ctx context.Context, dep control.Dependency) (control.Dependency, error) {
	dep = control.NormalizeDependency(dep)
	if strings.TrimSpace(dep.Name) == "" {
		return control.Dependency{}, fmt.Errorf("%w: dependency name is required", control.ErrInvalid)
	}
	dep.ID = control.NewID("dep")
	if dep.ObservedAt.IsZero() {
		dep.ObservedAt = s.now().UTC()
	}
	licenses := dep.Licenses
	if licenses == nil {
		licenses = []string{}
	}
	vulnerabilities := dep.Vulnerabilities
	if vulnerabilities == nil {
		vulnerabilities = []control.DependencyVulnerability{}
	}
	licensesJSON, err := json.Marshal(licenses)
	if err != nil {
		return control.Dependency{}, err
	}
	vulnerabilitiesJSON, err := json.Marshal(vulnerabilities)
	if err != nil {
		return control.Dependency{}, err
	}
	var agentID any
	var environmentID string
	if dep.AgentID != "" {
		agentEnv, err := s.agentEnvironmentID(ctx, dep.AgentID)
		if err != nil && !errors.Is(err, control.ErrNotFound) {
			return control.Dependency{}, err
		}
		if err == nil {
			agentID = dep.AgentID
			environmentID = agentEnv
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.Dependency{}, err
	}
	defer rollback(tx)
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO dependency_inventory (
			id, application_id, agent_id, name, version, ecosystem,
			package_path, licenses, vulnerabilities, first_observed_at, last_observed_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $10)
		ON CONFLICT (application_id, name, version, ecosystem)
		DO UPDATE SET
			agent_id = COALESCE(EXCLUDED.agent_id, dependency_inventory.agent_id),
			package_path = EXCLUDED.package_path,
			licenses = EXCLUDED.licenses,
			vulnerabilities = EXCLUDED.vulnerabilities,
			last_observed_at = EXCLUDED.last_observed_at
		RETURNING id
	`, dep.ID, dep.ApplicationID, agentID, dep.Name, dep.Version, dep.Ecosystem, dep.PackagePath, string(licensesJSON), string(vulnerabilitiesJSON), dep.ObservedAt.UTC()).Scan(&dep.ID); err != nil {
		return control.Dependency{}, mapConstraintError(err)
	}
	if err := s.audit(ctx, tx, auditActorForAgent(dep.AgentID), "dependency.ingest", dep.ID, map[string]any{
		"application_id":  dep.ApplicationID,
		"ecosystem":       dep.Ecosystem,
		"package_path":    dep.PackagePath,
		"name":            dep.Name,
		"version":         dep.Version,
		"vulnerabilities": len(dep.Vulnerabilities),
	}); err != nil {
		return control.Dependency{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.Dependency{}, err
	}
	if s.analytics != nil {
		_ = s.analytics.IngestDependency(ctx, dep, environmentID)
	}
	return dep, nil
}

func (s *Store) IngestBaselineFinding(ctx context.Context, finding control.BaselineFinding) (control.BaselineFinding, error) {
	finding = control.NormalizeBaselineFinding(finding)
	if finding.CheckID == "" || finding.Title == "" || finding.ApplicationID == "" || finding.EnvironmentID == "" || finding.AgentID == "" {
		return control.BaselineFinding{}, fmt.Errorf("%w: baseline finding scope, check, and title are required", control.ErrInvalid)
	}
	if finding.ObservedAt.IsZero() {
		finding.ObservedAt = s.now().UTC()
	}
	finding.ID = control.NewID("bsl")
	attributes, err := json.Marshal(emptyMap(finding.Attributes))
	if err != nil {
		return control.BaselineFinding{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.BaselineFinding{}, err
	}
	defer rollback(tx)
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO baseline_findings (
			id, application_id, environment_id, agent_id, check_id, title, category,
			severity, status, resource, remediation, attributes, observed_at, ingested_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14)
		ON CONFLICT (application_id, environment_id, agent_id, check_id, resource)
		DO UPDATE SET
			id = EXCLUDED.id,
			title = EXCLUDED.title,
			category = EXCLUDED.category,
			severity = EXCLUDED.severity,
			status = EXCLUDED.status,
			remediation = EXCLUDED.remediation,
			attributes = EXCLUDED.attributes,
			observed_at = EXCLUDED.observed_at,
			ingested_at = EXCLUDED.ingested_at
		RETURNING id
	`, finding.ID, finding.ApplicationID, finding.EnvironmentID, finding.AgentID, finding.CheckID, finding.Title, finding.Category, finding.Severity, finding.Status, finding.Resource, finding.Remediation, string(attributes), finding.ObservedAt.UTC(), s.now().UTC()).Scan(&finding.ID); err != nil {
		return control.BaselineFinding{}, mapConstraintError(err)
	}
	if err := s.audit(ctx, tx, auditActorForAgent(finding.AgentID), "baseline.ingest", finding.ID, map[string]any{
		"application_id": finding.ApplicationID,
		"environment_id": finding.EnvironmentID,
		"agent_id":       finding.AgentID,
		"check_id":       finding.CheckID,
		"severity":       finding.Severity,
		"status":         finding.Status,
		"resource":       finding.Resource,
	}); err != nil {
		return control.BaselineFinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.BaselineFinding{}, err
	}
	return finding, nil
}

func (s *Store) ListEvents(ctx context.Context, query control.SecurityEventQuery) ([]control.SecurityEvent, error) {
	query = control.NormalizeSecurityEventQuery(query)
	if s.analytics != nil && !query.DeletedOnly {
		events, err := s.analytics.ListEvents(ctx, query)
		if err == nil {
			if query.IncludeDeleted {
				return events, nil
			}
			return s.excludeDeletedEvents(ctx, events)
		}
	}
	return s.listEventsFromPostgres(ctx, query)
}

func (s *Store) listEventsFromPostgres(ctx context.Context, query control.SecurityEventQuery) ([]control.SecurityEvent, error) {
	sqlQuery := `
		SELECT id, type, application_id, environment_id, agent_id, COALESCE(policy_id, ''), policy_version,
			hook, algorithm, severity, message, attributes::text, occurred_at, deleted_at, COALESCE(deleted_by, '')
		FROM event_ingest_outbox
	`
	args := []any{}
	where := []string{}
	addFilter := func(column string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if query.Type != "" {
		addFilter("type", query.Type)
	}
	if query.ApplicationID != "" {
		addFilter("application_id", query.ApplicationID)
	}
	if query.EnvironmentID != "" {
		addFilter("environment_id", query.EnvironmentID)
	}
	if query.AgentID != "" {
		addFilter("agent_id", query.AgentID)
	}
	if query.PolicyID != "" {
		addFilter("policy_id", query.PolicyID)
	}
	if query.Severity != "" {
		addFilter("severity", query.Severity)
	}
	if query.Hook != "" {
		addFilter("hook", query.Hook)
	}
	if !query.OccurredAfter.IsZero() {
		args = append(args, query.OccurredAfter.UTC())
		where = append(where, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	if !query.OccurredBefore.IsZero() {
		args = append(args, query.OccurredBefore.UTC())
		where = append(where, fmt.Sprintf("occurred_at <= $%d", len(args)))
	}
	if query.DeletedOnly {
		where = append(where, "deleted_at IS NOT NULL")
	} else if !query.IncludeDeleted {
		where = append(where, "deleted_at IS NULL")
	}
	if len(where) > 0 {
		sqlQuery += ` WHERE ` + strings.Join(where, " AND ")
	}
	args = append(args, query.Limit)
	sqlQuery += fmt.Sprintf(` ORDER BY occurred_at DESC LIMIT $%d`, len(args))
	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []control.SecurityEvent
	for rows.Next() {
		event, err := scanEventRows(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) SoftDeleteEvents(ctx context.Context, actorID string, request control.EventRecycleBinRequest) (control.EventRecycleBinReport, error) {
	ids, err := control.NormalizeEventRecycleBinIDs(request.IDs)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	defer rollback(tx)
	changed, err := updateEventRecycleBinRows(ctx, tx, ids, `
		UPDATE event_ingest_outbox
		SET deleted_at = $1, deleted_by = $2
		WHERE id IN (%s) AND deleted_at IS NULL
		RETURNING id
	`, s.now().UTC(), actorID)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	if len(changed) > 0 {
		if err := s.audit(ctx, tx, actorID, "event.recycle.delete", "events", map[string]any{"ids": changed, "count": len(changed)}); err != nil {
			return control.EventRecycleBinReport{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return control.EventRecycleBinReport{}, err
	}
	return control.EventRecycleBinReport{IDs: changed, Count: len(changed)}, nil
}

func (s *Store) RestoreDeletedEvents(ctx context.Context, actorID string, request control.EventRecycleBinRequest) (control.EventRecycleBinReport, error) {
	ids, err := control.NormalizeEventRecycleBinIDs(request.IDs)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	defer rollback(tx)
	changed, err := updateEventRecycleBinRows(ctx, tx, ids, `
		UPDATE event_ingest_outbox
		SET deleted_at = NULL, deleted_by = NULL
		WHERE id IN (%s) AND deleted_at IS NOT NULL
		RETURNING id
	`)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	if len(changed) > 0 {
		if err := s.audit(ctx, tx, actorID, "event.recycle.restore", "events", map[string]any{"ids": changed, "count": len(changed)}); err != nil {
			return control.EventRecycleBinReport{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return control.EventRecycleBinReport{}, err
	}
	return control.EventRecycleBinReport{IDs: changed, Count: len(changed)}, nil
}

func (s *Store) PurgeDeletedEvents(ctx context.Context, actorID string, request control.EventRecycleBinRequest) (control.EventRecycleBinReport, error) {
	ids, err := control.NormalizeEventRecycleBinIDs(request.IDs)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	defer rollback(tx)
	changed, err := updateEventRecycleBinRows(ctx, tx, ids, `
		DELETE FROM event_ingest_outbox
		WHERE id IN (%s) AND deleted_at IS NOT NULL
		RETURNING id
	`)
	if err != nil {
		return control.EventRecycleBinReport{}, err
	}
	if len(changed) > 0 {
		if err := s.audit(ctx, tx, actorID, "event.recycle.purge", "events", map[string]any{"ids": changed, "count": len(changed)}); err != nil {
			return control.EventRecycleBinReport{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return control.EventRecycleBinReport{}, err
	}
	if len(changed) > 0 {
		if analytics, ok := s.analytics.(EventDeletionAnalytics); ok {
			_ = analytics.DeleteEvents(ctx, changed)
		}
	}
	return control.EventRecycleBinReport{IDs: changed, Count: len(changed)}, nil
}

func (s *Store) ListDependencies(ctx context.Context, query control.DependencyQuery) ([]control.Dependency, error) {
	query = control.NormalizeDependencyQuery(query)
	sqlQuery := `
		SELECT id, application_id, COALESCE(agent_id, ''), name, version, ecosystem, package_path, licenses::text, vulnerabilities::text, last_observed_at
		FROM dependency_inventory
	`
	args := []any{}
	where := []string{}
	addFilter := func(column string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if query.ApplicationID != "" {
		addFilter("application_id", query.ApplicationID)
	}
	if query.AgentID != "" {
		addFilter("agent_id", query.AgentID)
	}
	if query.Name != "" {
		addFilter("name", query.Name)
	}
	if query.Ecosystem != "" {
		addFilter("ecosystem", query.Ecosystem)
	}
	if query.VulnerabilitySeverity != "" {
		selector, err := json.Marshal([]map[string]string{{"severity": query.VulnerabilitySeverity}})
		if err != nil {
			return nil, err
		}
		args = append(args, string(selector))
		where = append(where, fmt.Sprintf("vulnerabilities @> $%d::jsonb", len(args)))
	}
	if !query.ObservedAfter.IsZero() {
		args = append(args, query.ObservedAfter.UTC())
		where = append(where, fmt.Sprintf("last_observed_at >= $%d", len(args)))
	}
	if !query.ObservedBefore.IsZero() {
		args = append(args, query.ObservedBefore.UTC())
		where = append(where, fmt.Sprintf("last_observed_at <= $%d", len(args)))
	}
	if len(where) > 0 {
		sqlQuery += ` WHERE ` + strings.Join(where, " AND ")
	}
	args = append(args, query.Limit)
	sqlQuery += fmt.Sprintf(` ORDER BY last_observed_at DESC LIMIT $%d`, len(args))
	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dependencies []control.Dependency
	for rows.Next() {
		dep, err := scanDependencyRows(rows)
		if err != nil {
			return nil, err
		}
		dependencies = append(dependencies, dep)
	}
	return dependencies, rows.Err()
}

func (s *Store) ListBaselineFindings(ctx context.Context, query control.BaselineFindingQuery) ([]control.BaselineFinding, error) {
	query = control.NormalizeBaselineFindingQuery(query)
	sqlQuery := `
		SELECT id, application_id, environment_id, agent_id, check_id, title, category,
			severity, status, resource, remediation, attributes::text, observed_at
		FROM baseline_findings
	`
	args := []any{}
	where := []string{}
	addFilter := func(column string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if query.ApplicationID != "" {
		addFilter("application_id", query.ApplicationID)
	}
	if query.EnvironmentID != "" {
		addFilter("environment_id", query.EnvironmentID)
	}
	if query.AgentID != "" {
		addFilter("agent_id", query.AgentID)
	}
	if query.Severity != "" {
		addFilter("severity", query.Severity)
	}
	if query.Status != "" {
		addFilter("status", query.Status)
	}
	if query.Category != "" {
		addFilter("category", query.Category)
	}
	if !query.ObservedAfter.IsZero() {
		args = append(args, query.ObservedAfter.UTC())
		where = append(where, fmt.Sprintf("observed_at >= $%d", len(args)))
	}
	if !query.ObservedBefore.IsZero() {
		args = append(args, query.ObservedBefore.UTC())
		where = append(where, fmt.Sprintf("observed_at <= $%d", len(args)))
	}
	if len(where) > 0 {
		sqlQuery += ` WHERE ` + strings.Join(where, " AND ")
	}
	args = append(args, query.Limit)
	sqlQuery += fmt.Sprintf(` ORDER BY observed_at DESC LIMIT $%d`, len(args))
	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	findings := []control.BaselineFinding{}
	for rows.Next() {
		finding, err := scanBaselineFindingRows(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (s *Store) Overview(ctx context.Context) (control.Overview, error) {
	overview := control.Overview{
		EventsByType:       map[string]int{},
		EventsBySeverity:   map[string]int{},
		AttackTrend:        []control.TrendPoint{},
		AttacksByHook:      map[string]int{},
		AttacksByAlgorithm: map[string]int{},
		AttacksByUserAgent: map[string]int{},
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM applications WHERE organization_id = $1 AND deleted_at IS NULL`, s.organizationID).Scan(&overview.ApplicationCount); err != nil {
		return control.Overview{}, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents`).Scan(&overview.AgentCount); err != nil {
		return control.Overview{}, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE status = 'online'`).Scan(&overview.OnlineAgents); err != nil {
		return control.Overview{}, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_ingest_outbox WHERE deleted_at IS NULL`).Scan(&overview.EventCount); err != nil {
		return control.Overview{}, err
	}
	if err := scanCounts(ctx, s.db, `SELECT type, COUNT(*) FROM event_ingest_outbox WHERE deleted_at IS NULL GROUP BY type`, overview.EventsByType); err != nil {
		return control.Overview{}, err
	}
	if err := scanCounts(ctx, s.db, `SELECT severity, COUNT(*) FROM event_ingest_outbox WHERE deleted_at IS NULL GROUP BY severity`, overview.EventsBySeverity); err != nil {
		return control.Overview{}, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_ingest_outbox WHERE deleted_at IS NULL AND type = 'crash'`).Scan(&overview.CrashCount); err != nil {
		return control.Overview{}, err
	}
	attackTrend, err := scanTrendPoints(ctx, s.db, `
		SELECT date_trunc('day', occurred_at) AS bucket_start, COUNT(*)
		FROM event_ingest_outbox
		WHERE deleted_at IS NULL AND type = 'attack'
		GROUP BY bucket_start
		ORDER BY bucket_start ASC
	`)
	if err != nil {
		return control.Overview{}, err
	}
	overview.AttackTrend = attackTrend
	if err := scanCounts(ctx, s.db, `
		SELECT hook, COUNT(*)
		FROM event_ingest_outbox
		WHERE deleted_at IS NULL AND type = 'attack' AND hook <> ''
		GROUP BY hook
		ORDER BY COUNT(*) DESC, hook ASC
		LIMIT 10
	`, overview.AttacksByHook); err != nil {
		return control.Overview{}, err
	}
	if err := scanCounts(ctx, s.db, `
		SELECT algorithm, COUNT(*)
		FROM event_ingest_outbox
		WHERE deleted_at IS NULL AND type = 'attack' AND algorithm <> ''
		GROUP BY algorithm
		ORDER BY COUNT(*) DESC, algorithm ASC
		LIMIT 10
	`, overview.AttacksByAlgorithm); err != nil {
		return control.Overview{}, err
	}
	if err := scanCounts(ctx, s.db, `
		SELECT user_agent, COUNT(*)
		FROM (
			SELECT COALESCE(
				NULLIF(attributes->>'user_agent', ''),
				NULLIF(attributes->>'userAgent', ''),
				NULLIF(attributes->>'User-Agent', ''),
				NULLIF(attributes->>'user-agent', ''),
				NULLIF(attributes#>>'{request,user_agent}', ''),
				NULLIF(attributes#>>'{request,userAgent}', ''),
				NULLIF(attributes#>>'{request,headers,User-Agent}', ''),
				NULLIF(attributes#>>'{request,headers,user-agent}', ''),
				NULLIF(attributes#>>'{headers,User-Agent}', ''),
				NULLIF(attributes#>>'{headers,user-agent}', ''),
				'unknown'
			) AS user_agent
			FROM event_ingest_outbox
			WHERE deleted_at IS NULL AND type = 'attack'
		) AS user_agents
		GROUP BY user_agent
		ORDER BY COUNT(*) DESC, user_agent ASC
		LIMIT 10
	`, overview.AttacksByUserAgent); err != nil {
		return control.Overview{}, err
	}
	var deletedCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM event_ingest_outbox WHERE deleted_at IS NOT NULL`).Scan(&deletedCount); err != nil {
		return control.Overview{}, err
	}
	if s.analytics != nil && deletedCount == 0 {
		eventOverview, err := s.analytics.EventOverview(ctx)
		if err == nil {
			overview.EventCount = eventOverview.EventCount
			overview.EventsByType = eventOverview.EventsByType
			overview.EventsBySeverity = eventOverview.EventsBySeverity
		}
	}
	return overview, nil
}

func (s *Store) Observability(ctx context.Context, query control.ObservabilityQuery) (control.ObservabilityReport, error) {
	if s.analytics != nil {
		report, err := s.analytics.Observability(ctx, query)
		if err == nil {
			return report, nil
		}
	}
	return control.ObservabilityReport{
		RuleOverhead:      []control.RuleOverhead{},
		HookLatency:       []control.HookLatency{},
		AgentOverhead:     []control.AgentOverhead{},
		PolicyPerformance: []control.PolicyPerformance{},
	}, nil
}

func (s *Store) ListSystemSettings(ctx context.Context) ([]control.SystemSetting, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key, value::text, COALESCE(updated_by, ''), updated_at
		FROM system_settings
		ORDER BY key
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var settings []control.SystemSetting
	for rows.Next() {
		setting, err := scanSystemSettingRows(rows)
		if err != nil {
			return nil, err
		}
		settings = append(settings, setting)
	}
	return settings, rows.Err()
}

func (s *Store) UpsertSystemSetting(ctx context.Context, actorID string, setting control.SystemSetting) (control.SystemSetting, error) {
	key := normalizeSettingKey(setting.Key)
	if key == "" {
		return control.SystemSetting{}, fmt.Errorf("%w: setting key is required", control.ErrInvalid)
	}
	if setting.Value == nil {
		return control.SystemSetting{}, fmt.Errorf("%w: setting value is required", control.ErrInvalid)
	}
	body, err := json.Marshal(setting.Value)
	if err != nil {
		return control.SystemSetting{}, err
	}
	updatedAt := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.SystemSetting{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		INSERT INTO system_settings (key, value, updated_by, updated_at)
		VALUES ($1, $2::jsonb, NULLIF($3, ''), $4)
		ON CONFLICT (key)
		DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
		RETURNING key, value::text, COALESCE(updated_by, ''), updated_at
	`, key, string(body), actorID, updatedAt)
	updated, err := scanSystemSetting(row)
	if err != nil {
		return control.SystemSetting{}, err
	}
	if err := s.audit(ctx, tx, actorID, "system_settings.upsert", key, map[string]any{"key": key}); err != nil {
		return control.SystemSetting{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.SystemSetting{}, err
	}
	return updated, nil
}

func (s *Store) MaintenanceCleanup(ctx context.Context, actorID string, request control.MaintenanceCleanupRequest) (control.MaintenanceCleanupReport, error) {
	request, err := control.NormalizeMaintenanceCleanupRequest(request)
	if err != nil {
		return control.MaintenanceCleanupReport{}, err
	}
	if request.ApplicationID != "" {
		exists, err := rowExists(ctx, s.db, `SELECT 1 FROM applications WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`, request.ApplicationID, s.organizationID)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		if !exists {
			return control.MaintenanceCleanupReport{}, control.ErrNotFound
		}
	}
	report := emptyMaintenanceCleanupReport(request)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.MaintenanceCleanupReport{}, err
	}
	defer rollback(tx)
	if request.IncludeAlertDeliveries {
		count, err := s.countCleanupRows(ctx, tx, "alert_deliveries", "created_at", request)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		report.Counts["alert_deliveries"] = count
		if !request.DryRun {
			if err := s.deleteCleanupRows(ctx, tx, "alert_deliveries", "created_at", request); err != nil {
				return control.MaintenanceCleanupReport{}, err
			}
		}
	}
	if request.IncludeEvents {
		count, err := s.countCleanupRows(ctx, tx, "event_ingest_outbox", "occurred_at", request)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		report.Counts["events"] = count
		if !request.DryRun {
			if err := s.deleteCleanupRows(ctx, tx, "event_ingest_outbox", "occurred_at", request); err != nil {
				return control.MaintenanceCleanupReport{}, err
			}
		}
	}
	if request.IncludeDependencies {
		count, err := s.countCleanupRows(ctx, tx, "dependency_inventory", "last_observed_at", request)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		report.Counts["dependencies"] = count
		if !request.DryRun {
			if err := s.deleteCleanupRows(ctx, tx, "dependency_inventory", "last_observed_at", request); err != nil {
				return control.MaintenanceCleanupReport{}, err
			}
		}
	}
	if request.IncludeBaselineFindings {
		count, err := s.countCleanupRows(ctx, tx, "baseline_findings", "observed_at", request)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		report.Counts["baseline_findings"] = count
		if !request.DryRun {
			if err := s.deleteCleanupRows(ctx, tx, "baseline_findings", "observed_at", request); err != nil {
				return control.MaintenanceCleanupReport{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return control.MaintenanceCleanupReport{}, err
	}
	if analytics, ok := s.analytics.(MaintenanceAnalytics); ok {
		analyticsReport, err := analytics.CleanupOperationalData(ctx, request)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		for key, count := range analyticsReport.Counts {
			report.Counts[key] = count
		}
	}
	if !request.DryRun {
		if err := s.audit(ctx, s.db, actorID, "maintenance.cleanup", "operational-data", map[string]any{
			"application_id": request.ApplicationID,
			"before":         request.Before.Format(time.RFC3339),
			"counts":         report.Counts,
		}); err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
	}
	return report, nil
}

func (s *Store) ListAlertRules(ctx context.Context) ([]control.AlertRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, description, enabled, event_type, severity, condition, target, created_at, updated_at
		FROM alert_rules
		WHERE organization_id = $1
		ORDER BY name
	`, s.organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []control.AlertRule
	for rows.Next() {
		rule, err := scanAlertRuleRows(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *Store) CreateAlertRule(ctx context.Context, actorID string, input control.AlertRule) (control.AlertRule, error) {
	rule, err := control.PrepareAlertRule(input, s.now().UTC())
	if err != nil {
		return control.AlertRule{}, err
	}
	rule.ID = control.NewID("alr")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.AlertRule{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		INSERT INTO alert_rules (
			id, organization_id, name, description, enabled, event_type, severity,
			condition, target, created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), $11, $12)
		RETURNING id, name, description, enabled, event_type, severity, condition, target, created_at, updated_at
	`, rule.ID, s.organizationID, rule.Name, rule.Description, rule.Enabled, rule.EventType, rule.Severity, rule.Condition, rule.Target, actorID, rule.CreatedAt.UTC(), rule.UpdatedAt.UTC())
	created, err := scanAlertRule(row)
	if err != nil {
		return control.AlertRule{}, err
	}
	if err := s.audit(ctx, tx, actorID, "alert_rule.create", created.ID, map[string]any{"name": created.Name, "severity": created.Severity}); err != nil {
		return control.AlertRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.AlertRule{}, err
	}
	return created, nil
}

func (s *Store) UpdateAlertRule(ctx context.Context, actorID string, alertRuleID string, input control.AlertRule) (control.AlertRule, error) {
	rule, err := control.PrepareAlertRule(input, s.now().UTC())
	if err != nil {
		return control.AlertRule{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return control.AlertRule{}, err
	}
	defer rollback(tx)
	row := tx.QueryRowContext(ctx, `
		UPDATE alert_rules
		SET name = $3, description = $4, enabled = $5, event_type = $6,
			severity = $7, condition = $8, target = $9, updated_at = $10
		WHERE id = $1 AND organization_id = $2
		RETURNING id, name, description, enabled, event_type, severity, condition, target, created_at, updated_at
	`, alertRuleID, s.organizationID, rule.Name, rule.Description, rule.Enabled, rule.EventType, rule.Severity, rule.Condition, rule.Target, rule.UpdatedAt.UTC())
	updated, err := scanAlertRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return control.AlertRule{}, control.ErrNotFound
	}
	if err != nil {
		return control.AlertRule{}, err
	}
	if err := s.audit(ctx, tx, actorID, "alert_rule.update", alertRuleID, map[string]any{"name": updated.Name, "enabled": updated.Enabled}); err != nil {
		return control.AlertRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return control.AlertRule{}, err
	}
	return updated, nil
}

func (s *Store) ListAlertDeliveries(ctx context.Context) ([]control.AlertDelivery, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, alert_rule_id, alert_rule_name, event_id, event_type, severity,
			target, status, attempts, last_error, created_at, delivered_at
		FROM alert_deliveries
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT 500
	`, s.organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var deliveries []control.AlertDelivery
	for rows.Next() {
		delivery, err := scanAlertDeliveryRows(rows)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

func (s *Store) ListAuditLogs(ctx context.Context) ([]control.AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(actor_id, ''), action, resource, details::text, created_at
		FROM audit_logs
		ORDER BY created_at DESC
		LIMIT 500
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []control.AuditLog
	for rows.Next() {
		var log control.AuditLog
		var details string
		if err := rows.Scan(&log.ID, &log.ActorID, &log.Action, &log.Resource, &details, &log.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(details), &log.Details); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

func (s *Store) RecordAuditLog(ctx context.Context, actorID string, action string, resource string, details map[string]any) error {
	return s.audit(ctx, s.db, actorID, action, resource, details)
}

func emptyMaintenanceCleanupReport(request control.MaintenanceCleanupRequest) control.MaintenanceCleanupReport {
	return control.MaintenanceCleanupReport{
		ApplicationID: request.ApplicationID,
		Before:        request.Before,
		DryRun:        request.DryRun,
		Counts: map[string]int{
			"events":                   0,
			"dependencies":             0,
			"baseline_findings":        0,
			"alert_deliveries":         0,
			"clickhouse_events":        0,
			"clickhouse_event_details": 0,
			"clickhouse_dependencies":  0,
			"clickhouse_rollups":       0,
		},
	}
}

func (s *Store) countCleanupRows(ctx context.Context, q queryer, table string, timeColumn string, request control.MaintenanceCleanupRequest) (int, error) {
	where, args := cleanupWhere(table, timeColumn, request)
	var count int
	if err := q.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s AS t %s`, table, where), args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) deleteCleanupRows(ctx context.Context, q queryer, table string, timeColumn string, request control.MaintenanceCleanupRequest) error {
	where, args := cleanupWhere(table, timeColumn, request)
	_, err := q.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s AS t %s`, table, where), args...)
	return err
}

func cleanupWhere(table string, timeColumn string, request control.MaintenanceCleanupRequest) (string, []any) {
	args := []any{request.Before}
	where := fmt.Sprintf(`WHERE t.%s < $1`, timeColumn)
	if request.ApplicationID == "" {
		return where, args
	}
	args = append(args, request.ApplicationID)
	if table == "alert_deliveries" {
		where += ` AND EXISTS (
			SELECT 1 FROM event_ingest_outbox AS e
			WHERE e.id = t.event_id AND e.application_id = $2
		)`
		return where, args
	}
	where += ` AND t.application_id = $2`
	return where, args
}

func (s *Store) userByEmail(ctx context.Context, email string) (control.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, password_hash, to_json(roles)::text, created_at, updated_at, disabled_at
		FROM users
		WHERE email = $1 AND disabled_at IS NULL
	`, strings.TrimSpace(email))
	return scanUser(row)
}

func (s *Store) listEnabledAlertRulesForEvent(ctx context.Context, q queryer, eventType string) ([]control.AlertRule, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, name, description, enabled, event_type, severity, condition, target, created_at, updated_at
		FROM alert_rules
		WHERE organization_id = $1 AND enabled = true AND event_type = $2
		ORDER BY name
	`, s.organizationID, eventType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []control.AlertRule
	for rows.Next() {
		rule, err := scanAlertRuleRows(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *Store) agentEnvironmentID(ctx context.Context, agentID string) (string, error) {
	var environmentID string
	if err := s.db.QueryRowContext(ctx, `SELECT environment_id FROM agents WHERE id = $1`, agentID).Scan(&environmentID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", control.ErrNotFound
		}
		return "", err
	}
	return environmentID, nil
}

func (s *Store) policyByID(ctx context.Context, q queryer, policyID string) (control.PolicySet, error) {
	var policy control.PolicySet
	err := q.QueryRowContext(ctx, `
		SELECT id, name, description, created_at
		FROM policies
		WHERE id = $1 AND organization_id = $2
	`, policyID, s.organizationID).Scan(&policy.ID, &policy.Name, &policy.Description, &policy.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return control.PolicySet{}, control.ErrNotFound
	}
	if err != nil {
		return control.PolicySet{}, err
	}
	rows, err := q.QueryContext(ctx, `
		SELECT version, status, rules::text, canary_percent, created_at, published_at
		FROM policy_versions
		WHERE policy_id = $1
		ORDER BY version
	`, policyID)
	if err != nil {
		return control.PolicySet{}, err
	}
	defer rows.Close()
	for rows.Next() {
		version, err := scanPolicyVersionRows(rows)
		if err != nil {
			return control.PolicySet{}, err
		}
		policy.Versions = append(policy.Versions, version)
		if version.Status == "active" || version.Status == "canary" {
			active := version
			policy.Active = &active
		}
	}
	return policy, rows.Err()
}

func (s *Store) activePolicyVersion(ctx context.Context, policyID string, version int) (control.PolicyVersion, error) {
	args := []any{}
	query := `
		SELECT version, status, rules::text, canary_percent, created_at, published_at
		FROM policy_versions
	`
	if policyID != "" && version > 0 {
		query += ` WHERE policy_id = $1 AND version = $2`
		args = append(args, policyID, version)
	} else if policyID != "" {
		query += ` WHERE policy_id = $1 AND status IN ('active', 'canary')`
		args = append(args, policyID)
	} else {
		query += ` WHERE status IN ('active', 'canary')`
	}
	query += ` ORDER BY published_at DESC NULLS LAST, version DESC LIMIT 1`
	return scanPolicyVersion(s.db.QueryRowContext(ctx, query, args...))
}

func (s *Store) audit(ctx context.Context, q queryer, actorID string, action string, resource string, details map[string]any) error {
	body, err := json.Marshal(emptyMap(details))
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO audit_logs (id, actor_id, action, resource, details, created_at)
		VALUES ($1, NULLIF($2, ''), $3, $4, $5::jsonb, $6)
	`, control.NewID("aud"), actorID, action, resource, string(body), s.now().UTC())
	return err
}

func scanUser(row interface {
	Scan(...any) error
}) (control.User, error) {
	var user control.User
	var rolesJSON string
	var disabledAt sql.NullTime
	if err := row.Scan(&user.ID, &user.Email, &user.Name, &user.PasswordHash, &rolesJSON, &user.CreatedAt, &user.UpdatedAt, &disabledAt); err != nil {
		return control.User{}, err
	}
	if disabledAt.Valid {
		user.DisabledAt = &disabledAt.Time
	}
	var roles []string
	if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
		return control.User{}, err
	}
	for _, role := range roles {
		user.Roles = append(user.Roles, control.Role(role))
	}
	return user, nil
}

func scanSessionUser(row interface {
	Scan(...any) error
}) (control.User, time.Time, error) {
	var user control.User
	var rolesJSON string
	var expiresAt time.Time
	var disabledAt sql.NullTime
	if err := row.Scan(&user.ID, &user.Email, &user.Name, &user.PasswordHash, &rolesJSON, &user.CreatedAt, &user.UpdatedAt, &disabledAt, &expiresAt); err != nil {
		return control.User{}, time.Time{}, err
	}
	if disabledAt.Valid {
		user.DisabledAt = &disabledAt.Time
	}
	var roles []string
	if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
		return control.User{}, time.Time{}, err
	}
	for _, role := range roles {
		user.Roles = append(user.Roles, control.Role(role))
	}
	return user, expiresAt, nil
}

func publicUser(user control.User) control.User {
	user.PasswordHash = ""
	return user
}

func roleStrings(roles []control.Role) []string {
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		out = append(out, string(role))
	}
	return out
}

func auditActorForAgent(agentID string) string {
	if strings.TrimSpace(agentID) == "" {
		return "collector"
	}
	return agentID
}

func rolesToPostgresArray(roles []control.Role) string {
	values := roleStrings(roles)
	return "{" + strings.Join(values, ",") + "}"
}

func hasRole(roles []control.Role, role control.Role) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func scanDaemonWorkloadWithPrefix(row interface {
	Scan(...any) error
}, prefixes ...*string) (control.DaemonWorkload, error) {
	var workload control.DaemonWorkload
	var cmdlineJSON string
	var injectionReportedAt sql.NullTime
	var injectionStatusUpdatedAt sql.NullTime
	targets := make([]any, 0, len(prefixes)+18)
	for _, prefix := range prefixes {
		targets = append(targets, prefix)
	}
	targets = append(targets,
		&workload.ID,
		&workload.ApplicationID,
		&workload.NodeName,
		&workload.Type,
		&workload.PID,
		&cmdlineJSON,
		&workload.ContainerID,
		&workload.ContainerName,
		&workload.ImageID,
		&workload.ImageTag,
		&workload.InjectionStatus,
		&workload.InjectionError,
		&workload.InjectionHelperID,
		&workload.InjectionHelperVersion,
		&injectionReportedAt,
		&injectionStatusUpdatedAt,
		&workload.ObservedAt,
		&workload.UpdatedAt,
	)
	if err := row.Scan(targets...); err != nil {
		return control.DaemonWorkload{}, err
	}
	if err := json.Unmarshal([]byte(cmdlineJSON), &workload.Cmdline); err != nil {
		return control.DaemonWorkload{}, err
	}
	if injectionReportedAt.Valid {
		workload.InjectionReportedAt = injectionReportedAt.Time
	}
	if injectionStatusUpdatedAt.Valid {
		workload.InjectionStatusUpdatedAt = injectionStatusUpdatedAt.Time
	}
	return workload, nil
}

func scanDaemonWorkload(row interface {
	Scan(...any) error
}) (control.DaemonWorkload, error) {
	return scanDaemonWorkloadWithPrefix(row)
}

func scanAgent(row interface {
	Scan(...any) error
}) (control.Agent, error) {
	var agent control.Agent
	err := row.Scan(
		&agent.ID,
		&agent.ApplicationID,
		&agent.EnvironmentID,
		&agent.Hostname,
		&agent.Runtime,
		&agent.Version,
		&agent.Status,
		&agent.LastSeenAt,
		&agent.PolicyID,
		&agent.PolicyVersion,
	)
	return agent, err
}

func scanAgentRows(rows *sql.Rows) (control.Agent, error) {
	return scanAgent(rows)
}

func scanPolicyVersion(row interface {
	Scan(...any) error
}) (control.PolicyVersion, error) {
	var version control.PolicyVersion
	var rulesJSON string
	var publishedAt sql.NullTime
	err := row.Scan(&version.Version, &version.Status, &rulesJSON, &version.CanaryPercent, &version.CreatedAt, &publishedAt)
	if err != nil {
		return control.PolicyVersion{}, err
	}
	if err := json.Unmarshal([]byte(rulesJSON), &version.Rules); err != nil {
		return control.PolicyVersion{}, err
	}
	if publishedAt.Valid {
		version.PublishedAt = publishedAt.Time
	}
	return version, nil
}

func scanPolicyVersionRows(rows *sql.Rows) (control.PolicyVersion, error) {
	return scanPolicyVersion(rows)
}

func scanSystemSetting(row interface {
	Scan(...any) error
}) (control.SystemSetting, error) {
	var setting control.SystemSetting
	var valueJSON string
	if err := row.Scan(&setting.Key, &valueJSON, &setting.UpdatedBy, &setting.UpdatedAt); err != nil {
		return control.SystemSetting{}, err
	}
	if err := json.Unmarshal([]byte(valueJSON), &setting.Value); err != nil {
		return control.SystemSetting{}, err
	}
	return setting, nil
}

func scanSystemSettingRows(rows *sql.Rows) (control.SystemSetting, error) {
	return scanSystemSetting(rows)
}

func scanAlertRule(row interface {
	Scan(...any) error
}) (control.AlertRule, error) {
	var rule control.AlertRule
	err := row.Scan(
		&rule.ID,
		&rule.Name,
		&rule.Description,
		&rule.Enabled,
		&rule.EventType,
		&rule.Severity,
		&rule.Condition,
		&rule.Target,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)
	return rule, err
}

func scanAlertRuleRows(rows *sql.Rows) (control.AlertRule, error) {
	return scanAlertRule(rows)
}

func scanAlertDelivery(row interface {
	Scan(...any) error
}) (control.AlertDelivery, error) {
	var delivery control.AlertDelivery
	var deliveredAt sql.NullTime
	err := row.Scan(
		&delivery.ID,
		&delivery.AlertRuleID,
		&delivery.AlertRuleName,
		&delivery.EventID,
		&delivery.EventType,
		&delivery.Severity,
		&delivery.Target,
		&delivery.Status,
		&delivery.Attempts,
		&delivery.LastError,
		&delivery.CreatedAt,
		&deliveredAt,
	)
	if deliveredAt.Valid {
		delivery.DeliveredAt = &deliveredAt.Time
	}
	return delivery, err
}

func scanAlertDeliveryRows(rows *sql.Rows) (control.AlertDelivery, error) {
	return scanAlertDelivery(rows)
}

func normalizeSettingKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func scanEventRows(rows *sql.Rows) (control.SecurityEvent, error) {
	var event control.SecurityEvent
	var attrs string
	var deletedAt sql.NullTime
	if err := rows.Scan(
		&event.ID,
		&event.Type,
		&event.ApplicationID,
		&event.EnvironmentID,
		&event.AgentID,
		&event.PolicyID,
		&event.PolicyVersion,
		&event.Hook,
		&event.Algorithm,
		&event.Severity,
		&event.Message,
		&attrs,
		&event.OccurredAt,
		&deletedAt,
		&event.DeletedBy,
	); err != nil {
		return control.SecurityEvent{}, err
	}
	if err := json.Unmarshal([]byte(attrs), &event.Attributes); err != nil {
		return control.SecurityEvent{}, err
	}
	if deletedAt.Valid {
		event.DeletedAt = &deletedAt.Time
	}
	return event, nil
}

func (s *Store) excludeDeletedEvents(ctx context.Context, events []control.SecurityEvent) ([]control.SecurityEvent, error) {
	if len(events) == 0 {
		return events, nil
	}
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.ID)
	}
	deleted, err := s.deletedEventIDSet(ctx, ids)
	if err != nil {
		return nil, err
	}
	if len(deleted) == 0 {
		return events, nil
	}
	filtered := make([]control.SecurityEvent, 0, len(events))
	for _, event := range events {
		if !deleted[event.ID] {
			filtered = append(filtered, event)
		}
	}
	return filtered, nil
}

func (s *Store) deletedEventIDSet(ctx context.Context, ids []string) (map[string]bool, error) {
	placeholders, args := postgresPlaceholders(ids, 1)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT id
		FROM event_ingest_outbox
		WHERE deleted_at IS NOT NULL AND id IN (%s)
	`, placeholders), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deleted := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		deleted[id] = true
	}
	return deleted, rows.Err()
}

func updateEventRecycleBinRows(ctx context.Context, q queryer, ids []string, statement string, prefixArgs ...any) ([]string, error) {
	placeholders, idArgs := postgresPlaceholders(ids, len(prefixArgs)+1)
	args := append([]any{}, prefixArgs...)
	args = append(args, idArgs...)
	rows, err := q.QueryContext(ctx, fmt.Sprintf(statement, placeholders), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	changed := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		changed = append(changed, id)
	}
	return changed, rows.Err()
}

func postgresPlaceholders(ids []string, start int) (string, []any) {
	parts := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	for i, id := range ids {
		parts = append(parts, fmt.Sprintf("$%d", start+i))
		args = append(args, id)
	}
	return strings.Join(parts, ", "), args
}

func scanDependencyRows(rows *sql.Rows) (control.Dependency, error) {
	var dep control.Dependency
	var licensesJSON string
	var vulnerabilitiesJSON string
	if err := rows.Scan(
		&dep.ID,
		&dep.ApplicationID,
		&dep.AgentID,
		&dep.Name,
		&dep.Version,
		&dep.Ecosystem,
		&dep.PackagePath,
		&licensesJSON,
		&vulnerabilitiesJSON,
		&dep.ObservedAt,
	); err != nil {
		return control.Dependency{}, err
	}
	if err := json.Unmarshal([]byte(licensesJSON), &dep.Licenses); err != nil {
		return control.Dependency{}, err
	}
	if err := json.Unmarshal([]byte(vulnerabilitiesJSON), &dep.Vulnerabilities); err != nil {
		return control.Dependency{}, err
	}
	return dep, nil
}

func scanBaselineFindingRows(rows *sql.Rows) (control.BaselineFinding, error) {
	var finding control.BaselineFinding
	var attributes string
	if err := rows.Scan(
		&finding.ID,
		&finding.ApplicationID,
		&finding.EnvironmentID,
		&finding.AgentID,
		&finding.CheckID,
		&finding.Title,
		&finding.Category,
		&finding.Severity,
		&finding.Status,
		&finding.Resource,
		&finding.Remediation,
		&attributes,
		&finding.ObservedAt,
	); err != nil {
		return control.BaselineFinding{}, err
	}
	if err := json.Unmarshal([]byte(attributes), &finding.Attributes); err != nil {
		return control.BaselineFinding{}, err
	}
	return finding, nil
}

func scanCounts(ctx context.Context, q queryer, query string, target map[string]int, args ...any) error {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return err
		}
		target[key] = count
	}
	return rows.Err()
}

func scanTrendPoints(ctx context.Context, q queryer, query string, args ...any) ([]control.TrendPoint, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := []control.TrendPoint{}
	for rows.Next() {
		var point control.TrendPoint
		if err := rows.Scan(&point.BucketStart, &point.Count); err != nil {
			return nil, err
		}
		point.BucketStart = point.BucketStart.UTC()
		points = append(points, point)
	}
	return points, rows.Err()
}

func rowExists(ctx context.Context, q queryer, query string, args ...any) (bool, error) {
	var value int
	err := q.QueryRowContext(ctx, query, args...).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func hashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func secretPreview(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[len(value)-8:]
}

func emptyMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func mapConstraintError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if strings.Contains(message, "duplicate key") || strings.Contains(message, "violates foreign key") || strings.Contains(message, "violates check constraint") {
		return fmt.Errorf("%w: %s", control.ErrInvalid, message)
	}
	return err
}

func rollback(tx *sql.Tx) {
	_ = tx.Rollback()
}
