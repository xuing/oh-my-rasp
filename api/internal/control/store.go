package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrInvalid      = errors.New("invalid")
)

type Store interface {
	Login(ctx context.Context, email string, password string) (Session, User, error)
	UserForToken(ctx context.Context, token string) (User, error)
	ListUsers(ctx context.Context, queries ...UserQuery) ([]User, error)
	CreateUser(ctx context.Context, actorID string, input User, password string) (User, error)
	UpdateUser(ctx context.Context, actorID string, userID string, input User) (User, error)
	ListApplications(ctx context.Context) ([]Application, error)
	CreateApplication(ctx context.Context, actorID string, input Application) (Application, error)
	DeleteApplication(ctx context.Context, actorID string, appID string) error
	RotateApplicationSecret(ctx context.Context, actorID string, appID string) (Application, error)
	CreateEnvironment(ctx context.Context, actorID string, appID string, input Environment) (Environment, error)
	DaemonAccessToken(ctx context.Context) (DaemonAccessToken, error)
	ResetDaemonAccessToken(ctx context.Context, actorID string) (DaemonAccessToken, error)
	GetDaemonApplication(ctx context.Context, accessToken string, appID string) (DaemonApplication, error)
	ReportDaemonWorkloads(ctx context.Context, accessToken string, report DaemonWorkloadReport) ([]DaemonWorkload, error)
	ListDaemonWorkloads(ctx context.Context) ([]DaemonWorkload, error)
	ListDaemonCommands(ctx context.Context, accessToken string) ([]DaemonCommandGroup, error)
	ReportDaemonInjection(ctx context.Context, accessToken string, report DaemonInjectionReport) (DaemonWorkload, error)
	BindDaemonWorkload(ctx context.Context, actorID string, workloadID string, applicationID string) (DaemonWorkload, error)
	UnbindDaemonWorkload(ctx context.Context, actorID string, workloadID string) (DaemonWorkload, error)
	ListAgents(ctx context.Context) ([]Agent, error)
	UpdateAgentAlias(ctx context.Context, actorID string, agentID string, alias string) (Agent, error)
	SetAgentIgnored(ctx context.Context, actorID string, agentID string, ignored bool) (Agent, error)
	DeleteAgents(ctx context.Context, actorID string, agentIDs []string) (AgentBatchOperationReport, error)
	RegisterAgent(ctx context.Context, appID string, appSecret string, input Agent) (Agent, error)
	AuthorizeAgent(ctx context.Context, appID string, appSecret string, environmentID string, agentID string) error
	HeartbeatAgent(ctx context.Context, agentID string, status string) (Agent, error)
	GetAgentPolicy(ctx context.Context, agentID string) (PolicyVersion, error)
	ListPolicies(ctx context.Context) ([]PolicySet, error)
	CreatePolicy(ctx context.Context, actorID string, input PolicySet) (PolicySet, error)
	AddPolicyVersion(ctx context.Context, actorID string, policyID string, rules []Rule) (PolicySet, error)
	UpdatePolicyVersionRules(ctx context.Context, actorID string, policyID string, version int, rules []Rule) (PolicySet, error)
	RestoreDefaultPolicy(ctx context.Context, actorID string, policyID string) (PolicySet, error)
	ValidateRules(ctx context.Context, rules []Rule) RuleValidation
	TestRule(ctx context.Context, rule Rule, event SecurityEvent) RuleTestResult
	RolloutPolicy(ctx context.Context, actorID string, policyID string, rollout PolicyRollout) (PolicySet, error)
	RollbackPolicy(ctx context.Context, actorID string, policyID string) (PolicySet, error)
	IngestEvent(ctx context.Context, event SecurityEvent) (SecurityEvent, error)
	IngestDependency(ctx context.Context, dep Dependency) (Dependency, error)
	IngestBaselineFinding(ctx context.Context, finding BaselineFinding) (BaselineFinding, error)
	ListEvents(ctx context.Context, query SecurityEventQuery) ([]SecurityEvent, error)
	SoftDeleteEvents(ctx context.Context, actorID string, request EventRecycleBinRequest) (EventRecycleBinReport, error)
	RestoreDeletedEvents(ctx context.Context, actorID string, request EventRecycleBinRequest) (EventRecycleBinReport, error)
	PurgeDeletedEvents(ctx context.Context, actorID string, request EventRecycleBinRequest) (EventRecycleBinReport, error)
	ListDependencies(ctx context.Context, query DependencyQuery) ([]Dependency, error)
	DependencySummary(ctx context.Context) (DependencySummary, error)
	ListBaselineFindings(ctx context.Context, query BaselineFindingQuery) ([]BaselineFinding, error)
	Overview(ctx context.Context) (Overview, error)
	Observability(ctx context.Context, query ObservabilityQuery) (ObservabilityReport, error)
	ListSystemSettings(ctx context.Context) ([]SystemSetting, error)
	UpsertSystemSetting(ctx context.Context, actorID string, setting SystemSetting) (SystemSetting, error)
	MaintenanceCleanup(ctx context.Context, actorID string, request MaintenanceCleanupRequest) (MaintenanceCleanupReport, error)
	ListAlertRules(ctx context.Context) ([]AlertRule, error)
	CreateAlertRule(ctx context.Context, actorID string, input AlertRule) (AlertRule, error)
	UpdateAlertRule(ctx context.Context, actorID string, alertRuleID string, input AlertRule) (AlertRule, error)
	ListAlertDeliveries(ctx context.Context) ([]AlertDelivery, error)
	RecordAuditLog(ctx context.Context, actorID string, action string, resource string, details map[string]any) error
	ListAuditLogs(ctx context.Context) ([]AuditLog, error)
}

type MemoryStore struct {
	mu               sync.RWMutex
	now              func() time.Time
	organization     Organization
	users            map[string]User
	sessions         map[string]Session
	applications     map[string]Application
	environments     map[string]Environment
	daemonToken      DaemonAccessToken
	workloads        map[string]DaemonWorkload
	agents           map[string]Agent
	policies         map[string]PolicySet
	events           map[string]SecurityEvent
	dependencies     map[string]Dependency
	baselineFindings map[string]BaselineFinding
	settings         map[string]SystemSetting
	alertRules       map[string]AlertRule
	alertDeliveries  map[string]AlertDelivery
	auditLogs        []AuditLog
}

type MemorySeed struct {
	AdminEmail             string
	AdminPassword          string
	AdminName              string
	ApplicationID          string
	ApplicationName        string
	ApplicationDescription string
	ApplicationSecret      string
	EnvironmentID          string
	EnvironmentName        string
	EnvironmentKind        string
}

func NewMemoryStore(now func() time.Time) *MemoryStore {
	return NewMemoryStoreWithSeed(now, MemorySeed{})
}

func NewMemoryStoreWithSeed(now func() time.Time, seed MemorySeed) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	seed = normalizeMemorySeed(seed)
	store := &MemoryStore{
		now:              now,
		organization:     Organization{ID: "org_default", Name: "Default Organization"},
		users:            make(map[string]User),
		sessions:         make(map[string]Session),
		applications:     make(map[string]Application),
		environments:     make(map[string]Environment),
		workloads:        make(map[string]DaemonWorkload),
		agents:           make(map[string]Agent),
		policies:         make(map[string]PolicySet),
		events:           make(map[string]SecurityEvent),
		dependencies:     make(map[string]Dependency),
		baselineFindings: make(map[string]BaselineFinding),
		settings:         make(map[string]SystemSetting),
		alertRules:       make(map[string]AlertRule),
		alertDeliveries:  make(map[string]AlertDelivery),
	}
	admin := User{
		ID:           "usr_admin",
		Email:        seed.AdminEmail,
		Name:         seed.AdminName,
		PasswordHash: seed.AdminPassword,
		Roles:        []Role{RoleAdmin, RoleSecurityEngineer},
		CreatedAt:    now(),
		UpdatedAt:    now(),
	}
	store.users[admin.ID] = admin
	app := Application{
		ID:          seed.ApplicationID,
		Name:        seed.ApplicationName,
		Description: seed.ApplicationDescription,
		Secret:      seed.ApplicationSecret,
		CreatedAt:   now(),
	}
	env := Environment{
		ID:            seed.EnvironmentID,
		ApplicationID: app.ID,
		Name:          seed.EnvironmentName,
		Kind:          seed.EnvironmentKind,
		CreatedAt:     now(),
	}
	app.EnvironmentIDs = []string{env.ID}
	store.applications[app.ID] = app
	store.environments[env.ID] = env
	store.daemonToken = DaemonAccessToken{AccessToken: newSecret(), UpdatedAt: now()}
	for _, setting := range DefaultSystemSettings(now()) {
		store.settings[setting.Key] = setting
	}
	for _, alertRule := range DefaultAlertRules(now()) {
		store.alertRules[alertRule.ID] = alertRule
	}
	return store
}

func normalizeMemorySeed(seed MemorySeed) MemorySeed {
	if strings.TrimSpace(seed.AdminEmail) == "" {
		seed.AdminEmail = "admin@ohmyrasp.local"
	}
	if strings.TrimSpace(seed.AdminName) == "" {
		seed.AdminName = "Default Admin"
	}
	if seed.AdminPassword == "" {
		seed.AdminPassword = newSecret()
	}
	if strings.TrimSpace(seed.ApplicationID) == "" {
		seed.ApplicationID = "app_default"
	}
	if strings.TrimSpace(seed.ApplicationName) == "" {
		seed.ApplicationName = "Local Java Service"
	}
	if strings.TrimSpace(seed.ApplicationDescription) == "" {
		seed.ApplicationDescription = "Local development application"
	}
	if seed.ApplicationSecret == "" {
		seed.ApplicationSecret = newSecret()
	}
	if strings.TrimSpace(seed.EnvironmentID) == "" {
		seed.EnvironmentID = "env_default"
	}
	if strings.TrimSpace(seed.EnvironmentName) == "" {
		seed.EnvironmentName = "production"
	}
	if strings.TrimSpace(seed.EnvironmentKind) == "" {
		seed.EnvironmentKind = "production"
	}
	return seed
}

func (s *MemoryStore) Login(_ context.Context, email string, password string) (Session, User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.users {
		if strings.EqualFold(user.Email, email) && user.PasswordHash == password && user.DisabledAt == nil {
			session := Session{
				Token:     newID("ses"),
				UserID:    user.ID,
				ExpiresAt: s.now().Add(12 * time.Hour),
			}
			s.sessions[session.Token] = session
			s.audit(user.ID, "auth.login", "session", map[string]any{"email": email})
			return session, user, nil
		}
	}
	return Session{}, User{}, ErrUnauthorized
}

func (s *MemoryStore) UserForToken(_ context.Context, token string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[token]
	if !ok || s.now().After(session.ExpiresAt) {
		return User{}, ErrUnauthorized
	}
	user, ok := s.users[session.UserID]
	if !ok || user.DisabledAt != nil {
		return User{}, ErrUnauthorized
	}
	return user, nil
}

func (s *MemoryStore) ListUsers(_ context.Context, queries ...UserQuery) ([]User, error) {
	query, err := firstUserQuery(queries)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]User, 0, len(s.users))
	for _, user := range s.users {
		if !userMatchesQuery(user, query) {
			continue
		}
		users = append(users, publicUser(user))
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
	return users, nil
}

func (s *MemoryStore) CreateUser(_ context.Context, actorID string, input User, password string) (User, error) {
	user, password, err := PrepareUser(input, password, s.now())
	if err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.users {
		if strings.EqualFold(existing.Email, user.Email) {
			return User{}, fmt.Errorf("%w: user email already exists", ErrInvalid)
		}
	}
	user.ID = newID("usr")
	user.PasswordHash = password
	s.users[user.ID] = user
	s.audit(actorID, "user.create", user.ID, map[string]any{"email": user.Email, "roles": rolesAsStrings(user.Roles)})
	return publicUser(user), nil
}

func (s *MemoryStore) UpdateUser(_ context.Context, actorID string, userID string, input User) (User, error) {
	user, err := PrepareUserUpdate(input, s.now())
	if err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.users[userID]
	if !ok {
		return User{}, ErrNotFound
	}
	if actorID == userID {
		if user.DisabledAt != nil {
			return User{}, fmt.Errorf("%w: cannot disable your own user", ErrInvalid)
		}
		if !hasRole(user.Roles, RoleAdmin) {
			return User{}, fmt.Errorf("%w: cannot remove your own admin role", ErrInvalid)
		}
	}
	user.ID = userID
	user.Email = current.Email
	user.PasswordHash = current.PasswordHash
	user.CreatedAt = current.CreatedAt
	s.users[userID] = user
	if user.DisabledAt != nil {
		for token, session := range s.sessions {
			if session.UserID == userID {
				delete(s.sessions, token)
			}
		}
	}
	s.audit(actorID, "user.update", userID, map[string]any{"email": user.Email, "roles": rolesAsStrings(user.Roles), "disabled": user.DisabledAt != nil})
	return publicUser(user), nil
}

func (s *MemoryStore) ListApplications(_ context.Context) ([]Application, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	apps := make([]Application, 0, len(s.applications))
	for _, app := range s.applications {
		apps = append(apps, app)
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })
	return apps, nil
}

func (s *MemoryStore) CreateApplication(_ context.Context, actorID string, input Application) (Application, error) {
	if strings.TrimSpace(input.Name) == "" {
		return Application{}, fmt.Errorf("%w: application name is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	input.ID = newID("app")
	input.Secret = newSecret()
	input.CreatedAt = s.now()
	input.EnvironmentIDs = []string{}
	s.applications[input.ID] = input
	s.audit(actorID, "application.create", input.ID, map[string]any{"name": input.Name})
	return input, nil
}

func (s *MemoryStore) RotateApplicationSecret(_ context.Context, actorID string, appID string) (Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.applications[appID]
	if !ok {
		return Application{}, ErrNotFound
	}
	app.Secret = newSecret()
	s.applications[appID] = app
	s.audit(actorID, "application.secret.rotate", appID, map[string]any{"name": app.Name})
	return app, nil
}

func (s *MemoryStore) DeleteApplication(_ context.Context, actorID string, appID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.applications[appID]
	if !ok {
		return ErrNotFound
	}
	delete(s.applications, appID)
	for id, environment := range s.environments {
		if environment.ApplicationID == appID {
			delete(s.environments, id)
		}
	}
	for id, agent := range s.agents {
		if agent.ApplicationID == appID {
			delete(s.agents, id)
		}
	}
	for id, dependency := range s.dependencies {
		if dependency.ApplicationID == appID {
			delete(s.dependencies, id)
		}
	}
	for id, finding := range s.baselineFindings {
		if finding.ApplicationID == appID {
			delete(s.baselineFindings, id)
		}
	}
	for id, workload := range s.workloads {
		if workload.ApplicationID == appID {
			workload.ApplicationID = ""
			workload.UpdatedAt = s.now()
			s.workloads[id] = workload
		}
	}
	s.audit(actorID, "application.delete", appID, map[string]any{"name": app.Name})
	return nil
}

func (s *MemoryStore) CreateEnvironment(_ context.Context, actorID string, appID string, input Environment) (Environment, error) {
	if strings.TrimSpace(input.Name) == "" {
		return Environment{}, fmt.Errorf("%w: environment name is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.applications[appID]
	if !ok {
		return Environment{}, ErrNotFound
	}
	input.ID = newID("env")
	input.ApplicationID = appID
	input.CreatedAt = s.now()
	if input.Kind == "" {
		input.Kind = "custom"
	}
	s.environments[input.ID] = input
	app.EnvironmentIDs = append(app.EnvironmentIDs, input.ID)
	s.applications[appID] = app
	s.audit(actorID, "environment.create", input.ID, map[string]any{"application_id": appID, "name": input.Name})
	return input, nil
}

func (s *MemoryStore) DaemonAccessToken(_ context.Context) (DaemonAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.daemonToken.AccessToken == "" {
		s.daemonToken = DaemonAccessToken{AccessToken: newSecret(), UpdatedAt: s.now()}
	}
	return s.daemonToken, nil
}

func (s *MemoryStore) ResetDaemonAccessToken(_ context.Context, actorID string) (DaemonAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.daemonToken = DaemonAccessToken{AccessToken: newSecret(), UpdatedAt: s.now()}
	s.audit(actorID, "daemon.token.reset", "daemon", nil)
	return s.daemonToken, nil
}

func (s *MemoryStore) GetDaemonApplication(_ context.Context, accessToken string, appID string) (DaemonApplication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if accessToken == "" || accessToken != s.daemonToken.AccessToken {
		return DaemonApplication{}, ErrUnauthorized
	}
	app, ok := s.applications[strings.TrimSpace(appID)]
	if !ok || app.Secret == "" {
		return DaemonApplication{}, ErrNotFound
	}
	return DaemonApplication{
		ApplicationID:     app.ID,
		ApplicationSecret: app.Secret,
		Language:          "java",
	}, nil
}

func (s *MemoryStore) ReportDaemonWorkloads(_ context.Context, accessToken string, report DaemonWorkloadReport) ([]DaemonWorkload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.daemonToken.AccessToken == "" {
		s.daemonToken = DaemonAccessToken{AccessToken: newSecret(), UpdatedAt: s.now()}
	}
	if accessToken == "" || accessToken != s.daemonToken.AccessToken {
		return nil, ErrUnauthorized
	}
	if strings.TrimSpace(report.NodeName) == "" {
		return nil, fmt.Errorf("%w: daemon node name is required", ErrInvalid)
	}
	if len(report.Workloads) == 0 {
		return []DaemonWorkload{}, nil
	}
	now := s.now()
	reported := make([]DaemonWorkload, 0, len(report.Workloads))
	for _, input := range report.Workloads {
		workload, err := prepareDaemonWorkload(report.NodeName, input, now)
		if err != nil {
			return nil, err
		}
		if existing, ok := s.workloads[workload.ID]; ok {
			copyDaemonWorkloadRuntimeState(&workload, existing)
		}
		s.workloads[workload.ID] = workload
		reported = append(reported, workload)
	}
	return reported, nil
}

func (s *MemoryStore) ListDaemonWorkloads(_ context.Context) ([]DaemonWorkload, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	workloads := make([]DaemonWorkload, 0, len(s.workloads))
	for _, workload := range s.workloads {
		workloads = append(workloads, workload)
	}
	sort.Slice(workloads, func(i, j int) bool {
		if workloads[i].UpdatedAt.Equal(workloads[j].UpdatedAt) {
			return workloads[i].ID < workloads[j].ID
		}
		return workloads[i].UpdatedAt.After(workloads[j].UpdatedAt)
	})
	return workloads, nil
}

func (s *MemoryStore) ListDaemonCommands(_ context.Context, accessToken string) ([]DaemonCommandGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if accessToken == "" || accessToken != s.daemonToken.AccessToken {
		return nil, ErrUnauthorized
	}
	groups := map[string]*DaemonCommandGroup{}
	for _, workload := range s.workloads {
		if workload.ApplicationID == "" {
			continue
		}
		app, ok := s.applications[workload.ApplicationID]
		if !ok || app.Secret == "" {
			continue
		}
		group, ok := groups[app.ID]
		if !ok {
			group = &DaemonCommandGroup{
				ApplicationID:     app.ID,
				ApplicationSecret: app.Secret,
				Language:          "java",
				Workloads:         []DaemonWorkload{},
			}
			groups[app.ID] = group
		}
		group.Workloads = append(group.Workloads, workload)
	}
	commands := make([]DaemonCommandGroup, 0, len(groups))
	for _, group := range groups {
		sort.Slice(group.Workloads, func(i, j int) bool { return group.Workloads[i].ID < group.Workloads[j].ID })
		commands = append(commands, *group)
	}
	sort.Slice(commands, func(i, j int) bool { return commands[i].ApplicationID < commands[j].ApplicationID })
	return commands, nil
}

func (s *MemoryStore) ReportDaemonInjection(_ context.Context, accessToken string, input DaemonInjectionReport) (DaemonWorkload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if accessToken == "" || accessToken != s.daemonToken.AccessToken {
		return DaemonWorkload{}, ErrUnauthorized
	}
	report, err := PrepareDaemonInjectionReport(input, s.now())
	if err != nil {
		return DaemonWorkload{}, err
	}
	workload, ok := s.workloads[report.WorkloadID]
	if !ok {
		return DaemonWorkload{}, ErrNotFound
	}
	workload.InjectionStatus = report.Status
	workload.InjectionError = report.Error
	workload.InjectionHelperID = report.HelperID
	workload.InjectionHelperVersion = report.HelperVersion
	workload.InjectionReportedAt = report.ReportedAt
	workload.InjectionStatusUpdatedAt = s.now().UTC()
	workload.UpdatedAt = workload.InjectionStatusUpdatedAt
	s.workloads[workload.ID] = workload
	return workload, nil
}

func (s *MemoryStore) BindDaemonWorkload(_ context.Context, actorID string, workloadID string, applicationID string) (DaemonWorkload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(applicationID) == "" {
		return DaemonWorkload{}, fmt.Errorf("%w: application id is required", ErrInvalid)
	}
	if _, ok := s.applications[applicationID]; !ok {
		return DaemonWorkload{}, ErrNotFound
	}
	workload, ok := s.workloads[workloadID]
	if !ok {
		return DaemonWorkload{}, ErrNotFound
	}
	workload.ApplicationID = applicationID
	clearDaemonWorkloadInjection(&workload)
	workload.UpdatedAt = s.now()
	s.workloads[workloadID] = workload
	s.audit(actorID, "daemon.workload.bind", workloadID, map[string]any{"application_id": applicationID, "node_name": workload.NodeName, "type": workload.Type})
	return workload, nil
}

func copyDaemonWorkloadRuntimeState(next *DaemonWorkload, existing DaemonWorkload) {
	next.ApplicationID = existing.ApplicationID
	next.InjectionStatus = existing.InjectionStatus
	next.InjectionError = existing.InjectionError
	next.InjectionHelperID = existing.InjectionHelperID
	next.InjectionHelperVersion = existing.InjectionHelperVersion
	next.InjectionReportedAt = existing.InjectionReportedAt
	next.InjectionStatusUpdatedAt = existing.InjectionStatusUpdatedAt
}

func clearDaemonWorkloadInjection(workload *DaemonWorkload) {
	workload.InjectionStatus = ""
	workload.InjectionError = ""
	workload.InjectionHelperID = ""
	workload.InjectionHelperVersion = ""
	workload.InjectionReportedAt = time.Time{}
	workload.InjectionStatusUpdatedAt = time.Time{}
}

func (s *MemoryStore) UnbindDaemonWorkload(_ context.Context, actorID string, workloadID string) (DaemonWorkload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	workload, ok := s.workloads[workloadID]
	if !ok {
		return DaemonWorkload{}, ErrNotFound
	}
	workload.ApplicationID = ""
	clearDaemonWorkloadInjection(&workload)
	workload.UpdatedAt = s.now()
	s.workloads[workloadID] = workload
	s.audit(actorID, "daemon.workload.unbind", workloadID, map[string]any{"node_name": workload.NodeName, "type": workload.Type})
	return workload, nil
}

func (s *MemoryStore) ListAgents(_ context.Context) ([]Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agents := make([]Agent, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, agent)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].LastSeenAt.After(agents[j].LastSeenAt) })
	return agents, nil
}

func (s *MemoryStore) UpdateAgentAlias(_ context.Context, actorID string, agentID string, alias string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agents[agentID]
	if !ok {
		return Agent{}, ErrNotFound
	}
	agent.Alias = strings.TrimSpace(alias)
	s.agents[agentID] = agent
	s.audit(actorID, "agent.alias.update", agentID, map[string]any{"alias": agent.Alias})
	return agent, nil
}

func (s *MemoryStore) SetAgentIgnored(_ context.Context, actorID string, agentID string, ignored bool) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agents[agentID]
	if !ok {
		return Agent{}, ErrNotFound
	}
	if ignored {
		agent.IgnoredAt = s.now().UTC()
	} else {
		agent.IgnoredAt = time.Time{}
	}
	s.agents[agentID] = agent
	s.audit(actorID, "agent.ignore.update", agentID, map[string]any{"ignored": ignored})
	return agent, nil
}

func (s *MemoryStore) DeleteAgents(_ context.Context, actorID string, agentIDs []string) (AgentBatchOperationReport, error) {
	ids := NormalizeAgentIDs(agentIDs)
	if len(ids) == 0 {
		return AgentBatchOperationReport{}, fmt.Errorf("%w: agent ids are required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := s.agents[id]; !ok {
			continue
		}
		delete(s.agents, id)
		deleted = append(deleted, id)
	}
	if len(deleted) == 0 {
		return AgentBatchOperationReport{}, ErrNotFound
	}
	s.audit(actorID, "agent.delete", "agents", map[string]any{"ids": deleted, "count": len(deleted)})
	return AgentBatchOperationReport{IDs: deleted, Count: len(deleted)}, nil
}

func (s *MemoryStore) RegisterAgent(_ context.Context, appID string, appSecret string, input Agent) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.applications[appID]
	if !ok || app.Secret != appSecret {
		return Agent{}, ErrUnauthorized
	}
	env, ok := s.environments[input.EnvironmentID]
	if !ok {
		return Agent{}, ErrNotFound
	}
	if env.PolicyID != "" && env.PolicyVersion > 0 {
		input.PolicyID = env.PolicyID
		input.PolicyVersion = env.PolicyVersion
	} else if app.PolicyID != "" && app.PolicyVersion > 0 {
		input.PolicyID = app.PolicyID
		input.PolicyVersion = app.PolicyVersion
	} else if s.organization.PolicyID != "" && s.organization.PolicyVersion > 0 {
		input.PolicyID = s.organization.PolicyID
		input.PolicyVersion = s.organization.PolicyVersion
	}
	input.ID = newID("agt")
	input.ApplicationID = appID
	input.Status = "online"
	input.LastSeenAt = s.now()
	s.agents[input.ID] = input
	s.audit("agent", "agent.register", input.ID, map[string]any{"application_id": appID, "version": input.Version})
	return input, nil
}

func (s *MemoryStore) AuthorizeAgent(_ context.Context, appID string, appSecret string, environmentID string, agentID string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	app, ok := s.applications[appID]
	if !ok || app.Secret != appSecret {
		return ErrUnauthorized
	}
	if environmentID != "" {
		env, ok := s.environments[environmentID]
		if !ok {
			return ErrUnauthorized
		}
		if env.ApplicationID != appID {
			return ErrUnauthorized
		}
	}
	if agentID != "" {
		agent, ok := s.agents[agentID]
		if !ok {
			return ErrUnauthorized
		}
		if agent.ApplicationID != appID {
			return ErrUnauthorized
		}
		if environmentID != "" && agent.EnvironmentID != environmentID {
			return ErrUnauthorized
		}
	}
	return nil
}

func (s *MemoryStore) HeartbeatAgent(_ context.Context, agentID string, status string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agents[agentID]
	if !ok {
		return Agent{}, ErrNotFound
	}
	if status == "" {
		status = "online"
	}
	agent.Status = status
	agent.LastSeenAt = s.now()
	s.agents[agentID] = agent
	s.audit(agentID, "agent.heartbeat", agentID, map[string]any{"application_id": agent.ApplicationID, "status": agent.Status})
	return agent, nil
}

func (s *MemoryStore) GetAgentPolicy(_ context.Context, agentID string) (PolicyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[agentID]
	if !ok {
		return PolicyVersion{}, ErrNotFound
	}
	policyID := agent.PolicyID
	policyVersion := agent.PolicyVersion
	if policyID == "" && s.organization.PolicyID != "" {
		policyID = s.organization.PolicyID
		policyVersion = s.organization.PolicyVersion
	}
	if policyID != "" {
		policy := s.policies[policyID]
		for _, version := range policy.Versions {
			if version.Version == policyVersion {
				return version, nil
			}
		}
		if policy.Active != nil {
			return *policy.Active, nil
		}
	}
	return PolicyVersion{Version: 0, Status: "empty", Rules: []Rule{}}, nil
}

func (s *MemoryStore) ListPolicies(_ context.Context) ([]PolicySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policies := make([]PolicySet, 0, len(s.policies))
	for _, policy := range s.policies {
		policies = append(policies, policy)
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	return policies, nil
}

func (s *MemoryStore) CreatePolicy(_ context.Context, actorID string, input PolicySet) (PolicySet, error) {
	if strings.TrimSpace(input.Name) == "" {
		return PolicySet{}, fmt.Errorf("%w: policy name is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	input.ID = newID("pol")
	input.CreatedAt = s.now()
	input.Versions = []PolicyVersion{}
	s.policies[input.ID] = input
	s.audit(actorID, "policy.create", input.ID, map[string]any{"name": input.Name})
	return input, nil
}

func (s *MemoryStore) AddPolicyVersion(_ context.Context, actorID string, policyID string, rules []Rule) (PolicySet, error) {
	validation := s.ValidateRules(context.Background(), rules)
	if !validation.Valid {
		return PolicySet{}, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(validation.Errors, "; "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.policies[policyID]
	if !ok {
		return PolicySet{}, ErrNotFound
	}
	ensureRuleIDs(rules)
	version := PolicyVersion{
		Version:   len(policy.Versions) + 1,
		Status:    "draft",
		Rules:     rules,
		CreatedAt: s.now(),
	}
	policy.Versions = append(policy.Versions, version)
	s.policies[policyID] = policy
	s.audit(actorID, "policy.version.create", policyID, map[string]any{"version": version.Version})
	return policy, nil
}

func (s *MemoryStore) UpdatePolicyVersionRules(_ context.Context, actorID string, policyID string, version int, rules []Rule) (PolicySet, error) {
	if version <= 0 {
		return PolicySet{}, fmt.Errorf("%w: policy version must be positive", ErrInvalid)
	}
	validation := s.ValidateRules(context.Background(), rules)
	if !validation.Valid {
		return PolicySet{}, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(validation.Errors, "; "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.policies[policyID]
	if !ok {
		return PolicySet{}, ErrNotFound
	}
	for i := range policy.Versions {
		if policy.Versions[i].Version != version {
			continue
		}
		if policy.Versions[i].Status != "draft" {
			return PolicySet{}, fmt.Errorf("%w: only draft policy versions can be edited", ErrInvalid)
		}
		ensureRuleIDs(rules)
		policy.Versions[i].Rules = rules
		s.policies[policyID] = policy
		s.audit(actorID, "policy.version.update", policyID, map[string]any{"version": version, "rule_count": len(rules)})
		return policy, nil
	}
	return PolicySet{}, ErrNotFound
}

func ensureRuleIDs(rules []Rule) {
	for i := range rules {
		if rules[i].ID == "" {
			rules[i].ID = newID("rul")
		}
	}
}

func (s *MemoryStore) RestoreDefaultPolicy(_ context.Context, actorID string, policyID string) (PolicySet, error) {
	rules := DefaultPolicyRules()
	validation := ValidateRules(rules)
	if !validation.Valid {
		return PolicySet{}, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(validation.Errors, "; "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.policies[policyID]
	if !ok {
		return PolicySet{}, ErrNotFound
	}
	ensureRuleIDs(rules)
	version := PolicyVersion{
		Version:   len(policy.Versions) + 1,
		Status:    "draft",
		Rules:     rules,
		CreatedAt: s.now(),
	}
	policy.Versions = append(policy.Versions, version)
	s.policies[policyID] = policy
	s.audit(actorID, "policy.restore_default", policyID, map[string]any{"version": version.Version, "rule_count": len(rules)})
	return policy, nil
}

func (s *MemoryStore) ValidateRules(_ context.Context, rules []Rule) RuleValidation {
	return ValidateRules(rules)
}

func ValidateRules(rules []Rule) RuleValidation {
	var errors []string
	for i, rule := range rules {
		if strings.TrimSpace(rule.Name) == "" {
			errors = append(errors, fmt.Sprintf("rules[%d].name is required", i))
		}
		if strings.TrimSpace(rule.Hook) == "" {
			errors = append(errors, fmt.Sprintf("rules[%d].hook is required", i))
		}
		if !isSupportedPolicyHook(rule.Hook) {
			errors = append(errors, fmt.Sprintf("rules[%d].hook is not supported", i))
		}
		if strings.TrimSpace(rule.Expression) == "" {
			errors = append(errors, fmt.Sprintf("rules[%d].expression is required", i))
		} else if _, err := compileRuleExpression(rule.Expression); err != nil {
			errors = append(errors, fmt.Sprintf("rules[%d].expression %s", i, err.Error()))
		}
		if rule.Action != "" && !contains([]string{"log", "block", "ignore"}, rule.Action) {
			errors = append(errors, fmt.Sprintf("rules[%d].action must be log, block, or ignore", i))
		}
		if rule.Severity != "" && !contains([]string{"critical", "high", "medium", "low", "info"}, rule.Severity) {
			errors = append(errors, fmt.Sprintf("rules[%d].severity is not supported", i))
		}
		if rule.Algorithm != "" && !isSupportedPolicyAlgorithm(rule.Hook, rule.Algorithm) {
			errors = append(errors, fmt.Sprintf("rules[%d].algorithm is not supported for hook %s", i, rule.Hook))
		}
	}
	return RuleValidation{Valid: len(errors) == 0, Errors: errors}
}

func (s *MemoryStore) TestRule(_ context.Context, rule Rule, event SecurityEvent) RuleTestResult {
	return TestRule(rule, event)
}

func TestRule(rule Rule, event SecurityEvent) RuleTestResult {
	conditions, err := compileRuleExpression(rule.Expression)
	if err != nil {
		return RuleTestResult{Matched: false, Action: rule.Action, Algorithm: rule.Algorithm, Confidence: 0}
	}
	matched := ruleMatchesEvent(rule, conditions, event)
	confidence := ruleMatchConfidence(rule, conditions, event, matched)
	return RuleTestResult{Matched: matched, Action: rule.Action, Algorithm: rule.Algorithm, Confidence: confidence}
}

type ruleCondition struct {
	field    string
	operator string
	value    string
	regex    *regexp.Regexp
}

var ruleConditionPattern = regexp.MustCompile(`^\s*([a-zA-Z0-9_.-]+)\s*(==|!=|contains|matches)\s*(.+?)\s*$`)

func compileRuleExpression(expression string) ([]ruleCondition, error) {
	trimmed := strings.TrimSpace(expression)
	if trimmed == "" {
		return nil, errors.New("is required")
	}
	if strings.Contains(strings.ToLower(strings.ReplaceAll(trimmed, " ", "")), "while(true)") {
		return nil, errors.New("contains a forbidden endless loop")
	}
	parts := strings.Split(trimmed, "&&")
	conditions := make([]ruleCondition, 0, len(parts))
	for _, part := range parts {
		condition, err := compileRuleCondition(part)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, condition)
	}
	return conditions, nil
}

func compileRuleCondition(input string) (ruleCondition, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ruleCondition{}, errors.New("contains an empty condition")
	}
	matches := ruleConditionPattern.FindStringSubmatch(trimmed)
	if matches == nil {
		return ruleCondition{field: "any", operator: "contains", value: unquoteRuleValue(trimmed)}, nil
	}
	value := unquoteRuleValue(matches[3])
	if value == "" {
		return ruleCondition{}, errors.New("condition value is required")
	}
	condition := ruleCondition{
		field:    strings.ToLower(matches[1]),
		operator: strings.ToLower(matches[2]),
		value:    value,
	}
	if !isSupportedRuleField(condition.field) {
		return ruleCondition{}, fmt.Errorf("field %q is not supported", condition.field)
	}
	if condition.operator == "matches" {
		regex, err := regexp.Compile(value)
		if err != nil {
			return ruleCondition{}, fmt.Errorf("regex is invalid: %v", err)
		}
		condition.regex = regex
	}
	return condition, nil
}

func ruleMatchesEvent(rule Rule, conditions []ruleCondition, event SecurityEvent) bool {
	if rule.Hook != "" && event.Hook != "" && !strings.EqualFold(rule.Hook, event.Hook) {
		return false
	}
	for _, condition := range conditions {
		if !condition.matches(event) {
			return false
		}
	}
	return true
}

func (c ruleCondition) matches(event SecurityEvent) bool {
	values := ruleEventValues(event, c.field)
	switch c.operator {
	case "==":
		return anyString(values, func(value string) bool { return strings.EqualFold(value, c.value) })
	case "!=":
		return !anyString(values, func(value string) bool { return strings.EqualFold(value, c.value) })
	case "matches":
		return anyString(values, func(value string) bool { return c.regex.MatchString(value) })
	default:
		needle := strings.ToLower(c.value)
		return anyString(values, func(value string) bool { return strings.Contains(strings.ToLower(value), needle) })
	}
}

func ruleEventValues(event SecurityEvent, field string) []string {
	switch field {
	case "any":
		values := []string{event.Message, event.Hook, event.Algorithm, event.Severity}
		for key, value := range event.Attributes {
			values = append(values, key, fmt.Sprint(value))
		}
		return values
	case "message", "event.message":
		return []string{event.Message}
	case "hook", "event.hook":
		return []string{event.Hook}
	case "algorithm", "event.algorithm":
		return []string{event.Algorithm}
	case "severity", "event.severity":
		return []string{event.Severity}
	default:
		key := strings.TrimPrefix(field, "attributes.")
		key = strings.TrimPrefix(key, "event.attributes.")
		if value, ok := event.Attributes[key]; ok {
			return []string{fmt.Sprint(value)}
		}
		return nil
	}
}

func ruleMatchConfidence(rule Rule, conditions []ruleCondition, event SecurityEvent, matched bool) int {
	if !matched {
		return 0
	}
	if rule.Algorithm != "" && event.Algorithm != "" && strings.EqualFold(rule.Algorithm, event.Algorithm) {
		return 95
	}
	for _, condition := range conditions {
		if condition.operator == "==" || condition.operator == "matches" {
			return 90
		}
	}
	return 80
}

func unquoteRuleValue(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"'`)
}

func anyString(values []string, match func(string) bool) bool {
	for _, value := range values {
		if match(value) {
			return true
		}
	}
	return false
}

func isSupportedRuleField(field string) bool {
	if strings.HasPrefix(field, "attributes.") || strings.HasPrefix(field, "event.attributes.") {
		return true
	}
	return contains([]string{"any", "message", "event.message", "hook", "event.hook", "algorithm", "event.algorithm", "severity", "event.severity"}, field)
}

func isSupportedPolicyHook(hook string) bool {
	_, ok := supportedPolicyAlgorithms[strings.ToLower(strings.TrimSpace(hook))]
	return ok
}

func isSupportedPolicyAlgorithm(hook string, algorithm string) bool {
	normalizedHook := strings.ToLower(strings.TrimSpace(hook))
	normalizedAlgorithm := strings.ToLower(strings.TrimSpace(algorithm))
	if normalizedAlgorithm == "" {
		return true
	}
	if normalizedAlgorithm == normalizedHook+"_match" {
		return true
	}
	return supportedPolicyAlgorithms[normalizedHook][normalizedAlgorithm]
}

var supportedPolicyAlgorithms = map[string]map[string]bool{
	"command":         {"command_common": true, "command_dnslog": true, "command_error": true, "command_reflect": true, "command_userinput": true},
	"deletefile":      {"deletefile_userinput": true},
	"deserialization": {"deserialization_blacklist": true},
	"directory":       {"directory_reflect": true, "directory_unwanted": true, "directory_userinput": true},
	"dns":             {"dns_blacklist": true},
	"eval":            {"eval_regex": true},
	"fileupload":      {"fileupload_multipart_exe": true, "fileupload_multipart_html": true, "fileupload_multipart_script": true},
	"include":         {"include_protocol": true, "include_userinput": true},
	"jndi":            {"jndi_disable_all": true},
	"link":            {"link_webshell": true},
	"loadlibrary":     {"loadlibrary_unc": true},
	"ognl":            {"ognl_blacklist": true, "ognl_length_limit": true},
	"process":         {"process_match": true},
	"readfile":        {"readfile_outsidewebroot": true, "readfile_unwanted": true, "readfile_userinput": true, "readfile_userinput_http": true, "readfile_userinput_unwanted": true},
	"rename":          {"rename_webshell": true},
	"request":         {"request_scanner": true, "request_unusual": true, "xss_userinput": true},
	"response":        {"response_dataleak": true, "xss_echo": true},
	"sql":             {"sql_policy": true, "sql_regex": true, "sql_userinput": true},
	"sql_exception":   {"sql_exception": true},
	"ssrf":            {"ssrf_aws": true, "ssrf_common": true, "ssrf_obfuscate": true, "ssrf_protocol": true, "ssrf_userinput": true},
	"webdav":          {"fileupload_webdav": true},
	"webshell":        {"webshell_callable": true, "webshell_command": true, "webshell_eval": true, "webshell_file_put_contents": true, "webshell_ld_preload": true},
	"writefile":       {"writefile_ntfs": true, "writefile_reflect": true, "writefile_script": true},
	"xxe":             {"xxe_file": true, "xxe_protocol": true},
}

func SupportedPolicyAlgorithmCatalog() PolicyAlgorithmCatalog {
	hooks := make([]string, 0, len(supportedPolicyAlgorithms))
	for hook := range supportedPolicyAlgorithms {
		hooks = append(hooks, hook)
	}
	sort.Strings(hooks)
	items := make([]PolicyAlgorithm, 0, len(hooks))
	for _, hook := range hooks {
		algorithms := make([]string, 0, len(supportedPolicyAlgorithms[hook]))
		for algorithm := range supportedPolicyAlgorithms[hook] {
			algorithms = append(algorithms, algorithm)
		}
		sort.Strings(algorithms)
		items = append(items, PolicyAlgorithm{Hook: hook, Algorithms: algorithms})
	}
	return PolicyAlgorithmCatalog{Items: items}
}

func DefaultPolicyRules() []Rule {
	catalog := SupportedPolicyAlgorithmCatalog()
	rules := make([]Rule, 0)
	for _, item := range catalog.Items {
		for _, algorithm := range item.Algorithms {
			rules = append(rules, Rule{
				Name:        defaultPolicyRuleName(algorithm),
				Hook:        item.Hook,
				Algorithm:   algorithm,
				Action:      "block",
				Severity:    defaultPolicySeverity(item.Hook),
				Expression:  fmt.Sprintf(`algorithm == "%s"`, algorithm),
				Tags:        []string{"default", item.Hook},
				Description: "Built-in default detector rule restored from the algorithm catalog.",
			})
		}
	}
	return rules
}

func defaultPolicyRuleName(algorithm string) string {
	name := strings.ReplaceAll(algorithm, "_", " ")
	return "Default " + name
}

func defaultPolicySeverity(hook string) string {
	switch hook {
	case "jndi", "sql", "command", "deserialization", "webshell", "xxe":
		return "critical"
	case "ssrf", "fileupload", "include", "writefile", "loadlibrary", "eval", "ognl":
		return "high"
	case "request", "response", "readfile", "directory", "dns", "rename", "link", "deletefile":
		return "medium"
	default:
		return "high"
	}
}

func (s *MemoryStore) RolloutPolicy(_ context.Context, actorID string, policyID string, rollout PolicyRollout) (PolicySet, error) {
	if rollout.CanaryPercent < 0 || rollout.CanaryPercent > 100 {
		return PolicySet{}, fmt.Errorf("%w: canary percent must be between 0 and 100", ErrInvalid)
	}
	targetStatus := "active"
	if rollout.CanaryPercent < 100 {
		targetStatus = "canary"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.policies[policyID]
	if !ok {
		return PolicySet{}, ErrNotFound
	}
	if err := s.validatePolicyRolloutScope(&rollout); err != nil {
		return PolicySet{}, err
	}
	for i := range policy.Versions {
		if policy.Versions[i].Version == rollout.Version {
			for j := range policy.Versions {
				if j != i && (policy.Versions[j].Status == "active" || policy.Versions[j].Status == "canary") {
					policy.Versions[j].Status = "rolled_back"
				}
			}
			policy.Versions[i].Status = targetStatus
			policy.Versions[i].CanaryPercent = rollout.CanaryPercent
			policy.Versions[i].PublishedAt = s.now()
			active := policy.Versions[i]
			policy.Active = &active
			s.policies[policyID] = policy
			s.setPolicyAssignmentDefault(policyID, rollout)
			for id, agent := range s.agents {
				if !policyRolloutMatchesAgent(agent, rollout) {
					continue
				}
				agent.PolicyID = policyID
				agent.PolicyVersion = rollout.Version
				s.agents[id] = agent
			}
			s.audit(actorID, "policy.rollout", policyID, policyRolloutAuditDetails(rollout))
			return policy, nil
		}
	}
	return PolicySet{}, ErrNotFound
}

func (s *MemoryStore) validatePolicyRolloutScope(rollout *PolicyRollout) error {
	if rollout.EnvironmentID != "" {
		env, ok := s.environments[rollout.EnvironmentID]
		if !ok {
			return ErrNotFound
		}
		if rollout.ApplicationID != "" && rollout.ApplicationID != env.ApplicationID {
			return fmt.Errorf("%w: rollout environment does not belong to application", ErrInvalid)
		}
		rollout.ApplicationID = env.ApplicationID
	}
	if rollout.ApplicationID != "" {
		if _, ok := s.applications[rollout.ApplicationID]; !ok {
			return ErrNotFound
		}
	}
	return nil
}

func (s *MemoryStore) setPolicyAssignmentDefault(policyID string, rollout PolicyRollout) {
	if rollout.EnvironmentID != "" {
		env := s.environments[rollout.EnvironmentID]
		env.PolicyID = policyID
		env.PolicyVersion = rollout.Version
		s.environments[rollout.EnvironmentID] = env
		return
	}
	if rollout.ApplicationID != "" {
		app := s.applications[rollout.ApplicationID]
		app.PolicyID = policyID
		app.PolicyVersion = rollout.Version
		s.applications[rollout.ApplicationID] = app
		return
	}
	s.organization.PolicyID = policyID
	s.organization.PolicyVersion = rollout.Version
}

func policyRolloutMatchesAgent(agent Agent, rollout PolicyRollout) bool {
	if rollout.EnvironmentID != "" {
		return agent.EnvironmentID == rollout.EnvironmentID
	}
	if rollout.ApplicationID != "" {
		return agent.ApplicationID == rollout.ApplicationID
	}
	return true
}

func policyRolloutAuditDetails(rollout PolicyRollout) map[string]any {
	details := map[string]any{"version": rollout.Version, "canary_percent": rollout.CanaryPercent}
	if rollout.ApplicationID != "" {
		details["application_id"] = rollout.ApplicationID
	}
	if rollout.EnvironmentID != "" {
		details["environment_id"] = rollout.EnvironmentID
	}
	return details
}

func (s *MemoryStore) RollbackPolicy(_ context.Context, actorID string, policyID string) (PolicySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.policies[policyID]
	if !ok {
		return PolicySet{}, ErrNotFound
	}
	if policy.Active == nil || len(policy.Versions) == 0 {
		return PolicySet{}, ErrNotFound
	}
	targetIndex := -1
	for i := len(policy.Versions) - 1; i >= 0; i-- {
		if policy.Versions[i].Version < policy.Active.Version {
			targetIndex = i
			break
		}
	}
	if targetIndex == -1 {
		return PolicySet{}, ErrNotFound
	}
	for i := range policy.Versions {
		if policy.Versions[i].Status == "active" || policy.Versions[i].Status == "canary" {
			policy.Versions[i].Status = "rolled_back"
		}
	}
	policy.Versions[targetIndex].Status = "active"
	policy.Versions[targetIndex].CanaryPercent = 100
	policy.Versions[targetIndex].PublishedAt = s.now()
	active := policy.Versions[targetIndex]
	policy.Active = &active
	s.policies[policyID] = policy
	for id, app := range s.applications {
		if app.PolicyID == policyID {
			app.PolicyVersion = active.Version
			s.applications[id] = app
		}
	}
	for id, env := range s.environments {
		if env.PolicyID == policyID {
			env.PolicyVersion = active.Version
			s.environments[id] = env
		}
	}
	if s.organization.PolicyID == policyID {
		s.organization.PolicyVersion = active.Version
	}
	for id, agent := range s.agents {
		agent.PolicyID = policyID
		agent.PolicyVersion = active.Version
		s.agents[id] = agent
	}
	s.audit(actorID, "policy.rollback", policyID, map[string]any{"version": active.Version})
	return policy, nil
}

func (s *MemoryStore) IngestEvent(_ context.Context, event SecurityEvent) (SecurityEvent, error) {
	if event.Type == "" {
		return SecurityEvent{}, fmt.Errorf("%w: event type is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event.ID = newID("evt")
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now()
	}
	s.events[event.ID] = event
	for _, rule := range s.alertRules {
		if MatchAlertRule(rule, event) {
			delivery := NewAlertDelivery(rule, event, s.now())
			delivery.ID = newID("adl")
			s.alertDeliveries[delivery.ID] = delivery
		}
	}
	s.audit(actorIDForAgent(event.AgentID), "event.ingest", event.ID, map[string]any{
		"application_id": event.ApplicationID,
		"environment_id": event.EnvironmentID,
		"severity":       event.Severity,
		"type":           event.Type,
	})
	return event, nil
}

func (s *MemoryStore) IngestDependency(_ context.Context, dep Dependency) (Dependency, error) {
	dep = NormalizeDependency(dep)
	if dep.Name == "" {
		return Dependency{}, fmt.Errorf("%w: dependency name is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dep.ID = newID("dep")
	if dep.ObservedAt.IsZero() {
		dep.ObservedAt = s.now()
	}
	s.dependencies[dep.ID] = dep
	s.audit(actorIDForAgent(dep.AgentID), "dependency.ingest", dep.ID, map[string]any{
		"application_id": dep.ApplicationID,
		"ecosystem":      dep.Ecosystem,
		"package_path":   dep.PackagePath,
		"name":           dep.Name,
		"version":        dep.Version,
	})
	return dep, nil
}

func (s *MemoryStore) IngestBaselineFinding(_ context.Context, finding BaselineFinding) (BaselineFinding, error) {
	finding = NormalizeBaselineFinding(finding)
	if finding.CheckID == "" || finding.Title == "" || finding.ApplicationID == "" || finding.EnvironmentID == "" || finding.AgentID == "" {
		return BaselineFinding{}, fmt.Errorf("%w: baseline finding scope, check, and title are required", ErrInvalid)
	}
	if !contains([]string{"critical", "high", "medium", "low", "info"}, finding.Severity) {
		return BaselineFinding{}, fmt.Errorf("%w: unsupported baseline severity", ErrInvalid)
	}
	if !contains([]string{"failed", "warning", "passed", "suppressed"}, finding.Status) {
		return BaselineFinding{}, fmt.Errorf("%w: unsupported baseline status", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	finding.ID = newID("bsl")
	if finding.ObservedAt.IsZero() {
		finding.ObservedAt = s.now()
	}
	s.baselineFindings[finding.ID] = finding
	s.audit(actorIDForAgent(finding.AgentID), "baseline.ingest", finding.ID, map[string]any{
		"application_id": finding.ApplicationID,
		"environment_id": finding.EnvironmentID,
		"agent_id":       finding.AgentID,
		"check_id":       finding.CheckID,
		"severity":       finding.Severity,
		"status":         finding.Status,
	})
	return finding, nil
}

func (s *MemoryStore) ListEvents(_ context.Context, query SecurityEventQuery) ([]SecurityEvent, error) {
	query = NormalizeSecurityEventQuery(query)
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := make([]SecurityEvent, 0, len(s.events))
	for _, event := range s.events {
		if query.DeletedOnly && event.DeletedAt == nil {
			continue
		}
		if !query.DeletedOnly && !query.IncludeDeleted && event.DeletedAt != nil {
			continue
		}
		if SecurityEventMatchesQuery(event, query) {
			events = append(events, event)
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].OccurredAt.After(events[j].OccurredAt) })
	if len(events) > query.Limit {
		events = events[:query.Limit]
	}
	return events, nil
}

func (s *MemoryStore) SoftDeleteEvents(_ context.Context, actorID string, request EventRecycleBinRequest) (EventRecycleBinReport, error) {
	ids, err := NormalizeEventRecycleBinIDs(request.IDs)
	if err != nil {
		return EventRecycleBinReport{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	deletedAt := s.now()
	changed := make([]string, 0, len(ids))
	for _, id := range ids {
		event, ok := s.events[id]
		if !ok || event.DeletedAt != nil {
			continue
		}
		event.DeletedAt = &deletedAt
		event.DeletedBy = actorID
		s.events[id] = event
		changed = append(changed, id)
	}
	if len(changed) > 0 {
		s.audit(actorID, "event.recycle.delete", "events", map[string]any{"ids": changed, "count": len(changed)})
	}
	return EventRecycleBinReport{IDs: changed, Count: len(changed)}, nil
}

func (s *MemoryStore) RestoreDeletedEvents(_ context.Context, actorID string, request EventRecycleBinRequest) (EventRecycleBinReport, error) {
	ids, err := NormalizeEventRecycleBinIDs(request.IDs)
	if err != nil {
		return EventRecycleBinReport{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := make([]string, 0, len(ids))
	for _, id := range ids {
		event, ok := s.events[id]
		if !ok || event.DeletedAt == nil {
			continue
		}
		event.DeletedAt = nil
		event.DeletedBy = ""
		s.events[id] = event
		changed = append(changed, id)
	}
	if len(changed) > 0 {
		s.audit(actorID, "event.recycle.restore", "events", map[string]any{"ids": changed, "count": len(changed)})
	}
	return EventRecycleBinReport{IDs: changed, Count: len(changed)}, nil
}

func (s *MemoryStore) PurgeDeletedEvents(_ context.Context, actorID string, request EventRecycleBinRequest) (EventRecycleBinReport, error) {
	ids, err := NormalizeEventRecycleBinIDs(request.IDs)
	if err != nil {
		return EventRecycleBinReport{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := make([]string, 0, len(ids))
	for _, id := range ids {
		event, ok := s.events[id]
		if !ok || event.DeletedAt == nil {
			continue
		}
		delete(s.events, id)
		for deliveryID, delivery := range s.alertDeliveries {
			if delivery.EventID == id {
				delete(s.alertDeliveries, deliveryID)
			}
		}
		changed = append(changed, id)
	}
	if len(changed) > 0 {
		s.audit(actorID, "event.recycle.purge", "events", map[string]any{"ids": changed, "count": len(changed)})
	}
	return EventRecycleBinReport{IDs: changed, Count: len(changed)}, nil
}

func NormalizeSecurityEventQuery(query SecurityEventQuery) SecurityEventQuery {
	if query.Limit <= 0 {
		query.Limit = 500
	}
	if query.Limit > 1000 {
		query.Limit = 1000
	}
	return query
}

func NormalizeEventRecycleBinIDs(ids []string) ([]string, error) {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("%w: event id is required", ErrInvalid)
	}
	if len(normalized) > 1000 {
		return nil, fmt.Errorf("%w: too many event ids", ErrInvalid)
	}
	return normalized, nil
}

func SecurityEventMatchesQuery(event SecurityEvent, query SecurityEventQuery) bool {
	if query.Type != "" && event.Type != query.Type {
		return false
	}
	if query.ApplicationID != "" && event.ApplicationID != query.ApplicationID {
		return false
	}
	if query.EnvironmentID != "" && event.EnvironmentID != query.EnvironmentID {
		return false
	}
	if query.AgentID != "" && event.AgentID != query.AgentID {
		return false
	}
	if query.PolicyID != "" && event.PolicyID != query.PolicyID {
		return false
	}
	if query.Severity != "" && event.Severity != query.Severity {
		return false
	}
	if query.Hook != "" && event.Hook != query.Hook {
		return false
	}
	if !query.OccurredAfter.IsZero() && event.OccurredAt.Before(query.OccurredAfter) {
		return false
	}
	if !query.OccurredBefore.IsZero() && event.OccurredAt.After(query.OccurredBefore) {
		return false
	}
	return true
}

func (s *MemoryStore) ListDependencies(_ context.Context, query DependencyQuery) ([]Dependency, error) {
	query = NormalizeDependencyQuery(query)
	s.mu.RLock()
	defer s.mu.RUnlock()
	dependencies := make([]Dependency, 0, len(s.dependencies))
	for _, dep := range s.dependencies {
		if DependencyMatchesQuery(dep, query) {
			dependencies = append(dependencies, dep)
		}
	}
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].ObservedAt.After(dependencies[j].ObservedAt) })
	if len(dependencies) > query.Limit {
		dependencies = dependencies[:query.Limit]
	}
	return dependencies, nil
}

func (s *MemoryStore) DependencySummary(_ context.Context) (DependencySummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	summary := DependencySummary{
		DependenciesByEcosystem:   map[string]int{},
		VulnerabilitiesBySeverity: map[string]int{},
	}
	for _, dep := range s.dependencies {
		summary.DependencyCount++
		incrementIfPresent(summary.DependenciesByEcosystem, dep.Ecosystem)
		if len(dep.Vulnerabilities) > 0 {
			summary.VulnerableDependencyCount++
		}
		for _, vulnerability := range dep.Vulnerabilities {
			incrementIfPresent(summary.VulnerabilitiesBySeverity, vulnerability.Severity)
			if vulnerability.KnownExploited {
				summary.KnownExploitedCount++
			}
		}
	}
	return summary, nil
}

func NormalizeDependencyQuery(query DependencyQuery) DependencyQuery {
	query.VulnerabilitySeverity = strings.ToLower(strings.TrimSpace(query.VulnerabilitySeverity))
	if query.Limit <= 0 {
		query.Limit = 500
	}
	if query.Limit > 1000 {
		query.Limit = 1000
	}
	return query
}

func DependencyMatchesQuery(dep Dependency, query DependencyQuery) bool {
	if query.ApplicationID != "" && dep.ApplicationID != query.ApplicationID {
		return false
	}
	if query.AgentID != "" && dep.AgentID != query.AgentID {
		return false
	}
	if query.Name != "" && dep.Name != query.Name {
		return false
	}
	if query.Ecosystem != "" && dep.Ecosystem != query.Ecosystem {
		return false
	}
	if query.VulnerabilitySeverity != "" && !DependencyHasVulnerabilitySeverity(dep, query.VulnerabilitySeverity) {
		return false
	}
	if !query.ObservedAfter.IsZero() && dep.ObservedAt.Before(query.ObservedAfter) {
		return false
	}
	if !query.ObservedBefore.IsZero() && dep.ObservedAt.After(query.ObservedBefore) {
		return false
	}
	return true
}

func (s *MemoryStore) ListBaselineFindings(_ context.Context, query BaselineFindingQuery) ([]BaselineFinding, error) {
	query = NormalizeBaselineFindingQuery(query)
	s.mu.RLock()
	defer s.mu.RUnlock()
	findings := make([]BaselineFinding, 0, len(s.baselineFindings))
	for _, finding := range s.baselineFindings {
		if BaselineFindingMatchesQuery(finding, query) {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ObservedAt.After(findings[j].ObservedAt) })
	if len(findings) > query.Limit {
		findings = findings[:query.Limit]
	}
	return findings, nil
}

func NormalizeDependency(dep Dependency) Dependency {
	dep.ApplicationID = strings.TrimSpace(dep.ApplicationID)
	dep.AgentID = strings.TrimSpace(dep.AgentID)
	dep.Name = strings.TrimSpace(dep.Name)
	dep.Version = strings.TrimSpace(dep.Version)
	dep.Ecosystem = strings.ToLower(strings.TrimSpace(dep.Ecosystem))
	dep.PackagePath = strings.TrimSpace(dep.PackagePath)
	dep.Licenses = normalizeStringList(dep.Licenses)
	dep.Vulnerabilities = normalizeDependencyVulnerabilities(dep.Vulnerabilities)
	return dep
}

func DependencyHasVulnerabilitySeverity(dep Dependency, severity string) bool {
	severity = strings.ToLower(strings.TrimSpace(severity))
	if severity == "" {
		return true
	}
	for _, vulnerability := range dep.Vulnerabilities {
		if strings.ToLower(strings.TrimSpace(vulnerability.Severity)) == severity {
			return true
		}
	}
	return false
}

func NormalizeBaselineFinding(finding BaselineFinding) BaselineFinding {
	finding.ApplicationID = strings.TrimSpace(finding.ApplicationID)
	finding.EnvironmentID = strings.TrimSpace(finding.EnvironmentID)
	finding.AgentID = strings.TrimSpace(finding.AgentID)
	finding.CheckID = strings.TrimSpace(finding.CheckID)
	finding.Title = strings.TrimSpace(finding.Title)
	finding.Category = strings.ToLower(strings.TrimSpace(finding.Category))
	if finding.Category == "" {
		finding.Category = "runtime"
	}
	finding.Severity = strings.ToLower(strings.TrimSpace(finding.Severity))
	finding.Status = strings.ToLower(strings.TrimSpace(finding.Status))
	finding.Resource = strings.TrimSpace(finding.Resource)
	finding.Remediation = strings.TrimSpace(finding.Remediation)
	if finding.Attributes == nil {
		finding.Attributes = map[string]any{}
	}
	return finding
}

func NormalizeBaselineFindingQuery(query BaselineFindingQuery) BaselineFindingQuery {
	query.Severity = strings.ToLower(strings.TrimSpace(query.Severity))
	query.Status = strings.ToLower(strings.TrimSpace(query.Status))
	query.Category = strings.ToLower(strings.TrimSpace(query.Category))
	if query.Limit <= 0 {
		query.Limit = 500
	}
	if query.Limit > 1000 {
		query.Limit = 1000
	}
	return query
}

func BaselineFindingMatchesQuery(finding BaselineFinding, query BaselineFindingQuery) bool {
	if query.ApplicationID != "" && finding.ApplicationID != query.ApplicationID {
		return false
	}
	if query.EnvironmentID != "" && finding.EnvironmentID != query.EnvironmentID {
		return false
	}
	if query.AgentID != "" && finding.AgentID != query.AgentID {
		return false
	}
	if query.Severity != "" && finding.Severity != query.Severity {
		return false
	}
	if query.Status != "" && finding.Status != query.Status {
		return false
	}
	if query.Category != "" && finding.Category != query.Category {
		return false
	}
	if !query.ObservedAfter.IsZero() && finding.ObservedAt.Before(query.ObservedAfter) {
		return false
	}
	if !query.ObservedBefore.IsZero() && finding.ObservedAt.After(query.ObservedBefore) {
		return false
	}
	return true
}

func normalizeDependencyVulnerabilities(vulnerabilities []DependencyVulnerability) []DependencyVulnerability {
	if len(vulnerabilities) == 0 {
		return nil
	}
	result := make([]DependencyVulnerability, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		vulnerability.ID = strings.TrimSpace(vulnerability.ID)
		vulnerability.Severity = strings.ToLower(strings.TrimSpace(vulnerability.Severity))
		vulnerability.FixedVersion = strings.TrimSpace(vulnerability.FixedVersion)
		if vulnerability.ID == "" && vulnerability.Severity == "" {
			continue
		}
		result = append(result, vulnerability)
	}
	return result
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func (s *MemoryStore) Overview(_ context.Context) (Overview, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	overview := Overview{
		ApplicationCount:   len(s.applications),
		AgentCount:         len(s.agents),
		EventsByType:       map[string]int{},
		EventsBySeverity:   map[string]int{},
		AttacksByHook:      map[string]int{},
		AttacksByAlgorithm: map[string]int{},
		AttacksByUserAgent: map[string]int{},
	}
	for _, agent := range s.agents {
		if agent.Status == "online" {
			overview.OnlineAgents++
		}
	}
	attackBuckets := map[time.Time]int{}
	for _, event := range s.events {
		if event.DeletedAt != nil {
			continue
		}
		overview.EventCount++
		overview.EventsByType[event.Type]++
		overview.EventsBySeverity[event.Severity]++
		switch event.Type {
		case "attack":
			bucket := dayBucket(event.OccurredAt)
			attackBuckets[bucket]++
			incrementIfPresent(overview.AttacksByHook, event.Hook)
			incrementIfPresent(overview.AttacksByAlgorithm, event.Algorithm)
			overview.AttacksByUserAgent[userAgentFromAttributes(event.Attributes)]++
		case "crash":
			overview.CrashCount++
		}
	}
	overview.AttackTrend = trendPointsFromBuckets(attackBuckets)
	return overview, nil
}

func dayBucket(value time.Time) time.Time {
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}

func trendPointsFromBuckets(buckets map[time.Time]int) []TrendPoint {
	points := make([]TrendPoint, 0, len(buckets))
	for bucket, count := range buckets {
		points = append(points, TrendPoint{BucketStart: bucket, Count: count})
	}
	sort.Slice(points, func(i, j int) bool {
		return points[i].BucketStart.Before(points[j].BucketStart)
	})
	return points
}

func incrementIfPresent(target map[string]int, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	target[value]++
}

func userAgentFromAttributes(attributes map[string]any) string {
	for _, key := range []string{"user_agent", "userAgent", "User-Agent", "user-agent"} {
		if value := stringAttribute(attributes, key); value != "" {
			return value
		}
	}
	for _, key := range []string{"request", "headers"} {
		if nested, ok := attributes[key].(map[string]any); ok {
			if value := userAgentFromAttributes(nested); value != "" && value != "unknown" {
				return value
			}
		}
	}
	return "unknown"
}

func stringAttribute(attributes map[string]any, key string) string {
	if attributes == nil {
		return ""
	}
	value, ok := attributes[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func (s *MemoryStore) Observability(_ context.Context, query ObservabilityQuery) (ObservabilityReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	report := ObservabilityReport{
		RuleOverhead:      []RuleOverhead{},
		HookLatency:       []HookLatency{},
		AgentOverhead:     []AgentOverhead{},
		PolicyPerformance: []PolicyPerformance{},
	}
	hooks := map[string]*latencyAccumulator{}
	agents := map[string]*performanceAccumulator{}
	policies := map[string]*performanceAccumulator{}
	for _, event := range s.events {
		if event.DeletedAt != nil || !observabilityEventMatches(event, query) {
			continue
		}
		if event.Hook != "" {
			latency := intAttribute(event.Attributes, "latency_us")
			acc := hooks[event.Hook]
			if acc == nil {
				acc = &latencyAccumulator{}
				hooks[event.Hook] = acc
			}
			acc.add(latency)
		}
		if event.Type != "performance" {
			continue
		}
		if event.AgentID != "" {
			acc := agents[event.AgentID]
			if acc == nil {
				acc = &performanceAccumulator{}
				agents[event.AgentID] = acc
			}
			acc.add(event)
		}
		if event.PolicyID != "" {
			key := fmt.Sprintf("%s:%d", event.PolicyID, event.PolicyVersion)
			acc := policies[key]
			if acc == nil {
				acc = &performanceAccumulator{policyID: event.PolicyID, policyVersion: event.PolicyVersion}
				policies[key] = acc
			}
			acc.add(event)
		}
	}
	for hook, acc := range hooks {
		report.HookLatency = append(report.HookLatency, HookLatency{
			Hook:             hook,
			Calls:            acc.count,
			AverageLatencyUS: acc.average(),
			P95LatencyUS:     acc.p95(),
			MaxLatencyUS:     acc.max,
		})
	}
	for agentID, acc := range agents {
		report.AgentOverhead = append(report.AgentOverhead, AgentOverhead{
			AgentID:             agentID,
			Samples:             acc.samples,
			CPUOverheadPCT:      acc.averageCPU(),
			MemoryOverheadBytes: acc.averageMemory(),
			HookLatencyP95US:    acc.hookLatency.p95(),
			RuleEvalP95US:       acc.ruleEval.p95(),
		})
	}
	for _, acc := range policies {
		report.PolicyPerformance = append(report.PolicyPerformance, PolicyPerformance{
			PolicyID:         acc.policyID,
			PolicyVersion:    acc.policyVersion,
			Samples:          acc.samples,
			CPUOverheadPCT:   acc.averageCPU(),
			HookLatencyP95US: acc.hookLatency.p95(),
			RuleEvalP95US:    acc.ruleEval.p95(),
		})
	}
	sort.Slice(report.HookLatency, func(i, j int) bool { return report.HookLatency[i].P95LatencyUS > report.HookLatency[j].P95LatencyUS })
	sort.Slice(report.AgentOverhead, func(i, j int) bool {
		return report.AgentOverhead[i].HookLatencyP95US > report.AgentOverhead[j].HookLatencyP95US
	})
	sort.Slice(report.PolicyPerformance, func(i, j int) bool {
		return report.PolicyPerformance[i].HookLatencyP95US > report.PolicyPerformance[j].HookLatencyP95US
	})
	return report, nil
}

type latencyAccumulator struct {
	count  int
	total  int
	max    int
	values []int
}

func (a *latencyAccumulator) add(value int) {
	if value < 0 {
		value = 0
	}
	a.count++
	a.total += value
	if value > a.max {
		a.max = value
	}
	a.values = append(a.values, value)
}

func (a *latencyAccumulator) average() float64 {
	if a.count == 0 {
		return 0
	}
	return float64(a.total) / float64(a.count)
}

func (a *latencyAccumulator) p95() int {
	if len(a.values) == 0 {
		return 0
	}
	values := append([]int(nil), a.values...)
	sort.Ints(values)
	index := int(float64(len(values)-1) * 0.95)
	return values[index]
}

type performanceAccumulator struct {
	policyID      string
	policyVersion int
	samples       int
	cpuTotal      float64
	memoryTotal   int64
	hookLatency   latencyAccumulator
	ruleEval      latencyAccumulator
}

func (a *performanceAccumulator) add(event SecurityEvent) {
	a.samples++
	a.cpuTotal += floatAttribute(event.Attributes, "cpu_overhead_pct")
	a.memoryTotal += int64Attribute(event.Attributes, "memory_overhead_bytes")
	a.hookLatency.add(intAttribute(event.Attributes, "hook_latency_p95_us"))
	a.ruleEval.add(intAttribute(event.Attributes, "rule_eval_p95_us"))
}

func (a *performanceAccumulator) averageCPU() float64 {
	if a.samples == 0 {
		return 0
	}
	return a.cpuTotal / float64(a.samples)
}

func (a *performanceAccumulator) averageMemory() int64 {
	if a.samples == 0 {
		return 0
	}
	return a.memoryTotal / int64(a.samples)
}

func observabilityEventMatches(event SecurityEvent, query ObservabilityQuery) bool {
	if query.ApplicationID != "" && event.ApplicationID != query.ApplicationID {
		return false
	}
	if query.PolicyID != "" && event.PolicyID != query.PolicyID {
		return false
	}
	return true
}

func intAttribute(attributes map[string]any, key string) int {
	value := int64Attribute(attributes, key)
	if value > int64(^uint(0)>>1) {
		return int(^uint(0) >> 1)
	}
	return int(value)
}

func int64Attribute(attributes map[string]any, key string) int64 {
	switch value := attributes[key].(type) {
	case int:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	case float32:
		return int64(value)
	case json.Number:
		parsed, _ := strconv.ParseInt(string(value), 10, 64)
		return parsed
	default:
		return 0
	}
}

func floatAttribute(attributes map[string]any, key string) float64 {
	switch value := attributes[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case json.Number:
		parsed, _ := strconv.ParseFloat(string(value), 64)
		return parsed
	default:
		return 0
	}
}

func (s *MemoryStore) ListSystemSettings(_ context.Context) ([]SystemSetting, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	settings := make([]SystemSetting, 0, len(s.settings))
	for _, setting := range s.settings {
		settings = append(settings, setting)
	}
	sort.Slice(settings, func(i, j int) bool { return settings[i].Key < settings[j].Key })
	return settings, nil
}

func (s *MemoryStore) UpsertSystemSetting(_ context.Context, actorID string, setting SystemSetting) (SystemSetting, error) {
	key := normalizeSettingKey(setting.Key)
	if key == "" {
		return SystemSetting{}, fmt.Errorf("%w: setting key is required", ErrInvalid)
	}
	if setting.Value == nil {
		return SystemSetting{}, fmt.Errorf("%w: setting value is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	setting.Key = key
	setting.UpdatedBy = actorID
	setting.UpdatedAt = s.now()
	s.settings[key] = setting
	s.audit(actorID, "system_settings.upsert", key, map[string]any{"key": key})
	return setting, nil
}

func (s *MemoryStore) MaintenanceCleanup(_ context.Context, actorID string, request MaintenanceCleanupRequest) (MaintenanceCleanupReport, error) {
	request, err := NormalizeMaintenanceCleanupRequest(request)
	if err != nil {
		return MaintenanceCleanupReport{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	report := MaintenanceCleanupReport{
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
			"clickhouse_rollups":       0,
		},
	}
	if request.IncludeEvents {
		for id, event := range s.events {
			if event.OccurredAt.Before(request.Before) && cleanupApplicationMatches(request.ApplicationID, event.ApplicationID) {
				report.Counts["events"]++
				if !request.DryRun {
					delete(s.events, id)
				}
			}
		}
	}
	if request.IncludeDependencies {
		for id, dep := range s.dependencies {
			if dep.ObservedAt.Before(request.Before) && cleanupApplicationMatches(request.ApplicationID, dep.ApplicationID) {
				report.Counts["dependencies"]++
				if !request.DryRun {
					delete(s.dependencies, id)
				}
			}
		}
	}
	if request.IncludeBaselineFindings {
		for id, finding := range s.baselineFindings {
			if finding.ObservedAt.Before(request.Before) && cleanupApplicationMatches(request.ApplicationID, finding.ApplicationID) {
				report.Counts["baseline_findings"]++
				if !request.DryRun {
					delete(s.baselineFindings, id)
				}
			}
		}
	}
	if request.IncludeAlertDeliveries {
		for id, delivery := range s.alertDeliveries {
			if delivery.CreatedAt.Before(request.Before) {
				report.Counts["alert_deliveries"]++
				if !request.DryRun {
					delete(s.alertDeliveries, id)
				}
			}
		}
	}
	if !request.DryRun {
		s.audit(actorID, "maintenance.cleanup", "operational-data", map[string]any{
			"application_id": request.ApplicationID,
			"before":         request.Before.Format(time.RFC3339),
			"counts":         report.Counts,
		})
	}
	return report, nil
}

func (s *MemoryStore) ListAlertRules(_ context.Context) ([]AlertRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]AlertRule, 0, len(s.alertRules))
	for _, rule := range s.alertRules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules, nil
}

func (s *MemoryStore) CreateAlertRule(_ context.Context, actorID string, input AlertRule) (AlertRule, error) {
	rule, err := PrepareAlertRule(input, s.now())
	if err != nil {
		return AlertRule{}, err
	}
	rule.ID = newID("alr")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertRules[rule.ID] = rule
	s.audit(actorID, "alert_rule.create", rule.ID, map[string]any{"name": rule.Name})
	return rule, nil
}

func (s *MemoryStore) UpdateAlertRule(_ context.Context, actorID string, alertRuleID string, input AlertRule) (AlertRule, error) {
	rule, err := PrepareAlertRule(input, s.now())
	if err != nil {
		return AlertRule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.alertRules[alertRuleID]
	if !ok {
		return AlertRule{}, ErrNotFound
	}
	rule.ID = alertRuleID
	rule.CreatedAt = current.CreatedAt
	s.alertRules[alertRuleID] = rule
	s.audit(actorID, "alert_rule.update", alertRuleID, map[string]any{"name": rule.Name, "enabled": rule.Enabled})
	return rule, nil
}

func (s *MemoryStore) ListAlertDeliveries(_ context.Context) ([]AlertDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	deliveries := make([]AlertDelivery, 0, len(s.alertDeliveries))
	for _, delivery := range s.alertDeliveries {
		deliveries = append(deliveries, delivery)
	}
	sort.Slice(deliveries, func(i, j int) bool { return deliveries[i].CreatedAt.After(deliveries[j].CreatedAt) })
	return deliveries, nil
}

func (s *MemoryStore) ListAuditLogs(_ context.Context) ([]AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	logs := append([]AuditLog(nil), s.auditLogs...)
	sort.Slice(logs, func(i, j int) bool { return logs[i].CreatedAt.After(logs[j].CreatedAt) })
	return logs, nil
}

func (s *MemoryStore) RecordAuditLog(_ context.Context, actorID string, action string, resource string, details map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit(actorID, action, resource, details)
	return nil
}

func (s *MemoryStore) audit(actorID string, action string, resource string, details map[string]any) {
	s.auditLogs = append(s.auditLogs, AuditLog{
		ID:        newID("aud"),
		ActorID:   actorID,
		Action:    action,
		Resource:  resource,
		Details:   details,
		CreatedAt: s.now(),
	})
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func DefaultSystemSettings(now time.Time) []SystemSetting {
	return []SystemSetting{
		{Key: "server.public_url", Value: map[string]any{"url": ""}, UpdatedBy: "system", UpdatedAt: now},
		{Key: "agent.minimum_version", Value: map[string]any{"version": "1.0.0", "enforcement": "warn"}, UpdatedBy: "system", UpdatedAt: now},
		{Key: "alerts.delivery", Value: map[string]any{"interval_seconds": 300}, UpdatedBy: "system", UpdatedAt: now},
		{Key: "events.retention", Value: map[string]any{"attack_days": 180, "performance_days": 30, "dependency_days": 365, "audit_days": 365}, UpdatedBy: "system", UpdatedAt: now},
		{Key: "policy.canary", Value: map[string]any{"default_percent": 25, "auto_promote": false}, UpdatedBy: "system", UpdatedAt: now},
		{Key: "protection.allowlist", Value: map[string]any{"enabled": false, "mode": "monitor", "entries": []string{}}, UpdatedBy: "system", UpdatedAt: now},
		{Key: "protection.hardening", Value: map[string]any{"mode": "monitor", "block_reflection_abuse": true, "block_process_execution": true}, UpdatedBy: "system", UpdatedAt: now},
		{Key: "dependency.vulnerability_policy", Value: map[string]any{"fail_on_severity": "critical", "block_known_exploited": true}, UpdatedBy: "system", UpdatedAt: now},
	}
}

func NormalizeMaintenanceCleanupRequest(request MaintenanceCleanupRequest) (MaintenanceCleanupRequest, error) {
	request.ApplicationID = strings.TrimSpace(request.ApplicationID)
	request.Confirmation = strings.TrimSpace(request.Confirmation)
	if request.Before.IsZero() {
		return MaintenanceCleanupRequest{}, fmt.Errorf("%w: cleanup cutoff is required", ErrInvalid)
	}
	request.Before = request.Before.UTC()
	if !request.DryRun && request.Confirmation != "CLEAR_OPERATIONAL_DATA" {
		return MaintenanceCleanupRequest{}, fmt.Errorf("%w: destructive cleanup requires confirmation", ErrInvalid)
	}
	if !request.IncludeEvents && !request.IncludeDependencies && !request.IncludeBaselineFindings && !request.IncludeAlertDeliveries {
		return MaintenanceCleanupRequest{}, fmt.Errorf("%w: cleanup requires at least one data class", ErrInvalid)
	}
	return request, nil
}

func cleanupApplicationMatches(scope string, applicationID string) bool {
	return scope == "" || scope == applicationID
}

func DefaultAlertRules(now time.Time) []AlertRule {
	return []AlertRule{
		{
			ID:          "alr_critical_attack",
			Name:        "Critical attack event",
			Description: "Notify security owners when critical attack events are ingested.",
			Enabled:     true,
			EventType:   "attack",
			Severity:    "critical",
			Condition:   "severity == critical",
			Target:      "security-operations",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "alr_agent_crash",
			Name:        "Agent crash",
			Description: "Open an operational alert when an Agent crash is reported.",
			Enabled:     true,
			EventType:   "crash",
			Severity:    "high",
			Condition:   "event_type == crash",
			Target:      "platform-operations",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
}

func normalizeSettingKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func PrepareUser(input User, password string, now time.Time) (User, string, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Name = strings.TrimSpace(input.Name)
	password = strings.TrimSpace(password)
	if input.Email == "" || !strings.Contains(input.Email, "@") {
		return User{}, "", fmt.Errorf("%w: user email is required", ErrInvalid)
	}
	if input.Name == "" {
		return User{}, "", fmt.Errorf("%w: user name is required", ErrInvalid)
	}
	if len(password) < 8 {
		return User{}, "", fmt.Errorf("%w: user password must be at least 8 characters", ErrInvalid)
	}
	roles, err := NormalizeUserRoles(input.Roles)
	if err != nil {
		return User{}, "", err
	}
	input.Roles = roles
	input.CreatedAt = now
	input.UpdatedAt = now
	return input, password, nil
}

func PrepareUserUpdate(input User, now time.Time) (User, error) {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return User{}, fmt.Errorf("%w: user name is required", ErrInvalid)
	}
	roles, err := NormalizeUserRoles(input.Roles)
	if err != nil {
		return User{}, err
	}
	input.Roles = roles
	if input.DisabledAt != nil {
		disabledAt := now
		input.DisabledAt = &disabledAt
	}
	input.UpdatedAt = now
	return input, nil
}

func NormalizeUserRoles(roles []Role) ([]Role, error) {
	if len(roles) == 0 {
		return nil, fmt.Errorf("%w: at least one user role is required", ErrInvalid)
	}
	seen := map[Role]bool{}
	for _, role := range roles {
		role = Role(strings.ToLower(strings.TrimSpace(string(role))))
		if !validHumanRole(role) {
			return nil, fmt.Errorf("%w: user role is not supported", ErrInvalid)
		}
		seen[role] = true
	}
	ordered := make([]Role, 0, len(seen))
	for _, role := range []Role{RoleAdmin, RoleSecurityEngineer, RoleViewer} {
		if seen[role] {
			ordered = append(ordered, role)
		}
	}
	return ordered, nil
}

func NormalizeUserQuery(input UserQuery) (UserQuery, error) {
	input.Search = strings.ToLower(strings.TrimSpace(input.Search))
	input.Role = strings.ToLower(strings.TrimSpace(input.Role))
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	if input.Role != "" && !contains([]string{"admin", "security_engineer", "viewer"}, input.Role) {
		return UserQuery{}, fmt.Errorf("%w: user role filter is not supported", ErrInvalid)
	}
	if input.Status != "" && !contains([]string{"active", "disabled"}, input.Status) {
		return UserQuery{}, fmt.Errorf("%w: user status filter is not supported", ErrInvalid)
	}
	return input, nil
}

func firstUserQuery(queries []UserQuery) (UserQuery, error) {
	if len(queries) == 0 {
		return NormalizeUserQuery(UserQuery{})
	}
	return NormalizeUserQuery(queries[0])
}

func userMatchesQuery(user User, query UserQuery) bool {
	if query.Search != "" {
		haystack := strings.ToLower(strings.Join([]string{user.ID, user.Email, user.Name}, " "))
		if !strings.Contains(haystack, query.Search) {
			return false
		}
	}
	if query.Role != "" && !hasRole(user.Roles, Role(query.Role)) {
		return false
	}
	if query.Status == "active" && user.DisabledAt != nil {
		return false
	}
	if query.Status == "disabled" && user.DisabledAt == nil {
		return false
	}
	return true
}

func validHumanRole(role Role) bool {
	return role == RoleAdmin || role == RoleSecurityEngineer || role == RoleViewer
}

func hasRole(roles []Role, role Role) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func publicUser(user User) User {
	user.PasswordHash = ""
	return user
}

func rolesAsStrings(roles []Role) []string {
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		out = append(out, string(role))
	}
	return out
}

func actorIDForAgent(agentID string) string {
	if strings.TrimSpace(agentID) == "" {
		return "collector"
	}
	return agentID
}

func PrepareAlertRule(input AlertRule, now time.Time) (AlertRule, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.EventType = strings.ToLower(strings.TrimSpace(input.EventType))
	input.Severity = strings.ToLower(strings.TrimSpace(input.Severity))
	input.Condition = strings.TrimSpace(input.Condition)
	input.Target = strings.TrimSpace(input.Target)
	if input.Name == "" {
		return AlertRule{}, fmt.Errorf("%w: alert rule name is required", ErrInvalid)
	}
	if input.EventType == "" {
		return AlertRule{}, fmt.Errorf("%w: alert rule event type is required", ErrInvalid)
	}
	if !contains([]string{"attack", "hook", "performance", "crash", "error", "dependency"}, input.EventType) {
		return AlertRule{}, fmt.Errorf("%w: alert rule event type is not supported", ErrInvalid)
	}
	if input.Severity == "" {
		input.Severity = "high"
	}
	if !contains([]string{"critical", "high", "medium", "low"}, input.Severity) {
		return AlertRule{}, fmt.Errorf("%w: alert rule severity is not supported", ErrInvalid)
	}
	if input.Condition == "" {
		input.Condition = "true"
	}
	if input.Target == "" {
		return AlertRule{}, fmt.Errorf("%w: alert rule target is required", ErrInvalid)
	}
	if input.CreatedAt.IsZero() {
		input.CreatedAt = now
	}
	input.UpdatedAt = now
	return input, nil
}

func MatchAlertRule(rule AlertRule, event SecurityEvent) bool {
	if !rule.Enabled || rule.EventType != event.Type {
		return false
	}
	condition := strings.ToLower(strings.TrimSpace(rule.Condition))
	if condition == "" || condition == "true" {
		return true
	}
	parts := strings.Split(condition, "==")
	if len(parts) != 2 {
		return false
	}
	left := strings.TrimSpace(parts[0])
	right := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
	switch left {
	case "severity", "event.severity":
		return strings.EqualFold(event.Severity, right)
	case "event_type", "type", "event.type":
		return strings.EqualFold(event.Type, right)
	case "hook", "event.hook":
		return strings.EqualFold(event.Hook, right)
	case "algorithm", "event.algorithm":
		return strings.EqualFold(event.Algorithm, right)
	default:
		return false
	}
}

func NewAlertDelivery(rule AlertRule, event SecurityEvent, now time.Time) AlertDelivery {
	return AlertDelivery{
		AlertRuleID:   rule.ID,
		AlertRuleName: rule.Name,
		EventID:       event.ID,
		EventType:     event.Type,
		Severity:      rule.Severity,
		Target:        rule.Target,
		Status:        "queued",
		Attempts:      0,
		CreatedAt:     now,
	}
}

func prepareDaemonWorkload(nodeName string, input DaemonWorkloadInput, now time.Time) (DaemonWorkload, error) {
	if strings.TrimSpace(nodeName) == "" {
		return DaemonWorkload{}, fmt.Errorf("%w: daemon node name is required", ErrInvalid)
	}
	workloadType := strings.ToLower(strings.TrimSpace(input.Type))
	input.Type = workloadType
	if workloadType != "process" && workloadType != "container" {
		return DaemonWorkload{}, fmt.Errorf("%w: daemon workload type must be process or container", ErrInvalid)
	}
	if workloadType == "process" && input.PID == 0 && len(input.Cmdline) == 0 {
		return DaemonWorkload{}, fmt.Errorf("%w: process workload requires pid or cmdline", ErrInvalid)
	}
	if workloadType == "container" && strings.TrimSpace(input.ContainerID) == "" && strings.TrimSpace(input.ContainerName) == "" {
		return DaemonWorkload{}, fmt.Errorf("%w: container workload requires container id or name", ErrInvalid)
	}
	return PrepareDaemonWorkload(nodeName, input, now), nil
}

func NormalizeAgentIDs(ids []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

func newID(prefix string) string {
	return NewID(prefix)
}

func NewID(prefix string) string {
	return prefix + "_" + newSecret()[:16]
}

func newSecret() string {
	return NewSecret()
}

func NewSecret() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes[:])
}
