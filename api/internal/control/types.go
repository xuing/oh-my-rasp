package control

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

type Role string

const (
	RoleAdmin            Role = "admin"
	RoleSecurityEngineer Role = "security_engineer"
	RoleViewer           Role = "viewer"
	RoleAgent            Role = "agent"
)

type Organization struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	PolicyID      string `json:"policy_id,omitempty"`
	PolicyVersion int    `json:"policy_version,omitempty"`
}

type User struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	PasswordHash string     `json:"-"`
	Roles        []Role     `json:"roles"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DisabledAt   *time.Time `json:"disabled_at,omitempty"`
}

type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Application struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Secret         string    `json:"secret,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	PolicyID       string    `json:"policy_id,omitempty"`
	PolicyVersion  int       `json:"policy_version,omitempty"`
	EnvironmentIDs []string  `json:"environment_ids"`
}

type Environment struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	CreatedAt     time.Time `json:"created_at"`
	PolicyID      string    `json:"policy_id,omitempty"`
	PolicyVersion int       `json:"policy_version,omitempty"`
}

type Agent struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	EnvironmentID string    `json:"environment_id"`
	Hostname      string    `json:"hostname"`
	Alias         string    `json:"alias,omitempty"`
	Runtime       string    `json:"runtime"`
	Version       string    `json:"version"`
	Status        string    `json:"status"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	PolicyID      string    `json:"policy_id,omitempty"`
	PolicyVersion int       `json:"policy_version,omitempty"`
	IgnoredAt     time.Time `json:"ignored_at,omitempty"`
}

type AgentBatchOperationReport struct {
	IDs   []string `json:"ids"`
	Count int      `json:"count"`
}

type DaemonAccessToken struct {
	AccessToken string    `json:"access_token"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type DaemonWorkload struct {
	ID                       string    `json:"id"`
	ApplicationID            string    `json:"application_id,omitempty"`
	NodeName                 string    `json:"node_name"`
	Type                     string    `json:"type"`
	PID                      int       `json:"pid,omitempty"`
	Cmdline                  []string  `json:"cmdline,omitempty"`
	ContainerID              string    `json:"container_id,omitempty"`
	ContainerName            string    `json:"container_name,omitempty"`
	ImageID                  string    `json:"image_id,omitempty"`
	ImageTag                 string    `json:"image_tag,omitempty"`
	InjectionStatus          string    `json:"injection_status,omitempty"`
	InjectionError           string    `json:"injection_error,omitempty"`
	InjectionHelperID        string    `json:"injection_helper_id,omitempty"`
	InjectionHelperVersion   string    `json:"injection_helper_version,omitempty"`
	InjectionReportedAt      time.Time `json:"injection_reported_at,omitempty"`
	InjectionStatusUpdatedAt time.Time `json:"injection_status_updated_at,omitempty"`
	ObservedAt               time.Time `json:"observed_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type DaemonWorkloadInput struct {
	Type          string    `json:"type"`
	PID           int       `json:"pid,omitempty"`
	Cmdline       []string  `json:"cmdline,omitempty"`
	ContainerID   string    `json:"container_id,omitempty"`
	ContainerName string    `json:"container_name,omitempty"`
	ImageID       string    `json:"image_id,omitempty"`
	ImageTag      string    `json:"image_tag,omitempty"`
	ObservedAt    time.Time `json:"observed_at,omitempty"`
}

type DaemonWorkloadReport struct {
	NodeName  string                `json:"node_name"`
	Workloads []DaemonWorkloadInput `json:"workloads"`
}

type DaemonWorkloadBinding struct {
	ApplicationID string `json:"application_id"`
}

type DaemonInjectionReport struct {
	WorkloadID    string    `json:"workload_id"`
	Status        string    `json:"status"`
	Error         string    `json:"error,omitempty"`
	HelperID      string    `json:"helper_id,omitempty"`
	HelperVersion string    `json:"helper_version,omitempty"`
	ReportedAt    time.Time `json:"reported_at,omitempty"`
}

type DaemonCommandGroup struct {
	ApplicationID     string           `json:"application_id"`
	ApplicationSecret string           `json:"application_secret"`
	Language          string           `json:"language"`
	Workloads         []DaemonWorkload `json:"workloads"`
}

type DaemonApplication struct {
	ApplicationID     string `json:"application_id"`
	ApplicationSecret string `json:"application_secret"`
	Language          string `json:"language"`
}

func PrepareDaemonWorkload(nodeName string, input DaemonWorkloadInput, now time.Time) DaemonWorkload {
	nodeName = strings.TrimSpace(nodeName)
	workloadType := strings.ToLower(strings.TrimSpace(input.Type))
	observedAt := input.ObservedAt
	if observedAt.IsZero() {
		observedAt = now
	}
	workload := DaemonWorkload{
		NodeName:      nodeName,
		Type:          workloadType,
		PID:           input.PID,
		Cmdline:       append([]string{}, input.Cmdline...),
		ContainerID:   strings.TrimSpace(input.ContainerID),
		ContainerName: strings.TrimSpace(input.ContainerName),
		ImageID:       strings.TrimSpace(input.ImageID),
		ImageTag:      strings.TrimSpace(input.ImageTag),
		ObservedAt:    observedAt.UTC(),
		UpdatedAt:     now.UTC(),
	}
	workload.ID = DaemonWorkloadID(workload)
	return workload
}

func PrepareAndValidateDaemonWorkload(nodeName string, input DaemonWorkloadInput, now time.Time) (DaemonWorkload, error) {
	if strings.TrimSpace(nodeName) == "" {
		return DaemonWorkload{}, ErrInvalid
	}
	workloadType := strings.ToLower(strings.TrimSpace(input.Type))
	input.Type = workloadType
	if workloadType != "process" && workloadType != "container" {
		return DaemonWorkload{}, ErrInvalid
	}
	if workloadType == "process" && input.PID == 0 && len(input.Cmdline) == 0 {
		return DaemonWorkload{}, ErrInvalid
	}
	if workloadType == "container" && strings.TrimSpace(input.ContainerID) == "" && strings.TrimSpace(input.ContainerName) == "" {
		return DaemonWorkload{}, ErrInvalid
	}
	return PrepareDaemonWorkload(nodeName, input, now), nil
}

func PrepareDaemonInjectionReport(input DaemonInjectionReport, now time.Time) (DaemonInjectionReport, error) {
	input.WorkloadID = strings.TrimSpace(input.WorkloadID)
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.Error = strings.TrimSpace(input.Error)
	input.HelperID = strings.TrimSpace(input.HelperID)
	input.HelperVersion = strings.TrimSpace(input.HelperVersion)
	if input.ReportedAt.IsZero() {
		input.ReportedAt = now
	}
	input.ReportedAt = input.ReportedAt.UTC()
	if input.WorkloadID == "" {
		return DaemonInjectionReport{}, ErrInvalid
	}
	switch input.Status {
	case "injected", "failed", "uninstalled":
	default:
		return DaemonInjectionReport{}, ErrInvalid
	}
	if input.Status == "failed" && input.Error == "" {
		return DaemonInjectionReport{}, ErrInvalid
	}
	return input, nil
}

func DaemonWorkloadID(workload DaemonWorkload) string {
	identity := workload.NodeName + "|" + workload.Type
	switch workload.Type {
	case "process":
		if workload.PID != 0 {
			identity += "|pid:" + strconv.Itoa(workload.PID)
		} else {
			identity += "|cmd:" + strings.Join(workload.Cmdline, "\x00")
		}
	case "container":
		if workload.ContainerID != "" {
			identity += "|container:" + workload.ContainerID
		} else {
			identity += "|container-name:" + workload.ContainerName + "|" + workload.ImageTag
		}
	default:
		identity += "|unknown:" + strings.Join(workload.Cmdline, "\x00") + "|" + workload.ContainerID + "|" + workload.ContainerName
	}
	sum := sha256.Sum256([]byte(identity))
	return "wrk_" + hex.EncodeToString(sum[:])[:16]
}

type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Hook        string   `json:"hook"`
	Algorithm   string   `json:"algorithm"`
	Action      string   `json:"action"`
	Severity    string   `json:"severity"`
	Expression  string   `json:"expression"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
}

type PolicySet struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	CreatedAt   time.Time       `json:"created_at"`
	Active      *PolicyVersion  `json:"active,omitempty"`
	Versions    []PolicyVersion `json:"versions"`
}

type PolicyVersion struct {
	Version       int       `json:"version"`
	Status        string    `json:"status"`
	Rules         []Rule    `json:"rules"`
	CanaryPercent int       `json:"canary_percent"`
	CreatedAt     time.Time `json:"created_at"`
	PublishedAt   time.Time `json:"published_at,omitempty"`
}

type PolicyRollout struct {
	Version       int    `json:"version"`
	CanaryPercent int    `json:"canary_percent"`
	ApplicationID string `json:"application_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

type PolicyAlgorithm struct {
	Hook       string   `json:"hook"`
	Algorithms []string `json:"algorithms"`
}

type PolicyAlgorithmCatalog struct {
	Items []PolicyAlgorithm `json:"items"`
}

type SecurityEvent struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	ApplicationID string         `json:"application_id"`
	EnvironmentID string         `json:"environment_id"`
	AgentID       string         `json:"agent_id"`
	PolicyID      string         `json:"policy_id,omitempty"`
	PolicyVersion int            `json:"policy_version,omitempty"`
	Hook          string         `json:"hook,omitempty"`
	Algorithm     string         `json:"algorithm,omitempty"`
	Severity      string         `json:"severity"`
	Message       string         `json:"message"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Attributes    map[string]any `json:"attributes,omitempty"`
	DeletedAt     *time.Time     `json:"deleted_at,omitempty"`
	DeletedBy     string         `json:"deleted_by,omitempty"`
}

type SecurityEventQuery struct {
	Type           string    `json:"type,omitempty"`
	ApplicationID  string    `json:"application_id,omitempty"`
	EnvironmentID  string    `json:"environment_id,omitempty"`
	AgentID        string    `json:"agent_id,omitempty"`
	PolicyID       string    `json:"policy_id,omitempty"`
	Severity       string    `json:"severity,omitempty"`
	Hook           string    `json:"hook,omitempty"`
	OccurredAfter  time.Time `json:"occurred_after,omitempty"`
	OccurredBefore time.Time `json:"occurred_before,omitempty"`
	Limit          int       `json:"limit,omitempty"`
	DeletedOnly    bool      `json:"deleted_only,omitempty"`
	IncludeDeleted bool      `json:"include_deleted,omitempty"`
}

type EventRecycleBinRequest struct {
	IDs []string `json:"ids"`
}

type EventRecycleBinReport struct {
	IDs   []string `json:"ids"`
	Count int      `json:"count"`
}

type Dependency struct {
	ID              string                    `json:"id"`
	ApplicationID   string                    `json:"application_id"`
	AgentID         string                    `json:"agent_id"`
	Name            string                    `json:"name"`
	Version         string                    `json:"version"`
	Ecosystem       string                    `json:"ecosystem"`
	PackagePath     string                    `json:"package_path,omitempty"`
	Licenses        []string                  `json:"licenses,omitempty"`
	Vulnerabilities []DependencyVulnerability `json:"vulnerabilities,omitempty"`
	ObservedAt      time.Time                 `json:"observed_at"`
}

type DependencyVulnerability struct {
	ID             string  `json:"id"`
	Severity       string  `json:"severity"`
	CVSS           float64 `json:"cvss,omitempty"`
	KnownExploited bool    `json:"known_exploited,omitempty"`
	FixedVersion   string  `json:"fixed_version,omitempty"`
}

type DependencyQuery struct {
	ApplicationID         string    `json:"application_id,omitempty"`
	AgentID               string    `json:"agent_id,omitempty"`
	Name                  string    `json:"name,omitempty"`
	Ecosystem             string    `json:"ecosystem,omitempty"`
	VulnerabilitySeverity string    `json:"vulnerability_severity,omitempty"`
	ObservedAfter         time.Time `json:"observed_after,omitempty"`
	ObservedBefore        time.Time `json:"observed_before,omitempty"`
	Limit                 int       `json:"limit,omitempty"`
}

type DependencySummary struct {
	DependencyCount           int            `json:"dependency_count"`
	VulnerableDependencyCount int            `json:"vulnerable_dependency_count"`
	KnownExploitedCount       int            `json:"known_exploited_count"`
	DependenciesByEcosystem   map[string]int `json:"dependencies_by_ecosystem"`
	VulnerabilitiesBySeverity map[string]int `json:"vulnerabilities_by_severity"`
}

type BaselineFinding struct {
	ID            string         `json:"id"`
	ApplicationID string         `json:"application_id"`
	EnvironmentID string         `json:"environment_id"`
	AgentID       string         `json:"agent_id"`
	CheckID       string         `json:"check_id"`
	Title         string         `json:"title"`
	Category      string         `json:"category"`
	Severity      string         `json:"severity"`
	Status        string         `json:"status"`
	Resource      string         `json:"resource"`
	Remediation   string         `json:"remediation,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
	ObservedAt    time.Time      `json:"observed_at"`
}

type BaselineFindingQuery struct {
	ApplicationID  string    `json:"application_id,omitempty"`
	EnvironmentID  string    `json:"environment_id,omitempty"`
	AgentID        string    `json:"agent_id,omitempty"`
	Severity       string    `json:"severity,omitempty"`
	Status         string    `json:"status,omitempty"`
	Category       string    `json:"category,omitempty"`
	ObservedAfter  time.Time `json:"observed_after,omitempty"`
	ObservedBefore time.Time `json:"observed_before,omitempty"`
	Limit          int       `json:"limit,omitempty"`
}

type AuditLog struct {
	ID        string         `json:"id"`
	ActorID   string         `json:"actor_id"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Details   map[string]any `json:"details,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type SystemSetting struct {
	Key       string         `json:"key"`
	Value     map[string]any `json:"value"`
	UpdatedBy string         `json:"updated_by,omitempty"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type MaintenanceCleanupRequest struct {
	ApplicationID           string    `json:"application_id,omitempty"`
	Before                  time.Time `json:"before"`
	DryRun                  bool      `json:"dry_run"`
	IncludeEvents           bool      `json:"include_events"`
	IncludeDependencies     bool      `json:"include_dependencies"`
	IncludeBaselineFindings bool      `json:"include_baseline_findings"`
	IncludeAlertDeliveries  bool      `json:"include_alert_deliveries"`
	Confirmation            string    `json:"confirmation,omitempty"`
}

type MaintenanceCleanupReport struct {
	ApplicationID string         `json:"application_id,omitempty"`
	Before        time.Time      `json:"before"`
	DryRun        bool           `json:"dry_run"`
	Counts        map[string]int `json:"counts"`
}

type AlertRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	EventType   string    `json:"event_type"`
	Severity    string    `json:"severity"`
	Condition   string    `json:"condition"`
	Target      string    `json:"target"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AlertDelivery struct {
	ID            string     `json:"id"`
	AlertRuleID   string     `json:"alert_rule_id"`
	AlertRuleName string     `json:"alert_rule_name"`
	EventID       string     `json:"event_id"`
	EventType     string     `json:"event_type"`
	Severity      string     `json:"severity"`
	Target        string     `json:"target"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	LastError     string     `json:"last_error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}

type Overview struct {
	ApplicationCount   int            `json:"application_count"`
	AgentCount         int            `json:"agent_count"`
	OnlineAgents       int            `json:"online_agents"`
	EventCount         int            `json:"event_count"`
	EventsByType       map[string]int `json:"events_by_type"`
	EventsBySeverity   map[string]int `json:"events_by_severity"`
	AttackTrend        []TrendPoint   `json:"attack_trend"`
	AttacksByHook      map[string]int `json:"attacks_by_hook"`
	AttacksByAlgorithm map[string]int `json:"attacks_by_algorithm"`
	AttacksByUserAgent map[string]int `json:"attacks_by_user_agent"`
	CrashCount         int            `json:"crash_count"`
}

type EventOverview struct {
	EventCount       int            `json:"event_count"`
	EventsByType     map[string]int `json:"events_by_type"`
	EventsBySeverity map[string]int `json:"events_by_severity"`
}

type TrendPoint struct {
	BucketStart time.Time `json:"bucket_start"`
	Count       int       `json:"count"`
}

type RateLimitDecision struct {
	Allowed    bool          `json:"allowed"`
	Limit      int64         `json:"limit"`
	Remaining  int64         `json:"remaining"`
	RetryAfter time.Duration `json:"retry_after"`
}

type ObservabilityQuery struct {
	ApplicationID string `json:"application_id,omitempty"`
	PolicyID      string `json:"policy_id,omitempty"`
}

type ObservabilityReport struct {
	RuleOverhead      []RuleOverhead      `json:"rule_overhead"`
	HookLatency       []HookLatency       `json:"hook_latency"`
	AgentOverhead     []AgentOverhead     `json:"agent_overhead"`
	PolicyPerformance []PolicyPerformance `json:"policy_performance"`
}

type RuleOverhead struct {
	PolicyID         string  `json:"policy_id"`
	PolicyVersion    int     `json:"policy_version"`
	RuleID           string  `json:"rule_id"`
	Hook             string  `json:"hook"`
	Executions       int     `json:"executions"`
	Blocked          int     `json:"blocked"`
	AverageLatencyUS float64 `json:"average_latency_us"`
	P95LatencyUS     int     `json:"p95_latency_us"`
	MaxLatencyUS     int     `json:"max_latency_us"`
}

type HookLatency struct {
	Hook             string  `json:"hook"`
	Calls            int     `json:"calls"`
	AverageLatencyUS float64 `json:"average_latency_us"`
	P95LatencyUS     int     `json:"p95_latency_us"`
	MaxLatencyUS     int     `json:"max_latency_us"`
}

type AgentOverhead struct {
	AgentID             string  `json:"agent_id"`
	Samples             int     `json:"samples"`
	CPUOverheadPCT      float64 `json:"cpu_overhead_pct"`
	MemoryOverheadBytes int64   `json:"memory_overhead_bytes"`
	HookLatencyP95US    int     `json:"hook_latency_p95_us"`
	RuleEvalP95US       int     `json:"rule_eval_p95_us"`
}

type PolicyPerformance struct {
	PolicyID         string  `json:"policy_id"`
	PolicyVersion    int     `json:"policy_version"`
	Samples          int     `json:"samples"`
	CPUOverheadPCT   float64 `json:"cpu_overhead_pct"`
	HookLatencyP95US int     `json:"hook_latency_p95_us"`
	RuleEvalP95US    int     `json:"rule_eval_p95_us"`
}

type RuleValidation struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
}

type RuleTestResult struct {
	Matched    bool   `json:"matched"`
	Action     string `json:"action"`
	Algorithm  string `json:"algorithm"`
	Confidence int    `json:"confidence"`
}
