package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/ohmyrasp/control-plane/internal/generated"
)

type Server struct {
	store            control.Store
	logger           *slog.Logger
	rateLimiter      RateLimiter
	rateLimit        int64
	rateLimitWindow  time.Duration
	metrics          *metricsRecorder
	agentArtifactDir string
}

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int64, window time.Duration) (control.RateLimitDecision, error)
}

func NewServer(store control.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{store: store, logger: logger, metrics: newMetricsRecorder()}
}

func (s *Server) WithRateLimiter(limiter RateLimiter, limit int64, window time.Duration) *Server {
	s.rateLimiter = limiter
	s.rateLimit = limit
	s.rateLimitWindow = window
	return s
}

func (s *Server) WithAgentArtifactDir(dir string) *Server {
	s.agentArtifactDir = strings.TrimSpace(dir)
	return s
}

type eventQueryParameterSet generated.GetApiV1EventsAttackParams
type dependencyQueryParameterSet generated.GetApiV1DependenciesParams
type baselineFindingQueryParameterSet generated.GetApiV1BaselineFindingsParams

func eventQueryParams(r *http.Request) (eventQueryParameterSet, error) {
	values := r.URL.Query()
	occurredAfter, err := eventTimeQueryParam(values.Get("occurred_after"), "occurred_after")
	if err != nil {
		return eventQueryParameterSet{}, err
	}
	occurredBefore, err := eventTimeQueryParam(values.Get("occurred_before"), "occurred_before")
	if err != nil {
		return eventQueryParameterSet{}, err
	}
	limit, err := eventLimitQueryParam(values.Get("limit"))
	if err != nil {
		return eventQueryParameterSet{}, err
	}
	return eventQueryParameterSet{
		ApplicationId:  optionalString(values.Get("application_id")),
		EnvironmentId:  optionalString(values.Get("environment_id")),
		AgentId:        optionalString(values.Get("agent_id")),
		PolicyId:       optionalString(values.Get("policy_id")),
		Severity:       optionalString(values.Get("severity")),
		Hook:           optionalString(values.Get("hook")),
		OccurredAfter:  occurredAfter,
		OccurredBefore: occurredBefore,
		Limit:          limit,
	}, nil
}

func dependencyQueryParams(r *http.Request) (dependencyQueryParameterSet, error) {
	values := r.URL.Query()
	observedAfter, err := eventTimeQueryParam(values.Get("observed_after"), "observed_after")
	if err != nil {
		return dependencyQueryParameterSet{}, err
	}
	observedBefore, err := eventTimeQueryParam(values.Get("observed_before"), "observed_before")
	if err != nil {
		return dependencyQueryParameterSet{}, err
	}
	limit, err := eventLimitQueryParam(values.Get("limit"))
	if err != nil {
		return dependencyQueryParameterSet{}, err
	}
	vulnerabilitySeverity, err := dependencyVulnerabilitySeverityQueryParam(values.Get("vulnerability_severity"))
	if err != nil {
		return dependencyQueryParameterSet{}, err
	}
	return dependencyQueryParameterSet{
		ApplicationId:         optionalString(values.Get("application_id")),
		AgentId:               optionalString(values.Get("agent_id")),
		Name:                  optionalString(values.Get("name")),
		Ecosystem:             optionalString(values.Get("ecosystem")),
		VulnerabilitySeverity: vulnerabilitySeverity,
		ObservedAfter:         observedAfter,
		ObservedBefore:        observedBefore,
		Limit:                 limit,
	}, nil
}

func baselineFindingQueryParams(r *http.Request) (baselineFindingQueryParameterSet, error) {
	values := r.URL.Query()
	observedAfter, err := eventTimeQueryParam(values.Get("observed_after"), "observed_after")
	if err != nil {
		return baselineFindingQueryParameterSet{}, err
	}
	observedBefore, err := eventTimeQueryParam(values.Get("observed_before"), "observed_before")
	if err != nil {
		return baselineFindingQueryParameterSet{}, err
	}
	limit, err := eventLimitQueryParam(values.Get("limit"))
	if err != nil {
		return baselineFindingQueryParameterSet{}, err
	}
	severity, err := baselineSeverityQueryParam(values.Get("severity"))
	if err != nil {
		return baselineFindingQueryParameterSet{}, err
	}
	status, err := baselineStatusQueryParam(values.Get("status"))
	if err != nil {
		return baselineFindingQueryParameterSet{}, err
	}
	return baselineFindingQueryParameterSet{
		ApplicationId:  optionalString(values.Get("application_id")),
		EnvironmentId:  optionalString(values.Get("environment_id")),
		AgentId:        optionalString(values.Get("agent_id")),
		Severity:       severity,
		Status:         status,
		Category:       optionalString(values.Get("category")),
		ObservedAfter:  observedAfter,
		ObservedBefore: observedBefore,
		Limit:          limit,
	}, nil
}

func eventRecycleBinQueryParams(r *http.Request) (generated.GetApiV1EventsRecycleBinParams, error) {
	values := r.URL.Query()
	occurredAfter, err := eventTimeQueryParam(values.Get("occurred_after"), "occurred_after")
	if err != nil {
		return generated.GetApiV1EventsRecycleBinParams{}, err
	}
	occurredBefore, err := eventTimeQueryParam(values.Get("occurred_before"), "occurred_before")
	if err != nil {
		return generated.GetApiV1EventsRecycleBinParams{}, err
	}
	limit, err := eventLimitQueryParam(values.Get("limit"))
	if err != nil {
		return generated.GetApiV1EventsRecycleBinParams{}, err
	}
	eventType, err := eventTypeQueryParam(values.Get("type"))
	if err != nil {
		return generated.GetApiV1EventsRecycleBinParams{}, err
	}
	return generated.GetApiV1EventsRecycleBinParams{
		Type:           eventType,
		ApplicationId:  optionalString(values.Get("application_id")),
		EnvironmentId:  optionalString(values.Get("environment_id")),
		AgentId:        optionalString(values.Get("agent_id")),
		PolicyId:       optionalString(values.Get("policy_id")),
		Severity:       optionalString(values.Get("severity")),
		Hook:           optionalString(values.Get("hook")),
		OccurredAfter:  occurredAfter,
		OccurredBefore: occurredBefore,
		Limit:          limit,
	}, nil
}

func eventTimeQueryParam(raw string, name string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s must be RFC3339", control.ErrInvalid, name)
	}
	return &value, nil
}

func eventLimitQueryParam(raw string) (*int, error) {
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 || value > 1000 {
		return nil, fmt.Errorf("%w: limit must be between 1 and 1000", control.ErrInvalid)
	}
	return &value, nil
}

func eventTypeQueryParam(raw string) (*generated.GetApiV1EventsRecycleBinParamsType, error) {
	if raw == "" {
		return nil, nil
	}
	value := generated.GetApiV1EventsRecycleBinParamsType(strings.ToLower(strings.TrimSpace(raw)))
	if !value.Valid() {
		return nil, fmt.Errorf("%w: type must be one of attack, hook, performance, crash", control.ErrInvalid)
	}
	return &value, nil
}

func dependencyVulnerabilitySeverityQueryParam(raw string) (*generated.GetApiV1DependenciesParamsVulnerabilitySeverity, error) {
	if raw == "" {
		return nil, nil
	}
	value := generated.GetApiV1DependenciesParamsVulnerabilitySeverity(strings.ToLower(strings.TrimSpace(raw)))
	if !value.Valid() {
		return nil, fmt.Errorf("%w: vulnerability_severity must be one of critical, high, medium, low", control.ErrInvalid)
	}
	return &value, nil
}

func baselineSeverityQueryParam(raw string) (*generated.GetApiV1BaselineFindingsParamsSeverity, error) {
	if raw == "" {
		return nil, nil
	}
	value := generated.GetApiV1BaselineFindingsParamsSeverity(strings.ToLower(strings.TrimSpace(raw)))
	if !value.Valid() {
		return nil, fmt.Errorf("%w: severity must be one of critical, high, medium, low, info", control.ErrInvalid)
	}
	return &value, nil
}

func baselineStatusQueryParam(raw string) (*generated.GetApiV1BaselineFindingsParamsStatus, error) {
	if raw == "" {
		return nil, nil
	}
	value := generated.GetApiV1BaselineFindingsParamsStatus(strings.ToLower(strings.TrimSpace(raw)))
	if !value.Valid() {
		return nil, fmt.Errorf("%w: status must be one of failed, warning, passed, suppressed", control.ErrInvalid)
	}
	return &value, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func (s *Server) Routes() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(s.logRequests)
	router.Use(s.limitRequests)
	router.Use(middleware.Recoverer)

	strict := s.openAPIStrictHandler()

	router.Get("/healthz", strict.GetHealthz)
	router.Get("/readyz", strict.GetReadyz)
	router.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(s.metrics.render(r.Context(), s.store, time.Now)))
	})
	router.Get("/v1/service/app/get", s.legacyDaemonApplication)
	router.Get("/v1/service/command", s.legacyDaemonCommandWebsocket)
	router.Get("/v1/service/dl/agent/info", s.legacyDaemonArtifactInfo)
	router.Get("/v1/service/dl/agent", s.daemonArtifactDownload)

	router.Route("/api/v1", func(api chi.Router) {
		api.Post("/auth/login", strict.PostApiV1AuthLogin)

		api.Group(func(private chi.Router) {
			private.Use(s.requireAuthenticatedUser)
			private.With(s.requirePermission(permissionReadProfile)).Get("/me", strict.GetApiV1Me)
			private.With(s.requirePermission(permissionReadApplications)).Get("/applications", strict.GetApiV1Applications)
			private.With(s.requirePermission(permissionReadAgents)).Get("/agents", strict.GetApiV1Agents)
			private.With(s.requirePermission(permissionReadDaemon)).Get("/agent-artifacts", strict.GetApiV1AgentArtifacts)
			private.With(s.requirePermission(permissionManageDaemon)).Post("/agent-artifacts", strict.PostApiV1AgentArtifacts)
			private.With(s.requirePermission(permissionManageDaemon)).Get("/daemon/token", strict.GetApiV1DaemonToken)
			private.With(s.requirePermission(permissionManageDaemon)).Post("/daemon/token/reset", strict.PostApiV1DaemonTokenReset)
			private.With(s.requirePermission(permissionReadDaemon)).Get("/daemon/workloads", strict.GetApiV1DaemonWorkloads)
			private.With(s.requirePermission(permissionReadPolicies)).Get("/policies", strict.GetApiV1Policies)
			private.With(s.requirePermission(permissionReadEvents)).Get("/events/attack", func(w http.ResponseWriter, r *http.Request) {
				params, err := eventQueryParams(r)
				if err != nil {
					writeError(w, err)
					return
				}
				strict.GetApiV1EventsAttack(w, r, generated.GetApiV1EventsAttackParams(params))
			})
			private.With(s.requirePermission(permissionReadEvents)).Get("/events/hook", func(w http.ResponseWriter, r *http.Request) {
				params, err := eventQueryParams(r)
				if err != nil {
					writeError(w, err)
					return
				}
				strict.GetApiV1EventsHook(w, r, generated.GetApiV1EventsHookParams(params))
			})
			private.With(s.requirePermission(permissionReadEvents)).Get("/events/performance", func(w http.ResponseWriter, r *http.Request) {
				params, err := eventQueryParams(r)
				if err != nil {
					writeError(w, err)
					return
				}
				strict.GetApiV1EventsPerformance(w, r, generated.GetApiV1EventsPerformanceParams(params))
			})
			private.With(s.requirePermission(permissionReadEvents)).Get("/events/crash", func(w http.ResponseWriter, r *http.Request) {
				params, err := eventQueryParams(r)
				if err != nil {
					writeError(w, err)
					return
				}
				strict.GetApiV1EventsCrash(w, r, generated.GetApiV1EventsCrashParams(params))
			})
			private.With(s.requirePermission(permissionReadEvents)).Get("/events/recycle-bin", func(w http.ResponseWriter, r *http.Request) {
				params, err := eventRecycleBinQueryParams(r)
				if err != nil {
					writeError(w, err)
					return
				}
				strict.GetApiV1EventsRecycleBin(w, r, params)
			})
			private.With(s.requirePermission(permissionReadEvents)).Get("/dependencies", func(w http.ResponseWriter, r *http.Request) {
				params, err := dependencyQueryParams(r)
				if err != nil {
					writeError(w, err)
					return
				}
				strict.GetApiV1Dependencies(w, r, generated.GetApiV1DependenciesParams(params))
			})
			private.With(s.requirePermission(permissionReadEvents)).Get("/baseline-findings", func(w http.ResponseWriter, r *http.Request) {
				params, err := baselineFindingQueryParams(r)
				if err != nil {
					writeError(w, err)
					return
				}
				strict.GetApiV1BaselineFindings(w, r, generated.GetApiV1BaselineFindingsParams(params))
			})
			private.With(s.requirePermission(permissionReadAnalytics)).Get("/analytics/overview", strict.GetApiV1AnalyticsOverview)
			private.With(s.requirePermission(permissionReadAnalytics)).Get("/analytics/observability", func(w http.ResponseWriter, r *http.Request) {
				params := generated.GetApiV1AnalyticsObservabilityParams{}
				if applicationID := r.URL.Query().Get("application_id"); applicationID != "" {
					params.ApplicationId = &applicationID
				}
				if policyID := r.URL.Query().Get("policy_id"); policyID != "" {
					params.PolicyId = &policyID
				}
				strict.GetApiV1AnalyticsObservability(w, r, params)
			})
			private.With(s.requirePermission(permissionReadSettings)).Get("/system-settings", strict.GetApiV1SystemSettings)
			private.With(s.requirePermission(permissionReadSettings)).Get("/system/edition", strict.GetApiV1SystemEdition)
			private.With(s.requirePermission(permissionReadAlertRules)).Get("/alert-rules", strict.GetApiV1AlertRules)
			private.With(s.requirePermission(permissionReadAlertDeliveries)).Get("/alert-deliveries", strict.GetApiV1AlertDeliveries)
			private.With(s.requirePermission(permissionReadAuditLogs)).Get("/audit-logs", strict.GetApiV1AuditLogs)
			private.With(s.requirePermission(permissionReadUsers)).Get("/users", strict.GetApiV1Users)
			private.With(s.requirePermission(permissionManageUsers)).Post("/users", strict.PostApiV1Users)
			private.With(s.requirePermission(permissionManageUsers)).Put("/users/{userID}", func(w http.ResponseWriter, r *http.Request) {
				strict.PutApiV1UsersUserID(w, r, chi.URLParam(r, "userID"))
			})
			private.With(s.requirePermission(permissionManageApplications)).Post("/applications", strict.PostApiV1Applications)
			private.With(s.requirePermission(permissionManageApplications)).Post("/applications/{appID}/environments", func(w http.ResponseWriter, r *http.Request) {
				strict.PostApiV1ApplicationsAppIDEnvironments(w, r, chi.URLParam(r, "appID"))
			})
			private.With(s.requirePermission(permissionManageApplications)).Post("/applications/{appID}/secret/rotate", func(w http.ResponseWriter, r *http.Request) {
				strict.PostApiV1ApplicationsAppIDSecretRotate(w, r, chi.URLParam(r, "appID"))
			})
			private.With(s.requirePermission(permissionManageDaemon)).Post("/daemon/workloads/{workloadID}/bind", func(w http.ResponseWriter, r *http.Request) {
				strict.PostApiV1DaemonWorkloadsWorkloadIDBind(w, r, chi.URLParam(r, "workloadID"))
			})
			private.With(s.requirePermission(permissionManageDaemon)).Post("/daemon/workloads/{workloadID}/unbind", func(w http.ResponseWriter, r *http.Request) {
				strict.PostApiV1DaemonWorkloadsWorkloadIDUnbind(w, r, chi.URLParam(r, "workloadID"))
			})
			private.With(s.requirePermission(permissionManagePolicies)).Post("/policies", strict.PostApiV1Policies)
			private.With(s.requirePermission(permissionManagePolicies)).Post("/policies/{policyID}/versions", func(w http.ResponseWriter, r *http.Request) {
				strict.PostApiV1PoliciesPolicyIDVersions(w, r, chi.URLParam(r, "policyID"))
			})
			private.With(s.requirePermission(permissionManagePolicies)).Put("/policies/{policyID}/versions/{version}/rules", func(w http.ResponseWriter, r *http.Request) {
				version, err := strconv.Atoi(chi.URLParam(r, "version"))
				if err != nil || version <= 0 {
					writeError(w, control.ErrInvalid)
					return
				}
				strict.PutApiV1PoliciesPolicyIDVersionsVersionRules(w, r, chi.URLParam(r, "policyID"), version)
			})
			private.With(s.requirePermission(permissionEvaluatePolicies)).Post("/policies/validate", strict.PostApiV1PoliciesValidate)
			private.With(s.requirePermission(permissionEvaluatePolicies)).Post("/policies/test", strict.PostApiV1PoliciesTest)
			private.With(s.requirePermission(permissionManagePolicies)).Post("/policies/{policyID}/rollout", func(w http.ResponseWriter, r *http.Request) {
				strict.PostApiV1PoliciesPolicyIDRollout(w, r, chi.URLParam(r, "policyID"))
			})
			private.With(s.requirePermission(permissionManagePolicies)).Post("/policies/{policyID}/rollback", func(w http.ResponseWriter, r *http.Request) {
				strict.PostApiV1PoliciesPolicyIDRollback(w, r, chi.URLParam(r, "policyID"))
			})
			private.With(s.requirePermission(permissionManageSettings)).Put("/system-settings/{key}", func(w http.ResponseWriter, r *http.Request) {
				strict.PutApiV1SystemSettingsKey(w, r, chi.URLParam(r, "key"))
			})
			private.With(s.requirePermission(permissionManageSettings)).Post("/maintenance/cleanup", strict.PostApiV1MaintenanceCleanup)
			private.With(s.requirePermission(permissionManageEvents)).Post("/events/recycle-bin/delete", strict.PostApiV1EventsRecycleBinDelete)
			private.With(s.requirePermission(permissionManageEvents)).Post("/events/recycle-bin/restore", strict.PostApiV1EventsRecycleBinRestore)
			private.With(s.requirePermission(permissionManageEvents)).Post("/events/recycle-bin/purge", strict.PostApiV1EventsRecycleBinPurge)
			private.With(s.requirePermission(permissionManageAlertRules)).Post("/alert-rules", strict.PostApiV1AlertRules)
			private.With(s.requirePermission(permissionManageAlertRules)).Put("/alert-rules/{alertRuleID}", func(w http.ResponseWriter, r *http.Request) {
				strict.PutApiV1AlertRulesAlertRuleID(w, r, chi.URLParam(r, "alertRuleID"))
			})
		})

		api.Post("/agents/register", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1AgentsRegister(w, r, generated.PostApiV1AgentsRegisterParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
		api.Post("/agents/{agentID}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1AgentsAgentIDHeartbeat(w, r, chi.URLParam(r, "agentID"), generated.PostApiV1AgentsAgentIDHeartbeatParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
		api.Get("/agents/{agentID}/policy", func(w http.ResponseWriter, r *http.Request) {
			strict.GetApiV1AgentsAgentIDPolicy(w, r, chi.URLParam(r, "agentID"), generated.GetApiV1AgentsAgentIDPolicyParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
		api.Post("/daemon/workloads/report", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1DaemonWorkloadsReport(w, r, generated.PostApiV1DaemonWorkloadsReportParams{
				XOhMyRaspDaemonToken: r.Header.Get("X-OhMyRasp-Daemon-Token"),
			})
		})
		api.Post("/daemon/injection-reports", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1DaemonInjectionReports(w, r, generated.PostApiV1DaemonInjectionReportsParams{
				XOhMyRaspDaemonToken: r.Header.Get("X-OhMyRasp-Daemon-Token"),
			})
		})
		api.Get("/daemon/commands", func(w http.ResponseWriter, r *http.Request) {
			strict.GetApiV1DaemonCommands(w, r, generated.GetApiV1DaemonCommandsParams{
				XOhMyRaspDaemonToken: r.Header.Get("X-OhMyRasp-Daemon-Token"),
			})
		})
		api.Get("/daemon/app", s.daemonApplication)
		api.Get("/daemon/artifacts/agent/info", s.daemonArtifactInfo)
		api.Get("/daemon/artifacts/agent", s.daemonArtifactDownload)
		api.Post("/events/attack", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1EventsAttack(w, r, generated.PostApiV1EventsAttackParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
		api.Post("/events/hook", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1EventsHook(w, r, generated.PostApiV1EventsHookParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
		api.Post("/events/performance", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1EventsPerformance(w, r, generated.PostApiV1EventsPerformanceParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
		api.Post("/events/crash", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1EventsCrash(w, r, generated.PostApiV1EventsCrashParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
		api.Post("/dependencies", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1Dependencies(w, r, generated.PostApiV1DependenciesParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
		api.Post("/baseline-findings", func(w http.ResponseWriter, r *http.Request) {
			strict.PostApiV1BaselineFindings(w, r, generated.PostApiV1BaselineFindingsParams{
				XOhMyRaspAppID:     r.Header.Get("X-OhMyRasp-App-ID"),
				XOhMyRaspAppSecret: r.Header.Get("X-OhMyRasp-App-Secret"),
			})
		})
	})

	return router
}

func (s *Server) limitRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rateLimiter == nil || s.rateLimit <= 0 || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		decision, err := s.rateLimiter.Allow(r.Context(), rateLimitKey(r), s.rateLimit, s.rateLimitWindow)
		if err != nil {
			s.logger.Warn("rate limiter failed open", "error", err)
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(decision.Limit, 10))
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(decision.Remaining, 10))
		if !decision.Allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(maxInt64(1, int64(decision.RetryAfter/time.Second)), 10))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":       "rate_limited",
				"message":     "too many requests",
				"retry_after": decision.RetryAfter.String(),
				"status":      strconv.Itoa(http.StatusTooManyRequests),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	session, user, err := s.store.Login(r.Context(), input.Email, input.Password)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": session, "user": user})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": userFromRequest(r)})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": users})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string         `json:"email"`
		Name     string         `json:"name"`
		Password string         `json:"password"`
		Roles    []control.Role `json:"roles"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := s.store.CreateUser(r.Context(), userFromRequest(r).ID, control.User{
		Email: input.Email,
		Name:  input.Name,
		Roles: input.Roles,
	}, input.Password)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name     string         `json:"name"`
		Roles    []control.Role `json:"roles"`
		Disabled bool           `json:"disabled"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	var disabledAt *time.Time
	if input.Disabled {
		disabledAt = &time.Time{}
	}
	user, err := s.store.UpdateUser(r.Context(), userFromRequest(r).ID, chi.URLParam(r, "userID"), control.User{
		Name:       input.Name,
		Roles:      input.Roles,
		DisabledAt: disabledAt,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) listApplications(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApplications(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": apps})
}

func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	var input control.Application
	if !decodeJSON(w, r, &input) {
		return
	}
	app, err := s.store.CreateApplication(r.Context(), userFromRequest(r).ID, input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, app)
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	var input control.Environment
	if !decodeJSON(w, r, &input) {
		return
	}
	env, err := s.store.CreateEnvironment(r.Context(), userFromRequest(r).ID, chi.URLParam(r, "appID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, env)
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": agents})
}

func (s *Server) registerAgent(w http.ResponseWriter, r *http.Request) {
	var input control.Agent
	if !decodeJSON(w, r, &input) {
		return
	}
	appID := r.Header.Get("X-OhMyRasp-App-ID")
	appSecret := r.Header.Get("X-OhMyRasp-App-Secret")
	agent, err := s.store.RegisterAgent(r.Context(), appID, appSecret, input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, agent)
}

func (s *Server) heartbeatAgent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	agentID := chi.URLParam(r, "agentID")
	if err := s.store.AuthorizeAgent(r.Context(), r.Header.Get("X-OhMyRasp-App-ID"), r.Header.Get("X-OhMyRasp-App-Secret"), "", agentID); err != nil {
		writeError(w, err)
		return
	}
	agent, err := s.store.HeartbeatAgent(r.Context(), agentID, input.Status)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) getAgentPolicy(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentID")
	if err := s.store.AuthorizeAgent(r.Context(), r.Header.Get("X-OhMyRasp-App-ID"), r.Header.Get("X-OhMyRasp-App-Secret"), "", agentID); err != nil {
		writeError(w, err)
		return
	}
	policy, err := s.store.GetAgentPolicy(r.Context(), agentID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var input control.PolicySet
	if !decodeJSON(w, r, &input) {
		return
	}
	policy, err := s.store.CreatePolicy(r.Context(), userFromRequest(r).ID, input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": policies})
}

func (s *Server) addPolicyVersion(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Rules []control.Rule `json:"rules"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	policy, err := s.store.AddPolicyVersion(r.Context(), userFromRequest(r).ID, chi.URLParam(r, "policyID"), input.Rules)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) validateRules(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Rules []control.Rule `json:"rules"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	writeJSON(w, http.StatusOK, s.store.ValidateRules(r.Context(), input.Rules))
}

func (s *Server) testRule(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Rule  control.Rule          `json:"rule"`
		Event control.SecurityEvent `json:"event"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	writeJSON(w, http.StatusOK, s.store.TestRule(r.Context(), input.Rule, input.Event))
}

func (s *Server) rolloutPolicy(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Version       int    `json:"version"`
		CanaryPercent int    `json:"canary_percent"`
		ApplicationID string `json:"application_id"`
		EnvironmentID string `json:"environment_id"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	policy, err := s.store.RolloutPolicy(r.Context(), userFromRequest(r).ID, chi.URLParam(r, "policyID"), control.PolicyRollout{
		Version:       input.Version,
		CanaryPercent: input.CanaryPercent,
		ApplicationID: input.ApplicationID,
		EnvironmentID: input.EnvironmentID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.store.RollbackPolicy(r.Context(), userFromRequest(r).ID, chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) ingestEvent(eventType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input control.SecurityEvent
		if !decodeJSON(w, r, &input) {
			return
		}
		input.Type = eventType
		event, err := s.store.IngestEvent(r.Context(), input)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, event)
	}
}

func (s *Server) ingestDependency(w http.ResponseWriter, r *http.Request) {
	var input control.Dependency
	if !decodeJSON(w, r, &input) {
		return
	}
	dep, err := s.store.IngestDependency(r.Context(), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, dep)
}

func (s *Server) listAttackEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListEvents(r.Context(), control.SecurityEventQuery{Type: "attack"})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": events})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	overview, err := s.store.Overview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) observability(w http.ResponseWriter, r *http.Request) {
	report, err := s.store.Observability(r.Context(), control.ObservabilityQuery{
		ApplicationID: r.URL.Query().Get("application_id"),
		PolicyID:      r.URL.Query().Get("policy_id"),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) listSystemSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.ListSystemSettings(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": settings})
}

func (s *Server) upsertSystemSetting(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Value map[string]any `json:"value"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	setting, err := s.store.UpsertSystemSetting(r.Context(), userFromRequest(r).ID, control.SystemSetting{
		Key:   chi.URLParam(r, "key"),
		Value: input.Value,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, setting)
}

func (s *Server) listAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListAlertRules(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rules})
}

func (s *Server) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var input control.AlertRule
	if !decodeJSON(w, r, &input) {
		return
	}
	rule, err := s.store.CreateAlertRule(r.Context(), userFromRequest(r).ID, input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	var input control.AlertRule
	if !decodeJSON(w, r, &input) {
		return
	}
	rule, err := s.store.UpdateAlertRule(r.Context(), userFromRequest(r).ID, chi.URLParam(r, "alertRuleID"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) listAlertDeliveries(w http.ResponseWriter, r *http.Request) {
	deliveries, err := s.store.ListAlertDeliveries(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": deliveries})
}

func (s *Server) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := s.store.ListAuditLogs(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": logs})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(wrapped, r)
		s.logger.Info(
			"http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.Status(),
			"bytes", wrapped.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) requireAuthenticatedUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == auth || token == "" {
			writeError(w, control.ErrUnauthorized)
			return
		}
		user, err := s.store.UserForToken(r.Context(), token)
		if err != nil {
			writeError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

func (s *Server) requirePermission(permission permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !userHasPermission(userFromContext(r.Context()), permission) {
				writeError(w, control.ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasAnyRole(user control.User, roles []control.Role) bool {
	for _, have := range user.Roles {
		for _, want := range roles {
			if have == want {
				return true
			}
		}
	}
	return false
}

func rateLimitKey(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token != "" && token != auth {
		return "user:" + shortHash(token)
	}
	agentID := chi.URLParam(r, "agentID")
	if agentID != "" {
		return "agent:" + agentID
	}
	appID := r.Header.Get("X-OhMyRasp-App-ID")
	if appID != "" {
		return "app:" + appID
	}
	host := r.RemoteAddr
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		host = realIP
	} else if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		host = strings.TrimSpace(strings.Split(forwardedFor, ",")[0])
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return "ip:" + host
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func maxInt64(left int64, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json", "message": err.Error()})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "internal_error"
	switch {
	case errors.Is(err, control.ErrUnauthorized):
		status = http.StatusUnauthorized
		code = "unauthorized"
	case errors.Is(err, control.ErrForbidden):
		status = http.StatusForbidden
		code = "forbidden"
	case errors.Is(err, control.ErrNotFound):
		status = http.StatusNotFound
		code = "not_found"
	case errors.Is(err, control.ErrInvalid):
		status = http.StatusBadRequest
		code = "invalid_request"
	}
	writeJSON(w, status, map[string]any{"error": code, "message": err.Error(), "status": strconv.Itoa(status)})
}
