package httpapi

import (
	"context"
	"net/http"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/ohmyrasp/control-plane/internal/generated"
)

type strictServer struct {
	// The generated strict interface is embedded while route migration is
	// incremental. Only methods explicitly wired in Server.Routes may be called.
	generated.StrictServerInterface
	server *Server
}

func (s *Server) openAPIStrictHandler() generated.ServerInterface {
	return generated.NewStrictHandlerWithOptions(&strictServer{server: s}, nil, generated.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json", "message": err.Error()})
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeError(w, err)
		},
	})
}

func (s *strictServer) GetHealthz(context.Context, generated.GetHealthzRequestObject) (generated.GetHealthzResponseObject, error) {
	return generated.GetHealthz200JSONResponse{Status: "ok"}, nil
}

func (s *strictServer) GetReadyz(context.Context, generated.GetReadyzRequestObject) (generated.GetReadyzResponseObject, error) {
	return generated.GetReadyz200JSONResponse{Status: "ready"}, nil
}

func (s *strictServer) GetV1Version(context.Context, generated.GetV1VersionRequestObject) (generated.GetV1VersionResponseObject, error) {
	return generated.GetV1Version200JSONResponse(systemVersion()), nil
}

func (s *strictServer) GetApiV1SystemVersion(context.Context, generated.GetApiV1SystemVersionRequestObject) (generated.GetApiV1SystemVersionResponseObject, error) {
	return generated.GetApiV1SystemVersion200JSONResponse(systemVersion()), nil
}

func (s *strictServer) PostApiV1AuthLogin(ctx context.Context, request generated.PostApiV1AuthLoginRequestObject) (generated.PostApiV1AuthLoginResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	session, user, err := s.server.store.Login(ctx, string(request.Body.Email), request.Body.Password)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1AuthLogin200JSONResponse{
		Session: openAPISession(session),
		User:    openAPIUser(user),
	}, nil
}

func (s *strictServer) GetApiV1Me(ctx context.Context, _ generated.GetApiV1MeRequestObject) (generated.GetApiV1MeResponseObject, error) {
	return generated.GetApiV1Me200JSONResponse{User: openAPIUser(userFromContext(ctx))}, nil
}

func (s *strictServer) GetApiV1Applications(ctx context.Context, _ generated.GetApiV1ApplicationsRequestObject) (generated.GetApiV1ApplicationsResponseObject, error) {
	applications, err := s.server.store.ListApplications(ctx)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1Applications200JSONResponse{
		Items: openAPIApplications(applications),
	}, nil
}

func (s *strictServer) PostApiV1Applications(ctx context.Context, request generated.PostApiV1ApplicationsRequestObject) (generated.PostApiV1ApplicationsResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := control.Application{Name: request.Body.Name}
	if request.Body.Description != nil {
		input.Description = *request.Body.Description
	}
	application, err := s.server.store.CreateApplication(ctx, userFromContext(ctx).ID, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1Applications201JSONResponse(openAPIApplication(application)), nil
}

func (s *strictServer) GetApiV1ApplicationsExport(ctx context.Context, _ generated.GetApiV1ApplicationsExportRequestObject) (generated.GetApiV1ApplicationsExportResponseObject, error) {
	applications, err := s.server.store.ListApplications(ctx)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1ApplicationsExport200JSONResponse{
		Items: openAPIApplications(applications),
	}, nil
}

func (s *strictServer) DeleteApiV1ApplicationsAppID(ctx context.Context, request generated.DeleteApiV1ApplicationsAppIDRequestObject) (generated.DeleteApiV1ApplicationsAppIDResponseObject, error) {
	if err := s.server.store.DeleteApplication(ctx, userFromContext(ctx).ID, request.AppID); err != nil {
		return nil, err
	}
	return generated.DeleteApiV1ApplicationsAppID204Response{}, nil
}

func (s *strictServer) PostApiV1ApplicationsAppIDEnvironments(ctx context.Context, request generated.PostApiV1ApplicationsAppIDEnvironmentsRequestObject) (generated.PostApiV1ApplicationsAppIDEnvironmentsResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := control.Environment{Name: request.Body.Name}
	if request.Body.Kind != nil {
		input.Kind = *request.Body.Kind
	}
	environment, err := s.server.store.CreateEnvironment(ctx, userFromContext(ctx).ID, request.AppID, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1ApplicationsAppIDEnvironments201JSONResponse(openAPIEnvironment(environment)), nil
}

func (s *strictServer) GetApiV1ApplicationsAppIDSettings(ctx context.Context, request generated.GetApiV1ApplicationsAppIDSettingsRequestObject) (generated.GetApiV1ApplicationsAppIDSettingsResponseObject, error) {
	settings, err := s.server.store.ListApplicationSettings(ctx, request.AppID, "")
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1ApplicationsAppIDSettings200JSONResponse{Items: openAPIApplicationSettings(settings)}, nil
}

func (s *strictServer) PutApiV1ApplicationsAppIDSettings(ctx context.Context, request generated.PutApiV1ApplicationsAppIDSettingsRequestObject) (generated.PutApiV1ApplicationsAppIDSettingsResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	setting, err := s.server.store.UpsertApplicationSetting(ctx, userFromContext(ctx).ID, controlApplicationSettingFromOpenAPI(request.AppID, "", *request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PutApiV1ApplicationsAppIDSettings200JSONResponse(openAPIApplicationSetting(setting)), nil
}

func (s *strictServer) GetApiV1ApplicationsAppIDEnvironmentsEnvIDSettings(ctx context.Context, request generated.GetApiV1ApplicationsAppIDEnvironmentsEnvIDSettingsRequestObject) (generated.GetApiV1ApplicationsAppIDEnvironmentsEnvIDSettingsResponseObject, error) {
	settings, err := s.server.store.ListApplicationSettings(ctx, request.AppID, request.EnvID)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1ApplicationsAppIDEnvironmentsEnvIDSettings200JSONResponse{Items: openAPIApplicationSettings(settings)}, nil
}

func (s *strictServer) PutApiV1ApplicationsAppIDEnvironmentsEnvIDSettings(ctx context.Context, request generated.PutApiV1ApplicationsAppIDEnvironmentsEnvIDSettingsRequestObject) (generated.PutApiV1ApplicationsAppIDEnvironmentsEnvIDSettingsResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	setting, err := s.server.store.UpsertApplicationSetting(ctx, userFromContext(ctx).ID, controlApplicationSettingFromOpenAPI(request.AppID, request.EnvID, *request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PutApiV1ApplicationsAppIDEnvironmentsEnvIDSettings200JSONResponse(openAPIApplicationSetting(setting)), nil
}

func (s *strictServer) PostApiV1ApplicationsAppIDSecretRotate(ctx context.Context, request generated.PostApiV1ApplicationsAppIDSecretRotateRequestObject) (generated.PostApiV1ApplicationsAppIDSecretRotateResponseObject, error) {
	application, err := s.server.store.RotateApplicationSecret(ctx, userFromContext(ctx).ID, request.AppID)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1ApplicationsAppIDSecretRotate200JSONResponse(openAPIApplication(application)), nil
}

func (s *strictServer) GetApiV1DaemonToken(ctx context.Context, _ generated.GetApiV1DaemonTokenRequestObject) (generated.GetApiV1DaemonTokenResponseObject, error) {
	token, err := s.server.store.DaemonAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1DaemonToken200JSONResponse(openAPIDaemonAccessToken(token)), nil
}

func (s *strictServer) PostApiV1DaemonTokenReset(ctx context.Context, _ generated.PostApiV1DaemonTokenResetRequestObject) (generated.PostApiV1DaemonTokenResetResponseObject, error) {
	token, err := s.server.store.ResetDaemonAccessToken(ctx, userFromContext(ctx).ID)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1DaemonTokenReset200JSONResponse(openAPIDaemonAccessToken(token)), nil
}

func (s *strictServer) GetApiV1DaemonWorkloads(ctx context.Context, _ generated.GetApiV1DaemonWorkloadsRequestObject) (generated.GetApiV1DaemonWorkloadsResponseObject, error) {
	workloads, err := s.server.store.ListDaemonWorkloads(ctx)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1DaemonWorkloads200JSONResponse{Items: openAPIDaemonWorkloads(workloads)}, nil
}

func (s *strictServer) GetApiV1DaemonCommands(ctx context.Context, request generated.GetApiV1DaemonCommandsRequestObject) (generated.GetApiV1DaemonCommandsResponseObject, error) {
	commands, err := s.server.store.ListDaemonCommands(ctx, request.Params.XOhMyRaspDaemonToken)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1DaemonCommands200JSONResponse{Items: openAPIDaemonCommandGroups(commands)}, nil
}

func (s *strictServer) GetApiV1AgentArtifacts(context.Context, generated.GetApiV1AgentArtifactsRequestObject) (generated.GetApiV1AgentArtifactsResponseObject, error) {
	catalog, err := s.server.agentArtifactCatalog()
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1AgentArtifacts200JSONResponse(catalog), nil
}

func (s *strictServer) PostApiV1AgentArtifacts(ctx context.Context, request generated.PostApiV1AgentArtifactsRequestObject) (generated.PostApiV1AgentArtifactsResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	item, err := s.server.uploadAgentArtifact(ctx, userFromContext(ctx).ID, *request.Body)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1AgentArtifacts201JSONResponse(item), nil
}

func (s *strictServer) PostApiV1DaemonWorkloadsReport(ctx context.Context, request generated.PostApiV1DaemonWorkloadsReportRequestObject) (generated.PostApiV1DaemonWorkloadsReportResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	workloads, err := s.server.store.ReportDaemonWorkloads(ctx, request.Params.XOhMyRaspDaemonToken, controlDaemonWorkloadReportFromOpenAPI(*request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1DaemonWorkloadsReport200JSONResponse{Items: openAPIDaemonWorkloads(workloads)}, nil
}

func (s *strictServer) PostApiV1DaemonInjectionReports(ctx context.Context, request generated.PostApiV1DaemonInjectionReportsRequestObject) (generated.PostApiV1DaemonInjectionReportsResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	workload, err := s.server.store.ReportDaemonInjection(ctx, request.Params.XOhMyRaspDaemonToken, control.DaemonInjectionReport{
		WorkloadID:    request.Body.WorkloadId,
		Status:        string(request.Body.Status),
		HelperID:      stringFromPointer(request.Body.HelperId),
		HelperVersion: stringFromPointer(request.Body.HelperVersion),
		Error:         stringFromPointer(request.Body.Error),
		ReportedAt:    timeFromPointer(request.Body.ReportedAt),
	})
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1DaemonInjectionReports200JSONResponse(openAPIDaemonWorkload(workload)), nil
}

func (s *strictServer) PostApiV1DaemonWorkloadsWorkloadIDBind(ctx context.Context, request generated.PostApiV1DaemonWorkloadsWorkloadIDBindRequestObject) (generated.PostApiV1DaemonWorkloadsWorkloadIDBindResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	workload, err := s.server.store.BindDaemonWorkload(ctx, userFromContext(ctx).ID, request.WorkloadID, request.Body.ApplicationId)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1DaemonWorkloadsWorkloadIDBind200JSONResponse(openAPIDaemonWorkload(workload)), nil
}

func (s *strictServer) PostApiV1DaemonWorkloadsWorkloadIDUnbind(ctx context.Context, request generated.PostApiV1DaemonWorkloadsWorkloadIDUnbindRequestObject) (generated.PostApiV1DaemonWorkloadsWorkloadIDUnbindResponseObject, error) {
	workload, err := s.server.store.UnbindDaemonWorkload(ctx, userFromContext(ctx).ID, request.WorkloadID)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1DaemonWorkloadsWorkloadIDUnbind200JSONResponse(openAPIDaemonWorkload(workload)), nil
}

func (s *strictServer) GetApiV1Agents(ctx context.Context, request generated.GetApiV1AgentsRequestObject) (generated.GetApiV1AgentsResponseObject, error) {
	agents, err := s.server.store.ListAgents(ctx, control.AgentQuery{
		ApplicationID: stringFromPointer(request.Params.ApplicationId),
		EnvironmentID: stringFromPointer(request.Params.EnvironmentId),
	})
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1Agents200JSONResponse{
		Items: openAPIAgents(agents),
	}, nil
}

func (s *strictServer) PutApiV1AgentsAgentIDAlias(ctx context.Context, request generated.PutApiV1AgentsAgentIDAliasRequestObject) (generated.PutApiV1AgentsAgentIDAliasResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	agent, err := s.server.store.UpdateAgentAlias(ctx, userFromContext(ctx).ID, request.AgentID, request.Body.Alias)
	if err != nil {
		return nil, err
	}
	return generated.PutApiV1AgentsAgentIDAlias200JSONResponse(openAPIAgent(agent)), nil
}

func (s *strictServer) PostApiV1AgentsAgentIDIgnore(ctx context.Context, request generated.PostApiV1AgentsAgentIDIgnoreRequestObject) (generated.PostApiV1AgentsAgentIDIgnoreResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	agent, err := s.server.store.SetAgentIgnored(ctx, userFromContext(ctx).ID, request.AgentID, request.Body.Ignored)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1AgentsAgentIDIgnore200JSONResponse(openAPIAgent(agent)), nil
}

func (s *strictServer) DeleteApiV1AgentsAgentID(ctx context.Context, request generated.DeleteApiV1AgentsAgentIDRequestObject) (generated.DeleteApiV1AgentsAgentIDResponseObject, error) {
	report, err := s.server.store.DeleteAgents(ctx, userFromContext(ctx).ID, []string{request.AgentID})
	if err != nil {
		return nil, err
	}
	return generated.DeleteApiV1AgentsAgentID200JSONResponse(openAPIAgentBatchOperationReport(report)), nil
}

func (s *strictServer) PostApiV1AgentsBatchDelete(ctx context.Context, request generated.PostApiV1AgentsBatchDeleteRequestObject) (generated.PostApiV1AgentsBatchDeleteResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	report, err := s.server.store.DeleteAgents(ctx, userFromContext(ctx).ID, request.Body.Ids)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1AgentsBatchDelete200JSONResponse(openAPIAgentBatchOperationReport(report)), nil
}

func (s *strictServer) PostApiV1AgentsRegister(ctx context.Context, request generated.PostApiV1AgentsRegisterRequestObject) (generated.PostApiV1AgentsRegisterResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := control.Agent{
		EnvironmentID: request.Body.EnvironmentId,
		Hostname:      request.Body.Hostname,
		Version:       request.Body.Version,
	}
	if request.Body.Runtime != nil {
		input.Runtime = *request.Body.Runtime
	}
	agent, err := s.server.store.RegisterAgent(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1AgentsRegister201JSONResponse(openAPIAgent(agent)), nil
}

func (s *strictServer) PostApiV1AgentsAgentIDHeartbeat(ctx context.Context, request generated.PostApiV1AgentsAgentIDHeartbeatRequestObject) (generated.PostApiV1AgentsAgentIDHeartbeatResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	if err := s.authorizeAgent(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, "", request.AgentID); err != nil {
		return nil, err
	}
	agent, err := s.server.store.HeartbeatAgent(ctx, request.AgentID, request.Body.Status)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1AgentsAgentIDHeartbeat200JSONResponse(openAPIAgent(agent)), nil
}

func (s *strictServer) GetApiV1AgentsAgentIDPolicy(ctx context.Context, request generated.GetApiV1AgentsAgentIDPolicyRequestObject) (generated.GetApiV1AgentsAgentIDPolicyResponseObject, error) {
	started := time.Now()
	var policy control.PolicyVersion
	err := s.authorizeAgent(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, "", request.AgentID)
	if err == nil {
		policy, err = s.server.store.GetAgentPolicy(ctx, request.AgentID)
	}
	s.server.metrics.observePolicyPull(time.Since(started), err)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1AgentsAgentIDPolicy200JSONResponse(openAPIPolicyVersion(policy)), nil
}

func (s *strictServer) GetApiV1Policies(ctx context.Context, _ generated.GetApiV1PoliciesRequestObject) (generated.GetApiV1PoliciesResponseObject, error) {
	policies, err := s.server.store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1Policies200JSONResponse{
		Items: openAPIPolicySets(policies),
	}, nil
}

func (s *strictServer) GetApiV1PoliciesAlgorithms(context.Context, generated.GetApiV1PoliciesAlgorithmsRequestObject) (generated.GetApiV1PoliciesAlgorithmsResponseObject, error) {
	return generated.GetApiV1PoliciesAlgorithms200JSONResponse(openAPIPolicyAlgorithmCatalog(control.SupportedPolicyAlgorithmCatalog())), nil
}

func (s *strictServer) PostApiV1Policies(ctx context.Context, request generated.PostApiV1PoliciesRequestObject) (generated.PostApiV1PoliciesResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := control.PolicySet{Name: request.Body.Name}
	if request.Body.Description != nil {
		input.Description = *request.Body.Description
	}
	policy, err := s.server.store.CreatePolicy(ctx, userFromContext(ctx).ID, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1Policies201JSONResponse(openAPIPolicySet(policy)), nil
}

func (s *strictServer) PostApiV1PoliciesPolicyIDVersions(ctx context.Context, request generated.PostApiV1PoliciesPolicyIDVersionsRequestObject) (generated.PostApiV1PoliciesPolicyIDVersionsResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	policy, err := s.server.store.AddPolicyVersion(ctx, userFromContext(ctx).ID, request.PolicyID, controlRulesFromOpenAPI(request.Body.Rules))
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1PoliciesPolicyIDVersions201JSONResponse(openAPIPolicySet(policy)), nil
}

func (s *strictServer) PutApiV1PoliciesPolicyIDVersionsVersionRules(ctx context.Context, request generated.PutApiV1PoliciesPolicyIDVersionsVersionRulesRequestObject) (generated.PutApiV1PoliciesPolicyIDVersionsVersionRulesResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	policy, err := s.server.store.UpdatePolicyVersionRules(ctx, userFromContext(ctx).ID, request.PolicyID, request.Version, controlRulesFromOpenAPI(request.Body.Rules))
	if err != nil {
		return nil, err
	}
	return generated.PutApiV1PoliciesPolicyIDVersionsVersionRules200JSONResponse(openAPIPolicySet(policy)), nil
}

func (s *strictServer) PostApiV1PoliciesPolicyIDRestoreDefault(ctx context.Context, request generated.PostApiV1PoliciesPolicyIDRestoreDefaultRequestObject) (generated.PostApiV1PoliciesPolicyIDRestoreDefaultResponseObject, error) {
	policy, err := s.server.store.RestoreDefaultPolicy(ctx, userFromContext(ctx).ID, request.PolicyID)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1PoliciesPolicyIDRestoreDefault200JSONResponse(openAPIPolicySet(policy)), nil
}

func (s *strictServer) PostApiV1PoliciesValidate(ctx context.Context, request generated.PostApiV1PoliciesValidateRequestObject) (generated.PostApiV1PoliciesValidateResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	validation := s.server.store.ValidateRules(ctx, controlRulesFromOpenAPI(request.Body.Rules))
	return generated.PostApiV1PoliciesValidate200JSONResponse(openAPIRuleValidation(validation)), nil
}

func (s *strictServer) PostApiV1PoliciesTest(ctx context.Context, request generated.PostApiV1PoliciesTestRequestObject) (generated.PostApiV1PoliciesTestResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	result := s.server.store.TestRule(ctx, controlRuleFromOpenAPI(request.Body.Rule), controlSecurityEventFromOpenAPI(request.Body.Event, ""))
	return generated.PostApiV1PoliciesTest200JSONResponse(openAPIRuleTestResult(result)), nil
}

func (s *strictServer) PostApiV1PoliciesPolicyIDRollout(ctx context.Context, request generated.PostApiV1PoliciesPolicyIDRolloutRequestObject) (generated.PostApiV1PoliciesPolicyIDRolloutResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	rollout := control.PolicyRollout{
		Version:       request.Body.Version,
		CanaryPercent: request.Body.CanaryPercent,
	}
	if request.Body.ApplicationId != nil {
		rollout.ApplicationID = *request.Body.ApplicationId
	}
	if request.Body.EnvironmentId != nil {
		rollout.EnvironmentID = *request.Body.EnvironmentId
	}
	policy, err := s.server.store.RolloutPolicy(ctx, userFromContext(ctx).ID, request.PolicyID, rollout)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1PoliciesPolicyIDRollout200JSONResponse(openAPIPolicySet(policy)), nil
}

func (s *strictServer) PostApiV1PoliciesPolicyIDRollback(ctx context.Context, request generated.PostApiV1PoliciesPolicyIDRollbackRequestObject) (generated.PostApiV1PoliciesPolicyIDRollbackResponseObject, error) {
	policy, err := s.server.store.RollbackPolicy(ctx, userFromContext(ctx).ID, request.PolicyID)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1PoliciesPolicyIDRollback200JSONResponse(openAPIPolicySet(policy)), nil
}

func (s *strictServer) GetApiV1EventsAttack(ctx context.Context, request generated.GetApiV1EventsAttackRequestObject) (generated.GetApiV1EventsAttackResponseObject, error) {
	events, err := s.server.store.ListEvents(ctx, controlSecurityEventQueryFromParams("attack", eventQueryParameterSet(request.Params)))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1EventsAttack200JSONResponse{
		Items: openAPISecurityEvents(events),
	}, nil
}

func (s *strictServer) GetApiV1EventsHook(ctx context.Context, request generated.GetApiV1EventsHookRequestObject) (generated.GetApiV1EventsHookResponseObject, error) {
	events, err := s.server.store.ListEvents(ctx, controlSecurityEventQueryFromParams("hook", eventQueryParameterSet(request.Params)))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1EventsHook200JSONResponse{
		Items: openAPISecurityEvents(events),
	}, nil
}

func (s *strictServer) GetApiV1EventsPerformance(ctx context.Context, request generated.GetApiV1EventsPerformanceRequestObject) (generated.GetApiV1EventsPerformanceResponseObject, error) {
	events, err := s.server.store.ListEvents(ctx, controlSecurityEventQueryFromParams("performance", eventQueryParameterSet(request.Params)))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1EventsPerformance200JSONResponse{
		Items: openAPISecurityEvents(events),
	}, nil
}

func (s *strictServer) GetApiV1EventsCrash(ctx context.Context, request generated.GetApiV1EventsCrashRequestObject) (generated.GetApiV1EventsCrashResponseObject, error) {
	events, err := s.server.store.ListEvents(ctx, controlSecurityEventQueryFromParams("crash", eventQueryParameterSet(request.Params)))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1EventsCrash200JSONResponse{
		Items: openAPISecurityEvents(events),
	}, nil
}

func (s *strictServer) GetApiV1EventsError(ctx context.Context, request generated.GetApiV1EventsErrorRequestObject) (generated.GetApiV1EventsErrorResponseObject, error) {
	events, err := s.server.store.ListEvents(ctx, controlSecurityEventQueryFromParams("error", eventQueryParameterSet(request.Params)))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1EventsError200JSONResponse{
		Items: openAPISecurityEvents(events),
	}, nil
}

func (s *strictServer) GetApiV1EventsRecycleBin(ctx context.Context, request generated.GetApiV1EventsRecycleBinRequestObject) (generated.GetApiV1EventsRecycleBinResponseObject, error) {
	events, err := s.server.store.ListEvents(ctx, controlRecycleBinEventQueryFromParams(request.Params))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1EventsRecycleBin200JSONResponse{
		Items: openAPISecurityEvents(events),
	}, nil
}

func (s *strictServer) PostApiV1EventsRecycleBinDelete(ctx context.Context, request generated.PostApiV1EventsRecycleBinDeleteRequestObject) (generated.PostApiV1EventsRecycleBinDeleteResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	report, err := s.server.store.SoftDeleteEvents(ctx, userFromContext(ctx).ID, controlEventRecycleBinRequestFromOpenAPI(*request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1EventsRecycleBinDelete200JSONResponse(openAPIEventRecycleBinReport(report)), nil
}

func (s *strictServer) PostApiV1EventsRecycleBinRestore(ctx context.Context, request generated.PostApiV1EventsRecycleBinRestoreRequestObject) (generated.PostApiV1EventsRecycleBinRestoreResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	report, err := s.server.store.RestoreDeletedEvents(ctx, userFromContext(ctx).ID, controlEventRecycleBinRequestFromOpenAPI(*request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1EventsRecycleBinRestore200JSONResponse(openAPIEventRecycleBinReport(report)), nil
}

func (s *strictServer) PostApiV1EventsRecycleBinPurge(ctx context.Context, request generated.PostApiV1EventsRecycleBinPurgeRequestObject) (generated.PostApiV1EventsRecycleBinPurgeResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	report, err := s.server.store.PurgeDeletedEvents(ctx, userFromContext(ctx).ID, controlEventRecycleBinRequestFromOpenAPI(*request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1EventsRecycleBinPurge200JSONResponse(openAPIEventRecycleBinReport(report)), nil
}

func (s *strictServer) PostApiV1EventsAttack(ctx context.Context, request generated.PostApiV1EventsAttackRequestObject) (generated.PostApiV1EventsAttackResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := controlSecurityEventFromOpenAPI(*request.Body, "attack")
	if err := s.authorizeAgentReport(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, input.ApplicationID, input.EnvironmentID, input.AgentID); err != nil {
		return nil, err
	}
	event, err := s.server.store.IngestEvent(ctx, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1EventsAttack202JSONResponse(openAPISecurityEvent(event)), nil
}

func (s *strictServer) PostApiV1EventsHook(ctx context.Context, request generated.PostApiV1EventsHookRequestObject) (generated.PostApiV1EventsHookResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := controlSecurityEventFromOpenAPI(*request.Body, "hook")
	if err := s.authorizeAgentReport(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, input.ApplicationID, input.EnvironmentID, input.AgentID); err != nil {
		return nil, err
	}
	event, err := s.server.store.IngestEvent(ctx, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1EventsHook202JSONResponse(openAPISecurityEvent(event)), nil
}

func (s *strictServer) PostApiV1EventsPerformance(ctx context.Context, request generated.PostApiV1EventsPerformanceRequestObject) (generated.PostApiV1EventsPerformanceResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := controlSecurityEventFromOpenAPI(*request.Body, "performance")
	if err := s.authorizeAgentReport(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, input.ApplicationID, input.EnvironmentID, input.AgentID); err != nil {
		return nil, err
	}
	event, err := s.server.store.IngestEvent(ctx, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1EventsPerformance202JSONResponse(openAPISecurityEvent(event)), nil
}

func (s *strictServer) PostApiV1EventsCrash(ctx context.Context, request generated.PostApiV1EventsCrashRequestObject) (generated.PostApiV1EventsCrashResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := controlSecurityEventFromOpenAPI(*request.Body, "crash")
	if err := s.authorizeAgentReport(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, input.ApplicationID, input.EnvironmentID, input.AgentID); err != nil {
		return nil, err
	}
	event, err := s.server.store.IngestEvent(ctx, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1EventsCrash202JSONResponse(openAPISecurityEvent(event)), nil
}

func (s *strictServer) PostApiV1EventsError(ctx context.Context, request generated.PostApiV1EventsErrorRequestObject) (generated.PostApiV1EventsErrorResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := controlSecurityEventFromOpenAPI(*request.Body, "error")
	if err := s.authorizeAgentReport(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, input.ApplicationID, input.EnvironmentID, input.AgentID); err != nil {
		return nil, err
	}
	event, err := s.server.store.IngestEvent(ctx, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1EventsError202JSONResponse(openAPISecurityEvent(event)), nil
}

func (s *strictServer) GetApiV1Dependencies(ctx context.Context, request generated.GetApiV1DependenciesRequestObject) (generated.GetApiV1DependenciesResponseObject, error) {
	dependencies, err := s.server.store.ListDependencies(ctx, controlDependencyQueryFromParams(dependencyQueryParameterSet(request.Params)))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1Dependencies200JSONResponse{
		Items: openAPIDependencies(dependencies),
	}, nil
}

func (s *strictServer) GetApiV1DependenciesExport(ctx context.Context, _ generated.GetApiV1DependenciesExportRequestObject) (generated.GetApiV1DependenciesExportResponseObject, error) {
	dependencies, err := s.server.store.ListDependencies(ctx, control.DependencyQuery{Limit: 1000})
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1DependenciesExport200JSONResponse{
		Items: openAPIDependencies(dependencies),
	}, nil
}

func (s *strictServer) GetApiV1DependenciesSummary(ctx context.Context, request generated.GetApiV1DependenciesSummaryRequestObject) (generated.GetApiV1DependenciesSummaryResponseObject, error) {
	summary, err := s.server.store.DependencySummary(ctx, control.DependencyQuery{
		ApplicationID: stringFromPointer(request.Params.ApplicationId),
		AgentID:       stringFromPointer(request.Params.AgentId),
	})
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1DependenciesSummary200JSONResponse(openAPIDependencySummary(summary)), nil
}

func (s *strictServer) PostApiV1Dependencies(ctx context.Context, request generated.PostApiV1DependenciesRequestObject) (generated.PostApiV1DependenciesResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := controlDependencyFromOpenAPI(*request.Body)
	if err := s.authorizeAgentReport(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, input.ApplicationID, "", input.AgentID); err != nil {
		return nil, err
	}
	dependency, err := s.server.store.IngestDependency(ctx, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1Dependencies202JSONResponse(openAPIDependency(dependency)), nil
}

func (s *strictServer) GetApiV1BaselineFindings(ctx context.Context, request generated.GetApiV1BaselineFindingsRequestObject) (generated.GetApiV1BaselineFindingsResponseObject, error) {
	findings, err := s.server.store.ListBaselineFindings(ctx, controlBaselineFindingQueryFromParams(baselineFindingQueryParameterSet(request.Params)))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1BaselineFindings200JSONResponse{
		Items: openAPIBaselineFindings(findings),
	}, nil
}

func (s *strictServer) PostApiV1BaselineFindings(ctx context.Context, request generated.PostApiV1BaselineFindingsRequestObject) (generated.PostApiV1BaselineFindingsResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	input := controlBaselineFindingFromOpenAPI(*request.Body)
	if err := s.authorizeAgentReport(ctx, request.Params.XOhMyRaspAppID, request.Params.XOhMyRaspAppSecret, input.ApplicationID, input.EnvironmentID, input.AgentID); err != nil {
		return nil, err
	}
	finding, err := s.server.store.IngestBaselineFinding(ctx, input)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1BaselineFindings202JSONResponse(openAPIBaselineFinding(finding)), nil
}

func (s *strictServer) authorizeAgentReport(ctx context.Context, headerAppID string, appSecret string, bodyAppID string, environmentID string, agentID string) error {
	if headerAppID == "" || appSecret == "" || bodyAppID != headerAppID {
		return control.ErrUnauthorized
	}
	return s.server.store.AuthorizeAgent(ctx, headerAppID, appSecret, environmentID, agentID)
}

func (s *strictServer) authorizeAgent(ctx context.Context, appID string, appSecret string, environmentID string, agentID string) error {
	if appID == "" || appSecret == "" || agentID == "" {
		return control.ErrUnauthorized
	}
	return s.server.store.AuthorizeAgent(ctx, appID, appSecret, environmentID, agentID)
}

func (s *strictServer) GetApiV1AnalyticsOverview(ctx context.Context, request generated.GetApiV1AnalyticsOverviewRequestObject) (generated.GetApiV1AnalyticsOverviewResponseObject, error) {
	overview, err := s.server.store.Overview(ctx, control.OverviewQuery{
		ApplicationID: stringFromPointer(request.Params.ApplicationId),
		EnvironmentID: stringFromPointer(request.Params.EnvironmentId),
	})
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1AnalyticsOverview200JSONResponse(openAPIOverview(overview)), nil
}

func (s *strictServer) GetApiV1AnalyticsObservability(ctx context.Context, request generated.GetApiV1AnalyticsObservabilityRequestObject) (generated.GetApiV1AnalyticsObservabilityResponseObject, error) {
	query := control.ObservabilityQuery{}
	if request.Params.ApplicationId != nil {
		query.ApplicationID = *request.Params.ApplicationId
	}
	if request.Params.PolicyId != nil {
		query.PolicyID = *request.Params.PolicyId
	}
	report, err := s.server.store.Observability(ctx, query)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1AnalyticsObservability200JSONResponse(openAPIObservabilityReport(report)), nil
}

func (s *strictServer) GetApiV1AuditLogs(ctx context.Context, _ generated.GetApiV1AuditLogsRequestObject) (generated.GetApiV1AuditLogsResponseObject, error) {
	logs, err := s.server.store.ListAuditLogs(ctx)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1AuditLogs200JSONResponse{
		Items: openAPIAuditLogs(logs),
	}, nil
}

func (s *strictServer) GetApiV1SystemSettings(ctx context.Context, _ generated.GetApiV1SystemSettingsRequestObject) (generated.GetApiV1SystemSettingsResponseObject, error) {
	settings, err := s.server.store.ListSystemSettings(ctx)
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1SystemSettings200JSONResponse{Items: openAPISystemSettings(settings)}, nil
}

func (s *strictServer) GetApiV1SystemEdition(context.Context, generated.GetApiV1SystemEditionRequestObject) (generated.GetApiV1SystemEditionResponseObject, error) {
	return generated.GetApiV1SystemEdition200JSONResponse(openAPIEditionStatus()), nil
}

func (s *strictServer) PutApiV1SystemSettingsKey(ctx context.Context, request generated.PutApiV1SystemSettingsKeyRequestObject) (generated.PutApiV1SystemSettingsKeyResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	setting, err := s.server.store.UpsertSystemSetting(ctx, userFromContext(ctx).ID, control.SystemSetting{
		Key:   request.Key,
		Value: copyStringAnyMap(request.Body.Value),
	})
	if err != nil {
		return nil, err
	}
	return generated.PutApiV1SystemSettingsKey200JSONResponse(openAPISystemSetting(setting)), nil
}

func (s *strictServer) PostApiV1MaintenanceCleanup(ctx context.Context, request generated.PostApiV1MaintenanceCleanupRequestObject) (generated.PostApiV1MaintenanceCleanupResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	report, err := s.server.store.MaintenanceCleanup(ctx, userFromContext(ctx).ID, controlMaintenanceCleanupRequestFromOpenAPI(*request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1MaintenanceCleanup200JSONResponse(openAPIMaintenanceCleanupReport(report)), nil
}

func (s *strictServer) GetApiV1AlertRules(ctx context.Context, request generated.GetApiV1AlertRulesRequestObject) (generated.GetApiV1AlertRulesResponseObject, error) {
	rules, err := s.server.store.ListAlertRules(ctx, control.AlertRuleQuery{ApplicationID: stringFromPointer(request.Params.ApplicationId)})
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1AlertRules200JSONResponse{Items: openAPIAlertRules(rules)}, nil
}

func (s *strictServer) PostApiV1AlertRules(ctx context.Context, request generated.PostApiV1AlertRulesRequestObject) (generated.PostApiV1AlertRulesResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	rule, err := s.server.store.CreateAlertRule(ctx, userFromContext(ctx).ID, controlAlertRuleFromOpenAPI(*request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1AlertRules201JSONResponse(openAPIAlertRule(rule)), nil
}

func (s *strictServer) PutApiV1AlertRulesAlertRuleID(ctx context.Context, request generated.PutApiV1AlertRulesAlertRuleIDRequestObject) (generated.PutApiV1AlertRulesAlertRuleIDResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	rule, err := s.server.store.UpdateAlertRule(ctx, userFromContext(ctx).ID, request.AlertRuleID, controlAlertRuleFromOpenAPI(*request.Body))
	if err != nil {
		return nil, err
	}
	return generated.PutApiV1AlertRulesAlertRuleID200JSONResponse(openAPIAlertRule(rule)), nil
}

func (s *strictServer) GetApiV1AlertDeliveries(ctx context.Context, request generated.GetApiV1AlertDeliveriesRequestObject) (generated.GetApiV1AlertDeliveriesResponseObject, error) {
	deliveries, err := s.server.store.ListAlertDeliveries(ctx, control.AlertDeliveryQuery{ApplicationID: stringFromPointer(request.Params.ApplicationId)})
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1AlertDeliveries200JSONResponse{Items: openAPIAlertDeliveries(deliveries)}, nil
}

func (s *strictServer) GetApiV1Users(ctx context.Context, request generated.GetApiV1UsersRequestObject) (generated.GetApiV1UsersResponseObject, error) {
	users, err := s.server.store.ListUsers(ctx, controlUserQueryFromParams(request.Params))
	if err != nil {
		return nil, err
	}
	return generated.GetApiV1Users200JSONResponse{Items: openAPIUsers(users)}, nil
}

func (s *strictServer) PostApiV1Users(ctx context.Context, request generated.PostApiV1UsersRequestObject) (generated.PostApiV1UsersResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	user, err := s.server.store.CreateUser(ctx, userFromContext(ctx).ID, control.User{
		Email: string(request.Body.Email),
		Name:  request.Body.Name,
		Roles: controlRolesFromUserCreate(request.Body.Roles),
	}, request.Body.Password)
	if err != nil {
		return nil, err
	}
	return generated.PostApiV1Users201JSONResponse(openAPIUser(user)), nil
}

func (s *strictServer) PutApiV1UsersUserID(ctx context.Context, request generated.PutApiV1UsersUserIDRequestObject) (generated.PutApiV1UsersUserIDResponseObject, error) {
	if request.Body == nil {
		return nil, control.ErrInvalid
	}
	var disabledAt *time.Time
	if request.Body.Disabled {
		disabledAt = &time.Time{}
	}
	user, err := s.server.store.UpdateUser(ctx, userFromContext(ctx).ID, request.UserID, control.User{
		Name:       request.Body.Name,
		Roles:      controlRolesFromUserUpdate(request.Body.Roles),
		DisabledAt: disabledAt,
	})
	if err != nil {
		return nil, err
	}
	return generated.PutApiV1UsersUserID200JSONResponse(openAPIUser(user)), nil
}

func openAPISession(session control.Session) generated.Session {
	return generated.Session{
		Token:     session.Token,
		UserId:    session.UserID,
		ExpiresAt: session.ExpiresAt,
	}
}

func openAPIUser(user control.User) generated.User {
	return generated.User{
		Id:         user.ID,
		Email:      openapi_types.Email(user.Email),
		Name:       user.Name,
		Roles:      openAPIUserRoles(user.Roles),
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
		DisabledAt: user.DisabledAt,
	}
}

func openAPIUserRoles(roles []control.Role) []generated.UserRoles {
	result := make([]generated.UserRoles, 0, len(roles))
	for _, role := range roles {
		switch role {
		case control.RoleAdmin:
			result = append(result, generated.UserRolesAdmin)
		case control.RoleSecurityEngineer:
			result = append(result, generated.UserRolesSecurityEngineer)
		case control.RoleViewer:
			result = append(result, generated.UserRolesViewer)
		}
	}
	return result
}

func openAPIUsers(users []control.User) []generated.User {
	result := make([]generated.User, 0, len(users))
	for _, user := range users {
		result = append(result, openAPIUser(user))
	}
	return result
}

func controlRolesFromUserCreate(roles []generated.UserCreateRoles) []control.Role {
	result := make([]control.Role, 0, len(roles))
	for _, role := range roles {
		result = append(result, control.Role(role))
	}
	return result
}

func controlRolesFromUserUpdate(roles []generated.UserUpdateRoles) []control.Role {
	result := make([]control.Role, 0, len(roles))
	for _, role := range roles {
		result = append(result, control.Role(role))
	}
	return result
}

func controlUserQueryFromParams(params generated.GetApiV1UsersParams) control.UserQuery {
	query := control.UserQuery{}
	if params.Search != nil {
		query.Search = *params.Search
	}
	if params.Role != nil {
		query.Role = string(*params.Role)
	}
	if params.Status != nil {
		query.Status = string(*params.Status)
	}
	return query
}

func openAPIApplications(applications []control.Application) []generated.Application {
	result := make([]generated.Application, 0, len(applications))
	for _, application := range applications {
		result = append(result, openAPIApplication(application))
	}
	return result
}

func openAPIApplication(application control.Application) generated.Application {
	var secret *string
	if application.Secret != "" {
		secret = &application.Secret
	}
	var policyID *string
	if application.PolicyID != "" {
		policyID = &application.PolicyID
	}
	var policyVersion *int
	if application.PolicyVersion != 0 {
		policyVersion = &application.PolicyVersion
	}
	environmentIDs := make([]string, 0, len(application.EnvironmentIDs))
	environmentIDs = append(environmentIDs, application.EnvironmentIDs...)
	return generated.Application{
		Id:             application.ID,
		Name:           application.Name,
		Description:    application.Description,
		Secret:         secret,
		CreatedAt:      application.CreatedAt,
		PolicyId:       policyID,
		PolicyVersion:  policyVersion,
		EnvironmentIds: environmentIDs,
	}
}

func openAPIEnvironment(environment control.Environment) generated.Environment {
	var policyID *string
	if environment.PolicyID != "" {
		policyID = &environment.PolicyID
	}
	var policyVersion *int
	if environment.PolicyVersion != 0 {
		policyVersion = &environment.PolicyVersion
	}
	return generated.Environment{
		Id:            environment.ID,
		ApplicationId: environment.ApplicationID,
		Name:          environment.Name,
		Kind:          environment.Kind,
		CreatedAt:     environment.CreatedAt,
		PolicyId:      policyID,
		PolicyVersion: policyVersion,
	}
}

func openAPIAgents(agents []control.Agent) []generated.Agent {
	result := make([]generated.Agent, 0, len(agents))
	for _, agent := range agents {
		result = append(result, openAPIAgent(agent))
	}
	return result
}

func openAPIAgent(agent control.Agent) generated.Agent {
	var policyID *string
	if agent.PolicyID != "" {
		policyID = &agent.PolicyID
	}
	var policyVersion *int
	if agent.PolicyVersion != 0 {
		policyVersion = &agent.PolicyVersion
	}
	var alias *string
	if agent.Alias != "" {
		alias = &agent.Alias
	}
	var ignoredAt *time.Time
	if !agent.IgnoredAt.IsZero() {
		ignoredAt = &agent.IgnoredAt
	}
	return generated.Agent{
		Id:            agent.ID,
		ApplicationId: agent.ApplicationID,
		EnvironmentId: agent.EnvironmentID,
		Hostname:      agent.Hostname,
		Alias:         alias,
		Runtime:       agent.Runtime,
		Version:       agent.Version,
		Status:        agent.Status,
		LastSeenAt:    agent.LastSeenAt,
		PolicyId:      policyID,
		PolicyVersion: policyVersion,
		IgnoredAt:     ignoredAt,
	}
}

func openAPIAgentBatchOperationReport(report control.AgentBatchOperationReport) generated.AgentBatchOperationReport {
	return generated.AgentBatchOperationReport{
		Ids:   report.IDs,
		Count: report.Count,
	}
}

func openAPIDaemonAccessToken(token control.DaemonAccessToken) generated.DaemonAccessToken {
	return generated.DaemonAccessToken{
		AccessToken: token.AccessToken,
		UpdatedAt:   token.UpdatedAt,
	}
}

func openAPIDaemonWorkloads(workloads []control.DaemonWorkload) []generated.DaemonWorkload {
	result := make([]generated.DaemonWorkload, 0, len(workloads))
	for _, workload := range workloads {
		result = append(result, openAPIDaemonWorkload(workload))
	}
	return result
}

func openAPIDaemonCommandGroups(commands []control.DaemonCommandGroup) []generated.DaemonCommandGroup {
	result := make([]generated.DaemonCommandGroup, 0, len(commands))
	for _, command := range commands {
		result = append(result, generated.DaemonCommandGroup{
			ApplicationId:     command.ApplicationID,
			ApplicationSecret: command.ApplicationSecret,
			Language:          generated.DaemonCommandGroupLanguage(command.Language),
			Workloads:         openAPIDaemonWorkloads(command.Workloads),
		})
	}
	return result
}

func openAPIDaemonWorkload(workload control.DaemonWorkload) generated.DaemonWorkload {
	var appID *string
	if workload.ApplicationID != "" {
		appID = &workload.ApplicationID
	}
	var pid *int
	if workload.PID != 0 {
		pid = &workload.PID
	}
	var cmdline *[]string
	if len(workload.Cmdline) > 0 {
		copied := append([]string(nil), workload.Cmdline...)
		cmdline = &copied
	}
	var containerID *string
	if workload.ContainerID != "" {
		containerID = &workload.ContainerID
	}
	var containerName *string
	if workload.ContainerName != "" {
		containerName = &workload.ContainerName
	}
	var imageID *string
	if workload.ImageID != "" {
		imageID = &workload.ImageID
	}
	var imageTag *string
	if workload.ImageTag != "" {
		imageTag = &workload.ImageTag
	}
	var injectionStatus *generated.DaemonWorkloadInjectionStatus
	if workload.InjectionStatus != "" {
		status := generated.DaemonWorkloadInjectionStatus(workload.InjectionStatus)
		injectionStatus = &status
	}
	var injectionError *string
	if workload.InjectionError != "" {
		injectionError = &workload.InjectionError
	}
	var injectionHelperID *string
	if workload.InjectionHelperID != "" {
		injectionHelperID = &workload.InjectionHelperID
	}
	var injectionHelperVersion *string
	if workload.InjectionHelperVersion != "" {
		injectionHelperVersion = &workload.InjectionHelperVersion
	}
	var injectionReportedAt *time.Time
	if !workload.InjectionReportedAt.IsZero() {
		injectionReportedAt = &workload.InjectionReportedAt
	}
	var injectionStatusUpdatedAt *time.Time
	if !workload.InjectionStatusUpdatedAt.IsZero() {
		injectionStatusUpdatedAt = &workload.InjectionStatusUpdatedAt
	}
	return generated.DaemonWorkload{
		Id:                       workload.ID,
		ApplicationId:            appID,
		NodeName:                 workload.NodeName,
		Type:                     generated.DaemonWorkloadType(workload.Type),
		Pid:                      pid,
		Cmdline:                  cmdline,
		ContainerId:              containerID,
		ContainerName:            containerName,
		ImageId:                  imageID,
		ImageTag:                 imageTag,
		InjectionStatus:          injectionStatus,
		InjectionError:           injectionError,
		InjectionHelperId:        injectionHelperID,
		InjectionHelperVersion:   injectionHelperVersion,
		InjectionReportedAt:      injectionReportedAt,
		InjectionStatusUpdatedAt: injectionStatusUpdatedAt,
		ObservedAt:               workload.ObservedAt,
		UpdatedAt:                workload.UpdatedAt,
	}
}

func stringFromPointer(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func timeFromPointer(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

func boolFromPointerDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func controlDaemonWorkloadReportFromOpenAPI(report generated.DaemonWorkloadReport) control.DaemonWorkloadReport {
	output := control.DaemonWorkloadReport{
		NodeName:  report.NodeName,
		Workloads: make([]control.DaemonWorkloadInput, 0, len(report.Workloads)),
	}
	for _, input := range report.Workloads {
		workload := control.DaemonWorkloadInput{
			Type: string(input.Type),
		}
		if input.Pid != nil {
			workload.PID = *input.Pid
		}
		if input.Cmdline != nil {
			workload.Cmdline = append([]string(nil), (*input.Cmdline)...)
		}
		if input.ContainerId != nil {
			workload.ContainerID = *input.ContainerId
		}
		if input.ContainerName != nil {
			workload.ContainerName = *input.ContainerName
		}
		if input.ImageId != nil {
			workload.ImageID = *input.ImageId
		}
		if input.ImageTag != nil {
			workload.ImageTag = *input.ImageTag
		}
		if input.ObservedAt != nil {
			workload.ObservedAt = *input.ObservedAt
		}
		output.Workloads = append(output.Workloads, workload)
	}
	return output
}

func openAPIPolicySets(policies []control.PolicySet) []generated.PolicySet {
	result := make([]generated.PolicySet, 0, len(policies))
	for _, policy := range policies {
		result = append(result, openAPIPolicySet(policy))
	}
	return result
}

func openAPIPolicyAlgorithmCatalog(catalog control.PolicyAlgorithmCatalog) generated.PolicyAlgorithmCatalog {
	items := make([]generated.PolicyAlgorithm, 0, len(catalog.Items))
	for _, item := range catalog.Items {
		items = append(items, generated.PolicyAlgorithm{
			Hook:       item.Hook,
			Algorithms: append([]string{}, item.Algorithms...),
		})
	}
	return generated.PolicyAlgorithmCatalog{Items: items}
}

func openAPIPolicySet(policy control.PolicySet) generated.PolicySet {
	var active *generated.PolicyVersion
	if policy.Active != nil {
		converted := openAPIPolicyVersion(*policy.Active)
		active = &converted
	}
	return generated.PolicySet{
		Id:          policy.ID,
		Name:        policy.Name,
		Description: policy.Description,
		CreatedAt:   policy.CreatedAt,
		Active:      active,
		Versions:    openAPIPolicyVersions(policy.Versions),
	}
}

func openAPIPolicyVersions(versions []control.PolicyVersion) []generated.PolicyVersion {
	result := make([]generated.PolicyVersion, 0, len(versions))
	for _, version := range versions {
		result = append(result, openAPIPolicyVersion(version))
	}
	return result
}

func openAPIPolicyVersion(version control.PolicyVersion) generated.PolicyVersion {
	var publishedAt *time.Time
	if !version.PublishedAt.IsZero() {
		publishedAt = &version.PublishedAt
	}
	var config *generated.ApplicationConfig
	if version.Config != nil {
		converted := openAPIApplicationConfig(*version.Config)
		config = &converted
	}
	return generated.PolicyVersion{
		Version:       version.Version,
		Status:        version.Status,
		Rules:         openAPIRules(version.Rules),
		CanaryPercent: version.CanaryPercent,
		CreatedAt:     version.CreatedAt,
		PublishedAt:   publishedAt,
		Config:        config,
	}
}

func openAPIRules(rules []control.Rule) []generated.Rule {
	result := make([]generated.Rule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, generated.Rule{
			Id:          rule.ID,
			Name:        rule.Name,
			Hook:        rule.Hook,
			Algorithm:   rule.Algorithm,
			Action:      rule.Action,
			Severity:    rule.Severity,
			Expression:  rule.Expression,
			Tags:        append([]string{}, rule.Tags...),
			Description: rule.Description,
		})
	}
	return result
}

func controlRulesFromOpenAPI(rules []generated.RuleInput) []control.Rule {
	result := make([]control.Rule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, controlRuleFromOpenAPI(rule))
	}
	return result
}

func controlRuleFromOpenAPI(rule generated.RuleInput) control.Rule {
	output := control.Rule{
		Name:       rule.Name,
		Hook:       rule.Hook,
		Expression: rule.Expression,
	}
	if rule.Id != nil {
		output.ID = *rule.Id
	}
	if rule.Algorithm != nil {
		output.Algorithm = *rule.Algorithm
	}
	if rule.Action != nil {
		output.Action = string(*rule.Action)
	}
	if rule.Severity != nil {
		output.Severity = *rule.Severity
	}
	if rule.Tags != nil {
		output.Tags = append([]string(nil), (*rule.Tags)...)
	}
	if rule.Description != nil {
		output.Description = *rule.Description
	}
	return output
}

func controlSecurityEventQueryFromParams(eventType string, params eventQueryParameterSet) control.SecurityEventQuery {
	query := control.SecurityEventQuery{Type: eventType}
	if params.ApplicationId != nil {
		query.ApplicationID = *params.ApplicationId
	}
	if params.EnvironmentId != nil {
		query.EnvironmentID = *params.EnvironmentId
	}
	if params.AgentId != nil {
		query.AgentID = *params.AgentId
	}
	if params.PolicyId != nil {
		query.PolicyID = *params.PolicyId
	}
	if params.Severity != nil {
		query.Severity = *params.Severity
	}
	if params.Hook != nil {
		query.Hook = *params.Hook
	}
	if params.OccurredAfter != nil {
		query.OccurredAfter = *params.OccurredAfter
	}
	if params.OccurredBefore != nil {
		query.OccurredBefore = *params.OccurredBefore
	}
	if params.Limit != nil {
		query.Limit = *params.Limit
	}
	return query
}

func controlRecycleBinEventQueryFromParams(params generated.GetApiV1EventsRecycleBinParams) control.SecurityEventQuery {
	query := control.SecurityEventQuery{DeletedOnly: true}
	if params.Type != nil {
		query.Type = string(*params.Type)
	}
	if params.ApplicationId != nil {
		query.ApplicationID = *params.ApplicationId
	}
	if params.EnvironmentId != nil {
		query.EnvironmentID = *params.EnvironmentId
	}
	if params.AgentId != nil {
		query.AgentID = *params.AgentId
	}
	if params.PolicyId != nil {
		query.PolicyID = *params.PolicyId
	}
	if params.Severity != nil {
		query.Severity = *params.Severity
	}
	if params.Hook != nil {
		query.Hook = *params.Hook
	}
	if params.OccurredAfter != nil {
		query.OccurredAfter = *params.OccurredAfter
	}
	if params.OccurredBefore != nil {
		query.OccurredBefore = *params.OccurredBefore
	}
	if params.Limit != nil {
		query.Limit = *params.Limit
	}
	return query
}

func controlSecurityEventFromOpenAPI(event generated.SecurityEventInput, eventType string) control.SecurityEvent {
	output := control.SecurityEvent{
		Type:          eventType,
		ApplicationID: event.ApplicationId,
		EnvironmentID: event.EnvironmentId,
		AgentID:       event.AgentId,
		Severity:      event.Severity,
		Message:       event.Message,
	}
	if event.PolicyId != nil {
		output.PolicyID = *event.PolicyId
	}
	if event.PolicyVersion != nil {
		output.PolicyVersion = *event.PolicyVersion
	}
	if event.Hook != nil {
		output.Hook = *event.Hook
	}
	if event.Algorithm != nil {
		output.Algorithm = *event.Algorithm
	}
	if event.OccurredAt != nil {
		output.OccurredAt = *event.OccurredAt
	}
	if event.Attributes != nil {
		output.Attributes = copyStringAnyMap(*event.Attributes)
	}
	return output
}

func openAPISecurityEvents(events []control.SecurityEvent) []generated.SecurityEvent {
	result := make([]generated.SecurityEvent, 0, len(events))
	for _, event := range events {
		result = append(result, openAPISecurityEvent(event))
	}
	return result
}

func openAPISecurityEvent(event control.SecurityEvent) generated.SecurityEvent {
	var policyID *string
	if event.PolicyID != "" {
		policyID = &event.PolicyID
	}
	var policyVersion *int
	if event.PolicyVersion != 0 {
		policyVersion = &event.PolicyVersion
	}
	var hook *string
	if event.Hook != "" {
		hook = &event.Hook
	}
	var algorithm *string
	if event.Algorithm != "" {
		algorithm = &event.Algorithm
	}
	var attributes *map[string]interface{}
	if event.Attributes != nil {
		copied := copyStringAnyMap(event.Attributes)
		attributes = &copied
	}
	var deletedBy *string
	if event.DeletedBy != "" {
		deletedBy = &event.DeletedBy
	}
	return generated.SecurityEvent{
		Id:            event.ID,
		Type:          generated.SecurityEventType(event.Type),
		ApplicationId: event.ApplicationID,
		EnvironmentId: event.EnvironmentID,
		AgentId:       event.AgentID,
		PolicyId:      policyID,
		PolicyVersion: policyVersion,
		Hook:          hook,
		Algorithm:     algorithm,
		Severity:      event.Severity,
		Message:       event.Message,
		OccurredAt:    event.OccurredAt,
		Attributes:    attributes,
		DeletedAt:     event.DeletedAt,
		DeletedBy:     deletedBy,
	}
}

func controlEventRecycleBinRequestFromOpenAPI(input generated.EventRecycleBinAction) control.EventRecycleBinRequest {
	return control.EventRecycleBinRequest{IDs: append([]string(nil), input.Ids...)}
}

func openAPIEventRecycleBinReport(report control.EventRecycleBinReport) generated.EventRecycleBinReport {
	return generated.EventRecycleBinReport{
		Ids:   append([]string(nil), report.IDs...),
		Count: report.Count,
	}
}

func controlDependencyFromOpenAPI(dependency generated.DependencyInput) control.Dependency {
	output := control.Dependency{
		ApplicationID: dependency.ApplicationId,
		Name:          dependency.Name,
	}
	if dependency.AgentId != nil {
		output.AgentID = *dependency.AgentId
	}
	if dependency.Version != nil {
		output.Version = *dependency.Version
	}
	if dependency.Ecosystem != nil {
		output.Ecosystem = *dependency.Ecosystem
	}
	if dependency.PackagePath != nil {
		output.PackagePath = *dependency.PackagePath
	}
	if dependency.Licenses != nil {
		output.Licenses = append([]string(nil), (*dependency.Licenses)...)
	}
	if dependency.Vulnerabilities != nil {
		output.Vulnerabilities = controlDependencyVulnerabilitiesFromOpenAPI(*dependency.Vulnerabilities)
	}
	if dependency.ObservedAt != nil {
		output.ObservedAt = *dependency.ObservedAt
	}
	return output
}

func controlDependencyQueryFromParams(params dependencyQueryParameterSet) control.DependencyQuery {
	query := control.DependencyQuery{}
	if params.ApplicationId != nil {
		query.ApplicationID = *params.ApplicationId
	}
	if params.AgentId != nil {
		query.AgentID = *params.AgentId
	}
	if params.Name != nil {
		query.Name = *params.Name
	}
	if params.Ecosystem != nil {
		query.Ecosystem = *params.Ecosystem
	}
	if params.VulnerabilitySeverity != nil {
		query.VulnerabilitySeverity = string(*params.VulnerabilitySeverity)
	}
	if params.ObservedAfter != nil {
		query.ObservedAfter = *params.ObservedAfter
	}
	if params.ObservedBefore != nil {
		query.ObservedBefore = *params.ObservedBefore
	}
	if params.Limit != nil {
		query.Limit = *params.Limit
	}
	return query
}

func openAPIDependency(dependency control.Dependency) generated.Dependency {
	licenses := append([]string(nil), dependency.Licenses...)
	packagePath := dependency.PackagePath
	vulnerabilities := openAPIDependencyVulnerabilities(dependency.Vulnerabilities)
	output := generated.Dependency{
		Id:            dependency.ID,
		ApplicationId: dependency.ApplicationID,
		AgentId:       dependency.AgentID,
		Name:          dependency.Name,
		Version:       dependency.Version,
		Ecosystem:     dependency.Ecosystem,
		ObservedAt:    dependency.ObservedAt,
	}
	if dependency.PackagePath != "" {
		output.PackagePath = &packagePath
	}
	if dependency.Licenses != nil {
		output.Licenses = &licenses
	}
	if dependency.Vulnerabilities != nil {
		output.Vulnerabilities = &vulnerabilities
	}
	return output
}

func openAPIDependencies(dependencies []control.Dependency) []generated.Dependency {
	result := make([]generated.Dependency, 0, len(dependencies))
	for _, dependency := range dependencies {
		result = append(result, openAPIDependency(dependency))
	}
	return result
}

func openAPIDependencySummary(summary control.DependencySummary) generated.DependencySummary {
	return generated.DependencySummary{
		DependencyCount:           summary.DependencyCount,
		VulnerableDependencyCount: summary.VulnerableDependencyCount,
		KnownExploitedCount:       summary.KnownExploitedCount,
		DependenciesByEcosystem:   copyStringIntMap(summary.DependenciesByEcosystem),
		VulnerabilitiesBySeverity: copyStringIntMap(summary.VulnerabilitiesBySeverity),
	}
}

func controlBaselineFindingFromOpenAPI(finding generated.BaselineFindingInput) control.BaselineFinding {
	output := control.BaselineFinding{
		ApplicationID: finding.ApplicationId,
		EnvironmentID: finding.EnvironmentId,
		AgentID:       finding.AgentId,
		CheckID:       finding.CheckId,
		Title:         finding.Title,
		Severity:      string(finding.Severity),
		Status:        string(finding.Status),
	}
	if finding.Category != nil {
		output.Category = *finding.Category
	}
	if finding.Resource != nil {
		output.Resource = *finding.Resource
	}
	if finding.Remediation != nil {
		output.Remediation = *finding.Remediation
	}
	if finding.Attributes != nil {
		output.Attributes = copyStringAnyMap(*finding.Attributes)
	}
	if finding.ObservedAt != nil {
		output.ObservedAt = *finding.ObservedAt
	}
	return output
}

func controlBaselineFindingQueryFromParams(params baselineFindingQueryParameterSet) control.BaselineFindingQuery {
	query := control.BaselineFindingQuery{}
	if params.ApplicationId != nil {
		query.ApplicationID = *params.ApplicationId
	}
	if params.EnvironmentId != nil {
		query.EnvironmentID = *params.EnvironmentId
	}
	if params.AgentId != nil {
		query.AgentID = *params.AgentId
	}
	if params.Severity != nil {
		query.Severity = string(*params.Severity)
	}
	if params.Status != nil {
		query.Status = string(*params.Status)
	}
	if params.Category != nil {
		query.Category = *params.Category
	}
	if params.ObservedAfter != nil {
		query.ObservedAfter = *params.ObservedAfter
	}
	if params.ObservedBefore != nil {
		query.ObservedBefore = *params.ObservedBefore
	}
	if params.Limit != nil {
		query.Limit = *params.Limit
	}
	return query
}

func openAPIBaselineFinding(finding control.BaselineFinding) generated.BaselineFinding {
	var remediation *string
	if finding.Remediation != "" {
		remediation = &finding.Remediation
	}
	var attributes *map[string]interface{}
	if finding.Attributes != nil {
		copied := copyStringAnyMap(finding.Attributes)
		attributes = &copied
	}
	return generated.BaselineFinding{
		Id:            finding.ID,
		ApplicationId: finding.ApplicationID,
		EnvironmentId: finding.EnvironmentID,
		AgentId:       finding.AgentID,
		CheckId:       finding.CheckID,
		Title:         finding.Title,
		Category:      finding.Category,
		Severity:      generated.BaselineFindingSeverity(finding.Severity),
		Status:        generated.BaselineFindingStatus(finding.Status),
		Resource:      finding.Resource,
		Remediation:   remediation,
		Attributes:    attributes,
		ObservedAt:    finding.ObservedAt,
	}
}

func openAPIBaselineFindings(findings []control.BaselineFinding) []generated.BaselineFinding {
	result := make([]generated.BaselineFinding, 0, len(findings))
	for _, finding := range findings {
		result = append(result, openAPIBaselineFinding(finding))
	}
	return result
}

func controlDependencyVulnerabilitiesFromOpenAPI(vulnerabilities []generated.DependencyVulnerability) []control.DependencyVulnerability {
	result := make([]control.DependencyVulnerability, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		output := control.DependencyVulnerability{
			ID:       vulnerability.Id,
			Severity: string(vulnerability.Severity),
		}
		if vulnerability.Cvss != nil {
			output.CVSS = float64(*vulnerability.Cvss)
		}
		if vulnerability.KnownExploited != nil {
			output.KnownExploited = *vulnerability.KnownExploited
		}
		if vulnerability.FixedVersion != nil {
			output.FixedVersion = *vulnerability.FixedVersion
		}
		result = append(result, output)
	}
	return result
}

func openAPIDependencyVulnerabilities(vulnerabilities []control.DependencyVulnerability) []generated.DependencyVulnerability {
	result := make([]generated.DependencyVulnerability, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		output := generated.DependencyVulnerability{
			Id:       vulnerability.ID,
			Severity: generated.DependencyVulnerabilitySeverity(vulnerability.Severity),
		}
		if vulnerability.CVSS != 0 {
			cvss := float32(vulnerability.CVSS)
			output.Cvss = &cvss
		}
		if vulnerability.KnownExploited {
			knownExploited := vulnerability.KnownExploited
			output.KnownExploited = &knownExploited
		}
		if vulnerability.FixedVersion != "" {
			fixedVersion := vulnerability.FixedVersion
			output.FixedVersion = &fixedVersion
		}
		result = append(result, output)
	}
	return result
}

func openAPIRuleValidation(validation control.RuleValidation) generated.RuleValidation {
	return generated.RuleValidation{
		Valid:  validation.Valid,
		Errors: append([]string(nil), validation.Errors...),
	}
}

func openAPIRuleTestResult(result control.RuleTestResult) generated.RuleTestResult {
	return generated.RuleTestResult{
		Matched:    result.Matched,
		Action:     result.Action,
		Algorithm:  result.Algorithm,
		Confidence: result.Confidence,
	}
}

func openAPIObservabilityReport(report control.ObservabilityReport) generated.ObservabilityReport {
	return generated.ObservabilityReport{
		RuleOverhead:      openAPIRuleOverhead(report.RuleOverhead),
		HookLatency:       openAPIHookLatency(report.HookLatency),
		AgentOverhead:     openAPIAgentOverhead(report.AgentOverhead),
		PolicyPerformance: openAPIPolicyPerformance(report.PolicyPerformance),
	}
}

func openAPIRuleOverhead(samples []control.RuleOverhead) []generated.RuleOverhead {
	result := make([]generated.RuleOverhead, 0, len(samples))
	for _, sample := range samples {
		result = append(result, generated.RuleOverhead{
			PolicyId:         sample.PolicyID,
			PolicyVersion:    sample.PolicyVersion,
			RuleId:           sample.RuleID,
			Hook:             sample.Hook,
			Executions:       sample.Executions,
			Blocked:          sample.Blocked,
			AverageLatencyUs: float32(sample.AverageLatencyUS),
			P95LatencyUs:     sample.P95LatencyUS,
			MaxLatencyUs:     sample.MaxLatencyUS,
		})
	}
	return result
}

func openAPIHookLatency(samples []control.HookLatency) []generated.HookLatency {
	result := make([]generated.HookLatency, 0, len(samples))
	for _, sample := range samples {
		result = append(result, generated.HookLatency{
			Hook:             sample.Hook,
			Calls:            sample.Calls,
			AverageLatencyUs: float32(sample.AverageLatencyUS),
			P50LatencyUs:     sample.P50LatencyUS,
			P95LatencyUs:     sample.P95LatencyUS,
			MaxLatencyUs:     sample.MaxLatencyUS,
		})
	}
	return result
}

func openAPIAgentOverhead(samples []control.AgentOverhead) []generated.AgentOverhead {
	result := make([]generated.AgentOverhead, 0, len(samples))
	for _, sample := range samples {
		result = append(result, generated.AgentOverhead{
			AgentId:             sample.AgentID,
			Samples:             sample.Samples,
			CpuOverheadPct:      float32(sample.CPUOverheadPCT),
			MemoryOverheadBytes: sample.MemoryOverheadBytes,
			HookLatencyP95Us:    sample.HookLatencyP95US,
			RuleEvalP95Us:       sample.RuleEvalP95US,
		})
	}
	return result
}

func openAPIPolicyPerformance(samples []control.PolicyPerformance) []generated.PolicyPerformance {
	result := make([]generated.PolicyPerformance, 0, len(samples))
	for _, sample := range samples {
		result = append(result, generated.PolicyPerformance{
			PolicyId:         sample.PolicyID,
			PolicyVersion:    sample.PolicyVersion,
			Samples:          sample.Samples,
			CpuOverheadPct:   float32(sample.CPUOverheadPCT),
			HookLatencyP95Us: sample.HookLatencyP95US,
			RuleEvalP95Us:    sample.RuleEvalP95US,
		})
	}
	return result
}

func openAPIOverview(overview control.Overview) generated.Overview {
	return generated.Overview{
		ApplicationCount:   overview.ApplicationCount,
		AgentCount:         overview.AgentCount,
		OnlineAgents:       overview.OnlineAgents,
		EventCount:         overview.EventCount,
		EventsByType:       copyStringIntMap(overview.EventsByType),
		EventsBySeverity:   copyStringIntMap(overview.EventsBySeverity),
		AttackTrend:        openAPITrendPoints(overview.AttackTrend),
		AttacksByHook:      copyStringIntMap(overview.AttacksByHook),
		AttacksByAlgorithm: copyStringIntMap(overview.AttacksByAlgorithm),
		AttacksByUserAgent: copyStringIntMap(overview.AttacksByUserAgent),
		CrashCount:         overview.CrashCount,
	}
}

func openAPITrendPoints(points []control.TrendPoint) []generated.TrendPoint {
	result := make([]generated.TrendPoint, 0, len(points))
	for _, point := range points {
		result = append(result, generated.TrendPoint{
			BucketStart: point.BucketStart,
			Count:       point.Count,
		})
	}
	return result
}

func openAPIAuditLogs(logs []control.AuditLog) []generated.AuditLog {
	result := make([]generated.AuditLog, 0, len(logs))
	for _, log := range logs {
		result = append(result, openAPIAuditLog(log))
	}
	return result
}

func openAPIAuditLog(log control.AuditLog) generated.AuditLog {
	var details *map[string]interface{}
	if log.Details != nil {
		copied := copyStringAnyMap(log.Details)
		details = &copied
	}
	return generated.AuditLog{
		Id:        log.ID,
		ActorId:   log.ActorID,
		Action:    log.Action,
		Resource:  log.Resource,
		Details:   details,
		CreatedAt: log.CreatedAt,
	}
}

func openAPISystemSettings(settings []control.SystemSetting) []generated.SystemSetting {
	result := make([]generated.SystemSetting, 0, len(settings))
	for _, setting := range settings {
		result = append(result, openAPISystemSetting(setting))
	}
	return result
}

func openAPISystemSetting(setting control.SystemSetting) generated.SystemSetting {
	var updatedBy *string
	if setting.UpdatedBy != "" {
		updatedBy = &setting.UpdatedBy
	}
	return generated.SystemSetting{
		Key:       setting.Key,
		Value:     copyStringAnyMap(setting.Value),
		UpdatedBy: updatedBy,
		UpdatedAt: setting.UpdatedAt,
	}
}

func openAPIApplicationSettings(settings []control.ApplicationSetting) []generated.ApplicationSetting {
	result := make([]generated.ApplicationSetting, 0, len(settings))
	for _, setting := range settings {
		result = append(result, openAPIApplicationSetting(setting))
	}
	return result
}

func openAPIApplicationSetting(setting control.ApplicationSetting) generated.ApplicationSetting {
	var environmentID *string
	if setting.EnvironmentID != "" {
		environmentID = &setting.EnvironmentID
	}
	var updatedBy *string
	if setting.UpdatedBy != "" {
		updatedBy = &setting.UpdatedBy
	}
	return generated.ApplicationSetting{
		ApplicationId: setting.ApplicationID,
		EnvironmentId: environmentID,
		Key:           setting.Key,
		Value:         copyStringAnyMap(setting.Value),
		UpdatedBy:     updatedBy,
		UpdatedAt:     setting.UpdatedAt,
	}
}

func controlApplicationSettingFromOpenAPI(appID string, environmentID string, input generated.ApplicationSettingUpdate) control.ApplicationSetting {
	return control.ApplicationSetting{
		ApplicationID: appID,
		EnvironmentID: environmentID,
		Key:           input.Key,
		Value:         copyStringAnyMap(input.Value),
	}
}

func openAPIApplicationConfig(config control.ApplicationConfig) generated.ApplicationConfig {
	return generated.ApplicationConfig{
		Allowlist:                     copyStringAnyMap(config.Allowlist),
		Hardening:                     copyStringAnyMap(config.Hardening),
		AlertDelivery:                 copyStringAnyMap(config.AlertDelivery),
		DependencyVulnerabilityPolicy: copyStringAnyMap(config.DependencyVulnerabilityPolicy),
	}
}

func openAPIEditionStatus() generated.EditionStatus {
	note := "Open-source self-hosted deployments do not require a license key and do not enforce license limits."
	return generated.EditionStatus{
		Edition:            generated.OssSelfHosted,
		DisplayName:        "Open Source Self-Hosted",
		DeploymentModel:    generated.SingleOrganizationSelfHosted,
		LicenseRequired:    false,
		LicenseEnforcement: generated.None,
		LicenseStatus:      generated.NotApplicable,
		Note:               &note,
	}
}

func controlMaintenanceCleanupRequestFromOpenAPI(input generated.MaintenanceCleanupRequest) control.MaintenanceCleanupRequest {
	includeEvents := boolFromPointerDefault(input.IncludeEvents, true)
	includeDependencies := boolFromPointerDefault(input.IncludeDependencies, true)
	includeBaselineFindings := boolFromPointerDefault(input.IncludeBaselineFindings, true)
	includeAlertDeliveries := boolFromPointerDefault(input.IncludeAlertDeliveries, true)
	return control.MaintenanceCleanupRequest{
		ApplicationID:           stringFromPointer(input.ApplicationId),
		Before:                  input.Before,
		DryRun:                  boolFromPointerDefault(input.DryRun, true),
		IncludeEvents:           includeEvents,
		IncludeDependencies:     includeDependencies,
		IncludeBaselineFindings: includeBaselineFindings,
		IncludeAlertDeliveries:  includeAlertDeliveries,
		Confirmation:            stringFromPointer(input.Confirmation),
	}
}

func openAPIMaintenanceCleanupReport(report control.MaintenanceCleanupReport) generated.MaintenanceCleanupReport {
	var applicationID *string
	if report.ApplicationID != "" {
		applicationID = &report.ApplicationID
	}
	return generated.MaintenanceCleanupReport{
		ApplicationId: applicationID,
		Before:        report.Before,
		Counts:        copyStringIntMap(report.Counts),
		DryRun:        report.DryRun,
	}
}

func openAPIAlertRules(rules []control.AlertRule) []generated.AlertRule {
	result := make([]generated.AlertRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, openAPIAlertRule(rule))
	}
	return result
}

func openAPIAlertRule(rule control.AlertRule) generated.AlertRule {
	var applicationID *string
	if rule.ApplicationID != "" {
		applicationID = &rule.ApplicationID
	}
	return generated.AlertRule{
		Id:            rule.ID,
		ApplicationId: applicationID,
		Name:          rule.Name,
		Description:   rule.Description,
		Enabled:       rule.Enabled,
		EventType:     generated.AlertRuleEventType(rule.EventType),
		Severity:      generated.AlertRuleSeverity(rule.Severity),
		Condition:     rule.Condition,
		Target:        rule.Target,
		CreatedAt:     rule.CreatedAt,
		UpdatedAt:     rule.UpdatedAt,
	}
}

func controlAlertRuleFromOpenAPI(rule generated.AlertRuleInput) control.AlertRule {
	output := control.AlertRule{
		Name:      rule.Name,
		Enabled:   rule.Enabled,
		EventType: string(rule.EventType),
		Severity:  string(rule.Severity),
		Target:    rule.Target,
	}
	if rule.ApplicationId != nil {
		output.ApplicationID = *rule.ApplicationId
	}
	if rule.Description != nil {
		output.Description = *rule.Description
	}
	if rule.Condition != nil {
		output.Condition = *rule.Condition
	}
	return output
}

func openAPIAlertDeliveries(deliveries []control.AlertDelivery) []generated.AlertDelivery {
	result := make([]generated.AlertDelivery, 0, len(deliveries))
	for _, delivery := range deliveries {
		result = append(result, openAPIAlertDelivery(delivery))
	}
	return result
}

func openAPIAlertDelivery(delivery control.AlertDelivery) generated.AlertDelivery {
	var lastError *string
	if delivery.LastError != "" {
		lastError = &delivery.LastError
	}
	var applicationID *string
	if delivery.ApplicationID != "" {
		applicationID = &delivery.ApplicationID
	}
	return generated.AlertDelivery{
		Id:            delivery.ID,
		ApplicationId: applicationID,
		AlertRuleId:   delivery.AlertRuleID,
		AlertRuleName: delivery.AlertRuleName,
		EventId:       delivery.EventID,
		EventType:     generated.AlertDeliveryEventType(delivery.EventType),
		Severity:      generated.AlertDeliverySeverity(delivery.Severity),
		Target:        delivery.Target,
		Status:        generated.AlertDeliveryStatus(delivery.Status),
		Attempts:      delivery.Attempts,
		LastError:     lastError,
		CreatedAt:     delivery.CreatedAt,
		DeliveredAt:   delivery.DeliveredAt,
	}
}

func copyStringIntMap(values map[string]int) map[string]int {
	copied := make(map[string]int, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

func copyStringAnyMap(values map[string]any) map[string]interface{} {
	copied := make(map[string]interface{}, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}
