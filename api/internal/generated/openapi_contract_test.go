package generated

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGeneratedOpenAPIIsCurrent(t *testing.T) {
	root := moduleRoot(t)
	tempDir := t.TempDir()
	tempConfig := filepath.Join(tempDir, "oapi-codegen.yaml")
	tempOutput := filepath.Join(tempDir, "openapi.gen.go")
	config, err := os.ReadFile(filepath.Join(root, "api", "oapi-codegen.yaml"))
	if err != nil {
		t.Fatalf("read codegen config: %v", err)
	}
	config = bytes.Replace(config, []byte("output: internal/generated/openapi.gen.go"), []byte("output: "+filepath.ToSlash(tempOutput)), 1)
	if err := os.WriteFile(tempConfig, config, 0o600); err != nil {
		t.Fatalf("write temp codegen config: %v", err)
	}
	command := exec.Command("go", "run", "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen", "-config", tempConfig, filepath.Join(root, "api", "openapi.yaml"))
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run oapi-codegen: %v\n%s", err, output)
	}
	want, err := os.ReadFile(filepath.Join(root, "internal", "generated", "openapi.gen.go"))
	if err != nil {
		t.Fatalf("read checked-in generated file: %v", err)
	}
	got, err := os.ReadFile(tempOutput)
	if err != nil {
		t.Fatalf("read regenerated file: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("generated OpenAPI code is stale; run go generate ./...")
	}
	if !strings.Contains(string(output), "OpenAPI 3.1") {
		t.Logf("oapi-codegen output: %s", output)
	}
}

func TestGeneratedContractsCoverControlPlaneResponses(t *testing.T) {
	now := time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC)
	target := "security-operations"

	login := PostApiV1AuthLogin200JSONResponse{
		Session: Session{
			Token:     "sess_contract",
			UserId:    "usr_contract",
			ExpiresAt: now.Add(8 * time.Hour),
		},
		User: User{
			Id:        "usr_contract",
			Email:     "admin@example.test",
			Name:      "Default Admin",
			Roles:     []UserRoles{UserRolesAdmin},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	if login.Session.UserId != login.User.Id || !login.User.Roles[0].Valid() {
		t.Fatalf("unexpected login contract: %#v", login)
	}
	me := GetApiV1Me200JSONResponse{User: login.User}
	if me.User.Email != "admin@example.test" {
		t.Fatalf("unexpected me contract: %#v", me)
	}

	description := "PCI scoped service"
	appCreate := PostApiV1ApplicationsJSONRequestBody{
		Name:        "Payments API",
		Description: &description,
	}
	appSecret := "app_secret_contract"
	appResponse := PostApiV1Applications201JSONResponse{
		Id:             "app_contract",
		Name:           appCreate.Name,
		Description:    *appCreate.Description,
		Secret:         &appSecret,
		CreatedAt:      now,
		EnvironmentIds: []string{"env_contract"},
	}
	if appResponse.Secret == nil || len(appResponse.EnvironmentIds) != 1 {
		t.Fatalf("unexpected application contract: %#v", appResponse)
	}
	rotatedAppSecret := "rotated_app_secret_contract"
	rotatedApp := PostApiV1ApplicationsAppIDSecretRotate200JSONResponse{
		Id:             appResponse.Id,
		Name:           appResponse.Name,
		Description:    appResponse.Description,
		Secret:         &rotatedAppSecret,
		CreatedAt:      appResponse.CreatedAt,
		EnvironmentIds: appResponse.EnvironmentIds,
	}
	if rotatedApp.Secret == nil || *rotatedApp.Secret == *appResponse.Secret {
		t.Fatalf("unexpected application secret rotation contract: %#v", rotatedApp)
	}

	environmentKind := "staging"
	environmentCreate := PostApiV1ApplicationsAppIDEnvironmentsJSONRequestBody{
		Name: "staging",
		Kind: &environmentKind,
	}
	environmentResponse := PostApiV1ApplicationsAppIDEnvironments201JSONResponse{
		Id:            "env_contract",
		ApplicationId: "app_contract",
		Name:          environmentCreate.Name,
		Kind:          *environmentCreate.Kind,
		CreatedAt:     now,
	}
	if environmentResponse.ApplicationId != "app_contract" {
		t.Fatalf("unexpected environment contract: %#v", environmentResponse)
	}

	runtime := "java"
	agentCreate := PostApiV1AgentsRegisterJSONRequestBody{
		EnvironmentId: "env_contract",
		Hostname:      "payments-1",
		Runtime:       &runtime,
		Version:       "1.0.0",
	}
	agentResponse := PostApiV1AgentsRegister201JSONResponse{
		Id:            "agt_contract",
		ApplicationId: "app_contract",
		EnvironmentId: agentCreate.EnvironmentId,
		Hostname:      agentCreate.Hostname,
		Runtime:       *agentCreate.Runtime,
		Version:       agentCreate.Version,
		Status:        "online",
		LastSeenAt:    now,
	}
	heartbeat := PostApiV1AgentsAgentIDHeartbeatJSONRequestBody{Status: "online"}
	heartbeatParams := PostApiV1AgentsAgentIDHeartbeatParams{XOhMyRaspAppID: "app_contract", XOhMyRaspAppSecret: "app_secret_contract"}
	heartbeatResponse := PostApiV1AgentsAgentIDHeartbeat200JSONResponse(agentResponse)
	policyPullParams := GetApiV1AgentsAgentIDPolicyParams{XOhMyRaspAppID: "app_contract", XOhMyRaspAppSecret: "app_secret_contract"}
	if heartbeat.Status != heartbeatResponse.Status || heartbeatParams.XOhMyRaspAppID != agentResponse.ApplicationId || policyPullParams.XOhMyRaspAppSecret == "" {
		t.Fatalf("unexpected Agent operation contract: %#v %#v %#v", heartbeat, heartbeatParams, policyPullParams)
	}
	daemonToken := GetApiV1DaemonToken200JSONResponse{AccessToken: "daemon_token_contract", UpdatedAt: now}
	daemonReportParams := PostApiV1DaemonWorkloadsReportParams{XOhMyRaspDaemonToken: daemonToken.AccessToken}
	daemonCmdline := []string{"/usr/bin/java", "-jar", "app.jar"}
	daemonPID := 4242
	daemonReport := PostApiV1DaemonWorkloadsReportJSONRequestBody{
		NodeName: "node-a",
		Workloads: []DaemonWorkloadInput{{
			Type:    DaemonWorkloadInputTypeProcess,
			Pid:     &daemonPID,
			Cmdline: &daemonCmdline,
		}},
	}
	daemonResponse := PostApiV1DaemonWorkloadsReport200JSONResponse{
		Items: []DaemonWorkload{{
			Id:         "wrk_contract",
			NodeName:   daemonReport.NodeName,
			Type:       DaemonWorkloadTypeProcess,
			Pid:        &daemonPID,
			Cmdline:    &daemonCmdline,
			ObservedAt: now,
			UpdatedAt:  now,
		}},
	}
	daemonBinding := PostApiV1DaemonWorkloadsWorkloadIDBindJSONRequestBody{ApplicationId: appResponse.Id}
	boundAppID := daemonBinding.ApplicationId
	daemonBound := PostApiV1DaemonWorkloadsWorkloadIDBind200JSONResponse(daemonResponse.Items[0])
	daemonBound.ApplicationId = &boundAppID
	daemonUnbound := PostApiV1DaemonWorkloadsWorkloadIDUnbind200JSONResponse(daemonResponse.Items[0])
	daemonInjectionError := "jattach permission denied"
	daemonInjectionHelper := "helper-node-a"
	daemonInjectionVersion := "1.2.3"
	daemonInjectionReport := PostApiV1DaemonInjectionReportsJSONRequestBody{
		WorkloadId:    daemonResponse.Items[0].Id,
		Status:        DaemonInjectionReportStatusFailed,
		Error:         &daemonInjectionError,
		HelperId:      &daemonInjectionHelper,
		HelperVersion: &daemonInjectionVersion,
		ReportedAt:    &now,
	}
	daemonInjectionParams := PostApiV1DaemonInjectionReportsParams{XOhMyRaspDaemonToken: daemonToken.AccessToken}
	injectionStatus := DaemonWorkloadInjectionStatusFailed
	daemonInjectionResponse := PostApiV1DaemonInjectionReports200JSONResponse(daemonResponse.Items[0])
	daemonInjectionResponse.InjectionStatus = &injectionStatus
	daemonInjectionResponse.InjectionError = &daemonInjectionError
	daemonInjectionResponse.InjectionHelperId = &daemonInjectionHelper
	daemonInjectionResponse.InjectionHelperVersion = &daemonInjectionVersion
	daemonInjectionResponse.InjectionReportedAt = &now
	daemonInjectionResponse.InjectionStatusUpdatedAt = &now
	daemonCommandsParams := GetApiV1DaemonCommandsParams{XOhMyRaspDaemonToken: daemonToken.AccessToken}
	daemonCommands := GetApiV1DaemonCommands200JSONResponse{
		Items: []DaemonCommandGroup{{
			ApplicationId:     appResponse.Id,
			ApplicationSecret: *appResponse.Secret,
			Language:          DaemonCommandGroupLanguageJava,
			Workloads:         daemonResponse.Items,
		}},
	}
	daemonAppParams := GetApiV1DaemonAppParams{AppId: appResponse.Id, XOhMyRaspDaemonToken: daemonToken.AccessToken}
	daemonApp := GetApiV1DaemonApp200JSONResponse{
		ApplicationId:     appResponse.Id,
		ApplicationSecret: *appResponse.Secret,
		Language:          DaemonApplicationLanguageJava,
	}
	systemType := "linux"
	languageVersion := "unknown"
	daemonArtifactInfoParams := GetApiV1DaemonArtifactsAgentInfoParams{
		AppId:                appResponse.Id,
		Language:             GetApiV1DaemonArtifactsAgentInfoParamsLanguageJava,
		SystemType:           &systemType,
		LanguageVersion:      &languageVersion,
		XOhMyRaspDaemonToken: daemonToken.AccessToken,
	}
	daemonArtifactInfo := GetApiV1DaemonArtifactsAgentInfo200JSONResponse{
		Filename:        "ohmyrasp-agent-java-linux-unknown.zip",
		ContentType:     "application/zip",
		Md5:             "0123456789abcdef0123456789abcdef",
		Size:            128,
		Language:        AgentArtifactInfoLanguageJava,
		SystemType:      systemType,
		LanguageVersion: languageVersion,
	}
	daemonArtifactParams := GetApiV1DaemonArtifactsAgentParams{
		AppId:                appResponse.Id,
		Language:             GetApiV1DaemonArtifactsAgentParamsLanguageJava,
		SystemType:           &systemType,
		LanguageVersion:      &languageVersion,
		XOhMyRaspDaemonToken: daemonToken.AccessToken,
	}
	daemonArtifact := GetApiV1DaemonArtifactsAgent200ApplicationzipResponse{Body: bytes.NewBufferString("zip"), ContentLength: 3}
	artifactCatalog := GetApiV1AgentArtifacts200JSONResponse{
		ArtifactDirConfigured:     true,
		GeneratedBootstrapEnabled: true,
		Items: []AgentArtifactCatalogItem{{
			Filename:        "agent-java-linux-unknown.zip",
			ContentType:     "application/zip",
			Md5:             "0123456789abcdef0123456789abcdef",
			Size:            128,
			Language:        "java",
			SystemType:      systemType,
			LanguageVersion: languageVersion,
			Source:          "filesystem",
			UpdatedAt:       now,
		}},
	}
	artifactUpload := PostApiV1AgentArtifactsJSONRequestBody{
		Filename:        &daemonArtifactInfo.Filename,
		Language:        AgentArtifactUploadLanguageJava,
		SystemType:      systemType,
		LanguageVersion: languageVersion,
		ContentBase64:   "UEsDBAoAAAAAA",
	}
	artifactUploadResponse := PostApiV1AgentArtifacts201JSONResponse{
		Filename:        "ohmyrasp-agent-java-linux-unknown.zip",
		ContentType:     "application/zip",
		Md5:             daemonArtifactInfo.Md5,
		Size:            128,
		Language:        "java",
		SystemType:      systemType,
		LanguageVersion: languageVersion,
		Source:          "uploaded",
		UpdatedAt:       now,
	}
	if !daemonResponse.Items[0].Type.Valid() || !daemonReport.Workloads[0].Type.Valid() || daemonReportParams.XOhMyRaspDaemonToken == "" || daemonInjectionParams.XOhMyRaspDaemonToken == "" || !daemonInjectionReport.Status.Valid() || daemonInjectionResponse.InjectionStatus == nil || !(*daemonInjectionResponse.InjectionStatus).Valid() || daemonCommandsParams.XOhMyRaspDaemonToken == "" || daemonBound.ApplicationId == nil || daemonUnbound.ApplicationId != nil || !daemonCommands.Items[0].Language.Valid() || daemonCommands.Items[0].ApplicationSecret == "" || daemonAppParams.AppId == "" || !daemonApp.Language.Valid() || daemonApp.ApplicationSecret == "" || !daemonArtifactInfoParams.Language.Valid() || !daemonArtifactInfo.Language.Valid() || daemonArtifactInfo.Md5 == "" || !daemonArtifactParams.Language.Valid() || daemonArtifact.ContentLength == 0 || artifactCatalog.Items[0].Source != "filesystem" || !artifactUpload.Language.Valid() || artifactUpload.ContentBase64 == "" || artifactUploadResponse.Source != "uploaded" {
		t.Fatalf("unexpected daemon inventory contract: %#v %#v %#v %#v %#v %#v %#v %#v", daemonReport, daemonResponse, daemonBound, daemonUnbound, daemonInjectionResponse, daemonCommands, daemonApp, daemonArtifactInfo)
	}

	algorithm := "sql_userinput"
	severity := "high"
	tags := []string{"sql", "user-input"}
	action := Block
	rule := RuleInput{
		Name:        "Block SQL user input",
		Hook:        "sql",
		Algorithm:   &algorithm,
		Action:      &action,
		Severity:    &severity,
		Expression:  "' OR '1'='1",
		Tags:        &tags,
		Description: &description,
	}
	if !(*rule.Action).Valid() {
		t.Fatalf("expected generated rule action enum to be valid")
	}
	policyCreate := PostApiV1PoliciesJSONRequestBody{Name: "Default Web Protection"}
	policyVersion := PostApiV1PoliciesPolicyIDVersionsJSONRequestBody{Rules: []RuleInput{rule}}
	policyRulesUpdate := PutApiV1PoliciesPolicyIDVersionsVersionRulesJSONRequestBody{Rules: []RuleInput{rule}}
	ruleValidation := PostApiV1PoliciesValidate200JSONResponse{Valid: true, Errors: []string{}}
	ruleTest := PostApiV1PoliciesTest200JSONResponse{Matched: true, Action: string(action), Algorithm: algorithm, Confidence: 80}
	rolloutApplication := "app_contract"
	rollout := PostApiV1PoliciesPolicyIDRolloutJSONRequestBody{Version: 1, CanaryPercent: 25, ApplicationId: &rolloutApplication}
	policyResponse := PostApiV1PoliciesPolicyIDVersions201JSONResponse{
		Id:          "pol_contract",
		Name:        policyCreate.Name,
		Description: "",
		CreatedAt:   now,
		Versions: []PolicyVersion{
			{
				Version:       1,
				Status:        "draft",
				Rules:         []Rule{{Id: "rul_contract", Name: rule.Name, Hook: rule.Hook, Algorithm: algorithm, Action: string(action), Severity: severity, Expression: rule.Expression, Tags: tags, Description: description}},
				CanaryPercent: rollout.CanaryPercent,
				CreatedAt:     now,
			},
		},
	}
	if len(policyVersion.Rules) != 1 || len(policyRulesUpdate.Rules) != 1 || !ruleValidation.Valid || !ruleTest.Matched || len(policyResponse.Versions) != 1 || rollout.ApplicationId == nil {
		t.Fatalf("unexpected policy contract: %#v %#v %#v %#v %#v", policyVersion, policyRulesUpdate, ruleValidation, ruleTest, policyResponse)
	}

	eventHook := "sql"
	attrs := map[string]interface{}{"path": "/checkout"}
	reportParams := PostApiV1EventsAttackParams{XOhMyRaspAppID: "app_contract", XOhMyRaspAppSecret: "app_secret_contract"}
	eventCreate := PostApiV1EventsAttackJSONRequestBody{
		ApplicationId: "app_contract",
		EnvironmentId: "env_contract",
		AgentId:       "agt_contract",
		Hook:          &eventHook,
		Algorithm:     &algorithm,
		Severity:      "critical",
		Message:       "SQL injection probe detected",
		Attributes:    &attrs,
	}
	eventResponse := PostApiV1EventsAttack202JSONResponse{
		Id:            "evt_contract",
		Type:          SecurityEventTypeAttack,
		ApplicationId: eventCreate.ApplicationId,
		EnvironmentId: eventCreate.EnvironmentId,
		AgentId:       eventCreate.AgentId,
		Hook:          eventCreate.Hook,
		Algorithm:     eventCreate.Algorithm,
		Severity:      eventCreate.Severity,
		Message:       eventCreate.Message,
		OccurredAt:    now,
		Attributes:    eventCreate.Attributes,
	}
	if !eventResponse.Type.Valid() || eventResponse.Attributes == nil {
		t.Fatalf("unexpected event contract: %#v", eventResponse)
	}
	if reportParams.XOhMyRaspAppID != eventCreate.ApplicationId || reportParams.XOhMyRaspAppSecret == "" {
		t.Fatalf("unexpected event report params: %#v", reportParams)
	}
	eventLimit := EventLimit(50)
	eventQueryParams := GetApiV1EventsAttackParams{
		ApplicationId:  &eventCreate.ApplicationId,
		EnvironmentId:  &eventCreate.EnvironmentId,
		AgentId:        &eventCreate.AgentId,
		Severity:       &eventCreate.Severity,
		Hook:           eventCreate.Hook,
		OccurredAfter:  &now,
		OccurredBefore: &now,
		Limit:          &eventLimit,
	}
	if eventQueryParams.ApplicationId == nil || eventQueryParams.Limit == nil || *eventQueryParams.Limit != eventLimit {
		t.Fatalf("unexpected event query params: %#v", eventQueryParams)
	}
	recycleType := GetApiV1EventsRecycleBinParamsTypeAttack
	recycleQueryParams := GetApiV1EventsRecycleBinParams{
		Type:          &recycleType,
		ApplicationId: &eventCreate.ApplicationId,
		Limit:         &eventLimit,
	}
	recycleAction := EventRecycleBinAction{Ids: []string{eventResponse.Id}}
	recycleReport := PostApiV1EventsRecycleBinDelete200JSONResponse{
		Ids:   recycleAction.Ids,
		Count: 1,
	}
	deletedBy := "usr_contract"
	recycledEvent := GetApiV1EventsRecycleBin200JSONResponse{
		Items: []SecurityEvent{{
			Id:            eventResponse.Id,
			Type:          SecurityEventTypeAttack,
			ApplicationId: eventResponse.ApplicationId,
			EnvironmentId: eventResponse.EnvironmentId,
			AgentId:       eventResponse.AgentId,
			Severity:      eventResponse.Severity,
			Message:       eventResponse.Message,
			OccurredAt:    eventResponse.OccurredAt,
			DeletedAt:     &now,
			DeletedBy:     &deletedBy,
		}},
	}
	if recycleQueryParams.Type == nil || !recycleQueryParams.Type.Valid() || recycleReport.Count != 1 || recycledEvent.Items[0].DeletedAt == nil {
		t.Fatalf("unexpected recycle-bin contract: %#v %#v %#v", recycleQueryParams, recycleReport, recycledEvent)
	}

	dependencyVersion := "2.17.2"
	ecosystem := "maven"
	dependencyAgent := "agt_contract"
	packagePath := "org/apache/logging/log4j/log4j-core/2.17.2/log4j-core-2.17.2.jar"
	dependencyLicenses := []string{"Apache-2.0"}
	dependencyVulnerabilities := []DependencyVulnerability{{
		Id:       "CVE-2021-45046",
		Severity: DependencyVulnerabilitySeverityHigh,
	}}
	dependencyParams := PostApiV1DependenciesParams{XOhMyRaspAppID: "app_contract", XOhMyRaspAppSecret: "app_secret_contract"}
	dependencyCreate := PostApiV1DependenciesJSONRequestBody{
		ApplicationId:   "app_contract",
		AgentId:         &dependencyAgent,
		Name:            "log4j-core",
		Version:         &dependencyVersion,
		Ecosystem:       &ecosystem,
		PackagePath:     &packagePath,
		Licenses:        &dependencyLicenses,
		Vulnerabilities: &dependencyVulnerabilities,
		ObservedAt:      &now,
	}
	dependencyResponse := PostApiV1Dependencies202JSONResponse{
		Id:              "dep_contract",
		ApplicationId:   dependencyCreate.ApplicationId,
		AgentId:         dependencyAgent,
		Name:            dependencyCreate.Name,
		Version:         *dependencyCreate.Version,
		Ecosystem:       *dependencyCreate.Ecosystem,
		PackagePath:     dependencyCreate.PackagePath,
		Licenses:        dependencyCreate.Licenses,
		Vulnerabilities: dependencyCreate.Vulnerabilities,
		ObservedAt:      *dependencyCreate.ObservedAt,
	}
	if dependencyResponse.Name != dependencyCreate.Name || dependencyResponse.Vulnerabilities == nil || len(*dependencyResponse.Vulnerabilities) != 1 {
		t.Fatalf("unexpected dependency contract: %#v", dependencyResponse)
	}
	if dependencyParams.XOhMyRaspAppID != dependencyCreate.ApplicationId || dependencyParams.XOhMyRaspAppSecret == "" {
		t.Fatalf("unexpected dependency report params: %#v", dependencyParams)
	}
	dependencyLimit := DependencyLimit(25)
	vulnerabilitySeverity := GetApiV1DependenciesParamsVulnerabilitySeverityHigh
	dependencyQueryParams := GetApiV1DependenciesParams{
		ApplicationId:         &dependencyCreate.ApplicationId,
		AgentId:               dependencyCreate.AgentId,
		Name:                  &dependencyCreate.Name,
		Ecosystem:             dependencyCreate.Ecosystem,
		VulnerabilitySeverity: &vulnerabilitySeverity,
		ObservedAfter:         &now,
		ObservedBefore:        &now,
		Limit:                 &dependencyLimit,
	}
	if dependencyQueryParams.Name == nil || dependencyQueryParams.Ecosystem == nil || dependencyQueryParams.VulnerabilitySeverity == nil || dependencyQueryParams.Limit == nil || *dependencyQueryParams.Limit != dependencyLimit {
		t.Fatalf("unexpected dependency query params: %#v", dependencyQueryParams)
	}

	baselineCategory := "runtime"
	baselineResource := "contract-agent"
	baselineRemediation := "Enable explicit runtime hardening before rollout."
	baselineAttributes := map[string]interface{}{"runtime": "java"}
	baselineParams := PostApiV1BaselineFindingsParams{XOhMyRaspAppID: "app_contract", XOhMyRaspAppSecret: "app_secret_contract"}
	baselineCreate := PostApiV1BaselineFindingsJSONRequestBody{
		ApplicationId: "app_contract",
		EnvironmentId: "env_contract",
		AgentId:       dependencyAgent,
		CheckId:       "jvm.security_manager",
		Title:         "JVM security manager disabled",
		Category:      &baselineCategory,
		Severity:      BaselineFindingInputSeverityMedium,
		Status:        BaselineFindingInputStatusWarning,
		Resource:      &baselineResource,
		Remediation:   &baselineRemediation,
		Attributes:    &baselineAttributes,
		ObservedAt:    &now,
	}
	baselineResponse := PostApiV1BaselineFindings202JSONResponse{
		Id:            "bsl_contract",
		ApplicationId: baselineCreate.ApplicationId,
		EnvironmentId: baselineCreate.EnvironmentId,
		AgentId:       baselineCreate.AgentId,
		CheckId:       baselineCreate.CheckId,
		Title:         baselineCreate.Title,
		Category:      *baselineCreate.Category,
		Severity:      BaselineFindingSeverityMedium,
		Status:        BaselineFindingStatusWarning,
		Resource:      *baselineCreate.Resource,
		Remediation:   baselineCreate.Remediation,
		Attributes:    baselineCreate.Attributes,
		ObservedAt:    *baselineCreate.ObservedAt,
	}
	if baselineResponse.CheckId != baselineCreate.CheckId || baselineResponse.Attributes == nil || !baselineResponse.Severity.Valid() || !baselineResponse.Status.Valid() {
		t.Fatalf("unexpected baseline finding contract: %#v", baselineResponse)
	}
	if baselineParams.XOhMyRaspAppID != baselineCreate.ApplicationId || baselineParams.XOhMyRaspAppSecret == "" {
		t.Fatalf("unexpected baseline report params: %#v", baselineParams)
	}
	baselineLimit := BaselineLimit(25)
	baselineSeverity := GetApiV1BaselineFindingsParamsSeverityMedium
	baselineStatus := GetApiV1BaselineFindingsParamsStatusWarning
	baselineQueryParams := GetApiV1BaselineFindingsParams{
		ApplicationId:  &baselineCreate.ApplicationId,
		EnvironmentId:  &baselineCreate.EnvironmentId,
		AgentId:        &baselineCreate.AgentId,
		Severity:       &baselineSeverity,
		Status:         &baselineStatus,
		Category:       baselineCreate.Category,
		ObservedAfter:  &now,
		ObservedBefore: &now,
		Limit:          &baselineLimit,
	}
	if baselineQueryParams.Severity == nil || baselineQueryParams.Status == nil || baselineQueryParams.Limit == nil || *baselineQueryParams.Limit != baselineLimit {
		t.Fatalf("unexpected baseline query params: %#v", baselineQueryParams)
	}

	overview := GetApiV1AnalyticsOverview200JSONResponse{
		ApplicationCount: 1,
		AgentCount:       1,
		OnlineAgents:     1,
		EventCount:       1,
		EventsByType:     map[string]int{"attack": 1},
		EventsBySeverity: map[string]int{"critical": 1},
	}
	editionNote := "Open-source self-hosted deployments do not require a license key."
	edition := GetApiV1SystemEdition200JSONResponse{
		Edition:            OssSelfHosted,
		DisplayName:        "Open Source Self-Hosted",
		DeploymentModel:    SingleOrganizationSelfHosted,
		LicenseRequired:    false,
		LicenseEnforcement: None,
		LicenseStatus:      NotApplicable,
		Note:               &editionNote,
	}
	details := map[string]interface{}{"application_id": "app_contract"}
	audit := GetApiV1AuditLogs200JSONResponse{
		Items: []AuditLog{{Id: "aud_contract", ActorId: "usr_contract", Action: "application.create", Resource: "app_contract", Details: &details, CreatedAt: now}},
	}
	cleanupApplicationID := "app_contract"
	cleanupDryRun := true
	cleanupIncludeDependencies := true
	cleanupConfirmation := "CLEAR_OPERATIONAL_DATA"
	cleanupRequest := PostApiV1MaintenanceCleanupJSONRequestBody{
		ApplicationId:       &cleanupApplicationID,
		Before:              now,
		DryRun:              &cleanupDryRun,
		IncludeDependencies: &cleanupIncludeDependencies,
		Confirmation:        &cleanupConfirmation,
	}
	cleanupReport := PostApiV1MaintenanceCleanup200JSONResponse{
		ApplicationId: cleanupRequest.ApplicationId,
		Before:        now,
		DryRun:        cleanupDryRun,
		Counts:        map[string]int{"events": 1, "dependencies": 1},
	}
	if overview.EventsByType["attack"] != 1 || len(audit.Items) != 1 || cleanupRequest.Before.IsZero() || cleanupReport.Counts["events"] != 1 || edition.LicenseRequired || !edition.Edition.Valid() || !edition.LicenseStatus.Valid() {
		t.Fatalf("unexpected overview/edition/audit/maintenance contract: %#v %#v %#v %#v %#v", overview, edition, audit, cleanupRequest, cleanupReport)
	}

	encoded, err := json.Marshal(GetApiV1AlertDeliveries200JSONResponse{
		Items: []AlertDelivery{
			{
				Id:            "adl_contract",
				AlertRuleId:   "alr_critical_attack",
				AlertRuleName: "Critical attack event",
				EventId:       "evt_contract",
				EventType:     AlertDeliveryEventTypeAttack,
				Severity:      AlertDeliverySeverityCritical,
				Target:        target,
				Status:        AlertDeliveryStatusQueued,
				Attempts:      0,
				CreatedAt:     now,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal alert delivery response: %v", err)
	}
	var decoded AlertDeliveryList
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode alert delivery response: %v", err)
	}
	if len(decoded.Items) != 1 || decoded.Items[0].Target != target || !decoded.Items[0].Status.Valid() {
		t.Fatalf("unexpected decoded alert delivery contract: %#v", decoded)
	}

	userCreate := PostApiV1UsersJSONRequestBody{
		Email:    "security@example.test",
		Name:     "Security Engineer",
		Password: "change-me-2",
		Roles:    []UserCreateRoles{UserCreateRolesSecurityEngineer},
	}
	if !userCreate.Roles[0].Valid() {
		t.Fatalf("expected generated user role enum to be valid")
	}

	alertRule := PostApiV1AlertRulesJSONRequestBody{
		Name:      "Critical attack event",
		Enabled:   true,
		EventType: AlertRuleInputEventTypeAttack,
		Severity:  AlertRuleInputSeverityCritical,
		Target:    target,
	}
	if !alertRule.EventType.Valid() || !alertRule.Severity.Valid() {
		t.Fatalf("expected generated alert rule enums to be valid")
	}

	report := GetApiV1AnalyticsObservability200JSONResponse{
		RuleOverhead: []RuleOverhead{{PolicyId: "pol_web", PolicyVersion: 1, RuleId: "rul_sql", Hook: "sql", Executions: 12, Blocked: 1, AverageLatencyUs: 410, P95LatencyUs: 1800, MaxLatencyUs: 4200}},
		HookLatency:  []HookLatency{{Hook: "sql", Calls: 12, AverageLatencyUs: 410, P95LatencyUs: 1800, MaxLatencyUs: 4200}},
		AgentOverhead: []AgentOverhead{{
			AgentId:             "agt_contract",
			Samples:             12,
			CpuOverheadPct:      1.2,
			MemoryOverheadBytes: 64 * 1024 * 1024,
			HookLatencyP95Us:    1800,
			RuleEvalP95Us:       900,
		}},
		PolicyPerformance: []PolicyPerformance{{PolicyId: "pol_web", PolicyVersion: 1, Samples: 12, CpuOverheadPct: 1.2, HookLatencyP95Us: 1800, RuleEvalP95Us: 900}},
	}
	if len(report.RuleOverhead) != 1 || report.RuleOverhead[0].PolicyVersion != 1 {
		t.Fatalf("unexpected observability contract: %#v", report)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
