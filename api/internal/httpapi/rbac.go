package httpapi

import "github.com/ohmyrasp/control-plane/internal/control"

type permission string

const (
	permissionReadProfile         permission = "profile:read"
	permissionReadUsers           permission = "users:read"
	permissionManageUsers         permission = "users:manage"
	permissionReadApplications    permission = "applications:read"
	permissionManageApplications  permission = "applications:manage"
	permissionReadAgents          permission = "agents:read"
	permissionManageAgents        permission = "agents:manage"
	permissionReadDaemon          permission = "daemon:read"
	permissionManageDaemon        permission = "daemon:manage"
	permissionReadPolicies        permission = "policies:read"
	permissionManagePolicies      permission = "policies:manage"
	permissionEvaluatePolicies    permission = "policies:evaluate"
	permissionReadEvents          permission = "events:read"
	permissionManageEvents        permission = "events:manage"
	permissionReadAnalytics       permission = "analytics:read"
	permissionReadSettings        permission = "settings:read"
	permissionManageSettings      permission = "settings:manage"
	permissionReadAlertRules      permission = "alert_rules:read"
	permissionManageAlertRules    permission = "alert_rules:manage"
	permissionReadAlertDeliveries permission = "alert_deliveries:read"
	permissionReadAuditLogs       permission = "audit_logs:read"
)

var permissionMatrix = map[permission][]control.Role{
	permissionReadProfile:         allHumanRoles(),
	permissionReadUsers:           {control.RoleAdmin},
	permissionManageUsers:         {control.RoleAdmin},
	permissionReadApplications:    allHumanRoles(),
	permissionManageApplications:  {control.RoleAdmin, control.RoleSecurityEngineer},
	permissionReadAgents:          allHumanRoles(),
	permissionManageAgents:        {control.RoleAdmin, control.RoleSecurityEngineer},
	permissionReadDaemon:          allHumanRoles(),
	permissionManageDaemon:        {control.RoleAdmin, control.RoleSecurityEngineer},
	permissionReadPolicies:        allHumanRoles(),
	permissionManagePolicies:      {control.RoleAdmin, control.RoleSecurityEngineer},
	permissionEvaluatePolicies:    {control.RoleAdmin, control.RoleSecurityEngineer},
	permissionReadEvents:          allHumanRoles(),
	permissionManageEvents:        {control.RoleAdmin, control.RoleSecurityEngineer},
	permissionReadAnalytics:       allHumanRoles(),
	permissionReadSettings:        allHumanRoles(),
	permissionManageSettings:      {control.RoleAdmin, control.RoleSecurityEngineer},
	permissionReadAlertRules:      allHumanRoles(),
	permissionManageAlertRules:    {control.RoleAdmin, control.RoleSecurityEngineer},
	permissionReadAlertDeliveries: allHumanRoles(),
	permissionReadAuditLogs:       allHumanRoles(),
}

func allHumanRoles() []control.Role {
	return []control.Role{control.RoleAdmin, control.RoleSecurityEngineer, control.RoleViewer}
}

func userHasPermission(user control.User, want permission) bool {
	allowedRoles, ok := permissionMatrix[want]
	if !ok {
		return false
	}
	return hasAnyRole(user, allowedRoles)
}
