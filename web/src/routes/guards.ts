import { redirect } from "@tanstack/react-router";
import { currentSession, type SessionSnapshot } from "../lib/api";

export type RequiredRole = "admin" | "security_engineer";

export function requireSession() {
  const session = currentSession();
  if (!session.token) {
    throw redirect({ to: "/login" });
  }
  return session;
}

export function requireRoles(roles: RequiredRole[]) {
  const session = requireSession();
  if (!canAccess(session, roles)) {
    throw redirect({ to: "/noaccess" });
  }
}

export function canAccess(session: SessionSnapshot, roles: RequiredRole[]) {
  if (roles.length === 0) {
    return Boolean(session.token);
  }
  return roles.some(role => session.roles.includes(role));
}
