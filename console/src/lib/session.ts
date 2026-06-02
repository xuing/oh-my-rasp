import { useSyncExternalStore } from "react";

export type Role = "admin" | "security_engineer" | "viewer" | string;

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  roles: Role[];
}

export interface Session {
  token: string | null;
  user: SessionUser | null;
}

const STORAGE_KEY = "ohmyrasp.console.session";
const EVENT = "ohmyrasp.session.changed";

function read(): Session {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { token: null, user: null };
    return JSON.parse(raw) as Session;
  } catch {
    return { token: null, user: null };
  }
}

let current: Session = read();

const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
  window.dispatchEvent(new Event(EVENT));
}

export function currentSession(): Session {
  return current;
}

export function saveSession(session: Session): void {
  current = session;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  emit();
}

export function clearSession(): void {
  current = { token: null, user: null };
  localStorage.removeItem(STORAGE_KEY);
  emit();
}

export function authToken(): string | null {
  return current.token;
}

export function hasRole(...roles: Role[]): boolean {
  const owned = new Set(current.user?.roles ?? []);
  return roles.some((r) => owned.has(r));
}

export const isPrivileged = () => hasRole("admin", "security_engineer");

// Keep tabs in sync.
if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key === STORAGE_KEY) {
      current = read();
      for (const l of listeners) l();
    }
  });
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

/** React hook returning the live session. */
export function useSession(): Session {
  return useSyncExternalStore(subscribe, currentSession, currentSession);
}
