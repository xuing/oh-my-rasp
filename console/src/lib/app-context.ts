import { useSyncExternalStore } from "react";

/**
 * Global application context. The selected application (and optional environment
 * sub-scope) scopes the entire console — every data view filters by it. This is
 * the core of the application-centric information architecture.
 */
export interface AppScope {
  applicationId: string | null;
  environmentId: string | null;
}

const STORAGE_KEY = "ohmyrasp.console.scope";

function read(): AppScope {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { applicationId: null, environmentId: null };
    return JSON.parse(raw) as AppScope;
  } catch {
    return { applicationId: null, environmentId: null };
  }
}

let current: AppScope = read();
const listeners = new Set<() => void>();

function commit(next: AppScope) {
  current = next;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  for (const l of listeners) l();
}

export function currentScope(): AppScope {
  return current;
}

export function selectApplication(applicationId: string | null) {
  // Switching application resets the environment sub-scope.
  commit({ applicationId, environmentId: null });
}

export function selectEnvironment(environmentId: string | null) {
  commit({ ...current, environmentId });
}

/** Ensure a valid selection exists once applications are known. */
export function ensureApplication(validIds: string[]) {
  if (validIds.length === 0) {
    if (current.applicationId !== null) commit({ applicationId: null, environmentId: null });
    return;
  }
  if (!current.applicationId || !validIds.includes(current.applicationId)) {
    commit({ applicationId: validIds[0], environmentId: null });
  }
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useAppScope(): AppScope {
  return useSyncExternalStore(subscribe, currentScope, currentScope);
}
