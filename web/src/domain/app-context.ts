import { useSyncExternalStore } from "react";

export type AppContext = {
  applicationId: string | null;
  environmentId: string | null;
};

const storageKey = "ohmyrasp.app_context";
export const appContextChangedEvent = "ohmyrasp.app_context.changed";

const emptyContext: AppContext = {
  applicationId: null,
  environmentId: null
};
let cachedRaw: string | null | undefined;
let cachedContext: AppContext = emptyContext;

export function currentApplicationContext(): AppContext {
  if (typeof window === "undefined") {
    return emptyContext;
  }
  const raw = window.localStorage.getItem(storageKey);
  if (raw === cachedRaw) {
    return cachedContext;
  }
  cachedRaw = raw;
  if (!raw) {
    cachedContext = emptyContext;
    return cachedContext;
  }
  try {
    const parsed = JSON.parse(raw) as Partial<AppContext>;
    cachedContext = normalizeContext(parsed);
    return cachedContext;
  } catch {
    cachedContext = emptyContext;
    return cachedContext;
  }
}

export function setSelectedApplication(applicationId: string | null) {
  const current = currentApplicationContext();
  saveApplicationContext({
    applicationId: cleanID(applicationId),
    environmentId: cleanID(applicationId) === current.applicationId ? current.environmentId : null
  });
}

export function setSelectedEnvironment(environmentId: string | null) {
  saveApplicationContext({
    ...currentApplicationContext(),
    environmentId: cleanID(environmentId)
  });
}

export function useApplicationContext() {
  return useSyncExternalStore(subscribe, currentApplicationContext, () => emptyContext);
}

function subscribe(callback: () => void) {
  if (typeof window === "undefined") {
    return () => undefined;
  }
  window.addEventListener("storage", callback);
  window.addEventListener(appContextChangedEvent, callback);
  return () => {
    window.removeEventListener("storage", callback);
    window.removeEventListener(appContextChangedEvent, callback);
  };
}

function saveApplicationContext(context: AppContext) {
  if (typeof window === "undefined") {
    return;
  }
  const normalized = normalizeContext(context);
  if (!normalized.applicationId) {
    window.localStorage.removeItem(storageKey);
  } else {
    window.localStorage.setItem(storageKey, JSON.stringify(normalized));
  }
  window.dispatchEvent(new Event(appContextChangedEvent));
}

function normalizeContext(context: Partial<AppContext>): AppContext {
  const applicationId = cleanID(context.applicationId);
  return {
    applicationId,
    environmentId: applicationId ? cleanID(context.environmentId) : null
  };
}

function cleanID(value: string | null | undefined) {
  const normalized = value?.trim() ?? "";
  return normalized || null;
}
