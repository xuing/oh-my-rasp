import { useSyncExternalStore } from "react";

export type Theme = "dark" | "light";

const STORAGE_KEY = "ohmyrasp.console.theme";

function detect(): Theme {
  if (typeof window === "undefined") return "dark";
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

let current: Theme = detect();
const listeners = new Set<() => void>();

/** Apply the theme to <html>. Dark is the default (no class); light adds `.light`. */
function apply() {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.toggle("light", current === "light");
  root.classList.toggle("dark", current === "dark");
  root.style.colorScheme = current;
}
apply();

export function currentTheme(): Theme {
  return current;
}

export function setTheme(theme: Theme) {
  if (theme === current) return;
  current = theme;
  localStorage.setItem(STORAGE_KEY, theme);
  apply();
  for (const l of listeners) l();
}

export function toggleTheme() {
  setTheme(current === "dark" ? "light" : "dark");
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, currentTheme, currentTheme);
}
