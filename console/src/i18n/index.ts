import { useSyncExternalStore } from "react";
import { messages } from "./messages";

/**
 * Lightweight i18n. Keys are the English source text (English-as-key), so the
 * English locale needs no table and new strings are visible in code. Chinese and
 * Japanese tables live in messages.ts.
 *
 * SPEC (enforced for all future UI work):
 *  - Every user-facing string MUST be rendered through `t()` / <T>.
 *  - When you add an English string, add its `zh` and `ja` entries to messages.ts.
 *  - Run `npm run i18n:check` to verify no locale is missing a key.
 */
export const supportedLanguages = [
  { code: "en", nativeLabel: "English" },
  { code: "zh", nativeLabel: "中文" },
  { code: "ja", nativeLabel: "日本語" }
] as const;

export type Lang = (typeof supportedLanguages)[number]["code"];

const STORAGE_KEY = "ohmyrasp.console.lang";
const codes = supportedLanguages.map((l) => l.code) as readonly string[];

function normalize(value: string | null | undefined): Lang | undefined {
  if (!value) return undefined;
  const base = value.toLowerCase().split("-")[0];
  return codes.includes(base) ? (base as Lang) : undefined;
}

function detect(): Lang {
  if (typeof window === "undefined") return "en";
  return normalize(localStorage.getItem(STORAGE_KEY)) ?? normalize(navigator.language) ?? "en";
}

let current: Lang = detect();
const listeners = new Set<() => void>();

function syncDocument() {
  if (typeof document !== "undefined") document.documentElement.lang = current;
}
syncDocument();

export function currentLang(): Lang {
  return current;
}

export function setLang(lang: Lang) {
  if (lang === current) return;
  current = lang;
  localStorage.setItem(STORAGE_KEY, lang);
  syncDocument();
  for (const l of listeners) l();
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export type Vars = Record<string, string | number>;

function interpolate(template: string, vars?: Vars): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, k: string) => (k in vars ? String(vars[k]) : `{${k}}`));
}

/** Non-reactive translate — for use outside React render. Prefer useT() in components. */
export function translate(key: string, vars?: Vars, lang: Lang = current): string {
  const table = messages[lang];
  const value = lang === "en" ? key : (table && table[key]) || key;
  return interpolate(value, vars);
}

export function useLang(): Lang {
  return useSyncExternalStore(subscribe, currentLang, currentLang);
}

/** React hook returning a translate function bound to the live language. */
export function useT(): (key: string, vars?: Vars) => string {
  const lang = useLang();
  return (key: string, vars?: Vars) => translate(key, vars, lang);
}
