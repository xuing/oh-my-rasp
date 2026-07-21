/**
 * i18n coverage check (run: `npm run i18n:check`).
 *
 * Enforces the i18n spec:
 *   1. zh and ja tables have identical key sets (parity).
 *   2. Every directly-quoted `t("…")` key in the source exists in both tables.
 *
 * Node 26 strips TypeScript types natively, so this runs without a build step.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { messages } from "../src/i18n/messages.ts";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (/\.tsx?$/.test(name) && !name.endsWith("messages.ts")) out.push(full);
  }
  return out;
}

// Extract keys from `t("…")` calls (handles escaped quotes).
const usedKeys = new Set<string>();
const callRe = /\bt\(\s*"((?:[^"\\]|\\.)*)"/g;
for (const file of walk(srcDir)) {
  const text = readFileSync(file, "utf8");
  let m: RegExpExecArray | null;
  while ((m = callRe.exec(text))) {
    usedKeys.add(m[1].replace(/\\"/g, '"'));
  }
}

const zh = new Set(Object.keys(messages.zh));
const ja = new Set(Object.keys(messages.ja));

const problems: string[] = [];

// 1. Parity between locales.
for (const k of zh) if (!ja.has(k)) problems.push(`ja missing key present in zh: "${k}"`);
for (const k of ja) if (!zh.has(k)) problems.push(`zh missing key present in ja: "${k}"`);

// 2. Every used key is translated in both locales.
for (const k of usedKeys) {
  if (!zh.has(k)) problems.push(`zh missing translation for used key: "${k}"`);
  if (!ja.has(k)) problems.push(`ja missing translation for used key: "${k}"`);
}

if (problems.length > 0) {
  console.error(`i18n coverage FAILED (${problems.length} issue(s)):`);
  for (const p of problems) console.error("  - " + p);
  process.exit(1);
}

console.log(`i18n coverage OK — ${usedKeys.size} used keys, zh=${zh.size}, ja=${ja.size}.`);
