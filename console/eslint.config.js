// Flat ESLint config for the OhMyRasp console.
//
// Stack: typescript-eslint (recommended, non type-checked for speed) +
// eslint-plugin-react-hooks + eslint-plugin-jsx-a11y. This is the console's
// first lint setup, so rules that are stylistic or too noisy against the
// existing code are dialed to "warn" (with a note) rather than blanket
// disabled — they still surface, they just don't block.
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y-x";
import globals from "globals";

export default defineConfig(
  {
    // Build output, deps, Playwright artifacts, and the e2e suite (its own
    // Playwright toolchain/globals) are out of scope for the app lint.
    ignores: ["dist/**", "node_modules/**", "test-results/**", "playwright-report/**", "e2e/**"]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.browser },
      parserOptions: { ecmaFeatures: { jsx: true } }
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      // exhaustive-deps flags intentional-omission effects in a few places;
      // surface as a warning rather than block the build.
      "react-hooks/exhaustive-deps": "warn"
    }
  },
  // Accessibility rules for JSX (scoped to component/route files).
  {
    ...jsxA11y.configs.recommended,
    files: ["src/**/*.tsx"]
  },
  // Node scripts and root build/test config run in Node, not the browser.
  {
    files: ["scripts/**/*.{ts,js}", "*.{js,ts,mjs,cjs}"],
    languageOptions: { globals: { ...globals.node } }
  }
);
