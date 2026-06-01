import "@testing-library/react";
import { beforeEach } from "vitest";
import i18n, { languageStorageKey } from "../i18n";

beforeEach(async () => {
  window.localStorage.removeItem(languageStorageKey);
  await i18n.changeLanguage("en");
});
