import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { resources } from "./resources";

export const languageStorageKey = "ohmyrasp.language";

export const supportedLanguages = [
  { code: "en", labelKey: "language.english", nativeLabel: "English" },
  { code: "zh", labelKey: "language.chinese", nativeLabel: "中文" },
  { code: "ja", labelKey: "language.japanese", nativeLabel: "日本語" }
] as const;

export type SupportedLanguage = (typeof supportedLanguages)[number]["code"];

const supportedLanguageCodes = supportedLanguages.map(language => language.code);

function isSupportedLanguage(value: string | undefined): value is SupportedLanguage {
  return supportedLanguageCodes.includes(value as SupportedLanguage);
}

function normalizeLanguage(value: string | undefined): SupportedLanguage | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.toLowerCase().split("-")[0];
  return isSupportedLanguage(normalized) ? normalized : undefined;
}

function detectInitialLanguage(): SupportedLanguage {
  if (typeof window === "undefined") {
    return "en";
  }
  const storedLanguage = normalizeLanguage(window.localStorage.getItem(languageStorageKey) ?? undefined);
  if (storedLanguage) {
    return storedLanguage;
  }
  return normalizeLanguage(window.navigator.language) ?? "en";
}

function syncDocumentLanguage(language: string) {
  if (typeof document !== "undefined") {
    document.documentElement.lang = language;
  }
}

void i18n.use(initReactI18next).init({
  resources,
  lng: detectInitialLanguage(),
  fallbackLng: "en",
  supportedLngs: supportedLanguageCodes,
  interpolation: {
    escapeValue: false
  },
  returnNull: false
});

i18n.on("languageChanged", language => {
  const normalizedLanguage = normalizeLanguage(language) ?? "en";
  if (typeof window !== "undefined") {
    window.localStorage.setItem(languageStorageKey, normalizedLanguage);
  }
  syncDocumentLanguage(normalizedLanguage);
});

syncDocumentLanguage(i18n.language);

export async function setAppLanguage(language: SupportedLanguage) {
  await i18n.changeLanguage(language);
}

export default i18n;
