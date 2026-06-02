const FOCUS_KEY = "ohmyrasp.console.focus";

export function storeFocusTarget(target: string) {
  sessionStorage.setItem(FOCUS_KEY, target);
}

export function consumeFocusTarget(): string | null {
  const target = sessionStorage.getItem(FOCUS_KEY);
  if (target) sessionStorage.removeItem(FOCUS_KEY);
  return target;
}

export function pendingFocusTarget(): string {
  return sessionStorage.getItem(FOCUS_KEY) || location.hash.replace(/^#/, "");
}

export function focusSection(target: string) {
  requestAnimationFrame(() => {
    const element = document.querySelector<HTMLElement>(`[data-section="${CSS.escape(target)}"]`);
    if (!element) return;
    element.scrollIntoView({ block: "start" });
    element.focus({ preventScroll: true });
  });
}

export function focusStoredSection() {
  const target = consumeFocusTarget() || location.hash.replace(/^#/, "");
  if (!target) return;
  focusSection(target);
}
