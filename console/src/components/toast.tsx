import { useCallback, useSyncExternalStore } from "react";
import { AnimatePresence, motion } from "motion/react";
import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { cn } from "../lib/cn";
import { useT } from "../i18n";

export type ToastTone = "error" | "success" | "info";

export interface Toast {
  id: number;
  tone: ToastTone;
  title: string;
  message?: string;
}

export interface ToastInput {
  title: string;
  message?: string;
  tone?: ToastTone;
  /** Auto-dismiss delay in ms. `0` keeps the toast until it is dismissed. */
  duration?: number;
}

/* ------------------------------------------------------------------------- *
 * Module-level store. Mirrors the i18n / theme stores so a toast can be
 * pushed imperatively from anywhere — crucially from the QueryClient's global
 * mutation `onError` handler, which runs outside the React tree and therefore
 * cannot call a hook.
 * ------------------------------------------------------------------------- */
let toasts: Toast[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}
function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}
function snapshot(): Toast[] {
  return toasts;
}

/** Push a toast from anywhere (components or non-React code). Returns its id. */
export function pushToast(input: ToastInput): number {
  const id = nextId++;
  const toast: Toast = {
    id,
    tone: input.tone ?? "info",
    title: input.title,
    message: input.message
  };
  toasts = [...toasts, toast];
  emit();
  const duration = input.duration ?? (toast.tone === "error" ? 8000 : 4500);
  if (duration > 0 && typeof window !== "undefined") {
    window.setTimeout(() => dismissToast(id), duration);
  }
  return id;
}

export function dismissToast(id: number): void {
  const next = toasts.filter((t) => t.id !== id);
  if (next.length !== toasts.length) {
    toasts = next;
    emit();
  }
}

/** Hook returning a bound `pushToast` for use inside components. */
export function useToast(): (input: ToastInput) => number {
  return useCallback((input: ToastInput) => pushToast(input), []);
}

const toneConfig: Record<ToastTone, { Icon: typeof AlertTriangle; accent: string; ring: string }> = {
  error: { Icon: AlertTriangle, accent: "text-critical", ring: "border-critical/40" },
  success: { Icon: CheckCircle2, accent: "text-signal", ring: "border-signal/40" },
  info: { Icon: Info, accent: "text-low", ring: "border-low/40" }
};

/**
 * App-wide toast region. Mount exactly once near the app root (see `main.tsx`).
 * The container is a live region so assistive tech announces new toasts; it is
 * pointer-transparent so it never blocks the UI beneath it.
 */
export function ToastViewport() {
  const items = useSyncExternalStore(subscribe, snapshot, snapshot);
  const t = useT();
  return (
    <div
      role="status"
      aria-live="assertive"
      aria-atomic="false"
      className="pointer-events-none fixed inset-x-0 bottom-0 z-[100] flex flex-col items-end gap-2 px-4 py-4 sm:inset-x-auto sm:right-0"
    >
      <AnimatePresence initial={false}>
        {items.map((toast) => {
          const { Icon, accent, ring } = toneConfig[toast.tone];
          return (
            <motion.div
              key={toast.id}
              layout
              initial={{ opacity: 0, x: 24, scale: 0.98 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 24, scale: 0.98 }}
              transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
              className={cn(
                "pointer-events-auto w-full max-w-sm overflow-hidden rounded-lg border bg-panel shadow-2xl",
                ring
              )}
            >
              <div className="flex items-start gap-3 px-4 py-3">
                <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", accent)} />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium text-ink">{toast.title}</div>
                  {toast.message && (
                    <div className="mt-0.5 break-words text-[12px] text-muted">{toast.message}</div>
                  )}
                </div>
                <button
                  type="button"
                  aria-label={t("Dismiss")}
                  onClick={() => dismissToast(toast.id)}
                  className="-mr-1 shrink-0 rounded-md p-1 text-faint transition-colors hover:bg-raised hover:text-ink"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
