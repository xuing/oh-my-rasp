import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { router } from "./router";
import { pushToast, ToastViewport } from "./components/toast";
import { translate } from "./i18n";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        // Never retry auth failures; the api layer already cleared the session.
        if (error instanceof Error && error.name === "ApiError" && (error as { status?: number }).status === 401) {
          return false;
        }
        return failureCount < 2;
      },
      staleTime: 10_000,
      refetchOnWindowFocus: false
    },
    mutations: {
      // Global fallback so a failed security action (disable user, rollback,
      // rollout, secret rotation, …) never fails silently. Individual mutations
      // may still add their own onSuccess/onError; a per-mutation onError would
      // override this default, but none currently do. Auth (401) failures are
      // swallowed here because the api layer already clears the session and
      // routes to /login, which is feedback enough.
      onError: (error) => {
        const status = error instanceof Error ? (error as { status?: number }).status : undefined;
        if (status === 401) return;
        pushToast({
          tone: "error",
          title: translate("Action failed"),
          message:
            error instanceof Error ? error.message : translate("An unexpected error occurred. Please try again.")
        });
      }
    }
  }
});

// When the API clears the session (401), drop the cache and route to login.
window.addEventListener("ohmyrasp.session.changed", () => {
  if (!localStorage.getItem("ohmyrasp.console.session")) {
    queryClient.clear();
    if (location.pathname !== "/login") router.navigate({ to: "/login" });
  }
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <ToastViewport />
    </QueryClientProvider>
  </StrictMode>
);
