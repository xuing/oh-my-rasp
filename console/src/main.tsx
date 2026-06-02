import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { router } from "./router";
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
    </QueryClientProvider>
  </StrictMode>
);
