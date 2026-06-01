import { afterEach, describe, expect, it, vi } from "vitest";
import { appContextChangedEvent, currentApplicationContext, setSelectedApplication, setSelectedEnvironment } from "./app-context";

afterEach(() => {
  window.localStorage.removeItem("ohmyrasp.app_context");
  vi.restoreAllMocks();
});

describe("application context store", () => {
  it("persists selected application and clears environment when the app changes", () => {
    const listener = vi.fn();
    window.addEventListener(appContextChangedEvent, listener);

    setSelectedApplication("app_a");
    setSelectedEnvironment("env_prod");

    expect(currentApplicationContext()).toEqual({
      applicationId: "app_a",
      environmentId: "env_prod"
    });

    setSelectedApplication("app_b");

    expect(currentApplicationContext()).toEqual({
      applicationId: "app_b",
      environmentId: null
    });
    expect(listener).toHaveBeenCalled();
    window.removeEventListener(appContextChangedEvent, listener);
  });
});
