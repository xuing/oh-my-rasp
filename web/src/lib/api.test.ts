import { afterEach, describe, expect, it, vi } from "vitest";
import { currentSession, loginWithPassword, saveSession, type LoginResponse } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("session API", () => {
  it("persists the real login response without seeded fallback users", () => {
    const result: LoginResponse = {
      session: {
        token: "real-session-token",
        user_id: "usr_real",
        expires_at: "2026-06-01T01:00:00Z"
      },
      user: {
        id: "usr_real",
        email: "operator@example.test",
        name: "Operator",
        roles: ["admin"],
        created_at: "2026-06-01T00:00:00Z",
        updated_at: "2026-06-01T00:00:00Z"
      }
    };

    saveSession(result);

    expect(currentSession()).toEqual({
      roles: ["admin"],
      token: "real-session-token",
      userEmail: "operator@example.test",
      userName: "Operator"
    });
  });

  it("throws when the login endpoint rejects credentials", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        statusText: "Unauthorized"
      })
    );

    await expect(loginWithPassword("admin@ohmyrasp.local", "wrong")).rejects.toThrow("401 Unauthorized");
  });
});
