import { afterEach, describe, expect, it } from "vitest";
import { canAccess, requireRoles } from "./guards";

afterEach(() => {
  window.localStorage.clear();
});

describe("route guards", () => {
  it("allows admin and security engineer sessions for restricted route groups", () => {
    expect(canAccess({ token: "ses", roles: ["admin"], userEmail: "", userName: "" }, ["admin"])).toBe(true);
    expect(canAccess({ token: "ses", roles: ["security_engineer"], userEmail: "", userName: "" }, ["admin", "security_engineer"])).toBe(true);
  });

  it("redirects viewers away from admin-only routes", () => {
    window.localStorage.setItem("ohmyrasp.session_token", "ses_viewer");
    window.localStorage.setItem("ohmyrasp.session_user_roles", JSON.stringify(["viewer"]));

    expect(() => requireRoles(["admin"])).toThrow();
    expect(canAccess({ token: "ses", roles: ["viewer"], userEmail: "", userName: "" }, ["admin"])).toBe(false);
  });
});
