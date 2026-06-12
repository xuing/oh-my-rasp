# 1. Portal, Authentication, And Initialization

Status: Completed

## Evaluation

| Feature | Best-practice alignment | Current need | Necessity | Decision |
|---|---|---|---|---|
| Portal entry, login route, token check, unauthenticated redirect | Aligns. A console should fail closed and redirect unauthenticated users before loading protected pages. | Needed. The API already enforces bearer authentication, but the frontend also needs predictable navigation behavior. | Necessary. | Implemented. Protected console routes now require a local session token before loading. |
| Route progress bar and legacy menu permission guard | Partially aligns. Permission-aware navigation is useful, but route progress bars are cosmetic and stale role decisions in the browser should not replace server RBAC. | Partially needed. Server-side RBAC already protects API operations; the frontend only needs clear fallback pages. | Progress bar unnecessary; browser-only permission enforcement unnecessary as an authority. | Implementation unnecessary. Server RBAC remains authoritative; the console now has a no-access route for denied navigation states. |
| 404 page and no-access page | Aligns. Explicit fallback pages avoid ambiguous blank screens and make route errors observable in E2E tests. | Needed. The app previously relied on generic router behavior. | Necessary. | Implemented `/noaccess` and root not-found rendering. |
| Initial configuration wizard | Does not align with this project's deployment model as a required path. Self-hosted Docker/Helm deployments should bootstrap admin credentials and defaults from environment or secret management, not an unauthenticated browser wizard. | Not currently needed. The project already has `.env.example`, bootstrap admin settings, seeded organization defaults, migrations, and system settings. | Unnecessary now. | Implementation unnecessary. Keep bootstrap declarative and automation-friendly. |
| Default user check endpoint | Weak alignment. A public or semi-public default-user check can leak security posture and creates legacy API coupling. | Not needed. `/api/v1/auth/login` and authenticated `/api/v1/me` cover the supported flow. | Unnecessary. | Implementation unnecessary. |

## Completed Features

- Protected route loading for `/`, `/applications`, `/agents`, `/policies`, `/events`, `/observability`, and `/access`.
- Dedicated `/noaccess` page.
- Root-level not-found rendering for unknown paths.
- Session role persistence from the real login response for future permission-aware navigation.
- Localized fallback page content in English, Chinese, and Japanese.
- Automated i18n audit remains part of `npm run build`, so new fallback text must be localized.

## New Capabilities

- Unauthenticated users are redirected to `/login` before protected console pages load.
- Unknown routes render a clear not-found view instead of relying on default router behavior.
- No-access states have a stable route that can be used by future frontend permission checks or API-error handling.
- Session snapshots now retain user roles from the login response.

## Implementation Tasks

Agent side:

- No Agent changes required. Portal authentication and initialization are control-plane concerns.

Backend side:

- No new endpoint required. Existing `/api/v1/auth/login`, `/api/v1/me`, and API RBAC remain the authority for authentication and authorization.
- Implementation unnecessary for legacy initial-configuration and default-user-check endpoints for the reasons above.

Frontend side:

- Add protected route guards for authenticated console routes.
- Add `/noaccess` and not-found pages.
- Persist user roles in the browser session snapshot.
- Localize all new user-facing text and keep it covered by the i18n audit gate.

## Verification

- `cd web && npm run build`
- `cd web && npm test`
- `cd web && npm run e2e`
- Live Docker Compose acceptance after rebuilding `web`.
