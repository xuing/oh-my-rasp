# 12. 前端页面覆盖

状态：`[Completed]`

## 完成的功能

- 主要控制台页面已覆盖：
  - `/login` 登录页
  - `/` 概览页
  - `/applications` 应用和环境页
  - `/agents` Agent、Daemon、artifact 和实例操作页
  - `/policies` 策略、规则、算法和发布流程页
  - `/events` 事件、依赖、基线和回收站页
  - `/observability` 可观测性页
  - `/access` 访问控制、审计、告警和系统设置页
- 旧前端路由兼容已覆盖：
  - `/addInstance` -> dedicated Agent onboarding
  - `/log/exceptions` -> focused Error Events route
  - `/log/crash` -> focused Crash Events route
  - `/log/audit` -> focused Audit Log route
  - `/platform` -> focused Platform Administration route
  - `/platform/user` -> focused User Administration route
  - `/settings/panel` -> focused Panel Settings route
  - `/settings/alarm` -> focused Alarm Settings route
  - `/settings/systemInfo` -> focused System Information route
  - `/settings/poolVersion` -> focused Agent Package Versions route
  - `/settings/version` -> focused Agent Version Status route
- fallback 页面已覆盖：
  - `/noaccess`
  - TanStack Router not found 页面

## 任务拆分

### 前端路由

- TanStack Router 明确定义现代页面和旧路径兼容入口。
- 需要登录的页面统一通过 `requireSession` 保护。
- 管理和运维页面使用 `requireRoles` 做 route-level RBAC，viewer 在页面渲染前进入 `/noaccess`。
- `/noaccess` 和 404 使用独立页面，不落到空白页或默认浏览器错误。
- shell/login/fallback、Agent onboarding、legacy focus wrappers 和 route guards 已拆到独立 route modules；生产构建使用 lazy routes 和 vendor chunk splitting。

### 页面能力

- `/addInstance` 页面承载旧添加实例向导的有效能力：应用/环境作用域、手动 Java Agent、Docker、Kubernetes、Daemon managed injection 和运行时证据校验。
- Agents 页面继续承载 Agent 注册、heartbeat、policy pull、Daemon workloads、workload 绑定、artifact upload/catalog/download、注入状态和 Agent inventory。
- Access & Audit 页面承载旧平台管理和系统设置能力：用户生命周期、RBAC、audit log、alert rules、alert deliveries、system settings、system version 和 edition status。
- Events 和 Observability 页面承载旧日志、异常、崩溃、可观测性和分析能力。

### 测试覆盖

- Vitest 覆盖 route guards、Agent onboarding 和 legacy focused routes。
- Playwright 覆盖登录、主导航、移动导航、受保护路由、viewer noaccess、404、旧路由聚焦和主要工作流提交。
- Live Playwright 覆盖 Docker Compose web proxy 下的登录、应用作用域创建、Agent 操作、访问管理和主要页面读取。

## 不复刻的旧功能

- 旧 `/addInstance` 中与当前 Java Agent 无关的 Windows、PHP 和客户端安装弹窗不复刻。当前 onboarding 只覆盖本项目可执行的 Java Agent、Docker、Kubernetes 和 Daemon managed injection 路径。
- 旧 `/platform` 的多租户组织/UPMS/Keycloak 管理页面不复刻。当前项目是单组织 self-hosted OSS 模型，平台管理落到用户、角色、审计、edition 和系统设置。
- 旧 `/settings/*` 的每个子页面不拆成多个独立 React 页面。当前统一放在 Access & Audit 和 Agents 中，避免重复表单和重复状态。

## 验证

- `docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...`
- `cd console && npm test`
- `cd console && npm run build`
- `cd console && npm run test:e2e`
- Focused Playwright (primary-page navigation, mobile nav, RBAC): `cd console && npm run test:e2e -- --grep "instances expose onboarding, artifacts, mobile nav, and RBAC correctly"`
- `docker compose build api migrate web && docker compose up -d web`
- `cd console && npm run test:e2e:live`
