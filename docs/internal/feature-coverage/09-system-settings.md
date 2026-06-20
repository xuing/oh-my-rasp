# 09. 系统设置

状态：`[Completed]`

## 完成的功能

- 系统设置兼容旧路由：
  - `/settings/panel` -> Access & Audit
  - `/settings/alarm` -> Access & Audit
  - `/settings/systemInfo` -> Access & Audit
  - `/settings/poolVersion` -> Agents
  - `/settings/version` -> Agents
- 后台地址配置进入统一 system settings：
  - 默认设置 `server.public_url`
  - `GET /api/v1/system-settings`
  - `PUT /api/v1/system-settings/server.public_url`
- 报警间隔进入统一 system settings：
  - 默认设置 `alerts.delivery.interval_seconds`
  - Access & Audit 的 Protection Configuration 可编辑并产生审计日志。
- 系统版本信息提供旧兼容和现代控制台接口：
  - `GET /v1/version`
  - `GET /api/v1/system/version`
  - 返回 component、version、commit、build_time、go_version。
- 系统信息继续使用标准运维端点：
  - `GET /healthz`
  - `GET /readyz`
  - `GET /metrics`
- 版本池和版本管理使用 Agent artifact 模型：
  - `GET /api/v1/agent-artifacts`
  - `POST /api/v1/agent-artifacts`
  - Agents 页面展示 artifact catalog、upload、bootstrap 校验和下载能力。

## 任务拆分

### Agent 侧

- Agent 不需要新增推送协议。Agent 和 Daemon 继续通过 artifact 下载与命令组拉取模型获取可用版本。
- 版本选择继续按 language、system_type、language_version 精确匹配，避免全局默认版本误配。

### 后端侧

- OpenAPI 增加 `SystemVersion` schema。
- 增加 `GET /v1/version` 与 `GET /api/v1/system/version`。
- 默认系统设置增加 `server.public_url` 与 `alerts.delivery`。
- API 测试覆盖公开版本端点、鉴权版本端点、默认系统设置和审计。

### 前端侧

- Access & Audit 新增 System Version 面板。
- Protection Configuration 新增 Public Console URL 输入项。
- 增加 `/settings/*` 兼容路由。
- Playwright E2E 覆盖系统版本展示、后台地址保存和旧设置路由。

## 不复刻的旧功能

- `/v1/ping` 不复刻。当前采用标准 `GET /healthz` 和 `GET /readyz` 区分进程存活与依赖就绪，语义更清晰。
- 全局默认版本池不实现。不同 JDK、操作系统和 artifact 形态需要精确匹配，单个默认版本容易造成错误升级。
- 控制台主动推送版本不实现。当前 Agent/Daemon 拉取模型更适合自托管网络边界，也更容易审计下载和注入状态。
- 独立应用升级配置不实现。当前通过 artifact catalog、`agent.minimum_version` 和 Daemon command group 表达升级控制，避免维护重复状态。
- `editDialog.vue` 不复刻。当前上传表单和 catalog 表格已经覆盖必要编辑、校验和详情展示。

## 验证

- `docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...`
- `cd console && npm test`
- `cd console && npm run build`
- `cd console && npm run test:e2e`
- `docker compose build api migrate web && docker compose up -d web`
- `cd console && npm run test:e2e:live`
- Live API acceptance:
  - `GET /v1/version` -> 200
  - `GET /api/v1/system/version` -> 200
  - `GET /api/v1/system-settings` contains `server.public_url` and `alerts.delivery`
  - `PUT /api/v1/system-settings/server.public_url` persists the URL setting
