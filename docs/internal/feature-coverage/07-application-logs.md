# 07. 应用日志

状态：`[Completed]`

## 完成的功能

- 异常日志落到新的 `error` 事件族：
  - `POST /api/v1/events/error`
  - `GET /api/v1/events/error`
  - 兼容旧页面路由 `/log/exceptions`
- 崩溃信息继续使用现有 `crash` 事件族：
  - `POST /api/v1/events/crash`
  - `GET /api/v1/events/crash`
  - 兼容旧页面路由 `/log/crash`
- 操作审计继续使用统一审计日志：
  - `GET /api/v1/audit-logs`
  - 兼容旧页面路由 `/log/audit`
- Events 工作台同时查询 attack、hook、performance、crash、error 事件，并在同一时间线中展示消息、等级、Hook、算法、策略版本和结构化参数。
- Event Recycle Bin 支持 `error` 类型事件的软删除、恢复、永久删除和审计记录。
- Alert rule / alert delivery 的事件类型枚举支持 `error`，避免后续异常类告警需要再次扩展合约。

## 任务拆分

### Agent 侧

- Java Agent 继续使用应用凭据上报日志事件。
- 异常日志不复刻旧 `/v1/agent/log/error` 路径，改为现代事件入口 `POST /api/v1/events/error`。
- 事件 payload 复用 `SecurityEventInput`，异常类、栈帧、线程、请求路径等详情进入 `attributes`。

### 后端侧

- OpenAPI 增加 `/api/v1/events/error` 查询和上报接口。
- strict handlers 增加 `GetApiV1EventsError` 和 `PostApiV1EventsError`。
- 事件类型枚举增加 `error`，覆盖 SecurityEvent、Recycle Bin、AlertRule、AlertDelivery。
- PostgreSQL migration `032_allow_error_event_alert_rules.sql` 扩展 alert rule 事件类型约束。
- API 测试覆盖 error 事件上报、搜索、结构化异常参数、聚合统计和审计日志。

### 前端侧

- Events 页面新增 `error` 查询，并纳入安全事件总数、时间线和详情参数显示。
- Pipeline 模型新增 `error` 行，明确异常日志进入 PostgreSQL + ClickHouse。
- Alert rule 表单新增 `error` 事件类型。
- 兼容旧路由：
  - `/log/exceptions` -> Events
  - `/log/crash` -> Events
  - `/log/audit` -> Access & Audit
- Playwright fixtures 和 E2E 覆盖异常日志可见性与旧路由访问；Java Agent producer 测试和 live API acceptance 覆盖真实 Agent error/crash 事件生产。

## 不复刻的旧功能

- `/v1/agent/log/error` 不单独实现。当前控制面以 `/api/v1/events/{type}` 表达所有 Agent 事件，保留旧上报路径会形成第二套鉴权和事件查询语义。
- `/v1/api/log/error/search`、`/v1/api/log/crash/search`、`/v1/api/operation/search` 不单独实现。同等能力已由 `GET /api/v1/events/error`、`GET /api/v1/events/crash` 和 `GET /api/v1/audit-logs` 覆盖。
- `viewDialog.vue` 不复刻为独立弹窗。当前 Events 和 Access & Audit 表格在行内展示 ID、消息、时间、策略、Hook、算法、结构化参数和审计详情；这避免为了旧组件名引入重复 UI 状态。

## 验证

- Java Agent producer acceptance 已证明 error/crash 事件由 Agent 侧路径上报到运行中的 API。
- 待最终验收批次执行全量 Go、Web unit、Playwright E2E、Docker Compose 和 live acceptance。
