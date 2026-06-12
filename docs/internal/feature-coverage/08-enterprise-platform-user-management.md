# 08. 企业管理、平台管理和用户管理

状态：`[Completed]`

## 完成的功能

- 平台管理入口兼容旧路由：
  - `/platform` -> Access & Audit
  - `/platform/user` -> Access & Audit
- 用户管理使用当前控制面的本地用户和 RBAC 模型：
  - `GET /api/v1/users`
  - `POST /api/v1/users`
  - `PUT /api/v1/users/{userID}`
- 用户搜索已覆盖旧 `/v3/upms/user/search` 的实际需要：
  - `search` 支持按 ID、邮箱、显示名过滤。
  - `role` 支持 admin、security_engineer、viewer。
  - `status` 支持 active、disabled。
- 用户禁用/恢复通过 `PUT /api/v1/users/{userID}` 的 `disabled` 字段实现。
- Access & Audit 页面新增用户搜索、角色筛选、状态筛选和清除筛选。
- 创建、更新、禁用用户都会写入审计日志，禁用用户会使已有 session 失效。

## 任务拆分

### 后端侧

- 增加 `control.UserQuery`。
- MemoryStore 和 PostgreSQL Store 的 `ListUsers` 支持 search、role、status。
- OpenAPI 为 `GET /api/v1/users` 增加查询参数。
- HTTP API 校验非法 role/status 并返回 400。
- 扩展 API 和 PostgreSQL 集成测试覆盖用户搜索、角色过滤、禁用状态过滤。

### 前端侧

- Access & Audit 的 User Administration 表格新增筛选条。
- `useUsers` 支持 query string 和 React Query key 隔离。
- 增加 `/platform` 和 `/platform/user` 兼容路由。
- Playwright E2E 覆盖用户搜索请求和旧平台路由。

## 不复刻的旧功能

- 多组织 CRUD 不实现。项目当前目标是单组织自托管控制台，多组织切换会带来隔离、审计、授权、计费和凭据边界，超出当前开源控制面的实际需求。
- UPMS 全平台用户体系不复刻。当前本地用户、角色、禁用状态、session 失效和审计日志已经覆盖自部署环境的管理需求。
- `/v3/upms/user`、`/v3/upms/user/status`、`/v3/upms/user/search` 不作为同名兼容 API 暴露。现代 API 使用 `/api/v1/users`，避免同时维护两套用户协议。
- `/v3/upms/tenants*` 不实现。租户 CRUD 与本项目的单组织部署模型冲突，保留会暗示不存在的隔离能力。

## 验证

- 待最终验收批次执行全量 Go、Web unit、Playwright E2E、Docker Compose 和 live acceptance。
