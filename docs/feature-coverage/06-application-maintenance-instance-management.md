# 06. 应用维护和实例管理

状态：`[Completed]`

## 完成的功能

- 实例管理统一落在现代 `Agents` 工作台，兼容旧路由 `/maintain/hosts` 和 `/addInstance`。
- Agent 清单支持搜索、应用筛选、状态筛选、版本筛选、显示/隐藏已忽略实例。
- Agent 实例支持运维备注、忽略/恢复、单个删除、批量删除和 CSV 导出。
- Daemon workload 继续支持进程/容器资产视图、应用绑定、解绑、注入状态和注入错误显示。
- `/maintain/whitelist`、`/maintain/clearData`、`/maintain/general` 映射到 `Access & Audit`，复用允许列表、保护配置、系统设置和维护清理表单。
- `/maintain/upgrade` 映射到 `Agents`，复用 Agent artifact 上传、目录、bootstrap 校验和下载能力。
- 后端新增 Agent 维护接口：
  - `PUT /api/v1/agents/{agentID}/alias`
  - `POST /api/v1/agents/{agentID}/ignore`
  - `DELETE /api/v1/agents/{agentID}`
  - `POST /api/v1/agents/batch-delete`
- PostgreSQL 持久化 Agent 备注和忽略时间，并为忽略实例查询增加索引。
- 所有维护动作记录审计日志：`agent.alias.update`、`agent.ignore.update`、`agent.delete`。

## 新增能力

- 运维人员可以在同一视图里完成实例识别、版本核对、策略绑定状态确认、备注、忽略、删除和导出。
- 已忽略实例不会被硬删除，可以恢复；适合暂时下线、测试节点、重复注册节点等场景。
- 删除操作用于从活跃 Agent 清单中移除退役实例，批量删除用于清理旧批次节点。
- CSV 导出使用当前筛选结果生成，便于交接、巡检和离线审计。
- 兼容旧维护路由，但不引入旧平台的同名 API 形状，避免维持两套控制面语义。

## 任务拆分

### Agent 侧

- 无需改动 Java Agent 协议。实例维护属于控制面元数据；Agent 仍通过注册、心跳、策略拉取和事件上报维持生命周期。
- Daemon 注入链路继续使用 workload report、bind/unbind、commands 和 injection report；无需新增旧式 `auto_protect` 或 `add_protect` Agent endpoint。

### 后端侧

- 扩展 Agent 模型，增加 `alias` 和 `ignored_at`。
- 增加 Agent 维护 store 接口、memory store 实现和 PostgreSQL 实现。
- 增加 OpenAPI 合约和 strict handlers。
- 增加 PostgreSQL migration `031_add_agent_maintenance_fields.sql`。
- 增加 HTTP API 测试覆盖 remark、ignore/restore、delete、batch delete 和审计日志。

### 前端侧

- 增加 Agent Inventory 面板，提供筛选、备注、忽略/恢复、删除、批量删除、CSV 导出。
- 增加旧维护路由兼容映射：
  - `/maintain/hosts`
  - `/maintain/whitelist`
  - `/maintain/clearData`
  - `/maintain/general`
  - `/maintain/upgrade`
  - `/addInstance`
- 扩展 E2E workflow 覆盖 Agent 维护和导出操作。

## 不复刻的旧功能

- `rasp/search_old` 不单独实现。当前系统以活跃 Agent 清单、忽略状态和审计日志表达维护状态；保留旧实例搜索会制造第二套生命周期来源。
- `unloadDialog.vue` 不单独实现。当前控制台没有远程卸载命令通道，Daemon 只上报 `uninstalled` 结果；在缺少端侧确认和权限边界前，控制台卸载按钮会产生误导。
- 归档维护升级页不按旧 UI 复刻。当前 artifact catalog、上传、bootstrap 校验和下载已经覆盖实际升级包管理入口。

## 验证

- `go test ./internal/control ./internal/httpapi`
- `npm run build`
- 待最终验收批次执行全量 Go、Web unit、Playwright E2E、Docker Compose 和 live acceptance。
