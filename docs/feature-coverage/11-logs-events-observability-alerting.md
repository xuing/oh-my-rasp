# 11. 日志、事件、可观测性和告警

状态：`[Completed]`

## 完成的功能

- 事件模型已覆盖五类运行时事件：
  - `GET/POST /api/v1/events/attack`
  - `GET/POST /api/v1/events/hook`
  - `GET/POST /api/v1/events/performance`
  - `GET/POST /api/v1/events/crash`
  - `GET/POST /api/v1/events/error`
- 事件查询支持 application、environment、agent、policy、severity、hook、time range 和 limit 过滤。
- 事件元数据覆盖 request/rule/policy/algorithm 场景：
  - 顶层字段保存 `policy_id`、`policy_version`、`hook`、`algorithm`、`severity` 和 `message`。
  - `attributes` 保存请求参数、类名、方法名、执行动作、延迟、堆栈、规则命中上下文等扩展字段。
- Recycle bin 支持事件软删除、恢复和最终清理：
  - `GET /api/v1/events/recycle-bin`
  - `POST /api/v1/events/recycle-bin/delete`
  - `POST /api/v1/events/recycle-bin/restore`
  - `POST /api/v1/events/recycle-bin/purge`
- 可观测性报表已覆盖：
  - rule overhead
  - hook latency p50/p95/max/average
  - agent overhead
  - policy performance
  - `GET /api/v1/analytics/observability`
- Prometheus 指标已覆盖：
  - `GET /metrics`
  - policy pull latency
  - hook latency p95
  - policy rule evaluation p95
  - agent CPU overhead
  - application、agent 和 event totals
- 告警规则和投递记录已覆盖：
  - `GET /api/v1/alert-rules`
  - `POST /api/v1/alert-rules`
  - `PUT /api/v1/alert-rules/{alertRuleID}`
  - `GET /api/v1/alert-deliveries`
  - 后端 alert delivery worker 会投递 HTTP/HTTPS webhook target，并把不支持或失败的 target 标记为 `failed`。

## 任务拆分

### Agent 侧

- Agent 按事件类型上报 attack、hook、performance、crash 和 error。
- Hook event 的 `latency_us` 进入 hook latency 报表。
- Performance event 的 CPU、memory、hook latency 和 rule evaluation 指标进入 agent/policy performance 报表。
- 策略上下文通过 `policy_id`、`policy_version`、`hook` 和 `algorithm` 进入事件顶层字段，其他请求和命中上下文放入 `attributes`。

### 后端侧

- OpenAPI 的 `HookLatency` schema 增加 `p50_latency_us`。
- MemoryStore 和 ClickHouse analytics 都返回 hook latency p50/p95。
- ClickHouse 继续使用 `hook_events` 和 `performance_events` 作为可观测性聚合来源。
- 事件写入后会按 enabled alert rule 匹配并创建 alert delivery 记录；worker 周期性处理 queued delivery。
- HTTP/HTTPS webhook target 会收到 JSON payload，成功后状态变为 `delivered`；不支持的 target scheme 或 HTTP 失败会记录为 `failed`、递增 attempts 并写入 `last_error`。
- API 测试覆盖事件写入、recycle bin、observability、metrics、alert rule lifecycle 和 alert deliveries。

### 前端侧

- Security Events 页面展示事件管道、五类事件、过滤器、policy/algorithm 元数据和 attributes 详情。
- Event Recycle Bin 页面支持查看、恢复和清理删除事件。
- Observability 页面展示 rule overhead、hook latency、agent overhead 和 policy impact；hook latency 表格展示 avg/p50/p95/max。
- Access & Audit 页面展示 alert rule 创建、更新和 delivery history。

## 不复刻的旧功能

- 归档 Dashboard ECharts 图形不逐项复刻。当前 React 页面已经用表格、指标块和过滤器覆盖同一数据面，继续复制旧图表布局会增加维护面，且不改变控制面能力。
- 邮件服务配置和测试暂不实现。当前已支持 HTTP/HTTPS webhook 投递；SMTP 或第三方通知 provider 需要独立凭据、重试策略和密钥管理，后续接入真实 provider 后再增加 provider settings 和 test delivery。

## 验证

- `docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...`
- `cd web && npm test`
- `cd web && npm run build`
- `cd web && npm run e2e`
- `docker compose build api migrate web && docker compose up -d web`
- `cd web && npm run e2e:live`
- Live API acceptance:
  - typed event ingest and query return attack/hook/performance/crash/error events
  - observability report returns hook latency `p50_latency_us` and `p95_latency_us`
  - `/metrics` returns Prometheus metrics
  - alert rule match creates alert delivery records
  - HTTP webhook alert target becomes `delivered`; unsupported target becomes `failed` with `attempts` and `last_error`
