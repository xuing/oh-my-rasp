# 10. Agent、服务端和下载通道

状态：`[Completed]`

## 完成的功能

- Java Agent 使用现代控制面 API：
  - `POST /api/v1/agents/register`
  - `POST /api/v1/agents/{agentID}/heartbeat`
  - `GET /api/v1/agents/{agentID}/policy`
  - `POST /api/v1/events/attack`
- Agent 侧报告按数据类型拆分：
  - attack/hook/performance/crash/error events
  - dependencies
  - baseline findings
- Agent artifact 下载和目录能力：
  - `GET /api/v1/agent-artifacts`
  - `POST /api/v1/agent-artifacts`
  - `GET /api/v1/daemon/artifacts/agent/info`
  - `GET /api/v1/daemon/artifacts/agent`
- 兼容旧服务下载入口：
  - `/v1/service/dl/agent/info`
  - `/v1/service/dl/agent`
  - `/v2/service/dl/agent`
- 兼容旧 Service app 获取：
  - `/v1/service/app/get`
- Daemon command 和注入通道：
  - `GET /api/v1/daemon/token`
  - `POST /api/v1/daemon/token/reset`
  - `POST /api/v1/daemon/workloads/report`
  - `GET /api/v1/daemon/commands`
  - `POST /api/v1/daemon/injection-reports`
  - `POST /api/v1/daemon/workloads/{workloadID}/bind`
  - `POST /api/v1/daemon/workloads/{workloadID}/unbind`
  - `/v1/service/command` legacy WebSocket compatibility
  - `/v1/service/command/daemon_set/inject` legacy HTTP compatibility

## 任务拆分

### Agent 侧

- Java Agent `ControlPlaneClient` 已使用 `/api/v1` 注册、心跳、策略拉取和 attack event 上传。
- 检测事件使用应用凭据鉴权，policy_id/policy_version 随策略拉取结果回填。
- 旧 `/v1/agent/*` 同名路径不作为 Java Agent 默认协议，避免复制 OpenRASP/旧版产品的混合 payload。

### 后端侧

- 补齐 `/v2/service/dl/agent` alias，复用当前 daemon artifact 下载逻辑。
- 补齐 `/v1/service/command/daemon_set/inject`，复用 legacy daemon WebSocket 的 LZ4/JSON envelope 解析和 workload report 逻辑。
- API 测试覆盖 legacy app lookup、artifact info、v1/v2 artifact download、legacy WebSocket、legacy DaemonSet HTTP report、daemon token、workload bind/unbind 和 injection report。

### 前端侧

- Agents 页面已展示 artifact upload/catalog/bootstrap、daemon token、workload 绑定、注入状态和 Agent 操作。
- Live Playwright flow 覆盖 artifact upload、artifact info/download、daemon commands、workload report、bind/unbind 和 injection report。

## 不复刻的旧功能

- `/v1/agent/download_upgrade` 和 `/v1/agent/download_engine` 不实现。当前只发布 Java Agent artifact，不维护多语言 engine 包和旧升级包结构。
- `/v1/service/dl/rasp-agent-helper*` 和 `/v1/service/dl/rasp-injector*` 不实现。helper/injector 二进制不在当前维护范围内，发布空壳下载会造成错误安装。
- `install_legacy_helper.sh` 和 `uninstall_legacy_helper.sh` 不实现。旧脚本包含 systemd、root 权限和二进制布局假设，与当前 Docker/Daemon/API 模型不一致。
- 旧 `/v1/agent/log/*` 形态不复刻为同名 API。当前统一使用 typed `/api/v1/events/*`、`/api/v1/dependencies` 和 `/api/v1/baseline-findings`，鉴权、查询和保留策略更清晰。

## 验证

- `docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...`
- `cd console && npm test`
- `cd console && npm run build`
- `cd console && npm run test:e2e`
- `docker compose build api migrate web && docker compose up -d web`
- `cd console && npm run test:e2e:live`
