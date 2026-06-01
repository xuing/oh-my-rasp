# OhMyRASP

面向 Java 服务的自托管运行时应用自我保护（RASP）项目，包含控制平面、可观测性栈、兼容 Daemon 的 API，以及 Java Agent 概念验证实现。

**语言:** [English](README.md) | 简体中文

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![chi](https://img.shields.io/badge/chi-router-00ADD8?logo=go&logoColor=white)](https://github.com/go-chi/chi)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1-6BA539?logo=openapiinitiative&logoColor=white)](https://www.openapis.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=061A23)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-control_store-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![ClickHouse](https://img.shields.io/badge/ClickHouse-analytics-FFCC01?logo=clickhouse&logoColor=111111)](https://clickhouse.com/)
[![Valkey](https://img.shields.io/badge/Valkey-cache-B71C1C?logo=valkey&logoColor=white)](https://valkey.io/)
[![Prometheus](https://img.shields.io/badge/Prometheus-metrics-E6522C?logo=prometheus&logoColor=white)](https://prometheus.io/)
[![Alertmanager](https://img.shields.io/badge/Alertmanager-routing-E6522C?logo=prometheus&logoColor=white)](https://prometheus.io/docs/alerting/latest/alertmanager/)
[![Grafana](https://img.shields.io/badge/Grafana-dashboards-F46800?logo=grafana&logoColor=white)](https://grafana.com/)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Helm](https://img.shields.io/badge/Helm-chart-0F1689?logo=helm&logoColor=white)](https://helm.sh/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-ready-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Java](https://img.shields.io/badge/Java-agent-ED8B00?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![ASM](https://img.shields.io/badge/ASM-bytecode-5A45FF?logo=apache&logoColor=white)](https://asm.ow2.io/)
[![Nginx](https://img.shields.io/badge/Nginx-web_proxy-009639?logo=nginx&logoColor=white)](https://nginx.org/)
[![Playwright](https://img.shields.io/badge/Playwright-e2e-2EAD33?logo=playwright&logoColor=white)](https://playwright.dev/)
[![Vitest](https://img.shields.io/badge/Vitest-unit_tests-6E9F18?logo=vitest&logoColor=white)](https://vitest.dev/)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-CI-2088FF?logo=githubactions&logoColor=white)](https://github.com/features/actions)

OhMyRASP 面向希望拥有可审计、可自托管 RASP 控制平面的团队，而不是把安全能力完全交给黑盒设备。它把应用和 Agent 清单、策略生命周期管理、运行时遥测、Daemon 工作负载上报、审计能力，以及开源 Java Agent 测试平台整合在同一个仓库中。

## 项目状态

OhMyRASP 目前正处于活跃开发阶段。项目仍然不稳定：API、策略语义、Agent 打包方式、检测器行为和部署接口都可能随着架构成熟而快速变化。它适合实验、评估和贡献，但暂时不应被视为生产就绪的安全边界。

近期路线图将重点扩展规则和策略体系：

- 自动运行大量现有靶场和漏洞应用场景，并从观察到的攻击路径中提取可复用的 RASP 检测规则。
- 使用大语言模型（LLM）从靶场行为、漏洞模式和运行时证据中生成、审查并改进新的防护策略。
- 扩展 Java Agent 体系。当前 Java Agent 主要面向 JDK 25；后续将为每个 Java 长期支持版本（LTS）创建对应 Agent，使运行时覆盖能力能够匹配真实部署基线。
- 利用更宽松的 token 预算和 token liberalization 带来的能力，维护多个 Agent 变体、更丰富的规则生成流程，以及覆盖更多语言和运行时组合的自动化验证。

## 核心能力

- **自托管控制平面**：Go API、React 控制台、PostgreSQL、ClickHouse、Valkey、Prometheus、Alertmanager 和 Grafana。
- **Agent 生命周期 API**：应用密钥、Agent 注册、心跳、策略拉取、制品目录，以及制品上传和下载。
- **Daemon 兼容能力**：工作负载清单上报、绑定和解绑流程、注入报告，以及兼容旧版命令 websocket。
- **策略操作**：草稿编辑、验证、测试、版本管理、灰度发布、回滚和规则测试。
- **运行时遥测**：攻击、Hook、性能、崩溃、依赖和基线态势数据的上报、过滤查询和分析。
- **运维就绪能力**：Helm Chart、烟雾测试、发布流程、Runbook、Prometheus 规则、Alertmanager 配置和 Grafana 仪表盘。
- **Java Agent 概念验证**：基于 ASM 的 Java Agent 和对比式 Tomcat 测试平台，用于验证检测器行为。

## 技术架构

OhMyRASP 采用控制平面架构。Go API 是核心协调点：它通过 OpenAPI 定义的 HTTP 接口管理认证、RBAC、应用清单、环境清单、策略、Daemon 状态、Agent 制品元数据、审计日志和系统配置。React 控制台通过 API 提供操作员工作流，包括创建应用、管理策略、查看遥测、轮换凭据，以及监控 Daemon 和 Agent 活动。

运行时数据按访问模式拆分。PostgreSQL 保存权威控制平面状态，ClickHouse 存储高容量事件和性能遥测，Valkey 提供会话、策略拉取和限流缓存。Prometheus 抓取 API 指标和内置规则，Alertmanager 负责告警路由，Grafana 提供仪表盘。

Java 侧展示防护路径。Agent 向控制平面注册、发送心跳、拉取策略并上报运行时观测数据。兼容 Daemon 的 API 支持工作负载发现、将工作负载绑定到应用、命令下发、制品下载和注入结果上报。Java Agent 概念验证使用 ASM 字节码转换，在对比式 Tomcat 测试平台中 Hook 选定的运行时调用点。

```text
                 +-------------------+
                 |   Web Console     |
                 |  React + Vite     |
                 +---------+---------+
                           |
                           v
+-------------------+  +---+----------------+  +--------------------+
| Java Agents       |  | Control API        |  | Daemon / Helper    |
| heartbeat/policy  +->+ Go + OpenAPI       +<-+ workload commands  |
+-------------------+  +---+---+---+---+----+  +--------------------+
                           |   |   |
                +----------+   |   +----------------+
                v              v                    v
          PostgreSQL       ClickHouse             Valkey
        control state      telemetry              cache
                |
                v
   Prometheus + Alertmanager + Grafana
```

## 仓库结构

```text
api/          Go 控制平面 API、迁移、OpenAPI 合约和生成代码
web/          React 19 + Vite 控制台
java-agent/   Java Agent 和对比式 Tomcat 测试平台
deploy/       Helm Chart、可观测性资产、烟雾测试和验证脚本
docs/         架构说明、审计和运维 Runbook
.github/      CI 和发布流程
.archive/     已忽略的参考材料和上游源码快照
```

## 快速开始

创建本地环境文件：

```bash
cp .env.example .env
```

启动前请填写 `.env` 中所有空密码值：

```bash
POSTGRES_PASSWORD=
CLICKHOUSE_PASSWORD=
VALKEY_PASSWORD=
GRAFANA_ADMIN_PASSWORD=
OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD=
```

启动完整自托管栈：

```bash
docker compose --env-file .env -f docker-compose.yml up -d --build
docker compose --env-file .env -f docker-compose.yml ps
```

从运行 Docker 的主机访问服务：

| 服务 | URL |
| --- | --- |
| Web 控制台 | `http://<host>:18091` |
| API | `http://<host>:18090` |
| Grafana | `http://<host>:13000` |
| Prometheus | `http://<host>:19090` |
| Alertmanager | `http://<host>:19093` |
| ClickHouse HTTP | `http://<host>:18123` |

默认控制平面登录信息：

```text
Email: admin@ohmyrasp.local
Password: .env 中 OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD 的值
```

Grafana 登录信息：

```text
User: admin
Password: .env 中 GRAFANA_ADMIN_PASSWORD 的值
```

停止服务：

```bash
docker compose --env-file .env -f docker-compose.yml down
```

删除数据卷并进行一次干净的本地运行：

```bash
docker compose --env-file .env -f docker-compose.yml down -v
```

## 开发

后端检查：

```bash
docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go generate ./...
docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...
```

前端检查：

```bash
cd web
npm ci
npm run build
npm test
npm run e2e
OHMYRASP_E2E_LIVE_URL=http://127.0.0.1:18091 npm run e2e:live
```

部署和可观测性检查：

```bash
./deploy/scripts/smoke-control-plane.sh
./deploy/scripts/validate-helm-manifests.sh
./deploy/scripts/validate-observability-assets.sh
```

Java Agent 验收：

```bash
cd java-agent
bash scripts/acceptance.sh
```

Java Agent 验收脚本会在 `18080` 启动基线 Tomcat 实例，并在 `18081` 启动受保护 Tomcat 实例。这些端口有意与控制平面栈分离。

## 文档

- [控制平台概览](docs/control-platform.md)
- [能力审计](docs/capability-audit.md)
- [API 说明](docs/api.md)
- [Web 控制台说明](docs/web.md)
- [Java Agent 说明](docs/java-agent.md)
- [Runbooks](docs/runbooks/)

历史上游和参考材料会保留在本地 `.archive/` 目录中以便追溯，但该目录已被 Git 忽略，不属于发布仓库内容。

## 致谢

OhMyRASP 的 Java Agent 概念验证使用了 [ASM](https://asm.ow2.io/) 字节码工程库。感谢 ASM 项目及其维护者提供的工具，使精确的 JVM 插桩成为现实。

我们也感谢 [OpenRASP](https://github.com/baidu/openrasp) 项目。OpenRASP 帮助定义了围绕开放式运行时应用自我保护的许多理念和运维预期，并且仍然是该生态的重要参考。

## 安全

`.env` 会被有意忽略。请不要提交真实服务凭据、私有主机名、私有 IP 地址或生产 Agent 制品。

如需报告安全问题，请在公开细节前创建私有安全公告或联系维护者。

## 许可证

Apache License 2.0。详见 [LICENSE](LICENSE)。
