# OhMyRASP

**面向 Java 的运行时应用自我保护（RASP）—— 自托管、可审计、用真实漏洞验证。**

OhMyRASP 通过 ASM 字节码注入从 JVM 内部进行插桩，监视每一个危险调用点
（`Runtime.exec`、JDBC、JNDI、反序列化、文件 I/O 等），在特征检测的基础上
叠加请求参数关联与调用栈分析，判断该调用是否为攻击。检测结果可以在
monitor 模式下观察，也可以在 block 模式下直接拦截，且无需重启 JVM 即可
在运行时切换模式。

[![CI](https://github.com/xuing/oh-my-rasp/actions/workflows/ohmyrasp-control.yml/badge.svg)](https://github.com/xuing/oh-my-rasp/actions/workflows/ohmyrasp-control.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Java agents](https://img.shields.io/badge/Java-8%20%7C%2011%20%7C%2017%20%7C%2025-ED8B00?logo=openjdk&logoColor=white)](java-agent/)
[![Exploit scenarios](https://img.shields.io/badge/exploit_scenarios-136_verified-success)](docs/development/vulhub-coverage.md)

**语言：** [English](README.md) | 简体中文


## 为什么选择 OhMyRASP

大多数 RASP 产品是黑盒。OhMyRASP 恰恰相反：每一个 hook、每一条检测算法、
以及证明其有效的每一个测试，全部都在这个仓库里。

| | |
|---|---|
| **插桩的危险调用点家族** | 27 个 ASM hook 模块——进程执行、SQL、JNDI、反序列化（原生、Hessian、XStream、Fastjson 式类型化载荷、OpenWire）、文件 I/O、SSRF、XXE、表达式引擎、JWT/会话、压缩包、类加载等 |
| **检测算法** | 引擎共 52 项检测能力，其中 43 项由测试断言验证 |
| **端到端验证** | 136 个验收场景在真实 [Vulhub](https://github.com/vulhub/vulhub) 镜像上回放；[覆盖清单](docs/development/vulhub-coverage.md) 跟踪 130 个 Java/JVM CVE |
| **已验证拦截的知名 CVE** | Log4Shell（CVE-2021-44228）、Spring4Shell（CVE-2022-22965）、Fastjson autoType、Shiro rememberMe（CVE-2016-4437）、19 个 Struts2 公告（S2-001 … S2-067）、Tomcat 幽灵猫（CVE-2020-1938）、ActiveMQ OpenWire（CVE-2023-46604）、WebLogic XMLDecoder、Spring Cloud Gateway SpEL（CVE-2022-22947）、GeoServer（CVE-2024-36401）、XStream gadget、DataEase（2024–2025）等 |
| **运行时覆盖** | 为 Java 8、11、17、25 提供独立的 agent 构建；单个二进制同时覆盖 `javax.servlet` 与 `jakarta.servlet`（Tomcat 8.5 → 11） |
| **可度量的精确度** | 公开的[误报报告](java-agent/docs/FALSE-POSITIVE-REPORT.md)直接针对真实引擎生成、由 CI 保持更新——包括我们尚未解决的误报 |

检测引擎与纯模式匹配的区别：

- **请求污点关联** —— SQL 字符串或 shell 命令只有在确证包含攻击者可控的
  请求输入时（在调用点对照实时请求上下文检查），才会升级为攻击级别。
- **调用栈分析** —— 在调用点采集 `StackWalker` 栈轨迹，区分执行是*如何*
  到达这里的：同一个 `ProcessBuilder.start`，经由 Struts2 OGNL、Spring
  SpEL、XStream 反序列化链或普通应用代码到达时，会被分类为不同的算法。
- **六重路径解码** —— 将 URI 按六种解码形式（双重编码、超长 UTF-8、`%u`
  Unicode、ghost bits 等）归一化后对比，用一个通用检测器抓住
  Shiro/Nexus/GlassFish/Jetty 的各种路径混淆绕过。
- **密码学验证而非字符串匹配** —— 对默认密钥 JWT 进行真实的 HMAC 校验；
  对 Shiro `rememberMe` Cookie 实际解密以确认其中包含 Java 对象流。
- **响应侧泄漏检测** —— 在数据流出方向检查 Luhn 校验的银行卡号、身份证号
  和手机号，而不仅仅防御流入方向的攻击。
- **热路径零网络依赖** —— 事件写入本地 NDJSON spool 文件，由 Rust daemon
  负责跟踪和转发。off / monitor / block 模式通过轮询控制文件下发，无需
  重启 JVM。

完整细节见 **[docs/detection.md](docs/detection.md)**。

## 60 秒看到一次拦截

只需要 Docker。以下命令会启动一个挂载 agent（block 模式）的 Tomcat 11，
以及 daemon 的实时控制台：

```bash
cd java-agent
docker compose -f docker-compose.daemon.yml up -d --build

# 发起一次 SQL 注入——agent 在请求中途拦截
curl -L "http://localhost:18090/rasp/sqli?id=1+OR+1=1"
# → 被重定向到 /rasp/blocked

# 实时观察：攻击日志、各 hook 延迟、模式切换
open http://localhost:7070
```

> 演示应用默认使用 `18090` 端口，与控制平面 API 端口相同——如需同时运行
> 两者，请设置 `OHMYRASP_DEMO_PORT`。

还有一个完整的对比试验场（Tomcat 9、10、11 的基线与受保护实例并排对比），
见 [docs/getting-started.md](docs/getting-started.md)。

## 快速开始

### 1. 启动控制平面

```bash
cp .env.example .env
# 填写所有空白密码——请使用 URL 安全的值：
openssl rand -hex 18

docker compose --env-file .env -f docker-compose.yml up -d --build
```

| 服务 | 地址 |
| --- | --- |
| Web 控制台 | `http://<host>:18091` |
| API | `http://<host>:18090` |
| Grafana | `http://<host>:13000` |
| Prometheus | `http://<host>:19090` |
| Alertmanager | `http://<host>:19093` |
| ClickHouse HTTP | `http://<host>:18123` |

使用 `admin@ohmyrasp.local` 登录控制台，密码为 `.env` 中
`OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD` 的值。

### 2. 构建 agent

无需本地 JDK：

```bash
cd java-agent
docker run --rm -v "$PWD":/workspace -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-jdk25:agentJar
# → agent-jdk25/build/libs/ohmyrasp-agent.jar
```

旧版运行时请构建 `:agent-java8:agentJava8Jar`、
`:agent-java11:agentJava11Jar` 或 `:agent-java17:agentJava17Jar`。

### 3. 保护你的应用

独立运行（不需要控制平面）：

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=mode=monitor \
     -Dohmyrasp.log=/var/log/ohmyrasp/events.jsonl \
     -jar your-app.jar
```

接入控制平面（请先在控制台中创建应用以获取 id 和密钥）：

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=backend_url=http://<host>:18090,app_id=<app-id>,app_secret=<secret>,environment_id=<env-id>,mode=block \
     -jar your-app.jar
```

随后攻击事件会出现在控制台的 **Threats** 页面，附带严重级别、hook、算法
和请求上下文。完整教程：[docs/getting-started.md](docs/getting-started.md)。

## 架构

```text
                      ┌──────────────────────┐
                      │      Web 控制台       │
                      │    React 19 + Vite   │
                      └──────────┬───────────┘
                                 │
┌─────────────────┐   ┌──────────▼───────────┐   ┌─────────────────────┐
│   Host Daemon   │──►│      控制平面 API     │◄──│  Prometheus 规则     │
│      Rust       │   │     Go + OpenAPI     │   │  Alertmanager       │
└───▲─────────┬───┘   └───┬──────┬───────┬───┘   │  Grafana            │
    │ spool   │ 控制      │      │       │       └─────────────────────┘
    │ (NDJSON)│ 文件      ▼      ▼       ▼
┌───┴─────────▼───┐  PostgreSQL ClickHouse Valkey
│   Java Agent    │   控制状态    遥测数据   缓存
│  ASM 调用点钩子  │
└─────────────────┘
```

- **Java agent**（`java-agent/`）—— 在 27 个调用点家族注入 ASM 字节码
  hook，进程内检测，异步 NDJSON 事件 spool，控制文件模式切换。提供
  Java 8 / 11 / 17 / 25 构建。
- **Host daemon**（`daemon/`）—— Rust 实现；跟踪 agent spool、向控制平面
  转发事件、提供本地实时控制台、管理工作负载绑定与 agent 注入。
- **控制平面 API**（`api/`）—— Go 实现；认证、RBAC、应用与 agent 清单、
  策略生命周期（草稿 → 生效 → 金丝雀 → 回滚）、遥测摄入、制品目录、
  审计日志。OpenAPI 3.1 契约。
- **Web 控制台**（`console/`）—— React 19；总览仪表盘、威胁处置、应用与
  实例管理、策略编辑与测试、hook 延迟可观测性、依赖（SCA）与基线视图、
  RBAC 与审计。支持英文、中文、日本語。
- **部署**（`deploy/`）—— Helm chart、Prometheus 规则、Alertmanager 配置、
  Grafana 仪表盘、冒烟测试、运维手册。

更多细节：[docs/architecture.md](docs/architecture.md)。

## 项目状态

OhMyRASP 处于活跃开发中，**目前还不应作为生产环境的安全边界使用**。API、
策略语义和打包方式可能快速变化。当前适合实验、评估与参与贡献——上文的
测试证据真实且可复现。

近期重点：

- 解决已知的 JNDI 误报问题（`java:comp/env/*` 白名单）——见
  [误报报告](java-agent/docs/FALSE-POSITIVE-REPORT.md)。
- 在现有 53 个 Vulhub 组件根的基础上继续扩展漏洞语料，并利用 LLM 辅助
  分析靶场攻击路径、起草新检测规则供人工评审。
- 发布预构建制品（agent jar 与容器镜像）。

## 仓库结构

```text
api/          Go 控制平面 API、数据库迁移、OpenAPI 契约
console/      React 19 + Vite Web 控制台
java-agent/   Java agent（8/11/17/25）、检测引擎、Tomcat 试验场
daemon/       Rust host daemon（spool 转发、实时控制台、注入）
deploy/       Helm chart、可观测性资产、冒烟测试
docs/         用户与运维文档、开发清单、运维手册
.github/      CI 与发布工作流
```

## 开发

```bash
# Go 控制平面
docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...

# 控制台
cd console && npm ci && npm run build && npm test

# Java agent 单元测试 + 完整验收（6 个 Tomcat，约 136 个场景）
cd java-agent && bash scripts/acceptance.sh

# 部署校验
./deploy/scripts/smoke-control-plane.sh
./deploy/scripts/validate-helm-manifests.sh
```

完整开发指南见 [CONTRIBUTING.md](CONTRIBUTING.md)；漏洞报告方式见
[SECURITY.md](SECURITY.md)——**检测绕过明确属于受理范围，且尤其欢迎**。

## 文档

- [快速上手](docs/getting-started.md) —— 安装、运行、保护应用
- [检测深入解析](docs/detection.md) —— 引擎工作原理与数据
- [架构](docs/architecture.md) —— 控制平面、daemon、数据存储
- [Java agent](docs/agent.md) · [控制台](docs/console.md) · [API 参考](docs/api-reference.md)
- [运维手册](docs/runbooks/) —— Helm、备份恢复、升级、可观测性、发布
- [开发清单](docs/development/) —— 逐算法覆盖、Vulhub 回放清单

## 致谢

agent 构建于 [ASM](https://asm.ow2.io/) 字节码工程库之上——没有它，精确的
JVM 插桩将难以实现。

[OpenRASP](https://github.com/baidu/openrasp) 定义了开源运行时应用自我保护
的许多理念与运维预期，至今仍是该生态的重要参照。
[Vulhub](https://github.com/vulhub/vulhub) 让可复现的漏洞验证成为可能。

## 许可证

Apache License 2.0。见 [LICENSE](LICENSE)。
