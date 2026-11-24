# OhMyRASP

基于 ASM 字节码插桩、调用栈结构分析与请求参数关联的自托管 Java RASP。覆盖 JDK 8、11、17、21 与 25——既可以配合 Rust Host Daemon 与 Go/React 控制平面集中管控，也可以作为签名 [shirudo](https://github.com/shirudo-dev/shirudo) Java upatch 在目标机上无守护进程独立运行。

[![CI](https://github.com/xuing/oh-my-rasp/actions/workflows/ohmyrasp-control.yml/badge.svg)](https://github.com/xuing/oh-my-rasp/actions/workflows/ohmyrasp-control.yml)
[![Release](https://img.shields.io/github/v/release/xuing/oh-my-rasp?include_prereleases)](https://github.com/xuing/oh-my-rasp/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Java agents](https://img.shields.io/badge/Java-8%20%7C%2011%20%7C%2017%20%7C%2025-ED8B00?logo=openjdk&logoColor=white)](java-agent/)
[![Exploit scenarios](https://img.shields.io/badge/exploit_scenarios-136_verified-success)](docs/development/vulhub-coverage.md)

**语言：** [English](README.md) | 简体中文

---

## 60 秒看到一次真实拦截

只需要 Docker，启动挂载 block 模式 agent 的 Tomcat 11 与 daemon 本地控制台：

```bash
cd java-agent
docker compose -f docker-compose.daemon.yml up -d --build

# 发送一条 SQL 注入载荷
curl -L "http://localhost:18090/rasp/sqli?id=1+OR+1=1"
# -> 请求在执行到达数据库前被拦截，重定向至 /rasp/blocked

# 实时查看攻击日志、各 hook 耗时及在线切换 off / monitor / block 模式
open http://localhost:7070
```

> 演示应用默认占用 `18090` 端口（与控制平面 API 端口相同），同时运行两者时可通过 `OHMYRASP_DEMO_PORT` 改绑端口。

如果需要 Tomcat 9 / 10 / 11 基线与受保护实例并排对比试验场，见 [docs/getting-started.md](docs/getting-started.md)。

## 实测数据与漏洞覆盖

全部 hook、检测器与 Vulhub 回放脚本均在仓库内开源，并由 CI 持续回归。

| 维度 | 当前状态 | 依据 |
|---|---|---|
| 插桩调用点家族 | 28 个 ASM hook 模块 | [DETECTION-COVERAGE.md](java-agent/docs/DETECTION-COVERAGE.md) |
| 检测引擎 | 54 项检测能力，其中 43 个算法签名由端到端测试断言 | [docs/detection.md](docs/detection.md) |
| 漏洞回放矩阵 | 136 个场景，覆盖 53 个 [Vulhub](https://github.com/vulhub/vulhub) 组件根（追踪 130 个 CVE） | [vulhub-coverage.md](docs/development/vulhub-coverage.md) |
| 正常语料误报率 | 14 类共 83 条真实构造正常输入，`0 / 83` 误报 | [FALSE-POSITIVE-REPORT.md](java-agent/docs/FALSE-POSITIVE-REPORT.md) |
| 运行时支持 | JDK 8、11、17 各有独立构建，21 和 25 共用主 Agent；兼容 `javax.servlet` 与 `jakarta.servlet` | [docs/agent.md](docs/agent.md) |

**已验证拦截的代表性漏洞：**
- **OpenJDK Base64 AVX-512 尾部越界写（Java2Shell / Java4Shell，CVE-2026-114938）**，覆盖 JDK 8–25
- **JNDI 与反序列化：** Log4Shell（CVE-2021-44228）、Fastjson `autoType` 与 [1.2.83 `getResourceAsStream`](https://github.com/midisec/fastjson-1.2.83-gadget-rce)、Shiro `rememberMe`（CVE-2016-4437）、ActiveMQ OpenWire（CVE-2023-46604）、XStream、WebLogic XMLDecoder
- **表达式与模板 RCE：** 19 个 Struts2 OGNL 漏洞（S2-001 至 S2-067）、Spring4Shell（CVE-2022-22965）、Spring Cloud Gateway SpEL（CVE-2022-22947）、GeoServer（CVE-2024-36401）、DataEase（2024–2025）
- **Servlet、文件与 SQL：** Tomcat 幽灵猫（CVE-2020-1938）、Shiro/GlassFish/Jetty 路径混淆绕过、独立应用及全驱动 JDBC `Statement` SQL 注入

## 检测引擎工作原理

OhMyRASP 不在网络边界对 HTTP 报文做正则猜谜，而是直接把检测点放在 JDK 关键 sink 内部：

- **请求参数污点关联：** 命令执行与 SQL 注入在 sink 处对照 `ThreadLocal<RequestContext>` 校验参数来源，只有确认携带攻击者可控输入才升级为阻断级告警，避免误伤内部定时任务。
- **`StackWalker` 调用栈结构分析：** 在 `ProcessBuilder.start` 等危险入口检查实时调用栈帧，准确区分 Struts2 OGNL、Spring SpEL、MVEL、Groovy、XStream 反序列化链与正常业务代码。
- **六重路径解码对比：** 将请求 URI 同时按原始、单次解码、两次解码、低字节 Unicode、超长 UTF-8 与宽松百分号解码归一化并交叉比对，用一个通用检测器覆盖多类路径混淆绕过。
- **真实密码学验签/解密：** 对可疑默认密钥 Bearer JWT 执行真实 HMAC 校验，对 Shiro `rememberMe` Cookie 用已知默认密钥解密并检查 Java 序列化魔数头。
- **Java2Shell 零分配算术快路径（CVE-2026-114938）：** 在 `java.util.Base64$Decoder.decode0` 入口执行纯算术条件检查（`length >= 65`、`1 <= (length & 63) <= 3`、`1 <= padding <= 2`、`padding <= remainder`、严格 Base64 字符集、`!isMIME`），在本地 AVX-512 stub 越界写发生前阻断恶意输入，脱离 HTTP 请求上下文也可生效，且仅记录长度等元数据。
- **Fastjson 1.2.83 类资源边界拦截：** 仅在 `ParserConfig.checkAutoType` 调用栈内拦截 `ClassLoader.getResourceAsStream`，阻断 `http(s)://`、`jar:http(s)://` 及 `jar:file:/proc/self/fd/` 等外部资源加载，放行正常 classpath 与 Spring Boot `jar:nested:`。
- **热路径非阻塞写盘：** 告警异步进入本地 NDJSON spool（shirudo 独立模式下直接写 `stderr`），运行模式（`off` / `monitor` / `block`）可热切换而无需重启 JVM。

完整技术细节见 [docs/detection.md](docs/detection.md)。

## Shirudo Java Upatch 独立包

对于使用 **[shirudo](https://github.com/shirudo-dev/shirudo)** 拉取式、ML-DSA-87 签名、TPM2 度量体系的 Linux 目标机，OhMyRASP 在 [`deploy/shirudo/`](deploy/shirudo/README.md) 提供了开箱可签的 **Shirudo Java Upatch 打包方案**：

| 包名 | 目标 JVM | Upatch / JAR 文件名 | Gradle 模块 |
|---|---|---|---|
| `ohmyrasp-java8` | Java 8（classfile `<= 52`） | `ohmyrasp-java8.jar` | `:agent-java8` |
| `ohmyrasp-java11` | Java 11（classfile `<= 55`） | `ohmyrasp-java11.jar` | `:agent-java11` |
| `ohmyrasp-java17` | Java 17 与 Java 21（classfile `<= 61`） | `ohmyrasp-java17.jar` | `:agent-java17` |
| `ohmyrasp-jdk25` | Java 21 与 Java 25（classfile `<= 65`） | `ohmyrasp-jdk25.jar` | `:agent-jdk25` |

该系列包内置 `META-INF/ohmyrasp-shirudo.properties`（`standalone=true`、`lock_config=true`、`mode=block`、`control=none`、`log=stderr`、`latency_sample=0`）：

- **零后台线程**：不启动控制文件轮询线程与本地写盘线程。
- **防配置降级**：`lock_config=true` 只从已签名 JAR 内部加载，目标机上的 `/tmp/ohmyrasp-control.json` 或 `OHMYRASP_MODE=off` 等环境变量均无法关闭阻断。
- **零落盘噪声**：结构化 JSON 检测事件直接输出到 JVM `stderr`，不在 `/tmp` 生成 `ohmyrasp-events.jsonl`，也不打印 `hook_latency` 采样。

你可以从 [GitHub Releases](https://github.com/xuing/oh-my-rasp/releases) 直接下载预构建的 `ohmyrasp-shirudo-upatches-<version>.tar.gz` 签名发布，或在本地一键构建并运行实机容器冒烟测试：

```sh
# 使用 Operator 的 ML-DSA-87 私钥构建并签名全部 4 个 .bee 包
./deploy/shirudo/build-all.sh 0.2.0 --keys-dir <keys>

# 或仅构建 JAR 并运行 Beefile 校验与 Temurin 8/11/17/21/25 容器冒烟测试
./deploy/shirudo/build-all.sh --jar-only
./deploy/shirudo/verify-shirudo-upatch.sh
./deploy/shirudo/smoke-test.sh
```

`shirudo bpm install`、Java 8 `JAVA_TOOL_OPTIONS` 1024 字节限制、容器挂载方式及安全边界详见 [deploy/shirudo/README.md](deploy/shirudo/README.md)。

## 快速开始

### 方式 A：直接下载预构建 Release 制品

[GitHub Releases](https://github.com/xuing/oh-my-rasp/releases) 随版本发布标准 Java Agent JAR、shirudo 无守护进程 Java upatch JAR、`ohmyrasp-shirudo-upatches-<version>.tar.gz`、`ohmyrasp-daemon-linux-amd64.tar.gz`、Helm Chart、`SHA256SUMS.txt` 以及 SLSA provenance 证明。

### 方式 B：本地构建 Agent（仅需 Docker）

```bash
cd java-agent
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/tmp/gradle-home \
  -v "$PWD":/workspace -w /workspace gradle:9.9.2-jdk25 \
  gradle --no-daemon :agent-jdk25:agentJar
# -> agent-jdk25/build/libs/ohmyrasp-agent.jar
```

旧版 JDK 请构建 `:agent-java8:agentJava8Jar`、`:agent-java11:agentJava11Jar` 或 `:agent-java17:agentJava17Jar`（Java 21 和 25 共用上面的主 Agent）；无守护进程 shirudo 构建使用 `:agent-*:shirudoUpatchJar`。

### 挂载到目标应用

独立运行（无需控制平面）：

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=mode=monitor \
     -Dohmyrasp.log=/var/log/ohmyrasp/events.jsonl \
     -jar your-app.jar
```

接入自托管控制平面：

```bash
cp .env.example .env
# 填写 .env 中的空白密钥（可用 openssl rand -hex 18 生成）
docker compose --env-file .env -f docker-compose.yml up -d --build
```

| 服务 | 默认地址 |
|---|---|
| Web 控制台 | `http://<host>:18091` |
| 控制平面 API | `http://<host>:18090` |
| Grafana / Prometheus / Alertmanager | `:13000` / `:19090` / `:19093` |
| ClickHouse HTTP | `http://<host>:18123` |

使用 `admin@ohmyrasp.local` 与 `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD` 登录控制台创建应用获取 `app_id` 与 `app_secret`，然后启动目标 JVM：

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=backend_url=http://<host>:18090,app_id=<app-id>,app_secret=<secret>,environment_id=<env-id>,mode=block \
     -jar your-app.jar
```

完整操作见 [docs/getting-started.md](docs/getting-started.md)。

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

| 模块 | 技术栈 | 职责 |
|---|---|---|
| `java-agent/` | Java 8/11/17/25, ASM 9.11.1 | JVM 内置 hook、检测引擎、NDJSON spool、shirudo 独立包 |
| `daemon/` | Rust | 跟踪 agent spool、上报事件、本地实时控制台、注入管理 |
| `api/` | Go, OpenAPI 3.1 | RBAC、应用与实例清单、策略下发/灰度/回滚、遥测摄入 |
| `console/` | React 19, Vite | 概览仪表盘、威胁处置、策略编辑测试、延迟与基线视图（EN/中文/日本語） |
| `deploy/` | Helm, Compose, shirudo | Kubernetes Helm chart、可观测性资产、[shirudo Java upatch 包](deploy/shirudo/README.md) |

更多细节见 [docs/architecture.md](docs/architecture.md)。

## 项目状态

OhMyRASP 当前处于预发布阶段（[GitHub Releases](https://github.com/xuing/oh-my-rasp/releases) 已发布实验版 `v0.2.0-alpha.1`），API、策略语义与打包细节仍可能调整。单靠 JVM 内的 Java agent 无法防止目标机 `root` 绕过环境变量；如需抗 `root` 篡改边界，请配合内核级机制（例如 shirudo BPF upatch）共同部署。

## 开发与文档

```bash
# Go 控制平面
docker run --rm -v "$PWD/api":/src -w /src golang:1.26.5 go test ./...

# Web 控制台
cd console && npm ci && npm run build && npm test

# Java agent 单元测试 + 136 场景 Docker 验收矩阵
cd java-agent && bash scripts/acceptance.sh

# Shirudo upatch Beefile/JAR 校验与 Temurin 8/11/17/21/25 容器冒烟测试
./deploy/shirudo/build-all.sh --jar-only
./deploy/shirudo/verify-shirudo-upatch.sh
./deploy/shirudo/smoke-test.sh
```

- [快速上手](docs/getting-started.md) · [系统架构](docs/architecture.md) · [检测深入解析](docs/detection.md)
- [Java agent](docs/agent.md) · [Shirudo Java upatch 包](deploy/shirudo/README.md) · [Web 控制台](docs/console.md) · [API 参考](docs/api-reference.md)
- [运维手册](docs/runbooks/) · [算法覆盖清单](docs/development/algorithm-coverage.md) · [Vulhub 回放清单](docs/development/vulhub-coverage.md)
- [贡献指南](CONTRIBUTING.md) · [安全策略](SECURITY.md)（欢迎提交检测绕过报告）

## 致谢

Agent 基于 [ASM](https://asm.ow2.io/) 构建，借鉴了 [OpenRASP](https://github.com/baidu/openrasp) 的设计理念，通过 [Vulhub](https://github.com/vulhub/vulhub) 完成真实漏洞回归验证，并面向 [shirudo](https://github.com/shirudo-dev/shirudo) 提供原生 Java upatch 打包支持。

## 许可证

Apache License 2.0，详见 [LICENSE](LICENSE)。
