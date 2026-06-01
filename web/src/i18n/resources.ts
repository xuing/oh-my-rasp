export const resources = {
  en: {
    translation: {
      language: {
        label: "Language",
        english: "English",
        chinese: "Chinese",
        japanese: "Japanese"
      },
      shell: {
        product: "OhMyRasp Control",
        subtitle: "Self-hosted RASP platform",
        title: "RASP Control Plane",
        summary: "Single organization, multiple apps, environments, Agents, and policies.",
        validateRule: "Validate Rule",
        registerAgent: "Register Agent",
        signedIn: "Signed in",
        signIn: "Sign in",
        loadingConsole: "Loading console view."
      },
      login: {
        title: "Sign in to OhMyRasp",
        email: "Email",
        password: "Password",
        submit: "Sign in",
        submitting: "Signing in",
        error: "Unable to sign in with those credentials."
      },
      navigation: {
        overview: {
          label: "Overview",
          description: "Fleet posture, active policy versions, high-risk event trend, and online Agent health."
        },
        applications: {
          label: "Applications",
          description: "Single-organization inventory of applications and deployment environments."
        },
        agents: {
          label: "Agents",
          description: "Java Agent registration, heartbeat status, version drift, and assigned policy view."
        },
        policies: {
          label: "Policies",
          description: "Rule editing, validation, testing, versioning, canary rollout, and rollback workflows."
        },
        events: {
          label: "Events",
          description: "Attack, Hook, performance, crash, error, and dependency reports with queryable timeline."
        },
        observability: {
          label: "Observability",
          description: "Rule overhead, Hook latency, Agent overhead, and policy-version performance impact."
        },
        access: {
          label: "Access & Audit",
          description: "Enterprise login, RBAC, operation audit logs, alerts, and system settings."
        }
      },
      pages: {
        applications: {
          title: "Applications",
          summary: "Application and environment scope replaces the legacy tenant hierarchy. Each application owns its Agent secret, environment inventory, and policy assignment defaults."
        },
        agents: {
          title: "Agents",
          summary: "Registration, heartbeat, policy pulls, event reporting, version drift, and runtime metadata are grouped per application and environment."
        },
        policies: {
          title: "Policies",
          summary: "Policy sets are composed from rules and promoted through validation, simulation, versioning, canary release, and rollback."
        },
        events: {
          title: "Events",
          summary: "Attack, Hook, performance, crash, error, and dependency reports are split between transactional storage and analytical ClickHouse pipelines."
        },
        observability: {
          title: "Observability",
          summary: "Rule overhead, Hook latency, Agent overhead, and policy-version impact are tracked as first-class performance telemetry."
        },
        access: {
          title: "Access & Audit",
          summary: "Enterprise login, RBAC, system settings, alerts, and operation audit logs are modeled for a single self-hosted organization."
        }
      },
      overview: {
        metrics: {
          applications: "Applications",
          applicationsDetail: "managed services",
          onlineAgents: "Online Agents",
          onlineAgentsDetail: "{{rate}}% reporting",
          events: "Events",
          eventsDetail: "current query window",
          attacks: "Attacks",
          attacksDetail: "active attack events",
          crashes: "Crashes",
          crashesDetail: "agent crash reports",
          critical: "Critical",
          criticalDetail: "highest severity signals",
          hookP95: "Hook p95",
          hookP95Detail: "requires observability data"
        },
        attackTrend: "Attack Trend",
        eventDistribution: "Event Distribution",
        eventTypes: "Event Types",
        severities: "Severities",
        attackHooks: "Attack Hooks",
        topHooks: "Top Hooks",
        vulnerabilitySignals: "Risk Signals",
        topAlgorithms: "Top Algorithms",
        userAgents: "User-Agent Sources",
        topUserAgents: "Top User-Agents",
        noDashboardData: "No dashboard data",
        controlDomains: "Control Domains",
        policyLifecycle: "Policy Lifecycle"
      },
      lifecycle: {
        draft: "Draft",
        validate: "Validate",
        test: "Test",
        version: "Version",
        canary: "Canary",
        promote: "Promote",
        rollback: "Rollback"
      },
      onboarding: {
        addInstance: "Add Instance",
        summary: "Register a workload, install the Java agent, and verify that heartbeats plus runtime evidence arrive in the control plane.",
        badge: "Agent onboarding",
        targetScope: "Target Scope",
        application: "Application",
        environment: "Environment",
        defaultApplication: "app_default",
        applicationUnavailable: "Application metadata is unavailable.",
        appBadge: "app:",
        envBadge: "env:",
        copy: "Copy",
        heartbeat: "Heartbeat",
        heartbeatDetail: "Agent status changes to online after registration.",
        policyPull: "Policy pull",
        policyPullDetail: "Assigned policy version appears on the Agent row.",
        runtimeEvidence: "Runtime evidence",
        runtimeEvidenceDetail: "Dependency, baseline, performance, error, and crash records are produced by the Agent."
      },
      legacy: {
        focusedRoute: "Focused legacy route",
        maintainHosts: {
          label: "Host Maintenance",
          detail: "Agent inventory, ignore state, aliases, and heartbeat operations."
        },
        maintainClearData: {
          label: "Maintenance Cleanup",
          detail: "Operational data retention, dry-run cleanup, and confirmed purge controls."
        },
        maintainWhitelist: {
          label: "Protection Allowlist",
          detail: "Hardening settings and exception-oriented policy controls."
        },
        maintainGeneral: {
          label: "General Protection Settings",
          detail: "System settings, edition status, and control-plane version information."
        },
        maintainUpgrade: {
          label: "Agent Upgrade",
          detail: "Artifact catalog, daemon download metadata, and version drift checks."
        },
        algorithm: {
          label: "Algorithm Configuration",
          detail: "Policy versions, rule validation, rollout, rollback, and default rule restoration."
        },
        algorithmHardening: {
          label: "Hardening Configuration",
          detail: "Runtime hardening settings and system-level protection controls."
        },
        algorithmAlarm: {
          label: "Alarm Configuration",
          detail: "Alert rules, delivery targets, delivery history, and alert status."
        },
        logExceptions: {
          label: "Error Events",
          detail: "Agent-produced error events and exception attributes."
        },
        logCrash: {
          label: "Crash Events",
          detail: "Agent-produced crash events and uncaught exception context."
        },
        logAudit: {
          label: "Audit Log",
          detail: "Authenticated control-plane audit trail and operational write history."
        },
        platform: {
          label: "Platform Administration",
          detail: "Users, RBAC, system settings, edition status, and audit trail."
        },
        platformUser: {
          label: "User Administration",
          detail: "User lifecycle, role assignment, disabling, and filtered user search."
        },
        settingsPanel: {
          label: "Panel Settings",
          detail: "Console settings, system version, edition state, and operator-facing configuration."
        },
        settingsAlarm: {
          label: "Alarm Settings",
          detail: "Alert rules, alert deliveries, target status, and notification routing."
        },
        settingsSystemInfo: {
          label: "System Information",
          detail: "Control-plane version, build metadata, and edition state."
        },
        settingsPoolVersion: {
          label: "Agent Package Versions",
          detail: "Managed artifact catalog and daemon artifact lookup."
        },
        settingsVersion: {
          label: "Agent Version Status",
          detail: "Agent inventory versions, drift checks, and upgrade state."
        }
      }
    }
  },
  zh: {
    translation: {
      language: {
        label: "语言",
        english: "英语",
        chinese: "中文",
        japanese: "日语"
      },
      shell: {
        product: "OhMyRasp 控制台",
        subtitle: "自托管 RASP 平台",
        title: "RASP 控制平面",
        summary: "面向单个组织，统一管理应用、环境、Agent 和策略。",
        validateRule: "验证规则",
        registerAgent: "注册 Agent",
        signedIn: "已登录",
        signIn: "登录",
        loadingConsole: "正在加载控制台视图。"
      },
      login: {
        title: "登录 OhMyRasp",
        email: "邮箱",
        password: "密码",
        submit: "登录",
        submitting: "正在登录",
        error: "无法使用这组凭据登录。"
      },
      navigation: {
        overview: {
          label: "概览",
          description: "查看集群态势、活跃策略版本、高风险事件趋势和在线 Agent 健康状态。"
        },
        applications: {
          label: "应用",
          description: "单组织下的应用与部署环境清单。"
        },
        agents: {
          label: "Agent",
          description: "Java Agent 注册、心跳状态、版本漂移和已分配策略视图。"
        },
        policies: {
          label: "策略",
          description: "规则编辑、验证、测试、版本管理、灰度发布和回滚流程。"
        },
        events: {
          label: "事件",
          description: "攻击、Hook、性能、崩溃、异常和依赖报告，并支持时间线查询。"
        },
        observability: {
          label: "可观测性",
          description: "规则开销、Hook 延迟、Agent 开销和策略版本性能影响。"
        },
        access: {
          label: "访问与审计",
          description: "企业登录、RBAC、操作审计日志、告警和系统设置。"
        }
      },
      pages: {
        applications: {
          title: "应用",
          summary: "应用与环境范围替代了旧版租户层级。每个应用拥有自己的 Agent 密钥、环境清单和默认策略分配。"
        },
        agents: {
          title: "Agent",
          summary: "注册、心跳、策略拉取、事件上报、版本漂移和运行时元数据按应用与环境聚合。"
        },
        policies: {
          title: "策略",
          summary: "策略集由规则组成，并通过验证、模拟、版本管理、灰度发布和回滚完成生命周期管理。"
        },
        events: {
          title: "事件",
          summary: "攻击、Hook、性能、崩溃、异常和依赖报告分别进入事务型存储与 ClickHouse 分析管线。"
        },
        observability: {
          title: "可观测性",
          summary: "规则开销、Hook 延迟、Agent 开销和策略版本影响作为一等性能遥测数据跟踪。"
        },
        access: {
          title: "访问与审计",
          summary: "企业登录、RBAC、系统设置、告警和操作审计日志面向单个自托管组织建模。"
        }
      },
      overview: {
        metrics: {
          applications: "应用",
          applicationsDetail: "托管服务",
          onlineAgents: "在线 Agent",
          onlineAgentsDetail: "{{rate}}% 正在上报",
          events: "事件",
          eventsDetail: "当前查询窗口",
          attacks: "攻击",
          attacksDetail: "活跃攻击事件",
          crashes: "崩溃",
          crashesDetail: "Agent 崩溃上报",
          critical: "严重",
          criticalDetail: "最高风险信号",
          hookP95: "Hook P95",
          hookP95Detail: "需要可观测性数据"
        },
        attackTrend: "攻击趋势",
        eventDistribution: "事件分布",
        eventTypes: "事件类型",
        severities: "严重级别",
        attackHooks: "攻击 Hook",
        topHooks: "高频 Hook",
        vulnerabilitySignals: "风险信号",
        topAlgorithms: "高频算法",
        userAgents: "User-Agent 来源",
        topUserAgents: "高频 User-Agent",
        noDashboardData: "暂无仪表盘数据",
        controlDomains: "控制域",
        policyLifecycle: "策略生命周期"
      },
      lifecycle: {
        draft: "草稿",
        validate: "验证",
        test: "测试",
        version: "版本",
        canary: "灰度",
        promote: "发布",
        rollback: "回滚"
      },
      onboarding: {
        addInstance: "添加实例",
        summary: "注册工作负载、安装 Java Agent，并确认心跳与运行时证据进入控制平面。",
        badge: "Agent 接入",
        targetScope: "目标范围",
        application: "应用",
        environment: "环境",
        defaultApplication: "app_default",
        applicationUnavailable: "应用元数据不可用。",
        appBadge: "应用：",
        envBadge: "环境：",
        copy: "复制",
        heartbeat: "心跳",
        heartbeatDetail: "注册后 Agent 状态变为在线。",
        policyPull: "策略拉取",
        policyPullDetail: "Agent 行展示已分配的策略版本。",
        runtimeEvidence: "运行时证据",
        runtimeEvidenceDetail: "依赖、基线、性能、异常和崩溃记录由 Agent 产生。"
      },
      legacy: {
        focusedRoute: "已聚焦的旧版入口",
        maintainHosts: {
          label: "主机维护",
          detail: "Agent 清单、忽略状态、别名和心跳操作。"
        },
        maintainClearData: {
          label: "维护清理",
          detail: "运行数据保留、清理预览和确认清理控制。"
        },
        maintainWhitelist: {
          label: "防护白名单",
          detail: "加固设置和面向例外的策略控制。"
        },
        maintainGeneral: {
          label: "通用防护设置",
          detail: "系统设置、版本状态和控制平面版本信息。"
        },
        maintainUpgrade: {
          label: "Agent 升级",
          detail: "制品目录、Daemon 下载元数据和版本漂移检查。"
        },
        algorithm: {
          label: "算法配置",
          detail: "策略版本、规则验证、发布、回滚和默认规则恢复。"
        },
        algorithmHardening: {
          label: "加固配置",
          detail: "运行时加固设置和系统级防护控制。"
        },
        algorithmAlarm: {
          label: "告警配置",
          detail: "告警规则、投递目标、投递历史和告警状态。"
        },
        logExceptions: {
          label: "异常事件",
          detail: "Agent 产生的异常事件和异常属性。"
        },
        logCrash: {
          label: "崩溃事件",
          detail: "Agent 产生的崩溃事件和未捕获异常上下文。"
        },
        logAudit: {
          label: "审计日志",
          detail: "已认证控制平面审计轨迹和操作写入历史。"
        },
        platform: {
          label: "平台管理",
          detail: "用户、RBAC、系统设置、版本状态和审计轨迹。"
        },
        platformUser: {
          label: "用户管理",
          detail: "用户生命周期、角色分配、禁用和筛选搜索。"
        },
        settingsPanel: {
          label: "面板设置",
          detail: "控制台设置、系统版本、版本状态和运维配置。"
        },
        settingsAlarm: {
          label: "告警设置",
          detail: "告警规则、告警投递、目标状态和通知路由。"
        },
        settingsSystemInfo: {
          label: "系统信息",
          detail: "控制平面版本、构建元数据和版本状态。"
        },
        settingsPoolVersion: {
          label: "Agent 包版本",
          detail: "托管制品目录和 Daemon 制品查询。"
        },
        settingsVersion: {
          label: "Agent 版本状态",
          detail: "Agent 清单版本、漂移检查和升级状态。"
        }
      }
    }
  },
  ja: {
    translation: {
      language: {
        label: "言語",
        english: "英語",
        chinese: "中国語",
        japanese: "日本語"
      },
      shell: {
        product: "OhMyRasp コントロール",
        subtitle: "セルフホスト RASP プラットフォーム",
        title: "RASP コントロールプレーン",
        summary: "単一組織でアプリ、環境、Agent、ポリシーを管理します。",
        validateRule: "ルールを検証",
        registerAgent: "Agent を登録",
        signedIn: "ログイン済み",
        signIn: "サインイン",
        loadingConsole: "コンソールビューを読み込み中。"
      },
      login: {
        title: "OhMyRasp にサインイン",
        email: "メール",
        password: "パスワード",
        submit: "サインイン",
        submitting: "サインイン中",
        error: "この認証情報ではサインインできません。"
      },
      navigation: {
        overview: {
          label: "概要",
          description: "フリート状態、アクティブなポリシー、高リスクイベント傾向、オンライン Agent の健全性を表示します。"
        },
        applications: {
          label: "アプリケーション",
          description: "単一組織のアプリケーションとデプロイ環境のインベントリです。"
        },
        agents: {
          label: "Agent",
          description: "Java Agent の登録、ハートビート、バージョン差分、割り当て済みポリシーを管理します。"
        },
        policies: {
          label: "ポリシー",
          description: "ルール編集、検証、テスト、バージョン管理、カナリアリリース、ロールバックを扱います。"
        },
        events: {
          label: "イベント",
          description: "攻撃、Hook、性能、クラッシュ、エラー、依存関係レポートを検索可能なタイムラインで扱います。"
        },
        observability: {
          label: "可観測性",
          description: "ルール負荷、Hook レイテンシ、Agent 負荷、ポリシーバージョンの性能影響を表示します。"
        },
        access: {
          label: "アクセスと監査",
          description: "企業ログイン、RBAC、操作監査ログ、アラート、システム設定を扱います。"
        }
      },
      pages: {
        applications: {
          title: "アプリケーション",
          summary: "アプリケーションと環境のスコープが従来のテナント階層を置き換えます。各アプリは Agent シークレット、環境インベントリ、既定のポリシー割り当てを持ちます。"
        },
        agents: {
          title: "Agent",
          summary: "登録、ハートビート、ポリシー取得、イベント送信、バージョン差分、ランタイムメタデータをアプリと環境ごとに整理します。"
        },
        policies: {
          title: "ポリシー",
          summary: "ポリシーセットはルールから構成され、検証、シミュレーション、バージョン管理、カナリアリリース、ロールバックで運用します。"
        },
        events: {
          title: "イベント",
          summary: "攻撃、Hook、性能、クラッシュ、エラー、依存関係レポートをトランザクションストアと ClickHouse 分析パイプラインに分離します。"
        },
        observability: {
          title: "可観測性",
          summary: "ルール負荷、Hook レイテンシ、Agent 負荷、ポリシーバージョン影響を主要な性能テレメトリとして追跡します。"
        },
        access: {
          title: "アクセスと監査",
          summary: "企業ログイン、RBAC、システム設定、アラート、操作監査ログを単一のセルフホスト組織向けにモデル化します。"
        }
      },
      overview: {
        metrics: {
          applications: "アプリケーション",
          applicationsDetail: "管理対象サービス",
          onlineAgents: "オンライン Agent",
          onlineAgentsDetail: "{{rate}}% レポート中",
          events: "イベント",
          eventsDetail: "現在のクエリ期間",
          attacks: "攻撃",
          attacksDetail: "アクティブな攻撃イベント",
          crashes: "クラッシュ",
          crashesDetail: "Agent クラッシュレポート",
          critical: "重大",
          criticalDetail: "最高深刻度の信号",
          hookP95: "Hook p95",
          hookP95Detail: "可観測性データが必要"
        },
        attackTrend: "攻撃トレンド",
        eventDistribution: "イベント分布",
        eventTypes: "イベントタイプ",
        severities: "深刻度",
        attackHooks: "攻撃 Hook",
        topHooks: "上位 Hook",
        vulnerabilitySignals: "リスク信号",
        topAlgorithms: "上位アルゴリズム",
        userAgents: "User-Agent ソース",
        topUserAgents: "上位 User-Agent",
        noDashboardData: "ダッシュボードデータはありません",
        controlDomains: "制御ドメイン",
        policyLifecycle: "ポリシーライフサイクル"
      },
      lifecycle: {
        draft: "下書き",
        validate: "検証",
        test: "テスト",
        version: "バージョン",
        canary: "カナリア",
        promote: "昇格",
        rollback: "ロールバック"
      },
      onboarding: {
        addInstance: "インスタンスを追加",
        summary: "ワークロードを登録し、Java Agent をインストールして、ハートビートとランタイム証跡がコントロールプレーンに届くことを確認します。",
        badge: "Agent オンボーディング",
        targetScope: "対象スコープ",
        application: "アプリケーション",
        environment: "環境",
        defaultApplication: "app_default",
        applicationUnavailable: "アプリケーションメタデータを利用できません。",
        appBadge: "app:",
        envBadge: "env:",
        copy: "コピー",
        heartbeat: "ハートビート",
        heartbeatDetail: "登録後に Agent ステータスがオンラインへ変わります。",
        policyPull: "ポリシー取得",
        policyPullDetail: "割り当て済みポリシーバージョンが Agent 行に表示されます。",
        runtimeEvidence: "ランタイム証跡",
        runtimeEvidenceDetail: "依存関係、ベースライン、性能、エラー、クラッシュ記録は Agent が生成します。"
      },
      legacy: {
        focusedRoute: "フォーカス済みレガシールート",
        maintainHosts: {
          label: "ホスト保守",
          detail: "Agent インベントリ、無視状態、エイリアス、ハートビート操作。"
        },
        maintainClearData: {
          label: "保守クリーンアップ",
          detail: "運用データ保持、ドライラン、確認付き削除操作。"
        },
        maintainWhitelist: {
          label: "保護許可リスト",
          detail: "強化設定と例外向けポリシー制御。"
        },
        maintainGeneral: {
          label: "一般保護設定",
          detail: "システム設定、エディション状態、コントロールプレーンバージョン情報。"
        },
        maintainUpgrade: {
          label: "Agent アップグレード",
          detail: "アーティファクトカタログ、Daemon ダウンロードメタデータ、バージョン差分確認。"
        },
        algorithm: {
          label: "アルゴリズム設定",
          detail: "ポリシーバージョン、ルール検証、ロールアウト、ロールバック、既定ルール復元。"
        },
        algorithmHardening: {
          label: "強化設定",
          detail: "ランタイム強化設定とシステムレベルの保護制御。"
        },
        algorithmAlarm: {
          label: "アラーム設定",
          detail: "アラートルール、配信先、配信履歴、アラート状態。"
        },
        logExceptions: {
          label: "エラーイベント",
          detail: "Agent が生成したエラーイベントと例外属性。"
        },
        logCrash: {
          label: "クラッシュイベント",
          detail: "Agent が生成したクラッシュイベントと未捕捉例外コンテキスト。"
        },
        logAudit: {
          label: "監査ログ",
          detail: "認証済みコントロールプレーン監査証跡と操作履歴。"
        },
        platform: {
          label: "プラットフォーム管理",
          detail: "ユーザー、RBAC、システム設定、エディション状態、監査証跡。"
        },
        platformUser: {
          label: "ユーザー管理",
          detail: "ユーザーライフサイクル、ロール割り当て、無効化、フィルター検索。"
        },
        settingsPanel: {
          label: "パネル設定",
          detail: "コンソール設定、システムバージョン、エディション状態、運用設定。"
        },
        settingsAlarm: {
          label: "アラーム設定",
          detail: "アラートルール、アラート配信、宛先状態、通知ルーティング。"
        },
        settingsSystemInfo: {
          label: "システム情報",
          detail: "コントロールプレーンバージョン、ビルドメタデータ、エディション状態。"
        },
        settingsPoolVersion: {
          label: "Agent パッケージバージョン",
          detail: "管理対象アーティファクトカタログと Daemon アーティファクト検索。"
        },
        settingsVersion: {
          label: "Agent バージョン状態",
          detail: "Agent インベントリバージョン、差分確認、アップグレード状態。"
        }
      }
    }
  }
} as const;
