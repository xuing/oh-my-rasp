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
        signIn: "Sign in"
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
          description: "Attack, Hook, crash, performance, and dependency reports with queryable timeline."
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
          summary: "Attack, Hook, performance, crash, and dependency reports are split between transactional storage and analytical ClickHouse pipelines."
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
          hookP95: "Hook p95",
          hookP95Detail: "seed observability target"
        },
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
        signIn: "登录"
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
          description: "攻击、Hook、崩溃、性能和依赖报告，并支持时间线查询。"
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
          summary: "攻击、Hook、性能、崩溃和依赖报告分别进入事务型存储与 ClickHouse 分析管线。"
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
          hookP95: "Hook P95",
          hookP95Detail: "种子可观测性目标"
        },
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
        signIn: "サインイン"
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
          description: "攻撃、Hook、クラッシュ、性能、依存関係レポートを検索可能なタイムラインで扱います。"
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
          summary: "攻撃、Hook、性能、クラッシュ、依存関係レポートをトランザクションストアと ClickHouse 分析パイプラインに分離します。"
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
          hookP95: "Hook p95",
          hookP95Detail: "シード可観測性ターゲット"
        },
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
      }
    }
  }
} as const;
