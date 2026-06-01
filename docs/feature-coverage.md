# WEB/WEBAPI 功能覆盖树

本文梳理以下两个归档项目的功能，并标注当前 OhMyRasp 是否已经实现同等能力：

主要对照依据：

- 归档前端路由：`.archive/source-drop-1-rasp/legacy-web/src/router/index.ts` 和 `src/router/modules/*.ts`
- 归档前端 API：`.archive/source-drop-1-rasp/legacy-web/src/api/**/*.ts`
- 归档后端路由：`.archive/source-drop-1-rasp/legacy-webapi/src/rasp-cloud/routers/router.go` 和 `commentsRouter.go`
- 当前 API：`api/api/openapi.yaml`
- 当前 Web：`web/src/router.tsx`, `web/src/routes/pages.tsx`, `web/src/lib/api.ts`
- 当前 Java Agent：`java-agent/agent/src/main/java/io/ohmyrasp/agent/**`

## 1. 门户、认证和初始化 `[Completed]`

子文档：[`docs/feature-coverage/01-portal-auth-initialization.md`](feature-coverage/01-portal-auth-initialization.md)

- 门户入口
  - 登录页 `/`，Token 检查，未登录跳转登录 `[Completed]`
    - 归档：Vue 登录入口和路由守卫。
    - 当前：`/login`, `/api/v1/auth/login`, `/api/v1/me`。
  - 路由进度条和菜单权限守卫 `[Implementation Unnecessary]`
    - 当前有认证和角色权限，但没有复刻 Antiy 的 Vue 菜单守卫、企业上下文切换逻辑。
  - 404 页面 `/404` 和无权限页 `/noaccess` `[Completed]`
    - 当前有路由层错误处理和登录保护，但没有单独复刻这两个页面。
- 初始配置
  - 初始化配置页 `/initialConfiguration` `[Implementation Unnecessary]`
    - 归档：`/v1/init_config`。
    - 当前：默认种子组织、默认管理员、系统设置，未提供独立初始化向导。
- 用户体系
  - 默认用户检查 `/v2/user/default` `[Implementation Unnecessary]`
    - 当前有默认管理员和登录接口，但无完全一致的默认用户检查接口。

## 2. 应用管理 `[Completed]`

子文档：[`docs/feature-coverage/02-application-management.md`](feature-coverage/02-application-management.md)

- 应用列表和应用选择 `/application`
  - 应用列表查询 `/v1/api/app/get` `[Completed]`
    - 当前：`GET /api/v1/applications`。
  - 创建应用 `/v1/api/app` `[Completed]`
    - 当前：`POST /api/v1/applications`。
  - 删除应用 `/v1/api/app/delete` `[Completed]`
    - 当前：`DELETE /api/v1/applications/{appID}`，审计记录 `application.delete`。
  - 应用配置 `/v1/api/app/config` `[Implementation Unnecessary]`
    - 当前通过应用、环境、策略分配和系统设置覆盖部分配置，不是 Antiy 的单一 app config。
  - 应用初始化 `/v1/api/app/init` `[Completed]`
    - 当前应用创建时初始化 secret、环境和默认策略相关字段。
  - 应用导出 `/v1/api/app/export` `[Completed]`
    - 当前：`GET /api/v1/applications/export`，前端可下载 JSON 清单。
  - 应用概要 `/v1/api/app/summary` `[Completed]`
    - 当前：`GET /api/v1/analytics/overview` 提供应用数、Agent 数、事件统计。
- 应用密钥
  - 获取应用密钥 `/v1/api/app/secret/get` `[Implementation Unnecessary]`
    - 当前按最佳实践仅在创建和轮换时一次性返回密钥，不提供持久密钥读回接口。
  - 重新生成密钥 `/v1/api/app/secret/regenerate` `[Completed]`
    - 当前：`POST /api/v1/applications/{appID}/secret/rotate`。
- 应用环境
  - 归档无独立环境模型 `[Completed]`
    - 当前额外实现：`POST /api/v1/applications/{appID}/environments`。
- 应用标签和命令标签
  - 标签列表 `/v1/api/command/label/list` `[Implementation Unnecessary]`
  - 绑定标签 `/v1/api/command/label/bind` `[Implementation Unnecessary]`
  - 解绑标签 `/v1/api/command/label/unbind` `[Implementation Unnecessary]`
  - 命令设置查询 `/v1/api/command/setting` `[Implementation Unnecessary]`
    - 当前有 daemon command group，但没有 Antiy 的命令标签设置模型。
  - 命令设置重置 `/v1/api/command/setting/reset` `[Implementation Unnecessary]`

## 3. 安全总览 Dashboard `[Completed]`

- 安全总览页 `/dashboard`
  - 统计卡片 `[Completed]`
    - 当前：`GET /api/v1/analytics/overview`。
  - 攻击趋势图 `/v1/api/log/attack/aggr/time` `[Completed]`
    - 当前：`GET /api/v1/analytics/overview` 返回 `attack_trend`。
  - 攻击类型聚合 `/v1/api/log/attack/aggr/type` `[Completed]`
    - 当前：`events_by_type`、`events_by_severity` 和攻击 Hook/算法聚合共同覆盖总览聚合。
  - User-Agent 聚合 `/v1/api/log/attack/aggr/ua` `[Completed]`
    - 当前：`GET /api/v1/analytics/overview` 返回 `attacks_by_user_agent`。
  - 攻击崩溃概览组件 `[Completed]`
    - 当前：`GET /api/v1/analytics/overview` 返回 `crash_count`，总览页展示崩溃统计卡片。
  - 漏洞聚合概览 `/v1/api/log/attack/aggr/vuln` `[Implementation Unnecessary]`
    - 当前：不新增独立漏洞实体或旧式聚合接口；总览页以 `attacks_by_hook` 和 `attacks_by_algorithm` 展示风险信号，独立漏洞对象应留给依赖漏洞/安全分析模块建模。

## 4. 安全分析 `[Completed]`

- 漏洞列表 `/safe/vulns`
  - 攻击漏洞聚合 `/v1/api/log/attack/aggr/vuln` `[Implementation Unnecessary]`
    - 当前以事件、Hook、算法、依赖漏洞和 baseline findings 展示风险；不新增独立 legacy vuln 聚合实体。
  - 漏洞状态设置 `/v2/api/vuln/status` `[Implementation Unnecessary]`
    - 当前没有独立 vuln 生命周期对象；状态应归属于 baseline finding、dependency vulnerability 或后续专门漏洞管理模块。
  - 漏洞详情弹窗 `[Implementation Unnecessary]`
    - 当前不新增独立 vuln 详情对象；Events 页展示事件参数，依赖和 baseline 展示漏洞/修复上下文。
  - 攻击参数组件 `attackParams.vue` `[Completed]`
    - 当前 Events 页在事件和回收站行内展示攻击参数/attributes。
  - 修复建议组件 `fixSolutions.vue` `[Completed]`
    - 当前 baseline findings 展示 remediation；dependency vulnerabilities 展示 fixed_version/known_exploited 元数据。
- 攻击事件 `/safe/events`
  - 攻击事件搜索 `/v1/api/log/attack/search` `[Completed]`
    - 当前：`GET /api/v1/events/attack`，支持 application、environment、agent、severity、hook、algorithm、limit 等筛选。
  - 攻击事件上报 `/v1/agent/log/attack` `[Completed]`
    - 当前：`POST /api/v1/events/attack`，由 Agent 凭应用凭据上报。
  - 攻击事件详情弹窗 `[Completed]`
    - 当前 Events 页展示事件主体、ID、policy、algorithm、hook、severity、occurred_at 和 attributes。
  - 攻击参数组件 `attackParams.vue` `[Completed]`
  - 加入白名单弹窗 `addWhiltelist.vue` `[Implementation Unnecessary]`
    - 当前 allowlist 是集中保护配置，不从单个事件隐式写入。
  - 修复建议组件 `fixSolutions.vue` `[Implementation Unnecessary]`
    - 攻击事件是检测事实；修复建议归属于规则、baseline finding 或 dependency vulnerability。
  - 攻击事件删除到回收站 `/v1/api/log/attack` DELETE `[Completed]`
    - 当前：`POST /api/v1/events/recycle-bin/delete`。
- 攻击事件回收站 `/safe/recycleBin`
  - 回收站搜索 `/v1/api/log/attack/trash/search` `[Completed]`
    - 当前：`GET /api/v1/events/recycle-bin`。
  - 回收站恢复 `/v1/api/log/attack/trash/restore` `[Completed]`
    - 当前：`POST /api/v1/events/recycle-bin/restore`。
  - 回收站永久删除 `/v1/api/log/attack/trash` DELETE `[Completed]`
    - 当前：`POST /api/v1/events/recycle-bin/purge`。
  - 回收站事件详情、攻击参数、修复建议组件 `[Completed]`
    - 当前回收站展示删除状态、事件详情和攻击参数；修复建议不作为回收站特有对象建模。
- 配置安检 `/safe/baseline`
  - Policy/baseline 日志搜索 `/v1/api/log/policy/search` `[Completed]`
    - 当前：`GET /api/v1/baseline-findings`, `POST /api/v1/baseline-findings`。
  - 检查项、资源、修复建议、状态展示 `[Completed]`
    - 当前 baseline finding 含 check_id、title、category、resource、severity、status、remediation、attributes。
  - 安检参数组件 `baselineParams.vue` `[Completed]`
  - 归档的 policy alarm 日志兼容接口 `[Implementation Unnecessary]`
    - 当前 baseline findings 已覆盖配置安检日志；不新增 legacy policy alarm 兼容接口。
- 类库安全 `/safe/dependency`
  - 依赖上报 `/v1/agent/dependency` `[Completed]`
    - 当前：`POST /api/v1/dependencies`。
  - 依赖搜索 `/v1/api/dependency/search` `[Completed]`
    - 当前：`GET /api/v1/dependencies`。
  - 依赖聚合 `/v1/api/dependency/aggr` `[Completed]`
    - 当前：`GET /api/v1/dependencies/summary`。
  - 依赖删除 `/v1/api/dependency/delete` `[Implementation Unnecessary]`
    - 当前依赖是安全证据和最近观测库存；单条删除容易破坏审计，使用维护清理按范围和时间清除。
  - 外部漏洞源查询 `/vuln/api/v1/vuln/search_source_vulns` `[Implementation Unnecessary]`
    - 当前依赖上报携带漏洞元数据；外部源同步应作为后续独立情报集成，而非安全分析基础功能。
  - 依赖导出 `[Completed]`
    - 当前：`GET /api/v1/dependencies/export` 和 Events 页导出按钮。

## 5. 防护设置和检测算法 `[Completed]`

子文档：[`docs/feature-coverage/05-protection-settings-and-algorithms.md`](feature-coverage/05-protection-settings-and-algorithms.md)

- 防护设置页 `/algorithm`
  - 应用加固 `/algorithm/hardening`
    - App reinforces 配置 `/v1/api/app/general/app_reinforces` `[Completed]`
      - 当前：`protection.hardening` 系统设置，兼容路由 `/algorithm/hardening` 指向防护配置。
    - 通用 app hardening 视图 `[Completed]`
      - 当前 Access & Audit 页的 Protection Configuration 管理加固模式、反射滥用阻断、进程执行阻断和依赖漏洞阈值。
  - 报警设置 `/algorithm/alarm`
    - 应用报警配置 `/v1/api/app/alarm/config` `[Completed]`
      - 当前：`GET/POST/PUT /api/v1/alert-rules` 和 `GET /api/v1/alert-deliveries`。
    - 邮件测试 `/v1/api/app/email/test` `[Implementation Unnecessary]`
      - 当前未配置 SMTP/provider secret；在没有真实投递后端前新增测试邮件接口会产生误导性结果。
    - 报警间隔 `/v2/api/general/config` `[Completed]`
      - 当前：`alerts.delivery.interval_seconds` 系统设置，Protection Configuration 表单可编辑并审计。
  - 防护算法 `/algorithm/algorithm`
    - 获取应用算法配置 `/v2/api/algorithm/get` `[Completed]`
      - 当前：`GET /api/v1/policies/algorithms` 暴露 hook/algorithm catalog，`GET /api/v1/policies` 暴露版本化规则配置。
    - 更新应用算法配置 `/v2/api/algorithm/config` `[Completed]`
      - 当前：`POST /api/v1/policies`, `POST /api/v1/policies/{policyID}/versions`, `PUT /api/v1/policies/{policyID}/versions/{version}/rules`。
    - 恢复默认算法配置 `/v2/api/algorithm/restore` `[Completed]`
      - 当前：`POST /api/v1/policies/{policyID}/restore-default` 从算法目录生成新的默认草稿版本。
    - 策略校验 `[Completed]`
      - 当前：`POST /api/v1/policies/validate`。
    - 策略测试 `[Completed]`
      - 当前：`POST /api/v1/policies/test`。
    - 策略灰度发布 `[Completed]`
      - 当前：`POST /api/v1/policies/{policyID}/rollout`，支持全局、应用、环境范围和 canary percent。
    - 策略回滚 `[Completed]`
      - 当前：`POST /api/v1/policies/{policyID}/rollback`。
    - 高级配置弹窗 `advancedDialog.vue` `[Implementation Unnecessary]`
      - 当前策略编辑器已内联暴露 hook、algorithm、action、severity、expression、tags、校验、测试、发布和回滚；复刻旧弹窗会重复同一状态面。
- 检测 Hook 覆盖
  - request 请求检测 `[Completed]`
    - 当前算法：`request_scanner`, `request_unusual`, `xss_userinput`；浏览器可运行 playground 用例覆盖 scanner 和 missing User-Agent。
  - response 响应检测 `[Completed]`
    - 当前算法：`response_dataleak`, `xss_echo`；playground policy case 和 Agent detector tests 覆盖。
  - sql SQL 注入检测 `[Completed]`
    - 当前算法：`sql_userinput`, `sql_policy`, `sql_regex`。
  - sql_exception SQL 报错检测 `[Completed]`
    - 当前算法：`sql_exception`。
  - command 命令执行检测 `[Completed]`
    - 当前算法：`command_userinput`, `command_common`, `command_error`, `command_dnslog`, `command_reflect`。
  - process 进程检测 `[Completed]`
    - 当前策略支持 `process_match`，Java Agent 自动 Hook `ProcessBuilder.start`。
  - readfile 文件读取检测 `[Completed]`
    - 当前算法：`readfile_userinput`, `readfile_userinput_http`, `readfile_userinput_unwanted`, `readfile_unwanted`, `readfile_outsidewebroot`。
  - writefile 文件写入检测 `[Completed]`
    - 当前算法：`writefile_script`, `writefile_reflect`, `writefile_ntfs`。
  - deletefile 文件删除检测 `[Completed]`
    - 当前算法：`deletefile_userinput`。
  - directory 目录读取检测 `[Completed]`
    - 当前算法：`directory_userinput`, `directory_unwanted`, `directory_reflect`。
  - rename 文件重命名 webshell 检测 `[Completed]`
    - 当前算法：`rename_webshell`；playground 显式 case 覆盖危险重命名。
  - link 链接 webshell 检测 `[Completed]`
    - 当前算法：`link_webshell`；playground 显式 case 覆盖危险链接。
  - include 文件包含检测 `[Implementation Unnecessary]`
    - Java Agent 项目不自动实现 PHP include 字节码 Hook；当前保留 `include_userinput`, `include_protocol` 检测算法和显式 policy case。
  - fileupload 文件上传检测 `[Completed]`
    - 当前算法：`fileupload_multipart_script`, `fileupload_multipart_html`, `fileupload_multipart_exe`；playground 显式 case 覆盖。
  - webdav 上传检测 `[Completed]`
    - 当前算法：`fileupload_webdav`；playground 显式 case 覆盖。
  - ssrf URL 访问检测 `[Completed]`
    - 当前算法：`ssrf_userinput`, `ssrf_common`, `ssrf_aws`, `ssrf_obfuscate`, `ssrf_protocol`。
  - dns DNS 黑名单检测 `[Completed]`
    - 当前算法：`dns_blacklist`。
  - jndi JNDI 检测 `[Completed]`
    - 当前算法：`jndi_disable_all`。
  - xxe XML 外部实体检测 `[Completed]`
    - 当前算法：`xxe_file`, `xxe_protocol`。
  - deserialization 反序列化黑名单 `[Completed]`
    - 当前算法：`deserialization_blacklist`。
  - ognl 表达式检测 `[Completed]`
    - 当前算法：`ognl_blacklist`, `ognl_length_limit`；显式 detector hook 和 archived Java lab catalog 覆盖框架场景。
  - eval 动态执行检测 `[Completed]`
    - 当前算法：`eval_regex`；Java Agent 提供显式动态执行 detector hook。
  - loadlibrary 动态库加载检测 `[Completed]`
    - 当前算法：`loadlibrary_unc`。
  - webshell 检测 `[Completed]`
    - 当前算法：`webshell_callable`, `webshell_command`, `webshell_eval`, `webshell_file_put_contents`, `webshell_ld_preload`。
- 插件系统 `[Implementation Unnecessary]`
  - 插件管理页和隐藏视图 `/settings/plugins`, `/algorithm/plugins` `[Implementation Unnecessary]`
  - 应用插件查询 `/v1/api/app/plugin/get` `[Implementation Unnecessary]`
  - 应用插件选择 `/v1/api/app/plugin/select` `[Implementation Unnecessary]`
  - 插件删除 `/v1/api/plugin/delete` `[Implementation Unnecessary]`
  - 插件新增弹窗 `addDialog.vue` `[Implementation Unnecessary]`
  - 插件更新弹窗 `updateDialog.vue` `[Implementation Unnecessary]`
  - 插件查看弹窗 `viewDialog.vue` `[Implementation Unnecessary]`
    - 当前不引入未设计 ABI、签名、沙箱和回滚语义的运行时插件系统；检测扩展先通过 Java Agent 发布和版本化策略管理。

## 6. 应用维护和实例管理 `[Completed]`

子文档：[`docs/feature-coverage/06-application-maintenance-instance-management.md`](feature-coverage/06-application-maintenance-instance-management.md)

- 实例管理 `/maintain/hosts`
  - 实例搜索 `/v1/api/rasp/search` `[Completed]`
    - 当前：`GET /api/v1/agents` 和 `GET /api/v1/daemon/workloads`；前端 Agent Inventory 提供搜索、应用、状态、版本和忽略状态筛选。
  - 旧实例搜索 `/v1/api/rasp/search_old` `[Implementation Unnecessary]`
    - 当前不保留旧实例独立生命周期；使用活跃清单、忽略状态、删除审计和维护清理表达实例状态。
  - 实例版本搜索 `/v1/api/rasp/search/version` `[Completed]`
    - 当前 Agent Inventory 提供版本筛选，Agent artifact catalog 管理可用版本。
  - 实例详情 `/v1/api/rasp/info` `[Completed]`
    - 当前 Agents 页和 API 返回 runtime、version、status、last_seen_at、policy assignment、alias、ignored_at。
  - 实例资产信息 `/v1/api/rasp/asset_info` `[Completed]`
    - 当前 Daemon Workloads 返回 process/container、image、cmdline、pid、注入状态和错误。
  - 实例备注 `/v1/api/rasp/alias` `[Completed]`
    - 当前：`PUT /api/v1/agents/{agentID}/alias`，前端可保存 Agent remark。
  - 实例删除 `/v1/api/rasp/delete` `[Completed]`
    - 当前：`DELETE /api/v1/agents/{agentID}`。
  - 批量删除 `/v1/api/rasp/batch_delete` `[Completed]`
    - 当前：`POST /api/v1/agents/batch-delete`。
  - 忽略实例 `/v1/api/rasp/ignore` `[Completed]`
    - 当前：`POST /api/v1/agents/{agentID}/ignore`，支持忽略和恢复。
  - 自动保护开关 `/v1/api/rasp/auto_protect` `[Completed]`
    - 当前通过 daemon workload 绑定、命令组和注入报告实现自动化注入闭环。
  - 加入保护 `/v1/api/rasp/add_protect` `[Completed]`
    - 当前：`POST /api/v1/daemon/workloads/{workloadID}/bind`。
  - 实例 CSV 导出 `/v1/api/rasp/csv` `[Completed]`
    - 当前 Agent Inventory 按当前筛选结果导出 CSV。
  - 状态标签 online/offline/unknown/adding/error `[Completed]`
    - 当前 Agent status 展示 online/offline/degraded/disabled，Daemon injection_status 展示 injected/failed/uninstalled，忽略状态独立标记。
  - 实例详情弹窗 `viewDialog.vue` `[Implementation Unnecessary]`
    - 当前 Agent Inventory 和 Daemon Workloads 表格内联展示实例、策略、版本、资产和注入详情，避免重复弹窗状态面。
  - 卸载确认弹窗 `unloadDialog.vue` `[Implementation Unnecessary]`
    - 当前控制台没有远程卸载命令；Daemon 可上报 `uninstalled`，但不提供误导性的卸载按钮。
- 白名单管理 `/maintain/whitelist`
  - 白名单配置 `/v1/api/app/whitelist/config` `[Completed]`
    - 当前：`protection.allowlist` 系统设置，兼容路由 `/maintain/whitelist` 指向 Access & Audit 的 Protection Configuration。
- 清空数据 `/maintain/clearData`
  - 清空日志 `/v1/api/server/clear_logs` `[Completed]`
    - 当前：`POST /api/v1/maintenance/cleanup`，支持 events、dependencies、baseline_findings、alert_deliveries、dry_run、应用范围、时间范围。
- 通用设置 `/maintain/general`
  - 应用通用配置 `/v1/api/app/general/config` `[Completed]`
    - 当前 system settings、app/env/policy 数据和 Protection Configuration 覆盖通用配置入口，兼容路由 `/maintain/general` 指向 Access & Audit。
  - 应用加固配置 `/v1/api/app/general/app_reinforces` `[Completed]`
    - 当前：`protection.hardening` 系统设置。
- 应用维护升级视图 `/maintain/upgrade`
  - 归档存在 view 文件但未在主路由中挂载 `[Completed]`
    - 当前 `/maintain/upgrade` 兼容路由指向 Agents，使用 Agent artifact upload/catalog/bootstrap 校验和下载能力。

## 7. 应用日志 `[Completed]`

- 异常日志 `/log/exceptions`
  - Agent error log 上报 `/v1/agent/log/error` `[Completed]`
    - 当前：`POST /api/v1/events/error`，由 Agent 凭应用凭据上报异常和 error log。
  - 异常日志搜索 `/v1/api/log/error/search` `[Completed]`
    - 当前：`GET /api/v1/events/error`，支持 application、environment、agent、severity、hook、policy、time range、limit 等筛选。
  - 异常详情弹窗 `viewDialog.vue` `[Implementation Unnecessary]`
    - 当前 Events 表格行内展示 ID、消息、Hook、等级、策略、算法和 `attributes` 结构化异常参数，无需复刻旧组件名。
- 崩溃信息 `/log/crash`
  - 崩溃上报 `/v1/agent/crash/report` `[Completed]`
    - 当前：`POST /api/v1/events/crash`。
  - 崩溃搜索 `/v1/api/log/crash/search` `[Completed]`
    - 当前：`GET /api/v1/events/crash`。
  - 崩溃详情弹窗 `viewDialog.vue` `[Implementation Unnecessary]`
    - 当前 Events 表格行内展示崩溃详情和结构化参数。
- 操作审计 `/log/audit`
  - 操作审计搜索 `/v1/api/operation/search` `[Completed]`
    - 当前：`GET /api/v1/audit-logs`。
  - 登录、用户、应用、Agent、策略、事件回收站、维护、告警规则操作记录 `[Completed]`
  - 审计详情弹窗 `viewDialog.vue` `[Implementation Unnecessary]`
    - 当前 Access & Audit 表格行内展示 actor、action、resource、time 和 JSON details。

## 8. 企业管理、平台管理和用户管理 `[Completed]`

- 平台管理 `/platform`
  - 组织管理 `/platform` `[Implementation Unnecessary]`
    - 当前项目是单组织自托管控制台；`/platform` 兼容路由指向 Access & Audit，展示 OSS edition、RBAC、用户、审计和系统设置。
  - 平台用户管理 `/platform/user` `[Completed]`
    - 当前有本地用户、角色、禁用状态和审计日志；兼容路由 `/platform/user` 指向 Access & Audit。
  - 用户创建 `/v3/upms/user` `[Completed]`
    - 当前：`POST /api/v1/users`。
  - 用户更新 `/v3/upms/user` PUT `[Completed]`
    - 当前：`PUT /api/v1/users/{userID}`。
  - 用户状态变更 `/v3/upms/user/status` `[Completed]`
    - 当前：`PUT /api/v1/users/{userID}` 的 `disabled` 字段，持久化为 `disabled_at` 并使 session 失效。
  - 用户搜索 `/v3/upms/user/search` `[Completed]`
    - 当前：`GET /api/v1/users?search=&role=&status=`，支持邮箱/姓名/ID 搜索、角色和 active/disabled 状态筛选。
  - 租户创建、更新、删除、搜索 `/v3/upms/tenants*` `[Implementation Unnecessary]`
    - 当前项目不采用多租户模型；应用、环境、Agent 和策略在单组织内组合管理。

## 9. 系统设置 `[Completed]`

子文档：[`docs/feature-coverage/09-system-settings.md`](feature-coverage/09-system-settings.md)

- 后台地址 `/settings/panel`
  - 后台地址查询 `/v1/api/server/url/get` `[Completed]`
    - 当前：`GET /api/v1/system-settings` 返回 `server.public_url`。
  - 后台地址设置 `/v1/api/server/url` `[Completed]`
    - 当前：`PUT /api/v1/system-settings/server.public_url`，Access & Audit 的 Protection Configuration 可编辑 Public Console URL。
- 报警间隔 `/settings/alarm`
  - 全局报警配置 `/v2/api/general/config` `[Completed]`
    - 当前：`alerts.delivery.interval_seconds` 系统设置，兼容路由 `/settings/alarm` 指向 Access & Audit。
- 系统信息 `/settings/systemInfo`
  - 版本 `/v1/version` `[Completed]`
    - 当前：`GET /v1/version` 公开返回 component、version、commit、build_time、go_version；`GET /api/v1/system/version` 在控制台展示同一数据。
  - 健康检查 `/v1/ping` `[Completed]`
    - 当前：`GET /healthz`, `GET /readyz`，使用标准 liveness/readiness 语义，不复刻模糊的 ping 名称。
  - Prometheus 指标 `[Completed]`
    - 当前：`GET /metrics`。
- 版本池 `/settings/poolVersion`
  - 默认版本 `/v2/api/version_pool/default` `[Implementation Unnecessary]`
    - 当前按 language、system_type、language_version 精确解析 Agent artifact，避免全局默认版本误配到不同 JDK/系统。
  - 上传版本 `/v2/api/version_pool/upload` `[Completed]`
    - 当前：`POST /api/v1/agent-artifacts`。
  - 版本池编辑弹窗 `editDialog.vue` `[Implementation Unnecessary]`
    - 当前 Artifact Upload 与 Catalog 已覆盖上传、校验、下载 URL、MD5、大小、版本和系统类型展示。
- 版本管理 `/settings/version`
  - 当前版本 `/v2/api/version/current` `[Completed]`
    - 当前 Agents 页统计 Agent 当前版本、最新版本和 drifted 数量。
  - 版本详情 `/v2/api/version/detail` `[Completed]`
    - 当前 Agent Artifact Catalog 展示 language、system_type、language_version、filename、size、md5、download_url。
  - 版本列表 `/v2/api/version/list` `[Completed]`
    - 当前：`GET /api/v1/agent-artifacts`。
  - 推送版本 `/v2/api/version/push` `[Implementation Unnecessary]`
    - 当前采用 Agent/Daemon 拉取 artifact 和命令组模型，不从控制台主动推送二进制到实例。
  - 应用升级配置 `/v1/api/app/upgrade/get` `[Implementation Unnecessary]`
    - 当前升级策略由 artifact catalog、agent.minimum_version 和 Daemon command group 组合表达；不维护独立应用升级配置表。
  - 版本编辑弹窗 `editDialog.vue` `[Implementation Unnecessary]`
    - 当前 artifact 上传表单和 catalog 表格覆盖必要能力，避免重复弹窗状态。

## 10. Agent、服务端和下载通道 `[Completed]`

子文档：[`docs/feature-coverage/10-agent-service-download-channel.md`](feature-coverage/10-agent-service-download-channel.md)

- Agent 生命周期
  - Agent 注册 `/v1/agent/rasp` `[Completed]`
    - 当前：`POST /api/v1/agents/register`，Java Agent 客户端已使用现代 API。
  - Agent 心跳 `/v1/agent/heartbeat` `[Completed]`
    - 当前：`POST /api/v1/agents/{agentID}/heartbeat`。
  - Agent 报告 `/v1/agent/report` `[Completed]`
    - 当前拆分为 events、dependencies、baseline findings、heartbeat，避免一个混合端点承载不同数据保留和查询语义。
  - Agent 策略拉取 `[Completed]`
    - 当前：`GET /api/v1/agents/{agentID}/policy`。
  - Agent attack log `/v1/agent/log/attack` `[Completed]`
    - 当前：`POST /api/v1/events/attack`。
  - Agent policy log `/v1/agent/log/policy` `[Completed]`
    - 当前改为 `POST /api/v1/baseline-findings` 和 observability/performance events。
  - Agent error log `/v1/agent/log/error` `[Completed]`
    - 当前：`POST /api/v1/events/error`。
  - Agent dependency `/v1/agent/dependency` `[Completed]`
    - 当前：`POST /api/v1/dependencies`。
  - Agent crash `/v1/agent/crash/report` `[Completed]`
    - 当前：`POST /api/v1/events/crash`。
- 下载服务
  - 下载 Agent `/v1/service/dl/agent`, `/v2/service/dl/agent` `[Completed]`
    - 当前：`GET /api/v1/daemon/artifacts/agent`，并提供 `/v1/service/dl/agent` 与 `/v2/service/dl/agent` 兼容下载入口。
  - Agent 下载信息 `/v1/service/dl/agent/info` `[Completed]`
    - 当前：`GET /api/v1/daemon/artifacts/agent/info`。
  - 下载升级包 `/v1/agent/download_upgrade` `[Implementation Unnecessary]`
  - 下载引擎 `/v1/agent/download_engine` `[Implementation Unnecessary]`
  - 下载 helper `/v1/service/dl/rasp-agent-helper`, `rasp-agent-helper-arm64` `[Implementation Unnecessary]`
  - 下载 injector `/v1/service/dl/rasp-injector`, `rasp-injector-arm64` `[Implementation Unnecessary]`
  - 安装脚本下载 `/v1/service/dl/install_legacy_helper.sh` `[Implementation Unnecessary]`
  - 卸载脚本下载 `/v1/service/dl/uninstall_legacy_helper.sh` `[Implementation Unnecessary]`
    - 当前项目只发布 Java Agent artifact，不发布未维护的 helper/injector/engine 二进制和安装脚本。
- Service 应用接口
  - Service app 获取 `/v1/service/app/get` `[Completed]`
    - 当前：`GET /api/v1/daemon/app` 按 app id 返回 app secret 和语言，并提供 `/v1/service/app/get` 兼容响应。
- Command/Daemon 通道
  - WebSocket 命令 `/v1/service/command` GET `[Completed]`
    - 当前：`GET /api/v1/daemon/commands` 轮询式命令组，并提供 `/v1/service/command` 兼容 WebSocket。
  - DaemonSet 注入信息上传 `/v1/service/command/daemon_set/inject` `[Completed]`
    - 当前：`POST /api/v1/daemon/workloads/report` 和 `POST /api/v1/daemon/injection-reports`，并提供 legacy DaemonSet HTTP report 兼容入口。
  - Daemon token 获取 `[Completed]`
    - 当前额外实现：`GET /api/v1/daemon/token`。
  - Daemon token 重置 `[Completed]`
    - 当前额外实现：`POST /api/v1/daemon/token/reset`。
  - Workload 上报 `[Completed]`
    - 当前额外实现：`POST /api/v1/daemon/workloads/report`。
  - Workload 绑定应用 `[Completed]`
    - 当前额外实现：`POST /api/v1/daemon/workloads/{workloadID}/bind`。
  - Workload 解绑应用 `[Completed]`
    - 当前额外实现：`POST /api/v1/daemon/workloads/{workloadID}/unbind`。

## 11. 日志、事件、可观测性和告警

- 事件模型
  - Attack events `[请二次检查]`
  - Hook events `[请二次检查]`
    - 当前额外实现：`GET/POST /api/v1/events/hook`。
  - Performance events `[请二次检查]`
    - 当前额外实现：`GET/POST /api/v1/events/performance`。
  - Crash events `[请二次检查]`
  - Recycle bin `[请二次检查]`
  - Event metadata、request、rule、policy、algorithm 字段 `[请二次检查]`
- 可观测性
  - Hook latency p50/p95、agent performance、policy performance `[请二次检查]`
    - 当前：`GET /api/v1/analytics/observability`。
  - Prometheus metrics `[请二次检查]`
    - 当前：`GET /metrics`。
  - 归档 Dashboard ECharts 图形复刻 `[待检查]`
- 告警
  - 告警规则列表和创建 `[请二次检查]`
    - 当前：`GET/POST /api/v1/alert-rules`。
  - 告警规则更新 `[请二次检查]`
    - 当前：`PUT /api/v1/alert-rules/{alertRuleID}`。
  - 告警投递记录 `[请二次检查]`
    - 当前：`GET /api/v1/alert-deliveries`。
  - 邮件服务配置和测试 `[未覆盖]`

## 12. 前端页面覆盖

- 当前已实现页面
  - 登录 `/login` `[请二次检查]`
  - 概览 `/` `[待检查]`
  - 应用 `/applications` `[待检查]`
  - Agent `/agents` `[待检查]`
  - 策略 `/policies` `[请二次检查]`
  - 事件 `/events` `[请二次检查]`
  - 可观测性 `/observability` `[请二次检查]`
  - 访问与审计 `/access` `[待检查]`
- 归档页面未完全复刻
  - 添加实例向导 `/addInstance` `[待检查]`
    - 归档细分：手动添加、自动添加、Docker、Kubernetes、Windows、PHP、客户端安装弹窗。
    - 当前有 Agent artifact、daemon workload 绑定和注入状态，但没有完整向导 UI。
  - 平台管理 `/platform` `[未覆盖]`
  - 系统设置 `/settings/*` `[待检查]`
  - noaccess/404 专页 `[待检查]`

## 15. 主要差距汇总

- 多租户企业/组织/UPMS/Keycloak 体系没有覆盖。
- 应用标签、命令标签、实例备注、忽略、批量删除、CSV 导出没有覆盖。
- 漏洞列表的独立聚合、状态流转和外部漏洞源查询没有完整覆盖。
- 报警邮件配置和邮件测试没有覆盖。
- 部分算法当前已有策略名称和 Detector 支持，但自动 Hook 覆盖以 Java Agent 运行时为主，PHP/Windows/部分框架场景没有同等覆盖。
