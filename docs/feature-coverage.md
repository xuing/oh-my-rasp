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

## 2. 应用管理

- 应用列表和应用选择 `/application`
  - 应用列表查询 `/v1/api/app/get` `[请二次检查]`
    - 当前：`GET /api/v1/applications`。
  - 创建应用 `/v1/api/app` `[请二次检查]`
    - 当前：`POST /api/v1/applications`。
  - 删除应用 `/v1/api/app/delete` `[未覆盖]`
    - 当前没有应用删除 API。
  - 应用配置 `/v1/api/app/config` `[待检查]`
    - 当前通过应用、环境、策略分配和系统设置覆盖部分配置，不是 Antiy 的单一 app config。
  - 应用初始化 `/v1/api/app/init` `[待检查]`
    - 当前应用创建时初始化 secret、环境和默认策略相关字段。
  - 应用导出 `/v1/api/app/export` `[未覆盖]`
  - 应用概要 `/v1/api/app/summary` `[待检查]`
    - 当前：`GET /api/v1/analytics/overview` 提供应用数、Agent 数、事件统计。
- 应用密钥
  - 获取应用密钥 `/v1/api/app/secret/get` `[待检查]`
    - 当前列表返回应用 secret 相关数据，受权限保护。
  - 重新生成密钥 `/v1/api/app/secret/regenerate` `[请二次检查]`
    - 当前：`POST /api/v1/applications/{appID}/secret/rotate`。
- 应用环境
  - 归档无独立环境模型 `[请二次检查]`
    - 当前额外实现：`POST /api/v1/applications/{appID}/environments`。
- 应用标签和命令标签
  - 标签列表 `/v1/api/command/label/list` `[未覆盖]`
  - 绑定标签 `/v1/api/command/label/bind` `[未覆盖]`
  - 解绑标签 `/v1/api/command/label/unbind` `[未覆盖]`
  - 命令设置查询 `/v1/api/command/setting` `[待检查]`
    - 当前有 daemon command group，但没有 Antiy 的命令标签设置模型。
  - 命令设置重置 `/v1/api/command/setting/reset` `[未覆盖]`

## 3. 安全总览 Dashboard

- 安全总览页 `/dashboard`
  - 统计卡片 `[待检查]`
    - 当前：`GET /api/v1/analytics/overview`。
  - 攻击趋势图 `/v1/api/log/attack/aggr/time` `[待检查]`
    - 当前能按事件查询和概览统计，但没有同名时间聚合接口。
  - 攻击类型聚合 `/v1/api/log/attack/aggr/type` `[待检查]`
    - 当前有 `events_by_type` 和事件查询。
  - User-Agent 聚合 `/v1/api/log/attack/aggr/ua` `[未覆盖]`
  - 攻击崩溃概览组件 `[待检查]`
    - 当前有 crash event ingest/query，但没有归档前端同款 dashboard 组件。
  - 漏洞聚合概览 `/v1/api/log/attack/aggr/vuln` `[待检查]`
    - 当前 attack 事件可携带 hook/algorithm/severity，但没有独立漏洞聚合视图。

## 4. 安全分析

- 漏洞列表 `/safe/vulns`
  - 攻击漏洞聚合 `/v1/api/log/attack/aggr/vuln` `[待检查]`
    - 当前以事件和策略算法展示攻击面，没有复刻“漏洞列表”聚合实体。
  - 漏洞状态设置 `/v2/api/vuln/status` `[未覆盖]`
  - 漏洞详情弹窗 `[待检查]`
    - 当前事件详情展示 request、metadata、policy、algorithm 等字段，但没有独立 vuln 详情对象。
  - 攻击参数组件 `attackParams.vue` `[待检查]`
    - 当前事件详情展示请求上下文和 metadata，但不是同款参数组件。
  - 修复建议组件 `fixSolutions.vue` `[待检查]`
    - 当前可在 rule/baseline remediation 中表达修复建议，未实现归档同款漏洞修复建议组件。
- 攻击事件 `/safe/events`
  - 攻击事件搜索 `/v1/api/log/attack/search` `[请二次检查]`
    - 当前：`GET /api/v1/events/attack`，支持 application、environment、agent、severity、hook、algorithm、limit 等筛选。
  - 攻击事件上报 `/v1/agent/log/attack` `[请二次检查]`
    - 当前：`POST /api/v1/events/attack`，由 Agent 凭应用凭据上报。
  - 攻击事件详情弹窗 `[请二次检查]`
    - 当前 Events 页展示事件主体、request、metadata、rule、policy。
  - 攻击参数组件 `attackParams.vue` `[待检查]`
  - 加入白名单弹窗 `addWhiltelist.vue` `[未覆盖]`
    - 当前没有独立 whitelist 配置模型。
  - 修复建议组件 `fixSolutions.vue` `[待检查]`
  - 攻击事件删除到回收站 `/v1/api/log/attack` DELETE `[请二次检查]`
    - 当前：`POST /api/v1/events/recycle-bin/delete`。
- 攻击事件回收站 `/safe/recycleBin`
  - 回收站搜索 `/v1/api/log/attack/trash/search` `[请二次检查]`
    - 当前：`GET /api/v1/events/recycle-bin`。
  - 回收站恢复 `/v1/api/log/attack/trash/restore` `[请二次检查]`
    - 当前：`POST /api/v1/events/recycle-bin/restore`。
  - 回收站永久删除 `/v1/api/log/attack/trash` DELETE `[请二次检查]`
    - 当前：`POST /api/v1/events/recycle-bin/purge`。
  - 回收站事件详情、攻击参数、修复建议组件 `[待检查]`
    - 当前回收站复用事件详情和恢复/永久删除操作，但未复刻归档组件拆分。
- 配置安检 `/safe/baseline`
  - Policy/baseline 日志搜索 `/v1/api/log/policy/search` `[待检查]`
    - 当前：`GET /api/v1/baseline-findings`, `POST /api/v1/baseline-findings`。
  - 检查项、资源、修复建议、状态展示 `[请二次检查]`
    - 当前 baseline finding 含 check_id、title、category、resource、severity、status、remediation、attributes。
  - 安检参数组件 `baselineParams.vue` `[待检查]`
  - 归档的 policy alarm 日志兼容接口 `[未覆盖]`
- 类库安全 `/safe/dependency`
  - 依赖上报 `/v1/agent/dependency` `[请二次检查]`
    - 当前：`POST /api/v1/dependencies`。
  - 依赖搜索 `/v1/api/dependency/search` `[请二次检查]`
    - 当前：`GET /api/v1/dependencies`。
  - 依赖聚合 `/v1/api/dependency/aggr` `[待检查]`
    - 当前有依赖列表、漏洞元数据和 overview，但没有同名聚合接口。
  - 依赖删除 `/v1/api/dependency/delete` `[未覆盖]`
  - 外部漏洞源查询 `/vuln/api/v1/vuln/search_source_vulns` `[未覆盖]`
  - 依赖导出 `[未覆盖]`

## 5. 防护设置和检测算法

- 防护设置页 `/algorithm`
  - 应用加固 `/algorithm/hardening`
    - App reinforces 配置 `/v1/api/app/general/app_reinforces` `[待检查]`
      - 当前有 Java Agent 运行时 Hook 和策略，但没有同名“应用加固”配置页。
    - 通用 app hardening 视图 `[待检查]`
  - 报警设置 `/algorithm/alarm`
    - 应用报警配置 `/v1/api/app/alarm/config` `[待检查]`
      - 当前：`GET/POST/PUT /api/v1/alert-rules` 和 `GET /api/v1/alert-deliveries`。
    - 邮件测试 `/v1/api/app/email/test` `[未覆盖]`
    - 报警间隔 `/v2/api/general/config` `[待检查]`
      - 当前有系统设置，但没有同名报警间隔页面。
  - 防护算法 `/algorithm/algorithm`
    - 获取应用算法配置 `/v2/api/algorithm/get` `[待检查]`
      - 当前通过 policies/rules 表达 hook、algorithm、action、severity、expression。
    - 更新应用算法配置 `/v2/api/algorithm/config` `[待检查]`
      - 当前：`POST /api/v1/policies`, `POST /api/v1/policies/{policyID}/versions`, `PUT /api/v1/policies/{policyID}/versions/{version}/rules`。
    - 恢复默认算法配置 `/v2/api/algorithm/restore` `[待检查]`
      - 当前有默认策略和回滚，但没有同名 restore。
    - 策略校验 `[请二次检查]`
      - 当前额外实现：`POST /api/v1/policies/validate`。
    - 策略测试 `[请二次检查]`
      - 当前额外实现：`POST /api/v1/policies/test`。
    - 策略灰度发布 `[请二次检查]`
      - 当前额外实现：`POST /api/v1/policies/{policyID}/rollout`，支持全局、应用、环境范围和 canary percent。
    - 策略回滚 `[请二次检查]`
      - 当前额外实现：`POST /api/v1/policies/{policyID}/rollback`。
    - 高级配置弹窗 `advancedDialog.vue` `[待检查]`
      - 当前策略规则支持 expression、hook、algorithm、action、severity，但没有归档同款高级配置弹窗。
- 检测 Hook 覆盖
  - request 请求检测 `[请二次检查]`
    - 当前算法：`request_scanner`, `request_unusual`, `xss_userinput`。
  - response 响应检测 `[待检查]`
    - 当前算法存在：`response_dataleak`, `xss_echo`，但 Java Agent 自动响应 Hook 未完整证明。
  - sql SQL 注入检测 `[请二次检查]`
    - 当前算法：`sql_userinput`, `sql_policy`, `sql_regex`。
  - sql_exception SQL 报错检测 `[请二次检查]`
    - 当前算法：`sql_exception`。
  - command 命令执行检测 `[请二次检查]`
    - 当前算法：`command_userinput`, `command_common`, `command_error`, `command_dnslog`, `command_reflect`。
  - process 进程检测 `[待检查]`
    - 当前策略支持 `process_match`，实际 Hook 聚焦 `ProcessBuilder.start`。
  - readfile 文件读取检测 `[请二次检查]`
    - 当前算法：`readfile_userinput`, `readfile_userinput_http`, `readfile_userinput_unwanted`, `readfile_unwanted`, `readfile_outsidewebroot`。
  - writefile 文件写入检测 `[请二次检查]`
    - 当前算法：`writefile_script`, `writefile_reflect`, `writefile_ntfs`。
  - deletefile 文件删除检测 `[请二次检查]`
    - 当前算法：`deletefile_userinput`。
  - directory 目录读取检测 `[请二次检查]`
    - 当前算法：`directory_userinput`, `directory_unwanted`, `directory_reflect`。
  - rename 文件重命名 webshell 检测 `[待检查]`
    - 当前算法存在 `rename_webshell`，但自动 Hook 覆盖程度弱于文件读写。
  - link 链接 webshell 检测 `[待检查]`
    - 当前算法存在 `link_webshell`，但自动 Hook 覆盖程度弱于文件读写。
  - include 文件包含检测 `[待检查]`
    - 当前算法存在 `include_userinput`, `include_protocol`，Java Agent 自动 Hook 未完整覆盖 PHP include 场景。
  - fileupload 文件上传检测 `[待检查]`
    - 当前算法存在 `fileupload_multipart_script`, `fileupload_multipart_html`, `fileupload_multipart_exe`，但没有完整上传框架 Hook。
  - webdav 上传检测 `[待检查]`
    - 当前算法存在 `fileupload_webdav`，自动 Hook 覆盖有限。
  - ssrf URL 访问检测 `[请二次检查]`
    - 当前算法：`ssrf_userinput`, `ssrf_common`, `ssrf_aws`, `ssrf_obfuscate`, `ssrf_protocol`。
  - dns DNS 黑名单检测 `[请二次检查]`
    - 当前算法：`dns_blacklist`。
  - jndi JNDI 检测 `[请二次检查]`
    - 当前算法：`jndi_disable_all`。
  - xxe XML 外部实体检测 `[请二次检查]`
    - 当前算法：`xxe_file`, `xxe_protocol`。
  - deserialization 反序列化黑名单 `[请二次检查]`
    - 当前算法：`deserialization_blacklist`。
  - ognl 表达式检测 `[待检查]`
    - 当前算法存在 `ognl_blacklist`, `ognl_length_limit`，自动 Hook 未完整覆盖具体框架。
  - eval 动态执行检测 `[待检查]`
    - 当前算法存在 `eval_regex`，Java 场景自动 Hook 覆盖有限。
  - loadlibrary 动态库加载检测 `[待检查]`
    - 当前算法存在 `loadlibrary_unc`，自动 Hook 覆盖有限。
  - webshell 检测 `[待检查]`
    - 当前算法：`webshell_callable`, `webshell_command`, `webshell_eval`, `webshell_file_put_contents`, `webshell_ld_preload`，但自动 Hook 以 Java Agent 为主。
- 插件系统
  - 插件管理页和隐藏视图 `/settings/plugins`, `/algorithm/plugins` `[未覆盖]`
  - 应用插件查询 `/v1/api/app/plugin/get` `[未覆盖]`
  - 应用插件选择 `/v1/api/app/plugin/select` `[未覆盖]`
  - 插件删除 `/v1/api/plugin/delete` `[未覆盖]`
  - 插件新增弹窗 `addDialog.vue` `[未覆盖]`
  - 插件更新弹窗 `updateDialog.vue` `[未覆盖]`
  - 插件查看弹窗 `viewDialog.vue` `[未覆盖]`

## 6. 应用维护和实例管理

- 实例管理 `/maintain/hosts`
  - 实例搜索 `/v1/api/rasp/search` `[请二次检查]`
    - 当前：`GET /api/v1/agents` 和 `GET /api/v1/daemon/workloads`。
  - 旧实例搜索 `/v1/api/rasp/search_old` `[未覆盖]`
  - 实例版本搜索 `/v1/api/rasp/search/version` `[待检查]`
    - 当前 Agent 和 artifacts 含版本字段，但没有同名版本搜索。
  - 实例详情 `/v1/api/rasp/info` `[请二次检查]`
    - 当前 Agents 页和 API 返回 runtime、version、status、last_seen_at、policy assignment。
  - 实例资产信息 `/v1/api/rasp/asset_info` `[待检查]`
    - 当前 daemon workload 返回 process/container、image、cmdline、pid，未完全覆盖归档资产详情模型。
  - 实例备注 `/v1/api/rasp/alias` `[未覆盖]`
    - 归档前端：`remarkDialog.vue`。
  - 实例删除 `/v1/api/rasp/delete` `[未覆盖]`
  - 批量删除 `/v1/api/rasp/batch_delete` `[未覆盖]`
  - 忽略实例 `/v1/api/rasp/ignore` `[未覆盖]`
  - 自动保护开关 `/v1/api/rasp/auto_protect` `[待检查]`
    - 当前通过 daemon workload 绑定、命令组和注入报告实现自动化注入闭环的一部分。
  - 加入保护 `/v1/api/rasp/add_protect` `[待检查]`
    - 当前：`POST /api/v1/daemon/workloads/{workloadID}/bind`，但无 Antiy 同款状态机。
  - 实例 CSV 导出 `/v1/api/rasp/csv` `[未覆盖]`
  - 状态标签 online/offline/unknown/adding/error `[待检查]`
    - 当前 Agent status 和 injection_status 可表达在线和注入状态，但枚举不完全一致。
  - 实例详情弹窗 `viewDialog.vue` `[请二次检查]`
    - 当前 Agents 页展示 Agent 和 workload 详情。
  - 卸载确认弹窗 `unloadDialog.vue` `[待检查]`
    - 当前可接收 daemon `uninstalled` 注入报告，但没有控制台卸载操作弹窗。
- 白名单管理 `/maintain/whitelist`
  - 白名单配置 `/v1/api/app/whitelist/config` `[未覆盖]`
    - 当前可通过策略规则表达 allow/block，但没有独立 whitelist config。
- 清空数据 `/maintain/clearData`
  - 清空日志 `/v1/api/server/clear_logs` `[请二次检查]`
    - 当前：`POST /api/v1/maintenance/cleanup`，支持 events、dependencies、baseline_findings、alert_deliveries、dry_run、应用范围、时间范围。
- 通用设置 `/maintain/general`
  - 应用通用配置 `/v1/api/app/general/config` `[待检查]`
    - 当前有 system settings 和 app/env/policy 数据，但没有归档同款通用配置页。
  - 应用加固配置 `/v1/api/app/general/app_reinforces` `[待检查]`
- 应用维护升级视图 `/maintain/upgrade`
  - 归档存在 view 文件但未在主路由中挂载 `[待检查]`
    - 当前版本和 artifact 能力在 Agent artifacts 里实现，不是维护菜单里的升级页。

## 7. 应用日志

- 异常日志 `/log/exceptions`
  - Agent error log 上报 `/v1/agent/log/error` `[待检查]`
    - 当前有 hook/performance/crash/attack 事件，没有独立 error log 类型。
  - 异常日志搜索 `/v1/api/log/error/search` `[待检查]`
    - 当前可在事件/审计/可观测性中排查，但无同名异常日志搜索。
  - 异常详情弹窗 `viewDialog.vue` `[待检查]`
- 崩溃信息 `/log/crash`
  - 崩溃上报 `/v1/agent/crash/report` `[请二次检查]`
    - 当前：`POST /api/v1/events/crash`。
  - 崩溃搜索 `/v1/api/log/crash/search` `[请二次检查]`
    - 当前：`GET /api/v1/events/crash`。
  - 崩溃详情弹窗 `viewDialog.vue` `[请二次检查]`
- 操作审计 `/log/audit`
  - 操作审计搜索 `/v1/api/operation/search` `[请二次检查]`
    - 当前：`GET /api/v1/audit-logs`。
  - 登录、用户、应用、Agent、策略、事件回收站、维护、告警规则操作记录 `[请二次检查]`
  - 审计详情弹窗 `viewDialog.vue` `[待检查]`

## 8. 企业管理、平台管理和用户管理

- 平台管理 `/platform`
  - 组织管理 `/platform` `[未覆盖]`
    - 当前仅有默认 Organization 结构，没有 UI/API 做多组织 CRUD。
  - 平台用户管理 `/platform/user` `[待检查]`
    - 当前有本地用户和角色，但不是 UPMS 全平台用户。
  - 用户创建 `/v3/upms/user` `[待检查]`
    - 当前：`POST /api/v1/users`。
  - 用户更新 `/v3/upms/user` PUT `[待检查]`
    - 当前：`PUT /api/v1/users/{userID}`。
  - 用户状态变更 `/v3/upms/user/status` `[待检查]`
    - 当前 `disabled_at` 支持禁用语义，但没有同名 API。
  - 用户搜索 `/v3/upms/user/search` `[待检查]`
    - 当前用户列表未提供完整搜索 API。
  - 租户创建、更新、删除、搜索 `/v3/upms/tenants*` `[未覆盖]`

## 9. 系统设置

- 后台地址 `/settings/panel`
  - 后台地址查询 `/v1/api/server/url/get` `[未覆盖]`
  - 后台地址设置 `/v1/api/server/url` `[未覆盖]`
- 报警间隔 `/settings/alarm`
  - 全局报警配置 `/v2/api/general/config` `[待检查]`
    - 当前有 system settings 和 alert rules，但没有同名 interval 页面。
- 系统信息 `/settings/systemInfo`
  - 版本 `/v1/version` `[待检查]`
    - 当前有 health/readiness、edition、metrics，但没有完全同名 version endpoint。
  - 健康检查 `/v1/ping` `[请二次检查]`
    - 当前：`GET /healthz`, `GET /readyz`。
  - Prometheus 指标 `[请二次检查]`
    - 当前额外实现：`GET /metrics`。
- 版本池 `/settings/poolVersion`
  - 默认版本 `/v2/api/version_pool/default` `[待检查]`
    - 当前有 agent artifact catalog，未实现默认版本池模型。
  - 上传版本 `/v2/api/version_pool/upload` `[待检查]`
    - 当前：`POST /api/v1/agent-artifacts`。
  - 版本池编辑弹窗 `editDialog.vue` `[待检查]`
- 版本管理 `/settings/version`
  - 当前版本 `/v2/api/version/current` `[待检查]`
  - 版本详情 `/v2/api/version/detail` `[待检查]`
  - 版本列表 `/v2/api/version/list` `[待检查]`
    - 当前：`GET /api/v1/agent-artifacts`。
  - 推送版本 `/v2/api/version/push` `[待检查]`
    - 当前通过 artifact 下载和 daemon command group 支持 Agent 拉取，未实现控制台推送版本。
  - 应用升级配置 `/v1/api/app/upgrade/get` `[未覆盖]`
  - 版本编辑弹窗 `editDialog.vue` `[待检查]`
    - 当前 artifact 上传表单覆盖部分能力。

## 10. Agent、服务端和下载通道

- Agent 生命周期
  - Agent 注册 `/v1/agent/rasp` `[请二次检查]`
    - 当前：`POST /api/v1/agents/register`。
  - Agent 心跳 `/v1/agent/heartbeat` `[请二次检查]`
    - 当前：`POST /api/v1/agents/{agentID}/heartbeat`。
  - Agent 报告 `/v1/agent/report` `[待检查]`
    - 当前拆分为 events、dependencies、baseline findings、heartbeat。
  - Agent 策略拉取 `[请二次检查]`
    - 当前：`GET /api/v1/agents/{agentID}/policy`。
  - Agent attack log `/v1/agent/log/attack` `[请二次检查]`
  - Agent policy log `/v1/agent/log/policy` `[待检查]`
    - 当前改为 baseline findings。
  - Agent error log `/v1/agent/log/error` `[待检查]`
  - Agent dependency `/v1/agent/dependency` `[请二次检查]`
  - Agent crash `/v1/agent/crash/report` `[请二次检查]`
- 下载服务
  - 下载 Agent `/v1/service/dl/agent`, `/v2/service/dl/agent` `[请二次检查]`
    - 当前：`GET /api/v1/daemon/artifacts/agent`, `GET /api/v1/agent-artifacts`。
  - Agent 下载信息 `/v1/service/dl/agent/info` `[请二次检查]`
    - 当前：`GET /api/v1/daemon/artifacts/agent/info`。
  - 下载升级包 `/v1/agent/download_upgrade` `[待检查]`
  - 下载引擎 `/v1/agent/download_engine` `[待检查]`
  - 下载 helper `/v1/service/dl/rasp-agent-helper`, `rasp-agent-helper-arm64` `[未覆盖]`
  - 下载 injector `/v1/service/dl/rasp-injector`, `rasp-injector-arm64` `[未覆盖]`
  - 安装脚本下载 `/v1/service/dl/install_legacy_helper.sh` `[未覆盖]`
  - 卸载脚本下载 `/v1/service/dl/uninstall_legacy_helper.sh` `[未覆盖]`
- Service 应用接口
  - Service app 获取 `/v1/service/app/get` `[待检查]`
    - 当前：`GET /api/v1/daemon/app` 按 app id 返回 app secret 和语言。
- Command/Daemon 通道
  - WebSocket 命令 `/v1/service/command` GET `[待检查]`
    - 当前：`GET /api/v1/daemon/commands` 轮询式命令组，不是 WebSocket。
  - DaemonSet 注入信息上传 `/v1/service/command/daemon_set/inject` `[请二次检查]`
    - 当前：`POST /api/v1/daemon/injection-reports`。
  - Daemon token 获取 `[请二次检查]`
    - 当前额外实现：`GET /api/v1/daemon/token`。
  - Daemon token 重置 `[请二次检查]`
    - 当前额外实现：`POST /api/v1/daemon/token/reset`。
  - Workload 上报 `[请二次检查]`
    - 当前额外实现：`POST /api/v1/daemon/workloads/report`。
  - Workload 绑定应用 `[请二次检查]`
    - 当前额外实现：`POST /api/v1/daemon/workloads/{workloadID}/bind`。
  - Workload 解绑应用 `[请二次检查]`
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
