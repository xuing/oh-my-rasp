我要基于 ASM 框架，做一个专为 JDK 25 且使用 JDK 25 相关特性的 Java RASP Agent。

我们最终是要做一个完整的 Agent,openrasp/agent/java 我们会参考这个的功能实现，但是我们不会参考它的任何代码，一点代码都不会参考。我们会做一个 Java Native 的 RASP 框架.
后期的话，我们计划通过云端来下发一些信息，包括 Hook 点（如果不能动态 Hook，那就是策略规则等），以及心跳上报之类的内容。不过这些我们先不做，目前先做一个原型验证，即开发一个针对异常行为进行拦截或记录的 RASP.

我们所有的技术选型全部都用市面上最新的。在做出任何决定的时候，我都建议你去网络上查询一下，看这是不是最佳实践。我们所有的软件包都必须保证是用最新的版本。你不可以写死它的版本号，要使用 Latest 版本

然后你可以多看一看 ASM 的相关文档。我已经在目录下帮你 clone 了 ASM 的项目，你可以直接去看一看它的使用方式。

我们的项目会在 MyRasp 里面进行开发。

这个第一版的项目，我希望你真正地把整个流程跑通。

具体要求如下：
1. 算法迁移：
   你要把所有以前用 JS 写的检测算法，全部翻译成 Java 版本。

2. 环境搭建：
   (a) 启动一个真正的 Web 服务（比如 Tomcat 之类的）。
   (b) 使用 Docker Compose 来建立测试项目。
   (c) 将 MyRasp 注入进去。

3. 验证与验收：
   (a) 编写用于验证 Hook 触发和策略触发的靶场项目及代码。
   (b) 针对每一种 Hook 和算法，都要编写相应的靶场案例。
   (c) 收集相关日志，并以日志的完整收集作为最终的验收标准。


----
首先把 MyRasp 改成 OhMyRasp。

然后靶场这边的话，你需要做一个前端页面，方便地把每一种测试样例做成一个接口，并提供一个可点击测试的方式。

跑两个环境：
1. 一个环境没有安装 RASP
2. 另一个环境安装了 RASP

通过这种方式进行对比测试。

对于安装了 RASP 的，我们在进行拦截之后，将其重定位到一个拦截页面中。
然后你再进行一次完整的测试，要让测试案例覆盖到所有的检测算法和所有的 hook 点。

进行测试并修复其中的所有问题，同时保持架构清晰、易扩展。
First, change "MyRasp" to "OhMyRasp". Next, regarding the testbed, you need to develop a front-end page where each test case can be easily made into an API endpoint, providing a clickable testing method. Run two environments: one without RASP installed and another with RASP installed, in order to conduct comparative testing. For the environment with RASP installed, once an attack is intercepted, redirect it to an interception page.
-----


Could you take a look at the service on port 18080?

It shouldn't have an agent configured, yet the protection was still triggered. How did the agent still get injected?

----

本项目是一个面向企业内部自部署的开源 RASP 控制平台，用于管理 RASP Agent、策略规则、防护配置、安全事件、性能数据、依赖信息、告警与审计日志。

平台不采用多租户模式。系统默认服务于一个组织，组织内部可以创建多个应用、多个环境、多个 Agent 实例和多套策略。组合优于继承。

1.2 核心目标
管理 Java RASP Agent 的注册、心跳、状态、版本、策略拉取和事件上报。
提供规则编辑、规则校验、规则测试、策略版本化、灰度发布、回滚能力。
提供攻击事件、Hook 事件、性能事件、崩溃事件、依赖信息的采集、存储、查询和聚合分析。
提供规则执行成本、Hook延迟、Agent 开销、策略版本影响的可观测能力。
提供企业内部可用的用户登录、角色权限、操作审计和系统设置。

推荐的技术选型
后端语言	Go 1.26
后端框架	net/http + chi
API 规范	OpenAPI 3.1
Go API 代码生成	oapi-codegen
主业务数据库	PostgreSQL
事件分析数据库	ClickHouse
缓存与会话	Valkey
指标系统	Prometheus
前端框架	React 19
前端语言	TypeScript
前端构建	Vite 8
前端路由	TanStack Router
前端请求状态	TanStack Query
前端 UI	shadcn/ui + Tailwind CSS 4
前端测试	Vitest + Playwright
容器部署	Docker Compose + Helm
CI/CD	GitHub Actions

我们要完整地重写这个目录(1. RASP)下的云控前后端。你可以建立web、api类似这样的目录来编辑这个项目。你要通过完善的测试

具体的业务能力和所需功能，你可以参考该文件夹下对应的文档以及代码，但你不能直接使用原先的代码，必须重新编写，并且要采用最新、最好的技术架构。

---------
恭喜你完成了这么伟大的工作，但是我需要验收。

你这样，你把 OhMyRASP 的所有相关内容都放到根目录下，不要放在子目录里。每一个文件或文件夹都起一个合适的名字，比如原本的 OhMyRASP，因为它其实是 Java Agent，你可以给它加一个叫 Java Agent 之类的名称，对吧？
然后你建立一个 archive 的文件夹，把其他无关的（比如说像 OpenRASP、ASM、OneDrive 的 ZIP，还有原先的 1.mrasp 这个文件夹）全部都放进去
在此之前，你需要把 1. Rasp 里面和OhMyRASP的东西拿出来。

MD 文件请统一放在 docs 里面。
