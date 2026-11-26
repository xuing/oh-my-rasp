# Hook Targets in Third-Party Libraries

> **Generated** by `scripts/gen-hook-targets.py` from `probes/hook-targets/recorded/` and
> `probes/hook-targets/libraries.toml`, not written by hand. Regenerate it after the
> `hook-targets` probe records a new map; `--check` fails CI when this file is stale.

A hook aimed at a library matches a class name and a method. When a release renames the method,
the hook stops applying and nothing says so. The `hook-targets` probe runs each packaged agent over
every class of real library JARs and records which methods come out calling back into the agent.
This page summarises those recorded maps; the full rows are in
[`recorded/primary.txt`](../probes/hook-targets/recorded/primary.txt) and
[`recorded/backport.txt`](../probes/hook-targets/recorded/backport.txt), the versions and why they
were chosen in [`libraries.toml`](../probes/hook-targets/libraries.toml).

A hooked method is one class, method and descriptor that an agent rewrites to call into itself. The
call-site rewriting that the primary agent applies to any class (JDBC and multipart call sites) is
not counted, only hooks on named targets. Primary is the JDK 21 and 25 agent, backport the Java 8,
11 and 17 agents, which record the same map.

## Hooked methods per library version

| Library | Version | Primary | Backport |
|---|---|--:|--:|
| `com.alibaba:fastjson` | 1.2.24 | 2 | 0 |
| `com.alibaba:fastjson` | 1.2.47 | 5 | 0 |
| `com.alibaba:fastjson` | 1.2.68 | 5 | 1 |
| `com.alibaba:fastjson` | 1.2.83 | 5 | 1 |
| `com.alibaba.fastjson2:fastjson2` | 2.0.10 | 2 | 0 |
| `com.alibaba.fastjson2:fastjson2` | 2.0.40 | 2 | 0 |
| `com.alibaba.fastjson2:fastjson2` | 2.0.66 | 2 | 0 |
| `com.fasterxml.jackson.core:jackson-databind` | 2.6.7 | 3 | 0 |
| `com.fasterxml.jackson.core:jackson-databind` | 2.9.10 | 2 | 0 |
| `com.fasterxml.jackson.core:jackson-databind` | 2.13.5 | 2 | 0 |
| `com.fasterxml.jackson.core:jackson-databind` | 2.17.2 | 2 | 0 |
| `com.fasterxml.jackson.core:jackson-databind` | 2.23.0 | 2 | 0 |
| `com.thoughtworks.xstream:xstream` | 1.4.5 | 11 | 1 |
| `com.thoughtworks.xstream:xstream` | 1.4.10 | 12 | 1 |
| `com.thoughtworks.xstream:xstream` | 1.4.17 | 12 | 1 |
| `com.thoughtworks.xstream:xstream` | 1.4.21 | 12 | 1 |
| `org.yaml:snakeyaml` | 1.17 | 1 | 0 |
| `org.yaml:snakeyaml` | 1.33 | 1 | 0 |
| `org.yaml:snakeyaml` | 2.0 | 1 | 0 |
| `org.yaml:snakeyaml` | 2.7 | 1 | 0 |
| `ognl:ognl` | 2.7.3 | 7 | 0 |
| `ognl:ognl` | 3.0.21 | 7 | 0 |
| `ognl:ognl` | 3.1.26 | 7 | 0 |
| `ognl:ognl` | 3.3.4 | 7 | 0 |
| `ognl:ognl` | 3.4.17 | 7 | 0 |
| `org.apache.struts:struts2-core` | 2.5.30 | 4 | 1 |
| `org.apache.struts:struts2-core` | 6.3.0.2 | 4 | 1 |
| `org.apache.struts:struts2-core` | 6.9.0 | 4 | 1 |
| `org.apache.struts:struts2-core` | 7.0.3 | 4 | 1 |
| `org.apache.struts.xwork:xwork-core` | 2.3.20 | 5 | 1 |
| `org.apache.struts.xwork:xwork-core` | 2.3.37 | 4 | 1 |
| `org.apache.velocity:velocity` | 1.5 | 6 | 0 |
| `org.apache.velocity:velocity` | 1.7 | 8 | 0 |
| `org.apache.velocity:velocity-engine-core` | 2.0 | 6 | 0 |
| `org.apache.velocity:velocity-engine-core` | 2.3 | 6 | 0 |
| `org.apache.velocity:velocity-engine-core` | 2.4.1 | 6 | 0 |
| `org.mvel:mvel2` | 2.1.3.Final | 39 | 0 |
| `org.mvel:mvel2` | 2.4.15.Final | 39 | 0 |
| `org.mvel:mvel2` | 2.6.0.Final | 39 | 0 |
| `org.codehaus.groovy:groovy` | 2.4.21 | 8 | 1 |
| `org.codehaus.groovy:groovy` | 3.0.25 | 8 | 1 |
| `org.apache.groovy:groovy` | 4.0.31 | 10 | 0 |
| `org.apache.groovy:groovy` | 5.0.8 | 10 | 0 |
| `org.codehaus.groovy:groovy-jsr223` | 2.5.23 | 1 | 2 |
| `org.codehaus.groovy:groovy-jsr223` | 3.0.25 | 1 | 2 |
| `org.apache.groovy:groovy-jsr223` | 4.0.31 | 1 | 2 |
| `org.apache.groovy:groovy-jsr223` | 5.0.8 | 1 | 2 |
| `org.mozilla:rhino` | 1.7.7.2 | 5 | 5 |
| `org.mozilla:rhino` | 1.7.14 | 5 | 5 |
| `org.mozilla:rhino` | 1.8.1 | 5 | 5 |
| `org.mozilla:rhino` | 1.9.2 | 5 | 5 |
| `commons-jexl:commons-jexl` | 1.1 | 2 | 0 |
| `org.apache.commons:commons-jexl` | 2.0.1 | 13 | 2 |
| `org.apache.commons:commons-jexl` | 2.1.1 | 18 | 3 |
| `org.apache.commons:commons-jexl3` | 3.0 | 24 | 3 |
| `org.apache.commons:commons-jexl3` | 3.2.1 | 27 | 3 |
| `org.apache.commons:commons-jexl3` | 3.5.0 | 27 | 3 |
| `org.apache.commons:commons-jexl3` | 3.7.1 | 28 | 3 |
| `javax.el:javax.el-api` | 2.2.1 (no hook, see below) | 0 | 0 |
| `javax.el:javax.el-api` | 3.0.0 | 3 | 0 |
| `jakarta.el:jakarta.el-api` | 3.0.3 | 3 | 0 |
| `jakarta.el:jakarta.el-api` | 4.0.0 | 3 | 0 |
| `jakarta.el:jakarta.el-api` | 5.0.1 | 3 | 0 |
| `jakarta.el:jakarta.el-api` | 6.0.1 | 3 | 0 |
| `org.apache.tomcat:tomcat-jasper-el` | 8.5.100 | 4 | 6 |
| `org.apache.tomcat:tomcat-jasper-el` | 9.0.124 | 4 | 6 |
| `org.apache.tomcat:tomcat-jasper-el` | 10.1.62 | 4 | 6 |
| `org.apache.tomcat:tomcat-jasper-el` | 11.0.29 | 4 | 6 |
| `org.glassfish:jakarta.el` | 3.0.4 | 7 | 6 |
| `org.glassfish:jakarta.el` | 4.0.2 | 4 | 6 |
| `org.glassfish:javax.el` | 3.0.0 | 7 | 6 |
| `org.glassfish:javax.el` | 3.0.1-b12 | 7 | 6 |
| `de.odysseus.juel:juel-impl` | 2.2.7 | 4 | 6 |
| `com.github.albfernandez:jboss-el` | 1.1.0 | 4 | 5 |
| `com.github.albfernandez:jboss-el` | 1.1.1 | 4 | 5 |
| `xalan:xalan` | 2.7.1 | 5 | 0 |
| `xalan:xalan` | 2.7.3 | 5 | 0 |
| `jaxen:jaxen` | 1.1.6 | 2 | 0 |
| `jaxen:jaxen` | 1.2.0 | 2 | 0 |
| `jaxen:jaxen` | 2.0.6 | 2 | 0 |
| `commons-jxpath:commons-jxpath` | 1.3 | 19 | 0 |
| `commons-jxpath:commons-jxpath` | 1.4.0 | 19 | 0 |
| `org.codehaus.janino:janino` | 2.7.8 | 3 | 3 |
| `org.codehaus.janino:janino` | 3.0.16 | 2 | 2 |
| `org.codehaus.janino:janino` | 3.1.12 | 6 | 6 |
| `org.codehaus.janino:commons-compiler` | 2.7.8 | 2 | 2 |
| `org.codehaus.janino:commons-compiler` | 3.0.16 | 3 | 3 |
| `org.codehaus.janino:commons-compiler` | 3.1.12 | 3 | 3 |
| `org.springframework:spring-core` | 3.2.18.RELEASE | 1 | 1 |
| `org.springframework:spring-core` | 4.3.30.RELEASE | 1 | 1 |
| `org.springframework:spring-core` | 5.3.39 | 1 | 1 |
| `org.springframework:spring-core` | 6.2.19 | 1 | 1 |
| `org.springframework:spring-core` | 7.1.0 | 1 | 1 |
| `org.springframework:spring-beans` | 3.2.18.RELEASE | 12 | 8 |
| `org.springframework:spring-beans` | 4.3.30.RELEASE | 12 | 8 |
| `org.springframework:spring-beans` | 5.3.39 | 12 | 8 |
| `org.springframework:spring-beans` | 6.2.19 | 12 | 8 |
| `org.springframework:spring-beans` | 7.1.0 | 12 | 8 |
| `org.springframework:spring-context` | 3.2.18.RELEASE | 16 | 0 |
| `org.springframework:spring-context` | 4.3.30.RELEASE | 16 | 0 |
| `org.springframework:spring-context` | 5.3.39 | 16 | 0 |
| `org.springframework:spring-context` | 6.2.19 | 15 | 0 |
| `org.springframework:spring-context` | 7.1.0 | 15 | 0 |
| `org.springframework:spring-expression` | 3.2.18.RELEASE | 11 | 0 |
| `org.springframework:spring-expression` | 4.3.30.RELEASE | 11 | 0 |
| `org.springframework:spring-expression` | 5.3.39 | 11 | 0 |
| `org.springframework:spring-expression` | 6.2.19 | 11 | 0 |
| `org.springframework:spring-expression` | 7.1.0 | 11 | 0 |
| `org.springframework:spring-web` | 3.2.18.RELEASE | 4 | 20 |
| `org.springframework:spring-web` | 4.3.30.RELEASE | 4 | 23 |
| `org.springframework:spring-web` | 5.3.39 | 4 | 21 |
| `org.springframework:spring-web` | 6.2.19 | 3 | 17 |
| `org.springframework:spring-web` | 7.1.0 | 4 | 24 |
| `org.springframework:spring-test` | 4.3.30.RELEASE | 8 | 13 |
| `org.springframework:spring-test` | 5.3.39 | 6 | 13 |
| `org.springframework:spring-test` | 6.2.19 | 6 | 11 |
| `org.apache.xbean:xbean-spring` | 3.18 | 6 | 0 |
| `org.apache.xbean:xbean-spring` | 4.19 | 6 | 0 |
| `com.caucho:hessian` | 4.0.51 | 8 | 8 |
| `com.caucho:hessian` | 4.0.63 | 8 | 8 |
| `com.caucho:hessian` | 4.0.66 | 8 | 8 |
| `com.alibaba:hessian-lite` | 3.2.2 | 7 | 7 |
| `com.alibaba:hessian-lite` | 3.2.5 | 7 | 7 |
| `com.alibaba:hessian-lite` | 3.2.8 | 7 | 7 |
| `com.alibaba:hessian-lite` | 3.2.13 | 7 | 7 |
| `args4j:args4j` | 2.0.31 | 1 | 0 |
| `args4j:args4j` | 2.33 | 1 | 0 |
| `args4j:args4j` | 2.37 | 1 | 0 |
| `org.mybatis:mybatis` | 3.2.8 | 12 | 12 |
| `org.mybatis:mybatis` | 3.4.6 | 14 | 14 |
| `org.mybatis:mybatis` | 3.5.6 | 15 | 15 |
| `org.mybatis:mybatis` | 3.5.19 | 18 | 18 |
| `org.mybatis:mybatis` | 3.6.0 | 18 | 18 |
| `com.github.pagehelper:pagehelper` | 4.2.1 | 6 | 6 |
| `com.github.pagehelper:pagehelper` | 5.1.11 | 14 | 14 |
| `com.github.pagehelper:pagehelper` | 5.3.3 | 21 | 21 |
| `com.github.pagehelper:pagehelper` | 6.1.1 | 23 | 23 |
| `org.apache.xmlrpc:xmlrpc-common` | 3.0 | 1 | 0 |
| `org.apache.xmlrpc:xmlrpc-common` | 3.1.3 | 1 | 0 |
| `org.apache.activemq:activemq-client` | 5.15.16 | 5 | 5 |
| `org.apache.activemq:activemq-client` | 5.17.3 | 5 | 5 |
| `org.apache.activemq:activemq-client` | 5.19.12 | 5 | 5 |
| `org.apache.activemq:activemq-client` | 6.1.8 | 5 | 5 |
| `org.apache.activemq:activemq-openwire-legacy` | 5.15.16 | 7 | 7 |
| `org.apache.activemq:activemq-openwire-legacy` | 5.17.3 | 7 | 7 |
| `org.apache.activemq:activemq-openwire-legacy` | 5.19.12 | 7 | 7 |
| `org.apache.activemq:activemq-openwire-legacy` | 6.1.8 | 7 | 7 |
| `org.elasticsearch:elasticsearch` | 7.17.29 | 3 | 3 |
| `org.elasticsearch:elasticsearch` | 8.19.23 | 4 | 4 |
| `org.apache.spark:spark-core_2.12` | 2.4.8 | 16 | 33 |
| `org.apache.spark:spark-core_2.12` | 3.5.10 | 16 | 34 |
| `org.apache.hadoop:hadoop-yarn-server-resourcemanager` | 2.7.7 | 1 | 1 |
| `org.apache.hadoop:hadoop-yarn-server-resourcemanager` | 2.8.1 | 1 | 1 |
| `org.apache.hadoop:hadoop-yarn-server-resourcemanager` | 3.3.6 | 1 | 1 |
| `org.apache.hadoop:hadoop-yarn-server-resourcemanager` | 3.4.3 | 1 | 1 |
| `javax.servlet:javax.servlet-api` | 3.0.1 | 6 | 6 |
| `javax.servlet:javax.servlet-api` | 3.1.0 | 6 | 6 |
| `javax.servlet:javax.servlet-api` | 4.0.1 | 6 | 6 |
| `jakarta.servlet:jakarta.servlet-api` | 5.0.0 | 6 | 6 |
| `jakarta.servlet:jakarta.servlet-api` | 6.0.0 | 6 | 6 |
| `jakarta.servlet:jakarta.servlet-api` | 6.1.0 | 6 | 6 |
| `org.apache.tomcat:tomcat-catalina` | 7.0.109 | 9 | 18 |
| `org.apache.tomcat:tomcat-catalina` | 8.5.100 | 7 | 17 |
| `org.apache.tomcat:tomcat-catalina` | 9.0.124 | 7 | 17 |
| `org.apache.tomcat:tomcat-catalina` | 10.1.62 | 7 | 17 |
| `org.apache.tomcat:tomcat-catalina` | 11.0.29 | 7 | 17 |
| `org.apache.shiro:shiro-web` | 1.2.4 | 0 | 1 |
| `org.apache.shiro:shiro-web` | 1.13.0 | 0 | 1 |
| `org.apache.shiro:shiro-web` | 2.0.6 | 0 | 1 |
| `org.apache.shiro:shiro-web` | 3.0.2 | 0 | 1 |
| `org.glassfish.jersey.core:jersey-server` | 2.25.1 | 0 | 1 |
| `org.glassfish.jersey.core:jersey-server` | 2.46 | 0 | 1 |
| `org.glassfish.jersey.core:jersey-server` | 3.0.18 | 0 | 1 |
| `org.glassfish.jersey.core:jersey-server` | 3.1.12 | 0 | 1 |
| `org.glassfish.jersey.core:jersey-server` | 4.0.3 | 0 | 1 |
| `org.glassfish.jersey.media:jersey-media-multipart` | 2.25.1 | 0 | 1 |
| `org.glassfish.jersey.media:jersey-media-multipart` | 2.46 | 0 | 1 |
| `org.glassfish.jersey.media:jersey-media-multipart` | 3.0.18 | 0 | 1 |
| `org.glassfish.jersey.media:jersey-media-multipart` | 3.1.12 | 0 | 1 |
| `org.glassfish.jersey.media:jersey-media-multipart` | 4.0.3 | 0 | 1 |
| `commons-fileupload:commons-fileupload` | 1.2.2 | 1 | 1 |
| `commons-fileupload:commons-fileupload` | 1.3.3 | 1 | 1 |
| `commons-fileupload:commons-fileupload` | 1.4 | 1 | 1 |
| `commons-fileupload:commons-fileupload` | 1.6.0 | 1 | 1 |
| `io.undertow:undertow-servlet` | 1.4.28.Final | 3 | 13 |
| `io.undertow:undertow-servlet` | 2.0.42.Final | 3 | 14 |
| `io.undertow:undertow-servlet` | 2.2.39.Final | 3 | 14 |
| `io.undertow:undertow-servlet` | 2.3.27.Final | 3 | 14 |
| `io.undertow:undertow-servlet-jakarta` | 2.2.20.Final | 3 | 14 |
| `org.eclipse.jetty:jetty-util` | 9.4.57.v20241219 | 3 | 5 |
| `org.eclipse.jetty:jetty-server` | 9.4.57.v20241219 | 8 | 20 |
| `org.eclipse.jetty:jetty-server` | 10.0.26 | 14 | 30 |
| `org.eclipse.jetty:jetty-server` | 11.0.26 | 14 | 30 |
| `org.eclipse.jetty:jetty-server` | 12.0.41 | 0 | 1 |
| `xerces:xercesImpl` | 2.9.1 | 6 | 6 |
| `xerces:xercesImpl` | 2.11.0 | 6 | 6 |
| `xerces:xercesImpl` | 2.12.2 | 6 | 6 |
| `javax.activation:activation` | 1.1.1 | 2 | 2 |
| `com.sun.activation:javax.activation` | 1.2.0 | 2 | 2 |
| `jakarta.activation:jakarta.activation-api` | 1.2.2 | 2 | 2 |
| `jakarta.activation:jakarta.activation-api` | 2.0.1 | 2 | 2 |
| `jakarta.activation:jakarta.activation-api` | 2.1.3 | 2 | 2 |
| `org.apache.cxf:cxf-rt-databinding-aegis` | 2.7.18 | 1 | 1 |
| `org.apache.cxf:cxf-rt-databinding-aegis` | 3.6.9 | 1 | 1 |
| `org.apache.cxf:cxf-rt-databinding-aegis` | 4.0.11 | 1 | 1 |
| `net.sf.sevenzipjbinding:sevenzipjbinding` | 16.02-2.01 | 0 | 1 |
| `net.sf.sevenzipjbinding:sevenzipjbinding` | 26.06-2.3 | 0 | 1 |
| `org.apache.skywalking:storage-jdbc-hikaricp-plugin` | 8.9.1 | 0 | 1 |
| `org.apache.skywalking:storage-jdbc-hikaricp-plugin` | 9.7.0 | 0 | 1 |
| `com.h2database:h2` | 1.4.197 | 39 | 38 |
| `com.h2database:h2` | 1.4.200 | 39 | 38 |
| `com.h2database:h2` | 2.1.214 | 28 | 27 |
| `com.h2database:h2` | 2.3.232 | 28 | 27 |

## Versions with no hook

Each is listed under `none` in `libraries.toml` with its reason. A reason starting with FINDING
is a hook that should be fixed.

| Library | Version | Reason |
|---|---|---|
| `javax.el:javax.el-api` | 2.2.1 | javax.el.ELProcessor, the class the hook wants, first appears in EL 3.0; ExpressionFactory has no concrete method the hook rewrites |

## Hook families with no library target

Hook families that rewrite no method of any listed library, from
[`allowlist.toml`](../probes/hook-targets/allowlist.toml). The probe fails when one stops being needed.

**Primary**

| Hook family | Why |
|---|---|
| `ArchiveHookModule` | JDK-only: rewrites java.util.zip.ZipInputStream and ZipFile. |
| `Base64HookModule` | JDK-only: rewrites java.util.Base64$Decoder. |
| `ClassLoaderHookModule` | JDK-only: rewrites java.net.URLClassLoader, sun.rmi.server.LoaderHandler and URLClassPath loaders. |
| `FileHookModule` | JDK-only: rewrites java.io and java.nio.file classes. |
| `JavaBeansHookModule` | JDK-only: rewrites java.beans.Expression and Statement and com.sun.beans.decoder.DocumentHandler. |
| `JmxHookModule` | JDK-only: rewrites the JDK's DefaultMBeanServerInterceptor and BadAttributeValueExpException. |
| `JndiHookModule` | JDK-only: rewrites javax.naming.InitialContext and com.sun.jndi URL contexts. |
| `JwtHookModule` | Not a library: its target is io.dataease.auth.filter.CommunityTokenFilter, a class of the DataEase application. |
| `NetworkHookModule` | JDK-only: rewrites java.net.URL, InetAddress and the JDK's HTTP clients. |
| `ObjectInputStreamHookModule` | JDK-only: rewrites java.io.ObjectInputStream. |
| `RmiRegistryHookModule` | JDK-only: rewrites sun.rmi.registry.RegistryImpl. |

**Backport**

| Hook family | Why |
|---|---|
| `Java{N}Base64Transformer` | JDK-only: rewrites java.util.Base64$Decoder. |
| `Java{N}ClassLoaderTransformer` | JDK-only: rewrites java.net.URLClassLoader, sun.rmi.server.LoaderHandler and URLClassPath loaders. |
| `Java{N}FileTransformer` | JDK-only: rewrites java.io and java.nio.file classes. |
| `Java{N}JavaBeansTransformer` | JDK-only: rewrites java.beans.Expression and Statement and com.sun.beans.decoder.DocumentHandler. |
| `Java{N}JmxTransformer` | JDK-only: rewrites the JDK's DefaultMBeanServerInterceptor and BadAttributeValueExpException. |
| `Java{N}JndiTransformer` | JDK-only: rewrites javax.naming.InitialContext and com.sun.jndi URL contexts. |
| `Java{N}JwtTransformer` | Not a library: its target is io.dataease.auth.filter.CommunityTokenFilter, a class of the DataEase application. |
| `Java{N}UrlTransformer` | JDK-only: rewrites java.net.URL and the JDK's HTTP clients. |

## Version gaps

A method (class and method name) that an agent hooks in some versions of a library and not in
others. Most are renames between major versions (`javax` to `jakarta`, a moved package, a new
signature); each is a place to check that the hook still covers what it did.

### Primary

| Library | Hooked in | Not hooked in | Methods |
|---|---|---|---|
| `com.alibaba:fastjson` | 1.2.47 1.2.68 1.2.83 | 1.2.24 | `com/alibaba/fastjson/parser/ParserConfig.checkAutoType` |
| `com.github.pagehelper:pagehelper` | 4.2.1 | 5.1.11 5.3.3 6.1.1 | `com/github/pagehelper/dialect/Db2Dialect.getPageSql`<br>`com/github/pagehelper/dialect/HsqldbDialect.getPageSql`<br>`com/github/pagehelper/dialect/InformixDialect.getPageSql`<br>`com/github/pagehelper/dialect/MySqlDialect.getPageSql`<br>and 2 more |
| `com.github.pagehelper:pagehelper` | 5.1.11 5.3.3 6.1.1 | 4.2.1 | `com/github/pagehelper/dialect/helper/Db2Dialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/HerdDBDialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/HsqldbDialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/InformixDialect.getPageSql`<br>and 10 more |
| `com.github.pagehelper:pagehelper` | 5.3.3 6.1.1 | 4.2.1 5.1.11 | `com/github/pagehelper/dialect/helper/AS400Dialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/CirroDataDialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/FirebirdDialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/Oracle9iDialect.getPageSql`<br>and 3 more |
| `com.github.pagehelper:pagehelper` | 6.1.1 | 4.2.1 5.1.11 5.3.3 | `com/github/pagehelper/dialect/helper/XuguDialect.getPageSql`<br>`com/github/pagehelper/dialect/rowbounds/XuguRowBoundsDialect.getPageSql` |
| `com.h2database:h2` | 1.4.197 1.4.200 | 2.1.214 2.3.232 | `org/h2/jdbc/JdbcPreparedStatement.execute`<br>`org/h2/jdbc/JdbcPreparedStatement.executeLargeUpdate`<br>`org/h2/jdbc/JdbcPreparedStatement.executeUpdate` |
| `com.h2database:h2` | 2.1.214 2.3.232 | 1.4.197 1.4.200 | `org/h2/jdbc/meta/DatabaseMetaLegacy.executeQuery` |
| `com.thoughtworks.xstream:xstream` | 1.4.10 1.4.17 1.4.21 | 1.4.5 | `com/thoughtworks/xstream/mapper/SecurityMapper.realClass` |
| `jakarta.activation:jakarta.activation-api` | 1.2.2 | 2.0.1 2.1.3 | `javax/activation/URLDataSource.<init>`<br>`javax/activation/URLDataSource.getInputStream` |
| `jakarta.activation:jakarta.activation-api` | 2.0.1 2.1.3 | 1.2.2 | `jakarta/activation/URLDataSource.<init>`<br>`jakarta/activation/URLDataSource.getInputStream` |
| `jakarta.el:jakarta.el-api` | 3.0.3 | 4.0.0 5.0.1 6.0.1 | `javax/el/ELProcessor.eval`<br>`javax/el/ELProcessor.getValue`<br>`javax/el/ELProcessor.setValue` |
| `jakarta.el:jakarta.el-api` | 4.0.0 5.0.1 6.0.1 | 3.0.3 | `jakarta/el/ELProcessor.eval`<br>`jakarta/el/ELProcessor.getValue`<br>`jakarta/el/ELProcessor.setValue` |
| `javax.el:javax.el-api` | 3.0.0 | 2.2.1 | `javax/el/ELProcessor.eval`<br>`javax/el/ELProcessor.getValue`<br>`javax/el/ELProcessor.setValue` |
| `org.apache.commons:commons-jexl` | 2.1.1 | 2.0.1 | `org/apache/commons/jexl2/UnifiedJEXL.createTemplate` |
| `org.apache.commons:commons-jexl3` | 3.2.1 3.5.0 3.7.1 | 3.0 | `org/apache/commons/jexl3/internal/Source.<init>` |
| `org.apache.commons:commons-jexl3` | 3.7.1 | 3.0 3.2.1 3.5.0 | `org/apache/commons/jexl3/internal/introspection/RecordGetExecutor.<init>` |
| `org.apache.spark:spark-core_2.12` | 2.4.8 | 3.5.10 | `org/spark_project/jetty/http/MultiPartFormInputStream$MultiPart.getSubmittedFileName`<br>`org/spark_project/jetty/http/MultiPartFormInputStream.getPart`<br>`org/spark_project/jetty/http/MultiPartFormInputStream.getParts`<br>`org/spark_project/jetty/server/MultiParts$MultiPartsHttpParser.getPart`<br>and 10 more |
| `org.apache.spark:spark-core_2.12` | 3.5.10 | 2.4.8 | `org/sparkproject/jetty/http/MultiPartFormInputStream$MultiPart.getSubmittedFileName`<br>`org/sparkproject/jetty/http/MultiPartFormInputStream.getPart`<br>`org/sparkproject/jetty/http/MultiPartFormInputStream.getParts`<br>`org/sparkproject/jetty/server/MultiParts$MultiPartsHttpParser.getPart`<br>and 10 more |
| `org.apache.struts:struts2-core` | 2.5.30 6.3.0.2 6.9.0 | 7.0.3 | `com/opensymphony/xwork2/ognl/OgnlUtil.getValue`<br>`com/opensymphony/xwork2/ognl/OgnlUtil.setValue`<br>`com/opensymphony/xwork2/util/classloader/FileResourceStore.getFile` |
| `org.apache.struts:struts2-core` | 7.0.3 | 2.5.30 6.3.0.2 6.9.0 | `org/apache/struts2/ognl/OgnlUtil.getValue`<br>`org/apache/struts2/ognl/OgnlUtil.setValue`<br>`org/apache/struts2/util/classloader/FileResourceStore.getFile` |
| `org.apache.tomcat:tomcat-catalina` | 7.0.109 | 8.5.100 9.0.124 10.1.62 11.0.29 | `org/apache/catalina/websocket/WsHttpServletRequestWrapper.getPart`<br>`org/apache/catalina/websocket/WsHttpServletRequestWrapper.getParts` |
| `org.apache.velocity:velocity` | 1.7 | 1.5 | `org/apache/velocity/runtime/RuntimeInstance.evaluate` |
| `org.codehaus.janino:commons-compiler` | 3.0.16 3.1.12 | 2.7.8 | `org/codehaus/commons/compiler/util/resource/DirectoryResourceCreator.getFile` |
| `org.codehaus.janino:janino` | 2.7.8 | 3.0.16 3.1.12 | `org/codehaus/janino/util/resource/DirectoryResourceCreator.getFile` |
| `org.codehaus.janino:janino` | 2.7.8 3.0.16 | 3.1.12 | `org/codehaus/janino/Compiler$2.getFile` |
| `org.codehaus.janino:janino` | 3.1.12 | 2.7.8 3.0.16 | `org/codehaus/janino/ClassBodyEvaluator.cook`<br>`org/codehaus/janino/Compiler$3.getFile`<br>`org/codehaus/janino/ExpressionEvaluator.cook`<br>`org/codehaus/janino/ScriptEvaluator.cook` |
| `org.eclipse.jetty:jetty-server` | 10.0.26 11.0.26 | 9.4.57.v20241219 12.0.41 | `org/eclipse/jetty/server/MultiPartFormInputStream$MultiPart.getSubmittedFileName`<br>`org/eclipse/jetty/server/MultiPartFormInputStream.getPart`<br>`org/eclipse/jetty/server/MultiPartFormInputStream.getParts`<br>`org/eclipse/jetty/server/MultiPartInputStreamParser$MultiPart.getSubmittedFileName`<br>and 2 more |
| `org.eclipse.jetty:jetty-server` | 9.4.57.v20241219 10.0.26 11.0.26 | 12.0.41 | `org/eclipse/jetty/server/MultiParts$MultiPartsHttpParser.getPart`<br>`org/eclipse/jetty/server/MultiParts$MultiPartsHttpParser.getParts`<br>`org/eclipse/jetty/server/MultiParts$MultiPartsUtilParser.getPart`<br>`org/eclipse/jetty/server/MultiParts$MultiPartsUtilParser.getParts`<br>and 4 more |
| `org.elasticsearch:elasticsearch` | 8.19.23 | 7.17.29 | `org/elasticsearch/common/settings/LocallyMountedSecrets.getFile` |
| `org.glassfish:jakarta.el` | 3.0.4 | 4.0.2 | `javax/el/ELProcessor.eval`<br>`javax/el/ELProcessor.getValue`<br>`javax/el/ELProcessor.setValue` |
| `org.mybatis:mybatis` | 3.4.6 3.5.6 3.5.19 3.6.0 | 3.2.8 | `org/apache/ibatis/executor/statement/BaseStatementHandler.prepare`<br>`org/apache/ibatis/executor/statement/SimpleStatementHandler.queryCursor` |
| `org.mybatis:mybatis` | 3.5.19 3.6.0 | 3.2.8 3.4.6 3.5.6 | `org/apache/ibatis/scripting/xmltags/TrimSqlNode$FilteredDynamicContext.lambda$applyPrefix$0`<br>`org/apache/ibatis/scripting/xmltags/TrimSqlNode$FilteredDynamicContext.lambda$applySuffix$1`<br>`org/apache/ibatis/scripting/xmltags/TrimSqlNode$FilteredDynamicContext.lambda$applySuffix$2` |
| `org.mybatis:mybatis` | 3.5.6 3.5.19 3.6.0 | 3.2.8 3.4.6 | `org/apache/ibatis/builder/SqlSourceBuilder.removeExtraWhitespaces` |
| `org.springframework:spring-beans` | 3.2.18.RELEASE 4.3.30.RELEASE | 5.3.39 6.2.19 7.1.0 | `org/springframework/beans/factory/support/AbstractAutowireCapableBeanFactory$8.run` |
| `org.springframework:spring-beans` | 5.3.39 | 3.2.18.RELEASE 4.3.30.RELEASE 6.2.19 7.1.0 | `org/springframework/beans/factory/support/AbstractAutowireCapableBeanFactory.lambda$invokeCustomInitMethod$7` |
| `org.springframework:spring-beans` | 6.2.19 7.1.0 | 3.2.18.RELEASE 4.3.30.RELEASE 5.3.39 | `org/springframework/beans/factory/support/AbstractBeanDefinition.setInitMethodNames` |
| `org.springframework:spring-context` | 3.2.18.RELEASE 4.3.30.RELEASE 5.3.39 | 6.2.19 7.1.0 | `org/springframework/remoting/rmi/RemoteInvocationSerializingExporter.doReadRemoteInvocation` |
| `org.springframework:spring-test` | 4.3.30.RELEASE | 5.3.39 6.2.19 | `org/springframework/mock/web/portlet/MockMultipartActionRequest.getFile`<br>`org/springframework/mock/web/portlet/MockMultipartActionRequest.getFiles` |
| `org.springframework:spring-web` | 3.2.18.RELEASE 4.3.30.RELEASE 5.3.39 | 6.2.19 7.1.0 | `org/springframework/web/multipart/commons/CommonsMultipartFile.getOriginalFilename` |
| `org.springframework:spring-web` | 7.1.0 | 3.2.18.RELEASE 4.3.30.RELEASE 5.3.39 6.2.19 | `org/springframework/http/converter/multipart/PartGenerator.getParts` |

### Backport

| Library | Hooked in | Not hooked in | Methods |
|---|---|---|---|
| `com.alibaba:fastjson` | 1.2.68 1.2.83 | 1.2.24 1.2.47 | `com/alibaba/fastjson/parser/ParserConfig.checkAutoType` |
| `com.github.pagehelper:pagehelper` | 4.2.1 | 5.1.11 5.3.3 6.1.1 | `com/github/pagehelper/dialect/Db2Dialect.getPageSql`<br>`com/github/pagehelper/dialect/HsqldbDialect.getPageSql`<br>`com/github/pagehelper/dialect/InformixDialect.getPageSql`<br>`com/github/pagehelper/dialect/MySqlDialect.getPageSql`<br>and 2 more |
| `com.github.pagehelper:pagehelper` | 5.1.11 5.3.3 6.1.1 | 4.2.1 | `com/github/pagehelper/dialect/helper/Db2Dialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/HerdDBDialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/HsqldbDialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/InformixDialect.getPageSql`<br>and 10 more |
| `com.github.pagehelper:pagehelper` | 5.3.3 6.1.1 | 4.2.1 5.1.11 | `com/github/pagehelper/dialect/helper/AS400Dialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/CirroDataDialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/FirebirdDialect.getPageSql`<br>`com/github/pagehelper/dialect/helper/Oracle9iDialect.getPageSql`<br>and 3 more |
| `com.github.pagehelper:pagehelper` | 6.1.1 | 4.2.1 5.1.11 5.3.3 | `com/github/pagehelper/dialect/helper/XuguDialect.getPageSql`<br>`com/github/pagehelper/dialect/rowbounds/XuguRowBoundsDialect.getPageSql` |
| `com.h2database:h2` | 1.4.197 1.4.200 | 2.1.214 2.3.232 | `org/h2/jdbc/JdbcPreparedStatement.execute`<br>`org/h2/jdbc/JdbcPreparedStatement.executeLargeUpdate`<br>`org/h2/jdbc/JdbcPreparedStatement.executeUpdate` |
| `com.h2database:h2` | 2.1.214 2.3.232 | 1.4.197 1.4.200 | `org/h2/jdbc/meta/DatabaseMetaLegacy.executeQuery` |
| `io.undertow:undertow-servlet` | 2.0.42.Final 2.2.39.Final 2.3.27.Final | 1.4.28.Final | `io/undertow/servlet/spec/HttpServletRequestImpl.getTrailerFields` |
| `jakarta.activation:jakarta.activation-api` | 1.2.2 | 2.0.1 2.1.3 | `javax/activation/URLDataSource.<init>`<br>`javax/activation/URLDataSource.getInputStream` |
| `jakarta.activation:jakarta.activation-api` | 2.0.1 2.1.3 | 1.2.2 | `jakarta/activation/URLDataSource.<init>`<br>`jakarta/activation/URLDataSource.getInputStream` |
| `org.apache.skywalking:storage-jdbc-hikaricp-plugin` | 8.9.1 | 9.7.0 | `org/apache/skywalking/oap/server/storage/plugin/jdbc/h2/dao/H2LogQueryDAO.queryLogs` |
| `org.apache.skywalking:storage-jdbc-hikaricp-plugin` | 9.7.0 | 8.9.1 | `org/apache/skywalking/oap/server/storage/plugin/jdbc/common/dao/JDBCLogQueryDAO.buildSQL` |
| `org.apache.spark:spark-core_2.12` | 2.4.8 | 3.5.10 | `org/spark_project/jetty/http/MultiPartFormInputStream$MultiPart.getSubmittedFileName`<br>`org/spark_project/jetty/http/MultiPartFormInputStream.deleteParts`<br>`org/spark_project/jetty/http/MultiPartFormInputStream.getParsedParts`<br>`org/spark_project/jetty/http/MultiPartFormInputStream.getPart`<br>and 26 more |
| `org.apache.spark:spark-core_2.12` | 3.5.10 | 2.4.8 | `org/sparkproject/jetty/http/MultiPartFormInputStream$MultiPart.getSubmittedFileName`<br>`org/sparkproject/jetty/http/MultiPartFormInputStream.deleteParts`<br>`org/sparkproject/jetty/http/MultiPartFormInputStream.getParsedParts`<br>`org/sparkproject/jetty/http/MultiPartFormInputStream.getPart`<br>and 27 more |
| `org.apache.struts:struts2-core` | 2.5.30 6.3.0.2 6.9.0 | 7.0.3 | `com/opensymphony/xwork2/util/classloader/FileResourceStore.getFile` |
| `org.apache.struts:struts2-core` | 7.0.3 | 2.5.30 6.3.0.2 6.9.0 | `org/apache/struts2/util/classloader/FileResourceStore.getFile` |
| `org.apache.tomcat:tomcat-catalina` | 7.0.109 | 8.5.100 9.0.124 10.1.62 11.0.29 | `org/apache/catalina/connector/Request.getNoteNames`<br>`org/apache/catalina/websocket/WsHttpServletRequestWrapper.getPart`<br>`org/apache/catalina/websocket/WsHttpServletRequestWrapper.getParts` |
| `org.apache.tomcat:tomcat-catalina` | 8.5.100 9.0.124 10.1.62 11.0.29 | 7.0.109 | `org/apache/catalina/connector/Request.getUpgradeProtocolName`<br>`org/apache/catalina/connector/Request.parseLocalesHeader` |
| `org.codehaus.janino:commons-compiler` | 3.0.16 3.1.12 | 2.7.8 | `org/codehaus/commons/compiler/util/resource/DirectoryResourceCreator.getFile` |
| `org.codehaus.janino:janino` | 2.7.8 | 3.0.16 3.1.12 | `org/codehaus/janino/util/resource/DirectoryResourceCreator.getFile` |
| `org.codehaus.janino:janino` | 2.7.8 3.0.16 | 3.1.12 | `org/codehaus/janino/Compiler$2.getFile` |
| `org.codehaus.janino:janino` | 3.1.12 | 2.7.8 3.0.16 | `org/codehaus/janino/ClassBodyEvaluator.cook`<br>`org/codehaus/janino/Compiler$3.getFile`<br>`org/codehaus/janino/ExpressionEvaluator.cook`<br>`org/codehaus/janino/ScriptEvaluator.cook` |
| `org.eclipse.jetty:jetty-server` | 10.0.26 11.0.26 | 9.4.57.v20241219 12.0.41 | `org/eclipse/jetty/server/MultiPartFormInputStream$MultiPart.getSubmittedFileName`<br>`org/eclipse/jetty/server/MultiPartFormInputStream.delete`<br>`org/eclipse/jetty/server/MultiPartFormInputStream.getPart`<br>`org/eclipse/jetty/server/MultiPartFormInputStream.getParts`<br>and 8 more |
| `org.eclipse.jetty:jetty-server` | 12.0.41 | 9.4.57.v20241219 10.0.26 11.0.26 | `org/eclipse/jetty/server/internal/HttpChannelState.initialize` |
| `org.eclipse.jetty:jetty-server` | 9.4.57.v20241219 | 10.0.26 11.0.26 12.0.41 | `org/eclipse/jetty/server/Request.getPushBuilder`<br>`org/eclipse/jetty/server/Request.mergeQueryParameters` |
| `org.eclipse.jetty:jetty-server` | 9.4.57.v20241219 10.0.26 11.0.26 | 12.0.41 | `org/eclipse/jetty/server/MultiParts$MultiPartsHttpParser.getPart`<br>`org/eclipse/jetty/server/MultiParts$MultiPartsHttpParser.getParts`<br>`org/eclipse/jetty/server/MultiParts$MultiPartsHttpParser.setNonComplianceViolationsOnRequest`<br>`org/eclipse/jetty/server/MultiParts$MultiPartsUtilParser.getPart`<br>and 13 more |
| `org.elasticsearch:elasticsearch` | 8.19.23 | 7.17.29 | `org/elasticsearch/common/settings/LocallyMountedSecrets.getFile` |
| `org.mybatis:mybatis` | 3.4.6 3.5.6 3.5.19 3.6.0 | 3.2.8 | `org/apache/ibatis/executor/statement/BaseStatementHandler.prepare`<br>`org/apache/ibatis/executor/statement/SimpleStatementHandler.queryCursor` |
| `org.mybatis:mybatis` | 3.5.19 3.6.0 | 3.2.8 3.4.6 3.5.6 | `org/apache/ibatis/scripting/xmltags/TrimSqlNode$FilteredDynamicContext.lambda$applyPrefix$0`<br>`org/apache/ibatis/scripting/xmltags/TrimSqlNode$FilteredDynamicContext.lambda$applySuffix$1`<br>`org/apache/ibatis/scripting/xmltags/TrimSqlNode$FilteredDynamicContext.lambda$applySuffix$2` |
| `org.mybatis:mybatis` | 3.5.6 3.5.19 3.6.0 | 3.2.8 3.4.6 | `org/apache/ibatis/builder/SqlSourceBuilder.removeExtraWhitespaces` |
| `org.springframework:spring-beans` | 3.2.18.RELEASE 4.3.30.RELEASE | 5.3.39 6.2.19 7.1.0 | `org/springframework/beans/factory/support/AbstractAutowireCapableBeanFactory$8.run` |
| `org.springframework:spring-beans` | 5.3.39 | 3.2.18.RELEASE 4.3.30.RELEASE 6.2.19 7.1.0 | `org/springframework/beans/factory/support/AbstractAutowireCapableBeanFactory.lambda$invokeCustomInitMethod$7` |
| `org.springframework:spring-beans` | 6.2.19 7.1.0 | 3.2.18.RELEASE 4.3.30.RELEASE 5.3.39 | `org/springframework/beans/factory/support/AbstractBeanDefinition.setInitMethodNames` |
| `org.springframework:spring-test` | 4.3.30.RELEASE | 5.3.39 6.2.19 | `org/springframework/mock/web/MockHttpServletRequest.addParameters`<br>`org/springframework/mock/web/MockHttpServletRequest.getLocale`<br>`org/springframework/mock/web/MockHttpServletRequest.setParameters`<br>`org/springframework/mock/web/portlet/MockMultipartActionRequest.getFile`<br>and 2 more |
| `org.springframework:spring-test` | 5.3.39 | 4.3.30.RELEASE 6.2.19 | `org/springframework/test/web/client/match/ContentRequestMatchers$MultipartHelper.parse`<br>`org/springframework/test/web/client/match/ContentRequestMatchers.lambda$formData$5`<br>`org/springframework/test/web/client/match/ContentRequestMatchers.lambda$multipartData$6` |
| `org.springframework:spring-test` | 5.3.39 6.2.19 | 4.3.30.RELEASE | `org/springframework/mock/web/MockMultipartHttpServletRequest.getMultipartHeaders`<br>`org/springframework/test/web/servlet/client/MockMvcHttpConnector.adaptRequest`<br>`org/springframework/test/web/servlet/client/MockMvcHttpConnector.adaptResponse` |
| `org.springframework:spring-test` | 6.2.19 | 4.3.30.RELEASE 5.3.39 | `org/springframework/mock/web/MockHttpServletRequest.startAsync` |
| `org.springframework:spring-web` | 3.2.18.RELEASE | 4.3.30.RELEASE 5.3.39 6.2.19 7.1.0 | `org/springframework/web/bind/WebDataBinder.bindMultipartFiles` |
| `org.springframework:spring-web` | 3.2.18.RELEASE 4.3.30.RELEASE | 5.3.39 6.2.19 7.1.0 | `org/springframework/web/bind/WebDataBinder.bindMultipart`<br>`org/springframework/web/bind/annotation/support/HandlerMethodInvoker.initBinder`<br>`org/springframework/web/bind/annotation/support/HandlerMethodInvoker.invokeHandlerMethod`<br>`org/springframework/web/bind/annotation/support/HandlerMethodInvoker.resolveRequestHeaderMap`<br>and 3 more |
| `org.springframework:spring-web` | 3.2.18.RELEASE 4.3.30.RELEASE 5.3.39 | 6.2.19 7.1.0 | `org/springframework/web/multipart/commons/CommonsFileUploadSupport.cleanupFileItems`<br>`org/springframework/web/multipart/commons/CommonsFileUploadSupport.parseFileItems`<br>`org/springframework/web/multipart/commons/CommonsMultipartFile.getOriginalFilename` |
| `org.springframework:spring-web` | 4.3.30.RELEASE | 3.2.18.RELEASE 5.3.39 6.2.19 7.1.0 | `org/springframework/web/bind/support/WebRequestDataBinder$Servlet3MultipartHelper.bindParts`<br>`org/springframework/web/multipart/support/MultipartResolutionDelegate$RequestPartResolver.resolvePartArray`<br>`org/springframework/web/multipart/support/MultipartResolutionDelegate$RequestPartResolver.resolvePartList` |
| `org.springframework:spring-web` | 4.3.30.RELEASE 5.3.39 6.2.19 7.1.0 | 3.2.18.RELEASE | `org/springframework/web/method/annotation/RequestParamMethodArgumentResolver.contributeMethodArgument` |
| `org.springframework:spring-web` | 5.3.39 | 3.2.18.RELEASE 4.3.30.RELEASE 6.2.19 7.1.0 | `org/springframework/web/method/annotation/ModelAttributeMethodProcessor.resolveConstructorArgument`<br>`org/springframework/web/method/annotation/ModelAttributeMethodProcessor.validateValueIfApplicable` |
| `org.springframework:spring-web` | 5.3.39 6.2.19 7.1.0 | 3.2.18.RELEASE 4.3.30.RELEASE | `org/springframework/web/bind/WebDataBinder.lambda$bindMultipart$0`<br>`org/springframework/web/method/annotation/RequestParamMapMethodArgumentResolver.resolveArgument`<br>`org/springframework/web/multipart/support/MultipartResolutionDelegate.resolvePartList`<br>`org/springframework/web/multipart/support/StandardServletPartUtils.getParts`<br>and 1 more |
| `org.springframework:spring-web` | 6.2.19 7.1.0 | 3.2.18.RELEASE 4.3.30.RELEASE 5.3.39 | `org/springframework/web/bind/ServletRequestDataBinder$ServletRequestValueResolver.getMultipartValue` |
| `org.springframework:spring-web` | 7.1.0 | 3.2.18.RELEASE 4.3.30.RELEASE 5.3.39 6.2.19 | `org/springframework/http/converter/multipart/MultipartHttpMessageConverter.applyDefaultCharset`<br>`org/springframework/http/converter/multipart/MultipartHttpMessageConverter.canWrite`<br>`org/springframework/http/converter/multipart/MultipartHttpMessageConverter.findConverterFor`<br>`org/springframework/http/converter/multipart/MultipartHttpMessageConverter.supportsMediaType`<br>and 3 more |
