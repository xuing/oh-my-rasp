package io.ohmyrasp.agent.sql;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.BitSet;
import java.util.List;
import org.junit.jupiter.api.Test;

class SqlStatementTest {
  @Test
  void distinguishesDirectConsoleExecutionFromNestedApplicationCode() {
    var editor = frame("org.h2.server.web.WebApp", "getResult");
    var jdbc = frame("org.h2.jdbc.JdbcStatement", "execute");
    var hook = frame("io.ohmyrasp.agent.hook.OhMyRaspHooks", "beforeSql");
    assertTrue(SqlStatement.directH2ConsoleCaller(new StackTraceElement[] {hook, jdbc, editor}));
    assertTrue(SqlStatement.directH2ConsoleCaller(new StackTraceElement[] {hook, editor}));
    var prepare = frame("org.h2.jdbc.JdbcConnection", "prepareCommand");
    var internal = frame("org.h2.jdbc.JdbcStatement", "executeInternal");
    assertTrue(SqlStatement.directH2ConsoleCaller(new StackTraceElement[] {hook, prepare, internal, jdbc, editor}));
    assertFalse(SqlStatement.directH2ConsoleCaller(new StackTraceElement[] {
        hook, prepare, frame("app.Report", "run"), internal, jdbc, editor}));
    var backport = frame("io.ohmyrasp.agent.java8.Java8RaspHooks", "beforeSqlStatement");
    assertTrue(SqlStatement.directH2ConsoleCaller(new StackTraceElement[] {backport, jdbc, editor}));
    assertFalse(SqlStatement.directH2ConsoleCaller(new StackTraceElement[] {
        hook, jdbc, frame("app.Report", "run"), jdbc, editor}));
    assertFalse(SqlStatement.directH2ConsoleCaller(new StackTraceElement[] {
        hook, jdbc, frame("app.WebApp", "getResult")}));
    assertFalse(SqlStatement.directH2ConsoleCaller(new StackTraceElement[] {
        hook, jdbc, frame("org.h2.server.web.WebApp", "query")}));
  }

  @Test
  void requiresEvidenceForBooleanComparisons() {
    SqlStatement query = new SqlStatement("select id from orders where state='OPEN' and 1=1");
    assertFalse(query.hasConstantDisjunction());
    assertFalse(query.matchesStructureFrom("OPEN"));
    assertTrue(query.matchesStructureFrom("and 1=1"));
    assertFalse(new SqlStatement("select id from orders where id=42 and 1=1").matchesStructureFrom("and 1=1"));
    assertFalse(new SqlStatement("select id from orders where state='OPEN' or 1=1.5").hasConstantDisjunction());
    assertFalse(new SqlStatement("select id from orders where state='OPEN' or 1=1+3").hasConstantDisjunction());
    assertTrue(new SqlStatement("select id from orders where state='OPEN' or 42=42").hasConstantDisjunction());
  }

  @Test
  void treatsMatchedDollarDelimitersAsDataForKnownDriversOnly() {
    String example = "select $$manual: sleep(2)$$ as excerpt";
    assertFalse(new SqlStatement(example, "org.h2.jdbc.JdbcStatement").matchesSinkPolicy());
    assertFalse(new SqlStatement(example, "org.postgresql.jdbc.PgStatement").matchesSinkPolicy());
    assertTrue(new SqlStatement(example, "com.mysql.cj.jdbc.StatementImpl").matchesSinkPolicy());
    assertTrue(new SqlStatement("select $$manual$$, sleep(2)", "org.h2.jdbc.JdbcStatement").matchesSinkPolicy());
  }

  @Test
  void recognizesTaggedDataAndNestedCommentsInPostgresql() {
    String driver = "org.postgresql.jdbc.PgStatement";
    String text = "select $Guide_2$Inner $Other$ sleep(1); -- words $Guide_2$";
    assertFalse(new SqlStatement(text, driver).matchesSinkPolicy());
    assertTrue(new SqlStatement(text + ", sleep(1)", driver).matchesSinkPolicy());
    assertTrue(new SqlStatement(text, "com.mysql.cj.jdbc.StatementImpl").matchesSinkPolicy());
    assertFalse(new SqlStatement("/* outer /* note */ sleep(1) */ select 1", driver).matchesSinkPolicy());
    assertFalse(new SqlStatement("/*! sleep(1) */ select 1", driver).matchesSinkPolicy());
    assertTrue(new SqlStatement("/*! sleep(1) */ select 1", "com.mysql.cj.jdbc.StatementImpl").matchesSinkPolicy());
    assertFalse(new SqlStatement("select E'example\\' sleep(1)'", driver).matchesSinkPolicy());
  }

  @Test
  void mysqlLineCommentsFollowTheDriverGrammar() {
    for (String mysql : List.of("com.mysql.cj.jdbc.StatementImpl", "org.mariadb.jdbc.MariaDbStatement")) {
      assertFalse(new SqlStatement("select 7 # statistic: benchmark(0,1)", mysql).matchesSinkPolicy());
      assertFalse(new SqlStatement("select 7 -- report\r benchmark(0,1)", mysql).matchesSinkPolicy());
      assertTrue(new SqlStatement("select 7 # reviewer's note\r\n, benchmark(0,1)", mysql).matchesSinkPolicy());
      assertFalse(new SqlStatement("select 9--2", mysql).hasCommentFrom("--2"));
      assertFalse(new SqlStatement("select 9--- weekly benchmark(0,1)", mysql).matchesSinkPolicy());
      assertTrue(new SqlStatement("select '#literal', benchmark(0,1)", mysql).matchesSinkPolicy());
      assertFalse(new SqlStatement("select '7' # 'note -- text'", mysql).hasTruncatedLiteral());
      assertFalse(new SqlStatement("select '7' # 'note -- text'", mysql).hasCommentFrom("# 'note -- text'"));
      String prefix = "select '", supplied = "weekly' #";
      BitSet marks = new BitSet();
      marks.set(prefix.length(), prefix.length() + supplied.length());
      assertEquals("quoted-slot-comment", new SqlStatement(prefix + supplied + "'", mysql).mapperControl(marks));
    }
    assertFalse(new SqlStatement("select 7 # benchmark(0,1)", "example.ReportPool").matchesSinkPolicy());
    assertFalse(new SqlStatement("select 9--2", "example.ReportPool").hasCommentFrom("--2"));
    assertFalse(new SqlStatement("select 7 -- report\r benchmark(0,1)", "example.ReportPool").matchesSinkPolicy());
    assertTrue(new SqlStatement("select 7 -- report\n, benchmark(0,1)", "example.ReportPool").matchesSinkPolicy());
    assertTrue(new SqlStatement("select 7 # benchmark(0,1)", "org.postgresql.jdbc.PgStatement").matchesSinkPolicy());
    assertTrue(new SqlStatement("select 1 from #reports where benchmark(0,1)=0",
        "com.microsoft.sqlserver.jdbc.SQLServerStatement").matchesSinkPolicy());
  }

  @Test
  void bracketIdentifiersFollowTheJdbcDialect() {
    String sqlite = "org.sqlite.jdbc4.JDBC4Statement";
    String sqlServer = "com.microsoft.sqlserver.jdbc.SQLServerStatement";
    String wrapper = "example.ReportConnection";
    for (String driver : List.of(sqlite, sqlServer, wrapper)) {
      assertFalse(new SqlStatement("select 7 as [weekly benchmark(7)]", driver).matchesSinkPolicy());
      assertFalse(new SqlStatement("select 7 as [weekly -- total]", driver).hasCommentFrom("-- total"));
      assertTrue(new SqlStatement("select 7 as [weekly], benchmark(7)", driver).matchesSinkPolicy());
    }
    assertFalse(new SqlStatement("select 7 as [benchmark(7)]").matchesSinkPolicy());
    assertTrue(new SqlStatement("select 7 as [weekly], benchmark(7)").matchesSinkPolicy());
    String escaped = "select 7 as [weekly]] benchmark(7)]";
    assertFalse(new SqlStatement(escaped, sqlServer).matchesSinkPolicy());
    assertFalse(new SqlStatement(escaped, wrapper).matchesSinkPolicy());
    // SQLite's first closing bracket terminates the token.
    assertTrue(new SqlStatement(escaped, sqlite).matchesSinkPolicy());
    assertTrue(new SqlStatement("select 7 as [reviewer's note], benchmark(7)", sqlite).matchesSinkPolicy());
    assertTrue(new SqlStatement("select metrics[benchmark(7)]", "org.postgresql.jdbc.PgStatement").matchesSinkPolicy());
    BitSet input = new BitSet();
    String query = "select 7 order by [benchmark(7)]";
    input.set(query.indexOf("benchmark"), query.indexOf(']'));
    assertNull(new SqlStatement(query, sqlite).mapperControl(input));
    String prefix = "select 7 as [";
    String label = "weekly] -- label";
    BitSet substituted = new BitSet();
    substituted.set(prefix.length(), prefix.length() + label.length());
    assertEquals("quoted-slot-comment", new SqlStatement(prefix + label + "]", sqlite).mapperControl(substituted));
    assertNull(new SqlStatement(prefix + label + "]", wrapper).mapperControl(substituted));

  }

  @Test
  void requiresMapperOffsetsInExecutableSql() {
    assertNull(mapperDecision("select '", "O''Brien -- weekly", "'"));
    assertEquals("quoted-slot-comment", mapperDecision("select '", "label' -- note", "'"));
    assertNull(mapperDecision("select id from reports order by id limit 1; select '", "sleep(0)", "'"));
    assertEquals("sort-policy-operation", mapperDecision("select id from reports order /* rank */ by id ", ",sleep(0)", ""));
    assertEquals("additional-statement", mapperDecision("select 1 ", "; select 7", ""));
    assertNull(mapperDecision("", "select 1; select 7", ""));
    // A later unambiguous boundary remains visible when the first marker's
    // comment meaning differs across the two MySQL parsing modes.
    assertEquals("additional-statement", mapperDecision("select 1 ", "--note\n; select 7", ""));
  }

  private static String mapperDecision(String prefix, String value, String suffix) {
    BitSet supplied = new BitSet();
    supplied.set(prefix.length(), prefix.length() + value.length());
    return new SqlStatement(prefix + value + suffix).mapperControl(supplied);
  }

  private static StackTraceElement frame(String owner, String method) {
    return new StackTraceElement(owner, method, null, -1);
  }
}
