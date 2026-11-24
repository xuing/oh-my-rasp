package io.ohmyrasp.agent.sql;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

  private static StackTraceElement frame(String owner, String method) {
    return new StackTraceElement(owner, method, null, -1);
  }
}
