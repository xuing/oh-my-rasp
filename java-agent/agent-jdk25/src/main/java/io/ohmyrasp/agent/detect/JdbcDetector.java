package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;
import io.ohmyrasp.agent.detect.RequestJson.JsonStringField;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.sql.MysqlDeserializationUrl;
import io.ohmyrasp.agent.sql.SqlStatement;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Classify JDBC statements, connection options and database error signals. */
public final class JdbcDetector {
  private JdbcDetector() {}

  private static final Pattern H2_CODE_CONTAINER =
      Pattern.compile("(?is)\\bcreate\\s+(?:alias|trigger)\\b");

  private static final Pattern H2_CODE_PRIMITIVE =
      Pattern.compile(
          "(?is)(?:java\\.lang\\.runtime|runtime\\s*\\.\\s*getruntime\\s*\\(|processbuilder|scriptenginemanager|javax\\.naming\\.initialcontext|urlclassloader|//\\s*javascript)");

  private static final Pattern H2_REMOTE_RUNSCRIPT =
      Pattern.compile("(?is)\\brunscript\\s+from\\s+['\"]?\\s*(?:https?|ftp|jar|ldap|rmi)://");

  private static final Pattern H2_INIT_SETTING = Pattern.compile("(?is)(?:^|;)\\s*init\\s*=");

  private static final Pattern DERBY_JAR_OPERATION =
      Pattern.compile("(?is)(?:\\bsqlj\\s*\\.\\s*(?:install|replace)_jar\\s*\\(|"
          + "\\bsyscs_util\\s*\\.\\s*syscs_set_database_property\\s*\\(\\s*['\"]derby\\.database\\.classpath['\"])");

  private static final Pattern DERBY_ROUTINE_LANGUAGE =
      Pattern.compile("(?i)\\b(?:language\\s+java|parameter\\s+style\\s+java)\\b");

  private static final Pattern DERBY_EXTERNAL_NAME = Pattern.compile("(?i)\\bexternal\\s+name\\b");

  public static Optional<Detection> detectSql(String query, RequestContext request) {
    return detectSql(query, request, null);
  }

  static Optional<Detection> detectSql(String query, RequestContext request, String jdbcClass) {
    if (query == null || query.isBlank()) {
      return Optional.empty();
    }
    return classifySql(new SqlStatement(query, jdbcClass), request);
  }

  public static Optional<Detection> detectSql(String query, RequestContext request, Object jdbcReceiver) {
    if (query == null || query.isBlank()) return Optional.empty();
    return classifySql(SqlStatement.fromJdbc(query, jdbcReceiver), request);
  }

  private static Optional<Detection> classifySql(SqlStatement statement, RequestContext request) {
    String query = statement.source();
    if (request.inputParameters().values().stream().flatMap(List::stream)
            .anyMatch(value -> statement.hasCommentFrom(value) || statement.matchesStructureFrom(value))
        || requestBodyControlsSql(statement, request)) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_userinput",
              95,
              "SQL query structure appears altered by request input",
              request,
              Map.of("query", abbreviate(query))));
    }
    if (statement.hasCommand(H2_REMOTE_RUNSCRIPT)
        || statement.definesSourceMatching(H2_CODE_CONTAINER, H2_CODE_PRIMITIVE)) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_h2_code_execution",
              95,
              "H2 SQL attempts to load script or executable Java code",
              request,
              Map.of("query", abbreviate(query))));
    }
    if (request.active() && (statement.matches(DERBY_JAR_OPERATION)
        || statement.hasClausesInOneCommand(DERBY_ROUTINE_LANGUAGE, DERBY_EXTERNAL_NAME))) {
      boolean requestControlled = request.hasParameterIn(query);
      return Optional.of(
          Detection.log(
              "sql",
              "sql_derby_code_execution",
              requestControlled ? 95 : 90,
              "Derby SQL attempts to load Java code or mutate the database classpath",
              request,
              Map.of(
                  "query", abbreviate(query),
                  "requestControlled", String.valueOf(requestControlled))));
    }
    boolean structuralSqlInjection = statement.hasTruncatedLiteral()
        || (statement.hasConstantDisjunction() && request.inputParameters().values().stream()
            .flatMap(List::stream).noneMatch(statement::isSubmittedConsoleSelect));
    if (structuralSqlInjection || statement.matchesSinkPolicy()) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_policy",
              structuralSqlInjection ? 90 : 85,
              "SQL query matched injection policy features",
              request,
              Map.of("query", abbreviate(query))));
    }
    return Optional.empty();
  }

  private static boolean requestBodyControlsSql(SqlStatement statement, RequestContext request) {
    String body = request.body();
    if (body.isEmpty() || !SqlStatement.mayControlStructure(body)) {
      return false;
    }
    if (!jsonConfigBody(request)) {
      return statement.matchesStructureFrom(body);
    }
    for (JsonStringField field : jsonStringFields(body)) {
      if (statement.matchesStructureFrom(field.value())) {
        return true;
      }
    }
    return false;
  }

  public static Optional<Detection> detectJdbcUrl(String url, RequestContext request) {
    if (url == null || url.isBlank()) {
      return Optional.empty();
    }
    String normalized = lower(url);
    if (normalized.startsWith("jdbc:h2:")
        && H2_INIT_SETTING.matcher(url).find()
        && h2DangerousSql(url)) {
      return Optional.of(
          Detection.log(
              "jdbc",
              "jdbc_h2_init",
              95,
              "H2 JDBC URL uses INIT to load script or executable Java code",
              request,
              Map.of("url", abbreviate(url))));
    }
    String trigger = MysqlDeserializationUrl.trigger(url);
    if (trigger != null) {
      // Decided whoever chose the URL, with the backports' rule (MysqlDeserializationUrl); a request that carries it
      // raises the confidence. The event names the driver, the host and the options, never the URL: a pool's URL can
      // hold the database password.
      boolean requestControlled = request.active() && request.hasParameterIn(url);
      return Optional.of(
          Detection.log(
              "jdbc",
              "jdbc_mysql_deserialization",
              requestControlled ? 95 : 92,
              requestControlled
                  ? "Request-controlled MySQL JDBC URL enables connector deserialization behavior"
                  : "MySQL JDBC URL enables connector deserialization behavior",
              request,
              Map.of("driver", MysqlDeserializationUrl.driver(url), "host", MysqlDeserializationUrl.host(url),
                  "options", trigger)));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectSqlException(
      String server,
      String errorCode,
      String errorState,
      String errorMessage,
      String query,
      RequestContext request) {
    String normalizedServer = lower(server);
    String normalizedCode = errorCode == null ? "" : errorCode.trim();
    String normalizedState = errorState == null ? "" : errorState.trim().toUpperCase(Locale.ROOT);
    String normalizedMessage = lower(errorMessage);
    String normalizedQuery = query == null ? "" : query;
    if (!isSqlExceptionSignal(
        normalizedServer, normalizedCode, normalizedState, normalizedMessage, normalizedQuery)) {
      return Optional.empty();
    }
    return Optional.of(
        Detection.log(
            "sql_exception",
            "sql_exception",
            70,
            "Database error signal detected: " + normalizedServer + " " + normalizedCode,
            request,
        Map.of(
                "server", normalizedServer,
                "errorCode", normalizedCode,
                "errorState", normalizedState,
                "message", abbreviate(errorMessage),
                "query", abbreviate(query))));
  }

  public static Optional<Detection> detectSqlRegex(
      String query, String regex, RequestContext request) {
    if (query == null || query.isBlank() || regex == null || regex.isBlank()) {
      return Optional.empty();
    }
    if (Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(query).find()) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_regex",
              60,
              "SQL query matched configured regex",
              request,
              Map.of("query", abbreviate(query), "regex", regex)));
    }
    return Optional.empty();
  }

  private static boolean isSqlExceptionSignal(
      String server, String code, String state, String message, String query) {
    return switch (server) {
      case "mysql" -> {
        if (code.equals("1062")) {
          yield query != null && Pattern.compile("(?i)rand").matcher(query).find();
        }
        if (code.equals("1064")) {
          yield Pattern.compile("(?i)syntax").matcher(message).find()
              && !Pattern.compile("(?i)in\\s*(\\(\\s*\\)|[^\\(\\w])").matcher(query).find();
        }
        yield Set.of("1060", "1105", "1367").contains(code);
      }
      case "pgsql" -> Set.of("42601", "22P02").contains(code) || Set.of("42601", "22P02").contains(state);
      case "sqlite" -> code.equals("1")
          && (message.contains("syntax") || message.contains("malformed match"));
      case "oracle" -> Set.of("933", "29257", "20000", "904", "19202", "1756", "1740", "920", "907", "911")
          .contains(code);
      case "hsql" -> Set.of("-5583", "-5584", "-5590").contains(code)
          || Set.of("42583", "42584", "42590").contains(state);
      case "mssql" -> Set.of("105", "245").contains(code);
      case "db2" -> state.equals("42603");
      default -> false;
    };
  }

  private static boolean h2DangerousSql(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    return H2_REMOTE_RUNSCRIPT.matcher(value).find()
        || (H2_CODE_CONTAINER.matcher(value).find() && H2_CODE_PRIMITIVE.matcher(value).find());
  }


  static boolean h2JdbcInitConfig(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    return lower(value).contains("jdbc:h2:")
        && H2_INIT_SETTING.matcher(value).find()
        && h2DangerousSql(value);
  }
}
