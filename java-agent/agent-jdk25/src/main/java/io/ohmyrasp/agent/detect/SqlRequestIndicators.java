package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;
import io.ohmyrasp.agent.detect.RequestJson.JsonStringField;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Request-field observations selected by explicit SQL metadata policy. */
final class SqlRequestIndicators {
  private SqlRequestIndicators() {}

  private static final Pattern SQL_POLICY =
      Pattern.compile(
          "(?is)(?:\\bunion\\s+(?:all\\s+)?select\\b|\\binformation_schema\\b|\\binto\\s+(?:out|dump)file\\b|/\\*!|\\bload_file\\s*\\(|\\bsleep\\s*\\(|\\bbenchmark\\s*\\()");

  private static final Pattern SQL_SORT_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:api|case|cases|list|lists|page|pages|query|search|table|track)(?:[;/]|/|$)");

  private static final Pattern SQL_SORT_CONTEXT_BODY =
      Pattern.compile("(?is)\"(?:orders?|sort(?:ers?)?|pageable|pagination)\"\\s*:");

  private static final Pattern SQL_SORT_INJECTION_VALUE =
      Pattern.compile(
          "(?is)(?:^|[,;])\\s*(?:if\\s*\\(|case\\s+when|select\\b|sleep\\s*\\(|benchmark\\s*\\(|extractvalue\\s*\\(|updatexml\\s*\\(|load_file\\s*\\()|(?:--|#|/\\*)");

  private static final Pattern SQL_IDENTIFIER_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:graphql|api|query|queries|metrics?|logs?|trace|traces|search|table|tables)(?:[;/]|/|$)");

  private static final Pattern SQL_IDENTIFIER_CONTEXT_BODY =
      Pattern.compile(
          "(?is)\"(?:query|variables|condition|metricname|tablename|columnname|fieldname|metric|table|column|dimension)\"\\s*:");

  private static final Pattern SAFE_SQL_IDENTIFIER_VALUE =
      Pattern.compile("(?is)^[A-Za-z0-9_.$:-]{1,128}$");

  private static final Pattern SQL_IDENTIFIER_INJECTION_VALUE =
      Pattern.compile(
          "(?is)(?:\\b(?:where|union|select|join|sleep|benchmark|case\\s+when)\\b|\\binformation_schema\\b|(?:--|#|/\\*|;))");

  private static final Set<String> SQL_SORT_INJECTION_FIELD_NAMES =
      Set.of(
          "direction",
          "dir",
          "order",
          "orderby",
          "ordertype",
          "sort",
          "sortby",
          "sortdirection",
          "sortorder",
          "sorttype",
          "type");

  private static final Set<String> SQL_IDENTIFIER_INJECTION_FIELD_NAMES =
      Set.of(
          "column",
          "columnname",
          "dimension",
          "dimensionname",
          "entity",
          "entityname",
          "field",
          "fieldname",
          "metric",
          "metricname",
          "table",
          "tablename");

  private record SqlSortInjectionMatch(String field, int valueLength) {}

  private record SqlIdentifierInjectionMatch(String field, int valueLength) {}

  static List<Detection> sqlRequestMetadata(RequestContext request, java.util.function.Predicate<String> selected) {
    List<Detection> candidates = new ArrayList<>();
    if (selected.test("request_sql_sort_injection")) {
      sqlSortInjection(request).ifPresent(match -> candidates.add(sqlMetadataFinding(request,
          "request_sql_sort_injection", match.field(), match.valueLength())));
    }
    if (selected.test("request_sql_identifier_injection")) {
      sqlIdentifierInjection(request).ifPresent(match -> candidates.add(sqlMetadataFinding(request,
          "request_sql_identifier_injection", match.field(), match.valueLength())));
    }
    return candidates;
  }

  private static Detection sqlMetadataFinding(RequestContext request, String algorithm, String field, int length) {
    return Detection.log("request", algorithm, 90, "A request field contains SQL-like text",
        new RequestContext(request.method(), request.uri(), "", Map.of(), Map.of()),
        Map.of("field", field, "valueLength", String.valueOf(length), "decision_basis", "request_metadata"));
  }

  private static Optional<SqlSortInjectionMatch> sqlSortInjection(RequestContext request) {
    if (request == null
        || !request.active()
        || !jsonConfigBody(request)
        || !sqlSortContext(request)) {
      return Optional.empty();
    }
    for (JsonStringField field : jsonStringFields(request.body())) {
      if (isSqlSortInjectionField(field.name()) && dangerousSqlSortValue(field.value())) {
        return Optional.of(new SqlSortInjectionMatch(field.name(), field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static boolean sqlSortContext(RequestContext request) {
    if (!SQL_SORT_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find()) {
      return false;
    }
    return SQL_SORT_CONTEXT_BODY.matcher(request.body()).find();
  }

  private static boolean isSqlSortInjectionField(String name) {
    return SQL_SORT_INJECTION_FIELD_NAMES.contains(normalizeParameterName(name));
  }

  private static boolean dangerousSqlSortValue(String value) {
    if (value == null || value.isBlank() || value.length() > 512) {
      return false;
    }
    String decoded = percentDecode(value).trim();
    String normalized = lower(decoded);
    if (normalized.equals("asc")
        || normalized.equals("desc")
        || normalized.equals("ascending")
        || normalized.equals("descending")) {
      return false;
    }
    return SQL_SORT_INJECTION_VALUE.matcher(decoded).find()
        || SQL_POLICY.matcher(decoded).find();
  }

  private static Optional<SqlIdentifierInjectionMatch> sqlIdentifierInjection(
      RequestContext request) {
    if (request == null
        || !request.active()
        || !jsonConfigBody(request)
        || !sqlIdentifierContext(request)) {
      return Optional.empty();
    }
    for (JsonStringField field : jsonStringFields(request.body())) {
      if (isSqlIdentifierInjectionField(field.name())
          && dangerousSqlIdentifierValue(field.value())) {
        return Optional.of(
            new SqlIdentifierInjectionMatch(field.name(), field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static boolean sqlIdentifierContext(RequestContext request) {
    if (!SQL_IDENTIFIER_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find()) {
      return false;
    }
    String body = request.body();
    boolean graphqlBody =
        body.contains("\"query\"")
            && body.contains("\"variables\"")
            && lower(body).contains("graphql");
    return graphqlBody || SQL_IDENTIFIER_CONTEXT_BODY.matcher(body).find();
  }

  private static boolean isSqlIdentifierInjectionField(String name) {
    return SQL_IDENTIFIER_INJECTION_FIELD_NAMES.contains(normalizeParameterName(name));
  }

  private static boolean dangerousSqlIdentifierValue(String value) {
    if (value == null || value.isBlank() || value.length() > 512) {
      return false;
    }
    String decoded = percentDecode(value).trim();
    if (SAFE_SQL_IDENTIFIER_VALUE.matcher(decoded).matches()) {
      return false;
    }
    return SQL_IDENTIFIER_INJECTION_VALUE.matcher(decoded).find()
        || SQL_POLICY.matcher(decoded).find();
  }
}
