package io.ohmyrasp.agent.policy;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class PolicyRule {
  private final String id;
  private final String name;
  private final String hook;
  private final String algorithm;
  private final String action;
  private final String severity;
  private final String expression;
  private final List<PolicyCondition> conditions;

  private PolicyRule(
      String id,
      String name,
      String hook,
      String algorithm,
      String action,
      String severity,
      String expression,
      List<PolicyCondition> conditions) {
    this.id = value(id);
    this.name = value(name);
    this.hook = normalize(hook);
    this.algorithm = normalize(algorithm);
    this.action = normalizeAction(action);
    this.severity = normalize(severity);
    this.expression = value(expression);
    this.conditions = List.copyOf(conditions);
  }

  static Optional<PolicyRule> fromMap(Map<?, ?> object) {
    String expression = stringField(object, "expression");
    List<PolicyCondition> conditions;
    try {
      conditions = PolicyCondition.compile(expression);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    return Optional.of(
        new PolicyRule(
            stringField(object, "id"),
            stringField(object, "name"),
            stringField(object, "hook"),
            stringField(object, "algorithm"),
            stringField(object, "action"),
            stringField(object, "severity"),
            expression,
            conditions));
  }

  public String id() {
    return id;
  }

  public String name() {
    return name;
  }

  public String hook() {
    return hook;
  }

  public String algorithm() {
    return algorithm;
  }

  public String action() {
    return action;
  }

  public String severity() {
    return severity;
  }

  public String expression() {
    return expression;
  }

  boolean matches(Detection detection) {
    if (!hook.isBlank() && !hook.equals(normalize(detection.hook()))) {
      return false;
    }
    if (!algorithm.isBlank() && !algorithm.equals(normalize(detection.algorithm()))) {
      return false;
    }
    if (conditions.isEmpty()) {
      return true;
    }
    for (PolicyCondition condition : conditions) {
      if (!condition.matches(detection)) {
        return false;
      }
    }
    return true;
  }

  private static String normalizeAction(String action) {
    String normalized = normalize(action);
    if ("block".equals(normalized) || "ignore".equals(normalized)) {
      return normalized;
    }
    return "log";
  }

  private static String normalize(String value) {
    return value(value).toLowerCase(Locale.ROOT);
  }

  private static String value(String value) {
    return value == null ? "" : value.trim();
  }

  private static String stringField(Map<?, ?> object, String name) {
    Object value = object.get(name);
    return value == null ? "" : String.valueOf(value);
  }

  private record PolicyCondition(String field, String operator, String value, Pattern regex) {
    private static final Pattern CONDITION_PATTERN =
        Pattern.compile(
            "^\\s*([a-zA-Z0-9_.-]+)\\s*(==|!=|contains|matches)\\s*(.+?)\\s*$",
            Pattern.CASE_INSENSITIVE);

    static List<PolicyCondition> compile(String expression) {
      if (expression == null || expression.isBlank()) {
        return List.of();
      }
      List<PolicyCondition> conditions = new ArrayList<>();
      for (String part : splitAnd(expression)) {
        String trimmed = part.trim();
        if (trimmed.isBlank()) {
          continue;
        }
        var matcher = CONDITION_PATTERN.matcher(trimmed);
        String field;
        String operator;
        String rawValue;
        if (matcher.matches()) {
          field = matcher.group(1).toLowerCase(Locale.ROOT);
          operator = matcher.group(2).toLowerCase(Locale.ROOT);
          rawValue = matcher.group(3);
        } else {
          field = "any";
          operator = "contains";
          rawValue = trimmed;
        }
        String value = unquote(rawValue);
        Pattern regex = null;
        if ("matches".equals(operator)) {
          try {
            regex = Pattern.compile(value);
          } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("invalid policy regex", e);
          }
        }
        conditions.add(new PolicyCondition(field, operator, value, regex));
      }
      return conditions;
    }

    boolean matches(Detection detection) {
      List<String> values = valuesFor(detection, field);
      return switch (operator) {
        case "==" -> any(values, item -> item.equalsIgnoreCase(value));
        case "!=" -> !any(values, item -> item.equalsIgnoreCase(value));
        case "matches" -> any(values, item -> regex.matcher(item).find());
        default -> {
          String needle = value.toLowerCase(Locale.ROOT);
          yield any(values, item -> item.toLowerCase(Locale.ROOT).contains(needle));
        }
      };
    }

    private static List<String> valuesFor(Detection detection, String field) {
      List<String> values = new ArrayList<>();
      RequestContext request = detection.request() == null ? RequestContext.empty() : detection.request();
      switch (field) {
        case "any" -> {
          values.add(detection.message());
          values.add(detection.hook());
          values.add(detection.algorithm());
          values.add(severity(detection.confidence()));
          detection.details().forEach(
              (key, value) -> {
                values.add(key);
                values.add(value);
              });
          values.add(request.method());
          values.add(request.uri());
          values.add(request.query());
          request.headers().forEach(
              (key, value) -> {
                values.add(key);
                values.add(value);
              });
          request.parameters().forEach(
              (key, items) -> {
                values.add(key);
                values.addAll(items);
              });
        }
        case "message", "event.message" -> values.add(detection.message());
        case "hook", "event.hook" -> values.add(detection.hook());
        case "algorithm", "event.algorithm" -> values.add(detection.algorithm());
        case "severity", "event.severity" -> values.add(severity(detection.confidence()));
        default -> values.addAll(attributeValues(detection, request, field));
      }
      values.removeIf(item -> item == null || item.isBlank());
      return values;
    }

    private static List<String> attributeValues(
        Detection detection, RequestContext request, String field) {
      String key = field;
      key = stripPrefix(key, "attributes.");
      key = stripPrefix(key, "event.attributes.");
      key = stripPrefix(key, "detail.");
      List<String> values = new ArrayList<>();
      String detail = detection.details().get(key);
      if (detail != null) {
        values.add(detail);
      }
      if (field.equals("request.method") || key.equals("request.method")) {
        values.add(request.method());
      } else if (field.equals("request.uri") || key.equals("request.uri")) {
        values.add(request.uri());
      } else if (field.equals("request.query") || key.equals("request.query")) {
        values.add(request.query());
      } else if (key.startsWith("request.header.")) {
        values.add(request.headers().get(stripPrefix(key, "request.header.")));
      } else if (key.startsWith("request.parameter.")) {
        values.addAll(request.parameters().getOrDefault(stripPrefix(key, "request.parameter."), List.of()));
      }
      return values;
    }

    private static List<String> splitAnd(String expression) {
      List<String> parts = new ArrayList<>();
      StringBuilder current = new StringBuilder();
      boolean quoted = false;
      char quote = 0;
      for (int i = 0; i < expression.length(); i++) {
        char ch = expression.charAt(i);
        if ((ch == '\'' || ch == '"') && (i == 0 || expression.charAt(i - 1) != '\\')) {
          if (quoted && quote == ch) {
            quoted = false;
          } else if (!quoted) {
            quoted = true;
            quote = ch;
          }
        }
        if (!quoted && ch == '&' && i + 1 < expression.length() && expression.charAt(i + 1) == '&') {
          parts.add(current.toString());
          current.setLength(0);
          i++;
          continue;
        }
        current.append(ch);
      }
      parts.add(current.toString());
      return parts;
    }

    private static String stripPrefix(String value, String prefix) {
      return value.startsWith(prefix) ? value.substring(prefix.length()) : value;
    }

    private static String unquote(String value) {
      String trimmed = value == null ? "" : value.trim();
      if (trimmed.length() >= 2) {
        char first = trimmed.charAt(0);
        char last = trimmed.charAt(trimmed.length() - 1);
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
          return trimmed.substring(1, trimmed.length() - 1);
        }
      }
      return trimmed;
    }

    private static String severity(int confidence) {
      if (confidence >= 90) {
        return "critical";
      }
      if (confidence >= 75) {
        return "high";
      }
      if (confidence >= 50) {
        return "medium";
      }
      return "low";
    }

    private static boolean any(List<String> values, Matcher matcher) {
      for (String item : values) {
        if (matcher.matches(item)) {
          return true;
        }
      }
      return false;
    }
  }

  @FunctionalInterface
  private interface Matcher {
    boolean matches(String value);
  }
}
