package io.ohmyrasp.agent.policy;

import io.ohmyrasp.agent.model.Detection;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class AgentPolicy {
  private static final AgentPolicy ABSENT =
      new AgentPolicy(false, 0, "", 100, List.of(), PolicyConfig.empty());
  private static final AgentPolicy EMPTY =
      new AgentPolicy(true, 0, "empty", 100, List.of(), PolicyConfig.empty());

  private final boolean loaded;
  private final int version;
  private final String status;
  private final int canaryPercent;
  private final List<PolicyRule> rules;
  private final PolicyConfig config;

  private AgentPolicy(
      boolean loaded,
      int version,
      String status,
      int canaryPercent,
      List<PolicyRule> rules,
      PolicyConfig config) {
    this.loaded = loaded;
    this.version = version;
    this.status = status == null ? "" : status;
    this.canaryPercent = Math.max(0, Math.min(100, canaryPercent));
    this.rules = List.copyOf(rules);
    this.config = config == null ? PolicyConfig.empty() : config;
  }

  public static AgentPolicy absent() {
    return ABSENT;
  }

  public static AgentPolicy empty() {
    return EMPTY;
  }

  public static AgentPolicy parse(String json) {
    if (json == null || json.isBlank()) {
      return empty();
    }
    Object parsed = SimpleJson.parse(json);
    if (!(parsed instanceof Map<?, ?> object)) {
      throw new IllegalArgumentException("policy root must be an object");
    }
    int version = intField(object, "version", 0);
    String status = stringField(object, "status", "");
    int canaryPercent = intField(object, "canary_percent", 100);
    List<PolicyRule> rules = new ArrayList<>();
    Object rawRules = object.get("rules");
    if (rawRules instanceof List<?> items) {
      for (Object item : items) {
        if (item instanceof Map<?, ?> ruleObject) {
          PolicyRule.fromMap(ruleObject).ifPresent(rules::add);
        }
      }
    }
    return new AgentPolicy(true, version, status, canaryPercent, rules, PolicyConfig.from(object.get("config")));
  }

  public boolean loaded() {
    return loaded;
  }

  public int version() {
    return version;
  }

  public String status() {
    return status;
  }

  public int canaryPercent() {
    return canaryPercent;
  }

  public List<PolicyRule> rules() {
    return rules;
  }

  public PolicyConfig config() {
    return config;
  }

  public PolicyEvaluation evaluate(Detection detection, String stableAgentKey) {
    if (!loaded) {
      return PolicyEvaluation.notControlled(detection);
    }
    if (detection == null || !activeStatus() || !inCanary(stableAgentKey)) {
      return PolicyEvaluation.ignore();
    }
    if (config.allowlisted(detection)) {
      return PolicyEvaluation.ignore();
    }

    Detection logMatch = null;
    for (PolicyRule rule : rules) {
      if (!rule.matches(detection)) {
        continue;
      }
      String action = rule.action();
      if ("ignore".equals(action)) {
        return PolicyEvaluation.ignore();
      }
      Detection candidate = detection.withAction(action);
      if ("block".equals(action)) {
        return PolicyEvaluation.emit(candidate);
      }
      if (logMatch == null) {
        logMatch = candidate;
      }
    }
    if (logMatch != null) {
      return PolicyEvaluation.emit(logMatch);
    }
    Detection hardening = config.hardeningDetection(detection);
    if (hardening != null) {
      return PolicyEvaluation.emit(hardening);
    }
    return PolicyEvaluation.ignore();
  }

  private boolean activeStatus() {
    String normalized = status.toLowerCase(Locale.ROOT);
    return normalized.isBlank()
        || "active".equals(normalized)
        || "canary".equals(normalized)
        || "empty".equals(normalized);
  }

  private boolean inCanary(String stableAgentKey) {
    if (canaryPercent >= 100) {
      return true;
    }
    if (canaryPercent <= 0) {
      return false;
    }
    String key = stableAgentKey == null || stableAgentKey.isBlank() ? "unknown" : stableAgentKey;
    return Math.floorMod(key.hashCode(), 100) < canaryPercent;
  }

  private static int intField(Map<?, ?> object, String name, int fallback) {
    Object value = object.get(name);
    if (value instanceof Number number) {
      return number.intValue();
    }
    if (value instanceof String string) {
      try {
        return Integer.parseInt(string.trim());
      } catch (NumberFormatException ignored) {
        return fallback;
      }
    }
    return fallback;
  }

  private static String stringField(Map<?, ?> object, String name, String fallback) {
    Object value = object.get(name);
    return value == null ? fallback : String.valueOf(value);
  }

  public record PolicyConfig(
      boolean allowlistEnabled,
      List<String> allowlistEntries,
      String hardeningMode,
      boolean blockReflectionAbuse,
      boolean blockProcessExecution) {
    static PolicyConfig empty() {
      return new PolicyConfig(false, List.of(), "monitor", false, false);
    }

    static PolicyConfig from(Object value) {
      if (!(value instanceof Map<?, ?> config)) {
        return empty();
      }
      Map<?, ?> allowlist = objectField(config, "allowlist");
      Map<?, ?> hardening = objectField(config, "hardening");
      return new PolicyConfig(
          boolField(allowlist, "enabled", false),
          stringListField(allowlist, "entries"),
          stringField(hardening, "mode", "monitor"),
          boolField(hardening, "block_reflection_abuse", false),
          boolField(hardening, "block_process_execution", false));
    }

    boolean allowlisted(Detection detection) {
      if (!allowlistEnabled || allowlistEntries.isEmpty() || detection == null) {
        return false;
      }
      String uri = detection.request() == null ? "" : detection.request().uri();
      String query = detection.request() == null ? "" : detection.request().query();
      String uriWithQuery = query.isBlank() ? uri : uri + "?" + query;
      for (String entry : allowlistEntries) {
        if (matches(entry, uri) || matches(entry, uriWithQuery) || detailsMatch(entry, detection.details())) {
          return true;
        }
      }
      return false;
    }

    Detection hardeningDetection(Detection detection) {
      if (detection == null || !"enforce".equalsIgnoreCase(hardeningMode)) {
        return null;
      }
      String hook = normalize(detection.hook());
      if (blockProcessExecution && ("command".equals(hook) || "process".equals(hook))) {
        return detection.withAction("block");
      }
      if (blockReflectionAbuse
          && ("eval".equals(hook)
              || "ognl".equals(hook)
              || "deserialization".equals(hook)
              || "jndi".equals(hook))) {
        return detection.withAction("block");
      }
      return null;
    }

    private static boolean detailsMatch(String entry, Map<String, String> details) {
      if (details == null || details.isEmpty()) {
        return false;
      }
      for (String value : details.values()) {
        if (matches(entry, value)) {
          return true;
        }
      }
      return false;
    }

    private static boolean matches(String entry, String value) {
      String pattern = normalize(entry);
      String candidate = normalize(value);
      if (pattern.isBlank() || candidate.isBlank()) {
        return false;
      }
      if (pattern.endsWith("*")) {
        return candidate.startsWith(pattern.substring(0, pattern.length() - 1));
      }
      return candidate.equals(pattern) || candidate.contains(pattern);
    }

    private static String normalize(String value) {
      return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
  }

  private static Map<?, ?> objectField(Map<?, ?> object, String name) {
    Object value = object.get(name);
    return value instanceof Map<?, ?> map ? map : Map.of();
  }

  private static boolean boolField(Map<?, ?> object, String name, boolean fallback) {
    Object value = object.get(name);
    if (value instanceof Boolean bool) {
      return bool;
    }
    if (value instanceof String string) {
      return "true".equalsIgnoreCase(string.trim());
    }
    return fallback;
  }

  private static List<String> stringListField(Map<?, ?> object, String name) {
    Object value = object.get(name);
    if (!(value instanceof List<?> items)) {
      return List.of();
    }
    var strings = new ArrayList<String>();
    for (Object item : items) {
      if (item != null && !String.valueOf(item).isBlank()) {
        strings.add(String.valueOf(item));
      }
    }
    return List.copyOf(strings);
  }
}
