package io.ohmyrasp.agent.policy;

import io.ohmyrasp.agent.model.Detection;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class AgentPolicy {
  private static final AgentPolicy ABSENT = new AgentPolicy(false, 0, "", 100, List.of());
  private static final AgentPolicy EMPTY = new AgentPolicy(true, 0, "empty", 100, List.of());

  private final boolean loaded;
  private final int version;
  private final String status;
  private final int canaryPercent;
  private final List<PolicyRule> rules;

  private AgentPolicy(
      boolean loaded, int version, String status, int canaryPercent, List<PolicyRule> rules) {
    this.loaded = loaded;
    this.version = version;
    this.status = status == null ? "" : status;
    this.canaryPercent = Math.max(0, Math.min(100, canaryPercent));
    this.rules = List.copyOf(rules);
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
    return new AgentPolicy(true, version, status, canaryPercent, rules);
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

  public PolicyEvaluation evaluate(Detection detection, String stableAgentKey) {
    if (!loaded) {
      return PolicyEvaluation.notControlled(detection);
    }
    if (detection == null || !activeStatus() || !inCanary(stableAgentKey)) {
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
}
