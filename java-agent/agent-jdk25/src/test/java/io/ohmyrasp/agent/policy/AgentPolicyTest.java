package io.ohmyrasp.agent.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class AgentPolicyTest {
  @Test
  void locationReflectionAndOrdinaryDirectoryInputEachRequireExactSelection() {
    var broad = AgentPolicy.parse("""
        {"rules":[{"hook":"directory","action":"block"}]}
        """);
    Map.of("directory_userinput", "requested_path_only", "directory_unwanted", "directory_location",
        "directory_reflect", "directory_dispatch").forEach((algorithm, basis) -> {
      var candidate = Detection.log("directory", algorithm, 65, "directory policy", RequestContext.empty(),
          Map.of("path", "/srv/reports", "decision_basis", basis));
      assertTrue(AgentPolicy.absent().evaluate(candidate, "").ignored());
      assertTrue(broad.evaluate(candidate, "").ignored());
      var selected = AgentPolicy.parse("""
          {"rules":[{"algorithm":"%s","action":"log"}]}
          """.formatted(algorithm));
      assertEquals("log", selected.evaluate(candidate, "").detection().action());
    });
  }

  @Test
  void reflectiveProcessDispatchRequiresItsOwnRule() {
    var candidate = Detection.log("command", "command_reflect", 70, "reflective dispatch",
        RequestContext.empty(), Map.of("decision_basis", "process_dispatch"));
    assertTrue(AgentPolicy.absent().evaluate(candidate, "").ignored());
    assertTrue(AgentPolicy.parse("""
        {"rules":[{"hook":"command","action":"block"}]}
        """).evaluate(candidate, "").ignored());
    assertEquals("log", AgentPolicy.parse("""
        {"rules":[{"algorithm":"command_reflect","action":"log"}]}
        """).evaluate(candidate, "").detection().action());
  }

  @Test
  void systemDirectoryReadRequiresAnExplicitFileRule() {
    var candidate = Detection.log("readFile", "readFile_outsideWebroot", 65, "system directory",
        RequestContext.empty(), Map.of("decision_basis", "system_directory", "path", "/etc/service/config"));
    assertTrue(AgentPolicy.absent().evaluate(candidate, "").ignored());
    var broad = AgentPolicy.parse("""
        {"rules":[{"hook":"readFile","action":"block"}]}
        """);
    assertTrue(broad.evaluate(candidate, "").ignored());
    for (String action : List.of("log", "block")) {
      var explicit = AgentPolicy.parse("""
          {"rules":[{"algorithm":"readFile_outsideWebroot","action":"%s"}]}
          """.formatted(action));
      assertEquals(action, explicit.evaluate(candidate, "").detection().action());
    }
  }

  @Test
  void onlyAnExplicitInputRuleSelectsAnOrdinaryRequestedFile() {
    var candidate = Detection.log("readFile", "readFile_userinput", 65, "requested path",
        RequestContext.empty(), Map.of("decision_basis", "requested_path_only", "path", "/srv/reports/inventory.csv"));
    assertTrue(AgentPolicy.absent().evaluate(candidate, "").ignored());
    assertTrue(AgentPolicy.parse("""
        {"rules":[{"hook":"readFile","action":"block"}]}
        """).evaluate(candidate, "").ignored());
    var rule = AgentPolicy.parse("""
        {"rules":[{"algorithm":"readFile_userinput","action":"log"}]}
        """);
    assertEquals("log", rule.evaluate(candidate, "").detection().action());
  }

  @Test
  void requiresExplicitPolicySelectionForArchiveMetadata() {
    var candidate = Detection.log("fileUpload", "fileUpload_java_archive", 90, "archive",
        RequestContext.empty(), Map.of("decision_basis", "deployment_context"));
    assertTrue(AgentPolicy.absent().evaluate(candidate, "").ignored());
    for (String field : List.of("algorithm", "event.algorithm")) {
      var monitor = AgentPolicy.parse("""
          {"status":"active","rules":[
            {"hook":"fileUpload","action":"block"},
            {"expression":"%s == 'fileUpload_java_archive'","action":"log"}]}
          """.formatted(field));
      assertEquals("log", monitor.evaluate(candidate, "").detection().action());
    }
    var broad = AgentPolicy.parse("""
        {"rules":[{"hook":"fileUpload","action":"block"}]}
        """);
    assertTrue(broad.evaluate(candidate, "").ignored());
    var block = AgentPolicy.parse("""
        {"rules":[{"algorithm":"fileUpload_java_archive","action":"block"}]}
        """);
    assertEquals("block", block.evaluate(candidate, "").detection().action());
  }

  @Test
  void appliesMatchingBlockRule() {
    AgentPolicy policy =
        AgentPolicy.parse(
            """
            {
              "version": 2,
              "status": "active",
              "canary_percent": 100,
              "rules": [
                {
                  "id": "rul_sql",
                  "name": "SQL block",
                  "hook": "sql",
                  "algorithm": "sql_userinput",
                  "action": "block",
                  "severity": "critical",
                  "expression": "algorithm == \\"sql_userinput\\""
                }
              ]
            }
            """);

    PolicyEvaluation evaluation = policy.evaluate(sqlDetection(), "agent-one");

    assertTrue(evaluation.controlled());
    assertFalse(evaluation.ignored());
    assertEquals("block", evaluation.detection().action());
  }

  @Test
  void ignoresUnmatchedDetectionWhenPolicyIsLoaded() {
    AgentPolicy policy =
        AgentPolicy.parse(
            """
            {
              "version": 2,
              "status": "active",
              "canary_percent": 100,
              "rules": [
                {
                  "name": "Command only",
                  "hook": "command",
                  "algorithm": "command_common",
                  "action": "block",
                  "expression": "algorithm == \\"command_common\\""
                }
              ]
            }
            """);

    PolicyEvaluation evaluation = policy.evaluate(sqlDetection(), "agent-one");

    assertTrue(evaluation.controlled());
    assertTrue(evaluation.ignored());
  }

  @Test
  void honorsIgnoreActionAndCanaryPercent() {
    AgentPolicy ignorePolicy =
        AgentPolicy.parse(
            """
            {
              "version": 2,
              "status": "active",
              "canary_percent": 100,
              "rules": [
                {
                  "name": "Ignore SQL",
                  "hook": "sql",
                  "algorithm": "sql_userinput",
                  "action": "ignore",
                  "expression": "algorithm == \\"sql_userinput\\""
                }
              ]
            }
            """);
    AgentPolicy zeroCanary =
        AgentPolicy.parse(
            """
            {
              "version": 2,
              "status": "canary",
              "canary_percent": 0,
              "rules": [
                {
                  "name": "SQL block",
                  "hook": "sql",
                  "algorithm": "sql_userinput",
                  "action": "block",
                  "expression": "algorithm == \\"sql_userinput\\""
                }
              ]
            }
            """);

    assertTrue(ignorePolicy.evaluate(sqlDetection(), "agent-one").ignored());
    assertTrue(zeroCanary.evaluate(sqlDetection(), "agent-one").ignored());
  }

  @Test
  void absentPolicyLeavesDetectionUncontrolledForStandaloneMode() {
    PolicyEvaluation evaluation = AgentPolicy.absent().evaluate(sqlDetection(), "agent-one");

    assertFalse(evaluation.controlled());
    assertFalse(evaluation.ignored());
    assertEquals("log", evaluation.detection().action());
  }

  @Test
  void appliesResolvedApplicationAllowlist() {
    AgentPolicy policy =
        AgentPolicy.parse(
            """
            {
              "version": 2,
              "status": "active",
              "canary_percent": 100,
              "config": {
                "allowlist": {
                  "enabled": true,
                  "mode": "enforce",
                  "entries": ["/admin/*"]
                }
              },
              "rules": [
                {
                  "name": "SQL block",
                  "hook": "sql",
                  "algorithm": "sql_userinput",
                  "action": "block",
                  "expression": "algorithm == \\"sql_userinput\\""
                }
              ]
            }
            """);

    PolicyEvaluation evaluation = policy.evaluate(sqlDetection("/admin/search"), "agent-one");

    assertTrue(policy.config().allowlistEnabled());
    assertTrue(evaluation.ignored());
  }

  @Test
  void hardeningEnforcementCanPromoteProcessDetectionToBlock() {
    AgentPolicy policy =
        AgentPolicy.parse(
            """
            {
              "version": 2,
              "status": "active",
              "canary_percent": 100,
              "config": {
                "hardening": {
                  "mode": "enforce",
                  "block_process_execution": true,
                  "block_reflection_abuse": false
                }
              },
              "rules": []
            }
            """);

    PolicyEvaluation evaluation = policy.evaluate(commandDetection(), "agent-one");

    assertTrue(evaluation.controlled());
    assertFalse(evaluation.ignored());
    assertEquals("block", evaluation.detection().action());
  }

  private static Detection sqlDetection() {
    return sqlDetection("/login");
  }

  private static Detection sqlDetection(String uri) {
    return new Detection(
        Instant.parse("2026-06-01T00:00:00Z"),
        "sql",
        "sql_userinput",
        "log",
        95,
        "SQL query structure appears altered by request input",
        new RequestContext("GET", uri, "value=x", Map.of("value", List.of("' OR '1'='1")), Map.of()),
        Map.of("query", "select * from users where name = '' OR '1'='1'"));
  }

  private static Detection commandDetection() {
    return new Detection(
        Instant.parse("2026-06-01T00:00:00Z"),
        "command",
        "command_common",
        "log",
        90,
        "Command execution observed",
        new RequestContext("POST", "/run", "", Map.of(), Map.of()),
        Map.of("command", "sh -c id"));
  }
}
