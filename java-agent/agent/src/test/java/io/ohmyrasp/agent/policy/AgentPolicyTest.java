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

  private static Detection sqlDetection() {
    return new Detection(
        Instant.parse("2026-06-01T00:00:00Z"),
        "sql",
        "sql_userinput",
        "log",
        95,
        "SQL query structure appears altered by request input",
        new RequestContext("GET", "/login", "value=x", Map.of("value", List.of("' OR '1'='1")), Map.of()),
        Map.of("query", "select * from users where name = '' OR '1'='1'"));
  }
}
