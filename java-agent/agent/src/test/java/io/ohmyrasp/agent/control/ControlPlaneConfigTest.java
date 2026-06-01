package io.ohmyrasp.agent.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class ControlPlaneConfigTest {
  @Test
  void readsAgentArgs() {
    ControlPlaneConfig config =
        ControlPlaneConfig.load(
            "backend_url=http://127.0.0.1:18090,app_id=app_1,app_secret=secret,environment_id=env_1,hostname=node-a,version=1.2.3");

    assertTrue(config.enabled());
    assertEquals("http://127.0.0.1:18090", config.backendUrl());
    assertEquals("app_1", config.applicationId());
    assertEquals("secret", config.applicationSecret());
    assertEquals("env_1", config.environmentId());
    assertEquals("node-a", config.hostname());
    assertEquals("java", config.runtime());
    assertEquals("1.2.3", config.version());
  }
}
