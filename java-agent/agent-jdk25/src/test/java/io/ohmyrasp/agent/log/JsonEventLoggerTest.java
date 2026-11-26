package io.ohmyrasp.agent.log;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Settings and writer lifecycle of the event logger. */
final class JsonEventLoggerTest {

  @Test
  void invalidSyncPropertyDoesNotHideAValidEnvironmentValue() {
    assertTrue(JsonEventLogger.flagValue("maybe", "true"), "an invalid ohmyrasp.log.sync property");
    assertFalse(JsonEventLogger.flagValue("false", "true"), "a valid false still wins");
    assertTrue(JsonEventLogger.flagValue(null, "on"));
    assertFalse(JsonEventLogger.flagValue("maybe", "perhaps"));
    assertFalse(JsonEventLogger.flagValue(null, null));
  }
}
