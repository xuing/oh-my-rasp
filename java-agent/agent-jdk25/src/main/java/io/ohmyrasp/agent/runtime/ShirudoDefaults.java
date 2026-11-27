package io.ohmyrasp.agent.runtime;

import java.util.Locale;
import java.util.Properties;

/**
 * Optional baked-in runtime defaults packaged at {@code /META-INF/ohmyrasp-shirudo.properties}
 * for daemonless standalone and shirudo upatch agent jars.
 */
public final class ShirudoDefaults {
  static final String RESOURCE_PATH = "/META-INF/ohmyrasp-shirudo.properties";
  private static final String AGENT_ENTRY_CLASS = "io.ohmyrasp.agent.OhMyRaspAgent";

  private static final ShirudoDefaults ABSENT =
      new ShirudoDefaults(false, false, false, null, null, null, null, null);

  private final boolean present;
  private final boolean standalone;
  private final boolean lockConfig;
  private final DetectionMode mode;
  private final String control;
  private final String outsideRequest;
  private final String log;
  private final Integer latencySample;

  private ShirudoDefaults(
      boolean present,
      boolean standalone,
      boolean lockConfig,
      DetectionMode mode,
      String control,
      String outsideRequest,
      String log,
      Integer latencySample) {
    this.present = present;
    this.standalone = standalone;
    this.lockConfig = lockConfig;
    this.mode = mode;
    this.control = control;
    this.outsideRequest = outsideRequest;
    this.log = log;
    this.latencySample = latencySample;
  }

  /**
   * The baked settings from the agent's own JAR or class directory, read by
   * {@link io.ohmyrasp.agent.util.BakedProperties}: absent for a general JAR; an IllegalStateException, which
   * fails the start, for an upatch JAR whose settings are missing or cannot be read.
   */
  public static ShirudoDefaults load() {
    Properties props = io.ohmyrasp.agent.util.BakedProperties.read(ShirudoDefaults.class, AGENT_ENTRY_CLASS);
    return props == null ? ABSENT : fromProperties(props);
  }

  static ShirudoDefaults absent() {
    return ABSENT;
  }

  static ShirudoDefaults fromProperties(Properties props) {
    if (props == null) {
      return ABSENT;
    }
    return new ShirudoDefaults(
        true,
        parseBoolean(props.getProperty("standalone")),
        parseBoolean(props.getProperty("lock_config")),
        DetectionMode.parse(props.getProperty("mode")),
        trimToNull(props.getProperty("control")),
        trimToNull(props.getProperty(io.ohmyrasp.agent.rules.OutsideRequest.CONTROL_KEY)),
        trimToNull(props.getProperty("log")),
        parseInteger(props.getProperty("latency_sample")));
  }

  public boolean isPresent() {
    return present;
  }

  public boolean standalone() {
    return standalone;
  }

  public boolean lockConfig() {
    return lockConfig;
  }

  public DetectionMode mode() {
    return mode;
  }

  public String control() {
    return control;
  }

  /** The baked {@code outside_request} as written, or null; {@code OutsideRequest.parse} reads it. */
  public String outsideRequest() {
    return outsideRequest;
  }

  public String log() {
    return log;
  }

  public Integer latencySample() {
    return latencySample;
  }

  static boolean parseBoolean(String value) {
    if (value == null) {
      return false;
    }
    return switch (value.trim().toLowerCase(Locale.ROOT)) {
      case "true", "1", "yes", "on" -> true;
      default -> false;
    };
  }

  private static String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  private static Integer parseInteger(String value) {
    String trimmed = trimToNull(value);
    if (trimmed == null) {
      return null;
    }
    try {
      return Integer.valueOf(trimmed);
    } catch (NumberFormatException e) {
      return null;
    }
  }
}
