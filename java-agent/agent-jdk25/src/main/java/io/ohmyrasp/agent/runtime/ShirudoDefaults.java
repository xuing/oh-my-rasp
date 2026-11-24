package io.ohmyrasp.agent.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Properties;

/**
 * Optional baked-in runtime defaults packaged at {@code /META-INF/ohmyrasp-shirudo.properties}
 * for daemonless standalone and shirudo upatch agent jars.
 */
public final class ShirudoDefaults {
  static final String RESOURCE_PATH = "/META-INF/ohmyrasp-shirudo.properties";

  private static final ShirudoDefaults ABSENT =
      new ShirudoDefaults(false, false, false, null, null, null, null);

  private final boolean present;
  private final boolean standalone;
  private final boolean lockConfig;
  private final DetectionMode mode;
  private final String control;
  private final String log;
  private final Integer latencySample;

  private ShirudoDefaults(
      boolean present,
      boolean standalone,
      boolean lockConfig,
      DetectionMode mode,
      String control,
      String log,
      Integer latencySample) {
    this.present = present;
    this.standalone = standalone;
    this.lockConfig = lockConfig;
    this.mode = mode;
    this.control = control;
    this.log = log;
    this.latencySample = latencySample;
  }

  public static ShirudoDefaults load() {
    try (InputStream in = ShirudoDefaults.class.getResourceAsStream(RESOURCE_PATH)) {
      if (in == null) {
        return ABSENT;
      }
      Properties props = new Properties();
      props.load(new InputStreamReader(in, StandardCharsets.UTF_8));
      return fromProperties(props);
    } catch (IOException | RuntimeException e) {
      return ABSENT;
    }
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
