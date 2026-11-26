package io.ohmyrasp.agent.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.ProtectionDomain;
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
    Properties props = new Properties();
    boolean found = false;
    try {
      URL resource = ownResource();
      if (resource == null) {
        return ABSENT;
      }
      URLConnection connection = resource.openConnection();
      connection.setUseCaches(false);
      try (InputStream in = connection.getInputStream()) {
        found = true;
        props.load(new InputStreamReader(in, StandardCharsets.UTF_8));
      }
    } catch (IOException | RuntimeException e) {
      // A missing resource leaves the defaults absent. A malformed one (Properties.load throws on a
      // bad unicode escape) keeps the keys read before the bad line, so a damaged later line cannot
      // erase an already-read lock_config or mode.
    }
    return found ? fromProperties(props) : ABSENT;
  }

  /**
   * The baked resource in the agent's own JAR or class directory, or null when that location is
   * unknown. A class-relative lookup is not used: the agent classes are on the bootstrap search,
   * where such a lookup searches the system class path and an application JAR that carries a
   * same-named file would win.
   */
  private static URL ownResource() throws MalformedURLException {
    URL location = codeLocation(ShirudoDefaults.class);
    if (location == null) {
      // Defined by the bootstrap loader, which records no code source. The agent JAR is the one the
      // system class loader loaded the entry class from.
      try {
        location = codeLocation(Class.forName(AGENT_ENTRY_CLASS, false, ClassLoader.getSystemClassLoader()));
      } catch (ClassNotFoundException | LinkageError e) {
        return null;
      }
    }
    if (location == null) {
      return null;
    }
    String base = location.toString();
    String entry = RESOURCE_PATH.substring(1);
    return URI.create(base.endsWith("/") ? base + entry : "jar:" + base + "!/" + entry).toURL();
  }

  private static URL codeLocation(Class<?> type) {
    ProtectionDomain domain = type.getProtectionDomain();
    CodeSource source = domain == null ? null : domain.getCodeSource();
    return source == null ? null : source.getLocation();
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
