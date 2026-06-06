package io.ohmyrasp.agent.control;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

public record ControlPlaneConfig(
    String backendUrl,
    String applicationId,
    String applicationSecret,
    String environmentId,
    String hostname,
    String runtime,
    String version) {

  public static ControlPlaneConfig load(String agentArgs) {
    Map<String, String> args = parseArgs(agentArgs);
    return new ControlPlaneConfig(
        setting(args, "backend_url", "ohmyrasp.backend_url", "OHMYRASP_BACKEND_URL"),
        setting(args, "app_id", "ohmyrasp.app_id", "OHMYRASP_APP_ID"),
        setting(args, "app_secret", "ohmyrasp.app_secret", "OHMYRASP_APP_SECRET"),
        setting(args, "environment_id", "ohmyrasp.environment_id", "OHMYRASP_ENVIRONMENT_ID"),
        setting(args, "hostname", "ohmyrasp.hostname", "OHMYRASP_HOSTNAME", detectHostname()),
        setting(args, "runtime", "ohmyrasp.runtime", "OHMYRASP_RUNTIME", "java"),
        setting(args, "version", "ohmyrasp.version", "OHMYRASP_VERSION", implementationVersion()));
  }

  public boolean enabled() {
    return !blank(backendUrl)
        && !blank(applicationId)
        && !blank(applicationSecret)
        && !blank(environmentId);
  }

  /**
   * Whether the agent should talk to the control plane directly (legacy single-
   * process mode). Off by default: the daemon owns cloud communication and the
   * agent only writes its local event spool.
   */
  public static boolean directCloudEnabled(String agentArgs) {
    String value =
        setting(
            parseArgs(agentArgs),
            "cloud_direct",
            "ohmyrasp.cloud.direct",
            "OHMYRASP_CLOUD_DIRECT",
            "");
    return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
      case "true", "1", "yes", "on" -> true;
      default -> false;
    };
  }

  private static Map<String, String> parseArgs(String agentArgs) {
    Map<String, String> values = new HashMap<>();
    if (agentArgs == null || agentArgs.isBlank()) {
      return values;
    }
    for (String item : agentArgs.split("[,;]")) {
      int separator = item.indexOf('=');
      if (separator <= 0) {
        continue;
      }
      values.put(normalize(item.substring(0, separator)), item.substring(separator + 1).trim());
    }
    return values;
  }

  private static String setting(Map<String, String> args, String key, String property, String env) {
    return setting(args, key, property, env, "");
  }

  private static String setting(
      Map<String, String> args, String key, String property, String env, String fallback) {
    String value = args.get(normalize(key));
    if (!blank(value)) {
      return value.trim();
    }
    value = System.getProperty(property);
    if (!blank(value)) {
      return value.trim();
    }
    value = System.getenv(env);
    if (!blank(value)) {
      return value.trim();
    }
    return fallback;
  }

  private static String normalize(String key) {
    return key.trim().replace('.', '_').replace('-', '_');
  }

  private static String detectHostname() {
    try {
      return InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException ignored) {
      return "unknown";
    }
  }

  private static String implementationVersion() {
    String version = ControlPlaneConfig.class.getPackage().getImplementationVersion();
    return blank(version) ? "unknown" : version;
  }

  private static boolean blank(String value) {
    return value == null || value.isBlank();
  }
}
