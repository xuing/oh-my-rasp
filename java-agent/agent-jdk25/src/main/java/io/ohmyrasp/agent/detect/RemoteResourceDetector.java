package io.ohmyrasp.agent.detect;

import io.ohmyrasp.agent.jmx.JmxDispatch;
import io.ohmyrasp.agent.naming.LookupRoute;
import io.ohmyrasp.agent.loading.CodebaseUrls;
import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Class loading, naming and configuration APIs that select remote sources. */
public final class RemoteResourceDetector {
  private RemoteResourceDetector() {}

  static final Set<String> SSRF_PROTOCOLS =
      Set.of("file", "gopher", "dict", "ftp", "ldap", "jar", "netdoc");

  static final Set<String> JNDI_LOOKUP_PROTOCOLS =
      Set.of("ldap", "ldaps", "rmi", "dns", "iiop", "corba", "corbaname", "corbaloc", "nis");

  // A lookup whose name resolves through a *remote* naming provider is the
  // JNDI-injection vector (Log4Shell-class). Local container lookups in the
  // `java:` namespace (java:comp/env/..., java:global/..., java:module/...) and
  // bare relative names are legitimate and must not trip the detector. Mirrors
  // the backports' REMOTE_JNDI_LOOKUP scheme set for cross-agent parity.
  private static final Pattern JNDI_REMOTE_LOOKUP =
      Pattern.compile(
          "(?is)^(ldap|ldaps|rmi|iiop|corbaname|corbaloc)://[^\\s\\u0000]{1,2048}");

  private static final Set<String> REMOTE_CONFIG_PROTOCOLS =
      Set.of("http", "https", "ftp", "ldap", "rmi");

  public static Optional<Detection> detectClassLoaderUrl(
      String rawUrl, String mechanism, RequestContext request) {
    if (rawUrl == null || rawUrl.isBlank()) {
      return Optional.empty();
    }
    String normalized = rawUrl.trim();
    String scheme = CodebaseUrls.remoteScheme(normalized);
    if (scheme.isEmpty()) {
      return Optional.empty();
    }
    String hook = mechanism == null || mechanism.isBlank() ? "classloader" : mechanism;
    boolean rmi = "RMIClassLoader".equals(hook);
    return Optional.of(
        Detection.log(
            "classloader",
            "classloader_remote",
            90,
            rmi ? "RMI selected a codebase loader for a remote URL" : "Class definition reached the VM handoff with a remote resource origin",
            request,
            Map.of(
                "mechanism", hook,
                "scheme", scheme,
                "url", abbreviate(normalized),
                "decision_basis", rmi ? "rmi_codebase_loader_selection" : "url_class_definition")));
  }

  public static Optional<Detection> detectSpringConfigLocation(
      String location, String mechanism, RequestContext request) {
    if (location == null || location.isBlank()) {
      return Optional.empty();
    }
    String normalized = location.trim();
    Optional<String> remoteScheme = remoteConfigScheme(normalized);
    if (remoteScheme.isEmpty()) {
      return Optional.empty();
    }
    String scheme = remoteScheme.orElseThrow();
    String hook = mechanism == null || mechanism.isBlank() ? "spring" : mechanism;
    int confidence = request.hasParameterIn(normalized) ? 100 : 90;
    return Optional.of(
        Detection.log(
            "spring",
            "spring_remote_config",
            confidence,
            "Spring configuration is loaded from a remote resource",
            request,
            Map.of(
                "mechanism", hook,
                "scheme", scheme,
                "location", abbreviate(normalized),
                "requestControlled", String.valueOf(request.hasParameterIn(normalized)))));
  }

  public static Optional<Detection> detectJndi(String name, RequestContext request, String operation) {
    if (name == null || name.isBlank()) {
      return Optional.empty();
    }
    var remote = JNDI_REMOTE_LOOKUP.matcher(name);
    if (!remote.find()) {
      return Optional.empty();
    }
    String scheme = remote.group(1).toLowerCase(Locale.ROOT);
    return Optional.of(
        Detection.log(
            "jndi",
            LookupRoute.LOGIN_LOOKUP.equals(operation) ? "jndi_jaas_config" : "jndi_disable_all",
            95,
            "JNDI lookup name matches the remote-scheme policy",
            request,
            Map.of(
                "name", abbreviate(name),
                "operation", operation,
                "decision_basis", LookupRoute.basis(operation),
                "scheme", scheme)));
  }

  static boolean containsRemoteProtocol(String value) {
    String normalized = lower(value);
    for (String protocol : REMOTE_CONFIG_PROTOCOLS) {
      if (normalized.contains(protocol + "://")) {
        return true;
      }
    }
    return false;
  }

  static Optional<String> remoteConfigScheme(String location) {
    if (location == null || location.isBlank()) {
      return Optional.empty();
    }
    String inspected = lower(location.trim());
    while (inspected.startsWith("xbean:")
        || inspected.startsWith("spring:")
        || inspected.startsWith("classpath*:")) {
      int colon = inspected.indexOf(':');
      inspected = inspected.substring(colon + 1);
    }
    if (inspected.startsWith("jar:")) {
      inspected = inspected.substring("jar:".length());
      int bang = inspected.indexOf("!/");
      if (bang >= 0) {
        inspected = inspected.substring(0, bang);
      }
    }
    try {
      String scheme = lower(URI.create(inspected).getScheme());
      return REMOTE_CONFIG_PROTOCOLS.contains(scheme) ? Optional.of(scheme) : Optional.empty();
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  public static Optional<Detection> detectJndi(String name, RequestContext request) {
    return detectJndi(name, request, "declared_lookup");
  }

  public static Optional<Detection> detectJmxMBeanInvoke(
      String mbeanName, String operationName, List<String> arguments, RequestContext request) {
    if (operationName == null || operationName.isBlank() || !request.active()) {
      return Optional.empty();
    }
    List<String> safeArguments = arguments == null ? List.of() : arguments;
    Optional<String> remoteConfig =
        safeArguments.stream()
            .filter(argument -> argument != null && looksLikeRemoteJmxConfig(argument))
            .findFirst();
    if (!isMutatingJmxOperation(operationName)) {
      return Optional.empty();
    }
    if (remoteConfig.isPresent()) {
      String matched = remoteConfig.orElseThrow();
      int confidence = request.hasParameterIn(matched) ? 100 : 90;
      return Optional.of(
          Detection.log(
              "jmx",
              "jmx_remote_config",
              confidence,
              "Request-time MBean invocation passes a remote configuration source",
              request,
              Map.of(
                  "mbean", abbreviate(String.valueOf(mbeanName)),
                  "operation", operationName,
                  "argument", abbreviate(matched),
                  "requestControlled", String.valueOf(request.hasParameterIn(matched)))));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectJaasConfig(
      String config, String mechanism, RequestContext request) {
    // Compatibility for declaration-only callers. Runtime policy uses the login module lookup.
    return Optional.empty();
  }

  private static boolean isMutatingJmxOperation(String operationName) {
    String normalized = lower(operationName);
    return normalized.startsWith("add")
        || normalized.startsWith("set")
        || normalized.startsWith("create")
        || normalized.startsWith("copy")
        || normalized.startsWith("load")
        || normalized.startsWith("reload")
        || normalized.startsWith("update")
        || normalized.startsWith("write")
        || normalized.startsWith("save")
        || normalized.startsWith("store")
        || normalized.startsWith("dump")
        || normalized.startsWith("install")
        || normalized.startsWith("deploy")
        || normalized.startsWith("import")
        || normalized.startsWith("start");
  }

  private static boolean looksLikeRemoteJmxConfig(String argument) {
    String normalized = lower(argument.trim());
    if (normalized.isBlank() || !containsRemoteProtocol(normalized) || !JmxDispatch.isLocationArgument(argument)) {
      return false;
    }
    return normalized.contains("brokerconfig=")
        || normalized.contains("xbean:")
        || normalized.contains("spring:")
        || (normalized.contains("config") && normalized.contains(".xml"));
  }
}
