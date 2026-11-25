package io.ohmyrasp.agent.detect;

import io.ohmyrasp.agent.naming.LookupRoute;
import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Class loading, naming and configuration APIs that select remote sources. */
final class RemoteResourceDetector {
  private RemoteResourceDetector() {}

  // A lookup whose name resolves through a *remote* naming provider is the
  // JNDI-injection vector (Log4Shell-class). Local container lookups in the
  // `java:` namespace (java:comp/env/..., java:global/..., java:module/...) and
  // bare relative names are legitimate and must not trip the detector. Mirrors
  // the backports' REMOTE_JNDI_LOOKUP scheme set for cross-agent parity.
  private static final Pattern JNDI_REMOTE_LOOKUP =
      Pattern.compile(
          "(?is)^(ldap|ldaps|rmi|iiop|corbaname|corbaloc)://[^\\s\\u0000]{1,2048}");

  private static final Set<String> REMOTE_CLASSLOADER_PROTOCOLS =
      Set.of("http", "https", "ftp", "ldap", "rmi");

  private static final Set<String> REMOTE_CONFIG_PROTOCOLS =
      Set.of("http", "https", "ftp", "ldap", "rmi");

  static Optional<Detection> detectClassLoaderUrl(
      String rawUrl, String mechanism, RequestContext request) {
    if (rawUrl == null || rawUrl.isBlank()) {
      return Optional.empty();
    }
    String normalized = rawUrl.trim();
    String inspected = lower(normalized);
    if (inspected.startsWith("jar:")) {
      inspected = inspected.substring("jar:".length());
      int bang = inspected.indexOf("!/");
      if (bang >= 0) {
        inspected = inspected.substring(0, bang);
      }
    }
    String scheme;
    try {
      scheme = lower(URI.create(inspected).getScheme());
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    if (!REMOTE_CLASSLOADER_PROTOCOLS.contains(scheme)) {
      return Optional.empty();
    }
    String hook = mechanism == null || mechanism.isBlank() ? "classloader" : mechanism;
    int confidence = request.hasParameterIn(normalized) ? 100 : 90;
    return Optional.of(
        Detection.log(
            "classloader",
            "classloader_remote",
            confidence,
            "Class loader is configured with a remote codebase URL",
            request,
            Map.of(
                "mechanism", hook,
                "scheme", scheme,
                "url", abbreviate(normalized),
                "requestControlled", String.valueOf(request.hasParameterIn(normalized)))));
  }

  static Optional<Detection> detectSpringConfigLocation(
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

  static Optional<Detection> detectJndi(String name, RequestContext request, String operation) {
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
}
