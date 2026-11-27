package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizePath;
import static io.ohmyrasp.agent.detect.DetectorStrings.protocolOf;
import static io.ohmyrasp.agent.detect.FilePaths.requestControlsReadPath;
import static io.ohmyrasp.agent.detect.FilePaths.sensitiveFileLocation;
import static io.ohmyrasp.agent.detect.RemoteResourceDetector.SSRF_PROTOCOLS;
import static io.ohmyrasp.agent.detect.RequestDecoding.PROTECTED_WEBAPP_RESOURCE;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;
import static io.ohmyrasp.agent.detect.RequestValues.bodyHasSinkValue;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.net.HttpTransportObservation;
import io.ohmyrasp.agent.net.NetworkHost;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/** Outbound destinations: URLs, HTTP transports, XML attachment references, DNS names and XML entity system IDs. */
public final class NetworkDestinationDetector {
  private NetworkDestinationDetector() {}

  private static final Pattern INTERNAL_ADMIN_PATH = Pattern.compile(
      "(?i)(?:^|/)(?:jolokia|manager|host-manager|admin|console|webtools|solr/admin|debug|server-status|actuator/(?:env|heapdump|shutdown))(?:[/;]|$)");

  private static final Pattern READ_SAFE_EXTENSION =
      Pattern.compile(
          "(?is).+\\.(?:docx?|dotx?|docm|dotm|xlsx?|xltx?|xlsm|xlsb|pptx?|ppsx?|ppsm|potx?|potm|7z|tar|gz|bz2|xz|rar|zip|jpe?g|png|gif|bmp|txt)$");

  public static Optional<Detection> detectUrl(String rawUrl, RequestContext request) {
    return detectUrl(rawUrl, request, false);
  }

  public static Optional<Detection> detectUrl(String rawUrl, RequestContext request, boolean includeDestinationPolicy) {
    if (rawUrl == null || rawUrl.isBlank()) {
      return Optional.empty();
    }
    URI uri;
    try {
      uri = URI.create(rawUrl);
    } catch (IllegalArgumentException e) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              70,
              "Malformed outbound URL detected",
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    String scheme = lower(uri.getScheme());
    String host = NetworkHost.normalize(uri.getHost());
    String path = lower(uri.getPath());
    if (scheme.equals("file") && (!request.active() || !fileUrlNeedsInspection(uri, rawUrl, request))) {
      return Optional.empty();
    }
    if (isLocalArchiveUrl(rawUrl, scheme)) {
      return Optional.empty();
    }
    if ("jar".equals(scheme)) {
      if (!request.active()) return Optional.empty();
      if (HttpTransportObservation.archiveAddress(rawUrl) != null) {
        if (!includeDestinationPolicy) return Optional.empty();
        return Optional.of(Detection.log("ssrf", "ssrf_protocol", 90, "HTTP archive URL opened",
            request, Map.of("url", abbreviate(rawUrl), "decision_basis", "archive_scheme_only")));
      }
    }
    if (SSRF_PROTOCOLS.contains(scheme)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_protocol",
              90,
              "Outbound request uses a dangerous protocol: " + scheme,
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    return classifyNetworkDestination(uri, rawUrl, host, path, request, includeDestinationPolicy, null, false);
  }

  public static Optional<Detection> classifyHttpTransport(java.net.URL url, RequestContext request, boolean includeDestinationPolicy, String peer, boolean redirected) {
    String address = HttpTransportObservation.address(url);
    URI uri = HttpTransportObservation.comparisonUri(url, address);
    return classifyNetworkDestination(uri, address, NetworkHost.normalize(url.getHost()),
        lower(uri == null ? url.getPath() : uri.getPath()), request, includeDestinationPolicy, peer, redirected);
  }

  public static Optional<Detection> classifyHttpTransport(URI uri, RequestContext request, boolean includeDestinationPolicy, String peer, boolean redirected) {
    return classifyNetworkDestination(uri, HttpTransportObservation.address(uri), NetworkHost.normalize(uri.getHost()),
        lower(uri.getPath()), request, includeDestinationPolicy, peer, redirected);
  }

  private static Optional<Detection> classifyNetworkDestination(URI uri, String rawUrl, String host, String path,
      RequestContext request, boolean includeDestinationPolicy, String peer, boolean redirected) {
    if (NetworkHost.isMetadata(host) || (peer != null && NetworkHost.isMetadata(peer))) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_aws",
              100,
              "Outbound request targets cloud instance metadata",
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    boolean internal = NetworkHost.isInternal(host) || (peer != null && NetworkHost.isInternal(peer));
    boolean admin = internal && INTERNAL_ADMIN_PATH.matcher(path).find();
    boolean supplied = redirected || requestControlsUrl(uri, rawUrl, host, request);
    boolean http = uri == null || "http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme());
    if ((!http && (supplied || admin)) || (internal && (supplied || (admin && requestControlsAdminPath(uri, request))))) {
      return Optional.of(Detection.log("ssrf", "ssrf_userinput", 90,
          "Request input selects an internal HTTP destination", request,
          Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    if (CallbackDomain.matches(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_common",
              90,
              "Outbound request targets a callback collection domain",
              request,
              Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    if (looksObfuscatedHost(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              80,
              "Outbound request host appears obfuscated",
              request,
              Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    if (includeDestinationPolicy && (admin || supplied)) {
      return Optional.of(Detection.log("ssrf", "ssrf_userinput", 80,
          "Outbound destination matches a managed egress policy candidate", request,
          Map.of("url", abbreviate(rawUrl), "host", host, "policy_basis", "destination_only")));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectXmlAttachmentReference(
      String mechanism, String rawHref, RequestContext request) {
    if (rawHref == null || rawHref.isBlank() || request == null || !request.active()) {
      return Optional.empty();
    }
    String hook = xmlAttachmentMechanism(mechanism);
    if (hook.isBlank()) {
      return Optional.empty();
    }
    String href = attachmentHref(rawHref);
    if (href.isBlank()) {
      return Optional.empty();
    }
    URI uri;
    try {
      uri = URI.create(href);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    String scheme = lower(uri.getScheme());
    String host = NetworkHost.normalize(uri.getHost());
    String path = lower(uri.getPath());
    if (isLocalArchiveUrl(href, scheme)) {
      return Optional.empty();
    }
    if (SSRF_PROTOCOLS.contains(scheme)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_protocol",
              95,
              "XML attachment reference uses a dangerous protocol: " + scheme,
              request,
              Map.of("mechanism", hook, "scheme", scheme, "href", abbreviate(href))));
    }
    if (!scheme.equals("http") && !scheme.equals("https")) {
      return Optional.empty();
    }
    if (NetworkHost.isMetadata(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_aws",
              100,
              "XML attachment reference targets cloud instance metadata",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (NetworkHost.isInternal(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_userinput",
              95,
              "XML attachment reference targets an internal address",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (CallbackDomain.matches(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_common",
              90,
              "XML attachment reference targets a callback collection domain",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (looksObfuscatedHost(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              85,
              "XML attachment reference host appears obfuscated",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectDns(String host, RequestContext request) {
    if (host == null || host.isBlank()) {
      return Optional.empty();
    }
    String normalized = NetworkHost.normalize(host);
    if (CallbackDomain.matches(normalized)) {
      return Optional.of(
          Detection.log(
              "dns",
              "dns_blacklist",
              95,
              "DNS lookup targets a callback collection domain",
              request,
              Map.of("host", normalized)));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectXxeEntity(String name, String systemId, RequestContext request) {
    return detectXxeEntity(name, systemId, request, false);
  }

  public static Optional<Detection> detectXxeEntity(String name, String systemId, RequestContext request, boolean parserOpen) {
    if ("[xml]".equals(name) || systemId == null) {
      return Optional.empty();
    }
    boolean unc = systemId.startsWith("\\\\") || systemId.startsWith("//");
    int colon = systemId.indexOf(':');
    String protocol = colon < 0 ? "" : lower(systemId.substring(0, colon));
    if (!unc && !SSRF_PROTOCOLS.contains(protocol) && !"http".equals(protocol) && !"https".equals(protocol)) {
      return Optional.empty();
    }
    return Optional.of(Detection.log(
        "xxe", "xxe_protocol", unc ? 100 : 90,
        unc ? "XML external entity uses SMB/UNC path" : "XML external entity uses protocol " + protocol,
        request, Map.of("name", String.valueOf(name), "systemId", abbreviate(systemId),
            "decision_basis", parserOpen ? "parser_url_open" : "declared_identifier")));
  }

  public static boolean requestSuppliesHttpUrl(URI uri, String address, String host, RequestContext request) {
    return requestControlsUrl(uri, address, NetworkHost.normalize(host), request);
  }

  private static boolean requestControlsAdminPath(URI destination, RequestContext request) {
    if (request == null || !request.active() || destination == null) return false;
    String path = destination.getRawPath();
    if (path == null || !path.startsWith("/")) return false;
    return request.inputParameters().values().stream().anyMatch(values -> values.contains(path))
        || bodyHasSinkValue(request, path);
  }

  private static boolean requestControlsUrl(URI destination, String rawUrl, String host, RequestContext request) {
    if (request == null || !request.active() || (host.isEmpty() && (destination == null || destination.getRawAuthority() == null))) {
      return false;
    }
    for (var parameter : request.inputParameters().entrySet()) {
      for (String value : parameter.getValue()) {
        if (value == null || value.isBlank()) {
          continue;
        }
        if (value.equals(rawUrl) || matchesHttpArchive(value, destination)) {
          return true;
        }
        if (!host.isEmpty()
            && ("host".equalsIgnoreCase(parameter.getKey()) || "hostname".equalsIgnoreCase(parameter.getKey()))
            && NetworkHost.destinationKey(value).equals(NetworkHost.destinationKey(host))) {
          return true;
        }
        if (destination != null && matchesUrlBase(value, destination)) {
          return true;
        }
      }
    }
    if (bodyHasSinkValue(request, rawUrl) || matchesHttpArchive(request.body().trim(), destination)) return true;
    if ((request.body().contains("!/") || request.body().indexOf('\\') >= 0) && jsonConfigBody(request)) {
      for (var field : jsonStringFields(request.body())) {
        if (matchesHttpArchive(field.value(), destination)) return true;
      }
    }
    return false;
  }

  private static boolean matchesHttpArchive(String value, URI destination) {
    String archive = HttpTransportObservation.archiveAddress(value);
    if (archive == null || destination == null) return false;
    try {
      URI supplied = URI.create(archive);
      String path = supplied.getRawPath();
      return supplied.getHost() != null && supplied.getScheme().equalsIgnoreCase(destination.getScheme())
          && NetworkHost.destinationKey(supplied.getHost()).equals(NetworkHost.destinationKey(destination.getHost()))
          && effectivePort(supplied) == effectivePort(destination)
          && (path.isEmpty() ? "/" : path).equals(destination.getRawPath())
          && java.util.Objects.equals(supplied.getRawQuery(), destination.getRawQuery());
    } catch (IllegalArgumentException invalid) {
      return false;
    }
  }

  private static boolean matchesUrlBase(String value, URI destination) {
    if (!value.regionMatches(true, 0, "https://", 0, 8)
        && !value.regionMatches(true, 0, "http://", 0, 7)) {
      return false;
    }
    URI supplied;
    try {
      supplied = URI.create(value);
    } catch (IllegalArgumentException ignored) {
      return false;
    }
    if (supplied.getHost() == null || !supplied.getScheme().equalsIgnoreCase(destination.getScheme())
        || !NetworkHost.destinationKey(supplied.getHost()).equals(NetworkHost.destinationKey(destination.getHost()))
        || effectivePort(supplied) != effectivePort(destination)) {
      return false;
    }
    String query = supplied.getRawQuery();
    String base = supplied.getRawPath();
    String path = destination.getRawPath();
    return (query == null || query.equals(destination.getRawQuery()))
        && (path.equals(base) || path.startsWith(base.endsWith("/") ? base : base + "/"));
  }

  private static int effectivePort(URI uri) {
    return uri.getPort() >= 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
  }

  private static boolean looksObfuscatedHost(String host) {
    if (host == null || host.isBlank()) {
      return false;
    }
    // URI.getHost retains the zone identifier of a scoped IPv6 address.
    if (host.indexOf(':') >= 0) {
      return false;
    }
    return host.matches("0x[0-9a-f]+")
        || host.matches("\\d+")
        || host.matches(".*%[0-9a-fA-F]{2}.*")
        || host.matches(".*[。｡．].*");
  }

  private static boolean isLocalArchiveUrl(String rawUrl, String scheme) {
    String normalized = lower(rawUrl);
    return "jar".equals(scheme)
        && (normalized.startsWith("jar:file:") || normalized.startsWith("jar:nested:"));
  }

  private static boolean fileUrlNeedsInspection(URI uri, String rawUrl, RequestContext request) {
    String path = uri.getPath();
    if (path == null || !path.startsWith("/") || path.startsWith("//")
        || path.indexOf('\\') >= 0 || path.indexOf('\0') >= 0 || uri.getRawAuthority() != null) {
      return true;
    }
    String normalized = normalizePath(path);
    boolean sensitive = sensitiveFileLocation(normalized);
    boolean deploymentResource = PROTECTED_WEBAPP_RESOURCE.matcher(normalized).find();
    if (sensitive || requestControlsReadPath(path, request, deploymentResource,
        deploymentResource || !READ_SAFE_EXTENSION.matcher(normalized).matches() || !protocolOf(path).isEmpty())
        || bodyHasSinkValue(request, rawUrl)) {
      return true;
    }
    // A fixed application path can be opened by URL APIs during a request.
    // Check whether a request value actually supplies the local URL or base.
    for (List<String> values : request.inputParameters().values()) {
      for (String value : values) {
        if (value == null || !value.regionMatches(true, 0, "file:", 0, 5)) {
          continue;
        }
        try {
          URI supplied = URI.create(value);
          String base = supplied.getPath();
          if (supplied.getRawAuthority() == null && base != null && !base.isEmpty()
              && (path.equals(base) || path.startsWith(base.endsWith("/") ? base : base + "/"))) {
            return true;
          }
        } catch (IllegalArgumentException ignored) {
          // Ordinary text can start with a URI scheme.
        }
      }
    }
    return false;
  }

  private static String xmlAttachmentMechanism(String mechanism) {
    String normalized = lower(mechanism).replace('_', '-');
    if (normalized.equals("cxf-aegis-xop") || normalized.equals("cxf-aegis-mtom")) {
      return "cxf-aegis-xop";
    }
    return "";
  }

  private static String attachmentHref(String href) {
    String value = href == null ? "" : href.trim();
    int cid = lower(value).indexOf("cid:");
    if (cid >= 0) {
      value = value.substring(cid + 4).trim();
    }
    return value;
  }
}
