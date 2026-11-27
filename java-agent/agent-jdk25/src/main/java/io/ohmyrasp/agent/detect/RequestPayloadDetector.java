package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DeserializationTypes.dangerousPolymorphicType;
import static io.ohmyrasp.agent.detect.DeserializationTypes.normalizeJavaTypeName;
import static io.ohmyrasp.agent.detect.DeserializationTypes.xmlGadgetClassPriority;
import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.JdbcDetector.h2JdbcInitConfig;
import static io.ohmyrasp.agent.detect.RemoteResourceDetector.JNDI_LOOKUP_PROTOCOLS;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodeXmlCharacterReferences;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedVariants;
import static io.ohmyrasp.agent.detect.RequestValues.redactBodyRequest;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** XML entity and polymorphic binding request rules. */
final class RequestPayloadDetector {
  private static final Pattern REQUEST_XXE_EXTERNAL_ENTITY =
      Pattern.compile(
          "(?is)<!\\s*DOCTYPE\\b.{0,4096}<!\\s*ENTITY\\b.{0,1024}\\b(?:SYSTEM|PUBLIC)\\b.{0,512}['\"]\\s*([a-z][a-z0-9.+-]{0,20}):");

  private static final Pattern REQUEST_TYPED_PARAMETER_CLASS =
      Pattern.compile(
          "^(?:\\[+L?)?[A-Za-z_$][\\w$]*(?:[.$][A-Za-z_$][\\w$]*){1,}(?:;|\\[\\])?$");

  private static final Pattern TYPED_PAYLOAD_CLASS_ATTRIBUTE =
      Pattern.compile(
          "(?is)\\b(?:type|class|classname|className|javaClass|@type)\\s*=\\s*['\"]([^'\"]{1,512})['\"]");

  private static final Pattern TYPED_PAYLOAD_JSON_TYPE =
      Pattern.compile(
          "(?is)[\"'](?:@type|class|classname|className|javaClass)[\"']\\s*:\\s*[\"']([^\"']{1,512})[\"']");

  private static final Pattern TYPED_PAYLOAD_YAML_TAG =
      Pattern.compile("(?m)!{1,2}\\s*([A-Za-z_$][\\w$]*(?:[./$][A-Za-z_$][\\w$]*){1,80})");

  private static final Pattern TYPED_PAYLOAD_REMOTE_NAMING_URL =
      Pattern.compile("(?is)\\b(ldap|ldaps|rmi|iiop|corba|corbaname|corbaloc)://[^\\s\"'<>]+");

  private static final Pattern XML_PAYLOAD_CLASS_ATTRIBUTE =
      Pattern.compile(
          "(?is)\\b(?:class|type|classname|className|javaClass)\\s*=\\s*['\"]([^'\"<>]{1,512})['\"]");

  private static final Pattern XML_PAYLOAD_CLASS_ELEMENT =
      Pattern.compile(
          "(?is)<\\s*(?:[A-Za-z0-9_.-]+:)?(?:class|type|classname|className|javaClass)\\b[^>]*>"
              + "\\s*([^<\\s]{1,512})\\s*</\\s*(?:[A-Za-z0-9_.-]+:)?"
              + "(?:class|type|classname|className|javaClass)\\s*>");

  private static final Pattern XML_PAYLOAD_JAVA_TYPE_TAG =
      Pattern.compile("(?is)<\\s*/?\\s*([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*){1,80})\\b");

  private static final Set<String> XXE_EXTERNAL_ENTITY_PROTOCOLS =
      Set.of("file", "jar", "http", "https", "ftp", "gopher", "ldap", "rmi", "netdoc");

  private RequestPayloadDetector() {}

  static Optional<Detection> binding(RequestContext request) {
    Optional<RequestXxePayloadMatch> xxePayload = requestXxePayload(request);
    if (xxePayload.isPresent()) {
      RequestXxePayloadMatch match = xxePayload.orElseThrow();
      RequestContext redactedRequest = redactXxePayloadRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_xxe_payload",
              90,
              "Request parameter carries an external XML entity payload",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "scheme", match.scheme(),
                  "xmlLength", String.valueOf(match.xmlLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<TypedParameterDeserializationMatch> typedParameter =
        typedParameterDeserialization(request);
    if (typedParameter.isPresent()) {
      TypedParameterDeserializationMatch match = typedParameter.orElseThrow();
      RequestContext redactedRequest = redactTypedParameterDeserializationRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_typed_parameter_deserialization",
              92,
              "Request parameter declares a dangerous Java binding type",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "class", match.className(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<XmlPolymorphicGadgetPayloadMatch> xmlGadgetPayload =
        xmlPolymorphicGadgetPayload(request);
    if (xmlGadgetPayload.isPresent()) {
      XmlPolymorphicGadgetPayloadMatch match = xmlGadgetPayload.orElseThrow();
      RequestContext redactedRequest = redactBodyRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_xml_polymorphic_gadget",
              93,
              "XML request payload declares a dangerous polymorphic gadget type",
              redactedRequest,
              Map.of(
                  "class", match.className(),
                  "source", match.source(),
                  "bodyLength", String.valueOf(match.bodyLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<TypedPayloadDeserializationMatch> typedPayload =
        typedPayloadDeserialization(request);
    if (typedPayload.isPresent()) {
      TypedPayloadDeserializationMatch match = typedPayload.orElseThrow();
      RequestContext redactedRequest = redactTypedPayloadDeserializationRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_typed_payload_deserialization",
              92,
              "Request payload declares a dangerous Java binding type",
              redactedRequest,
              Map.of(
                  "source", match.source(),
                  "parameter", match.parameter(),
                  "class", match.className(),
                  "trigger", match.trigger(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  private record RequestXxePayloadMatch(String parameter, String scheme, int xmlLength) {}

  private record TypedParameterDeserializationMatch(
      String parameter, String className, int valueLength) {}

  private record TypedParameterName(String parameter, String className) {}

  private record TypedPayloadDeserializationMatch(
      String source, String parameter, String className, String trigger, int valueLength) {}

  private record TypedPayloadValue(String className, String trigger) {}

  private record XmlPolymorphicGadgetPayloadMatch(
      String className, String source, int bodyLength) {}

  private record XmlTypeCandidate(String className, String source) {}

  private static Optional<RequestXxePayloadMatch> requestXxePayload(RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        String scheme = xxePayloadScheme(value);
        if (!scheme.isBlank()) {
          return Optional.of(
              new RequestXxePayloadMatch(
                  entry.getKey(), scheme, value == null ? 0 : value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static String xxePayloadScheme(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    String decoded = decodeXmlCharacterReferences(percentDecode(value));
    var matcher = REQUEST_XXE_EXTERNAL_ENTITY.matcher(decoded);
    while (matcher.find()) {
      String scheme = lower(matcher.group(1));
      if (XXE_EXTERNAL_ENTITY_PROTOCOLS.contains(scheme)) {
        return scheme;
      }
    }
    return "";
  }

  private static RequestContext redactXxePayloadRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(xxePayloadScheme(value).isBlank() ? value : "[redacted]");
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactXxePayloadQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactXxePayloadQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String value = percentDecode(parts[i].substring(separator + 1));
      if (!xxePayloadScheme(value).isBlank()) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TypedParameterDeserializationMatch> typedParameterDeserialization(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      Optional<TypedParameterName> typedName = typedParameterName(entry.getKey());
      if (typedName.isEmpty()) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value != null && !value.isBlank()) {
          TypedParameterName match = typedName.orElseThrow();
          return Optional.of(
              new TypedParameterDeserializationMatch(
                  match.parameter(), match.className(), value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<TypedParameterName> typedParameterName(String rawName) {
    if (rawName == null || rawName.isBlank()) {
      return Optional.empty();
    }
    String decoded = percentDecode(rawName).trim();
    int separator = decoded.lastIndexOf(':');
    if (separator <= 0 || separator == decoded.length() - 1) {
      return Optional.empty();
    }
    String parameter = decoded.substring(0, separator).trim();
    String type = decoded.substring(separator + 1).trim();
    if (type.endsWith("[]")) {
      type = type.substring(0, type.length() - 2);
    }
    String normalized = normalizeJavaTypeName(type);
    if (!REQUEST_TYPED_PARAMETER_CLASS.matcher(type).matches()
        && !REQUEST_TYPED_PARAMETER_CLASS.matcher(normalized).matches()) {
      return Optional.empty();
    }
    if (!dangerousPolymorphicType(normalized)) {
      return Optional.empty();
    }
    return Optional.of(new TypedParameterName(parameter, normalized));
  }

  private static RequestContext redactTypedParameterDeserializationRequest(
      RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (typedParameterName(name).isEmpty()) {
                parameters.put(name, values == null ? List.of() : values);
                return;
              }
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(value == null || value.isBlank() ? value : "[redacted]");
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTypedParameterDeserializationQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactTypedParameterDeserializationQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      String value = parts[i].substring(separator + 1);
      if (typedParameterName(percentDecode(name)).isPresent() && !percentDecode(value).isBlank()) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TypedPayloadDeserializationMatch> typedPayloadDeserialization(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<TypedPayloadValue> payload = typedPayloadValue(value);
        if (payload.isPresent()) {
          TypedPayloadValue match = payload.orElseThrow();
          return Optional.of(
              new TypedPayloadDeserializationMatch(
                  "parameter", entry.getKey(), match.className(), match.trigger(), value.length()));
        }
      }
    }
    Optional<TypedPayloadValue> bodyPayload = typedPayloadValue(request.body());
    return bodyPayload.map(
        match ->
            new TypedPayloadDeserializationMatch(
                "body", "body", match.className(), match.trigger(), request.body().length()));
  }

  private static Optional<TypedPayloadValue> typedPayloadValue(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    String inspected = value.length() > 8192 ? value.substring(0, 8192) : value;
    if (!mayCarryBindingSyntax(inspected)) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(inspected)) {
      if (!typedPayloadBindingSyntax(variant)) {
        continue;
      }
      Optional<String> className = dangerousTypedPayloadClass(variant);
      if (className.isEmpty()) {
        continue;
      }
      Optional<String> trigger = typedPayloadTrigger(variant);
      if (trigger.isPresent()) {
        return Optional.of(new TypedPayloadValue(className.orElseThrow(), trigger.orElseThrow()));
      }
    }
    return Optional.empty();
  }

  /**
   * Whether some decoding of the value can hold binding syntax: each form typedPayloadBindingSyntax accepts needs
   * one of these characters, and percent-decoding, the only decoding applied, needs a '%' to produce one.
   */
  private static boolean mayCarryBindingSyntax(String value) {
    for (int i = 0; i < value.length(); i++) {
      switch (value.charAt(i)) {
        case '<', '=', '"', '\'', '!', '@', '%' -> {
          return true;
        }
        default -> { }
      }
    }
    return false;
  }

  private static boolean typedPayloadBindingSyntax(String value) {
    String normalized = lower(value);
    return normalized.contains("<wddxpacket")
        || normalized.contains("<struct")
        || TYPED_PAYLOAD_CLASS_ATTRIBUTE.matcher(value).find()
        || TYPED_PAYLOAD_JSON_TYPE.matcher(value).find()
        || TYPED_PAYLOAD_YAML_TAG.matcher(value).find()
        || normalized.contains("@type")
        || normalized.contains("!!");
  }

  private static Optional<String> dangerousTypedPayloadClass(String value) {
    var candidates = new ArrayList<String>();
    var attributeMatcher = TYPED_PAYLOAD_CLASS_ATTRIBUTE.matcher(value);
    while (attributeMatcher.find()) {
      candidates.add(attributeMatcher.group(1));
    }
    var jsonMatcher = TYPED_PAYLOAD_JSON_TYPE.matcher(value);
    while (jsonMatcher.find()) {
      candidates.add(jsonMatcher.group(1));
    }
    var yamlMatcher = TYPED_PAYLOAD_YAML_TAG.matcher(value);
    while (yamlMatcher.find()) {
      candidates.add(yamlMatcher.group(1));
    }
    for (String candidate : candidates) {
      Optional<String> className = dangerousTypedPayloadClassCandidate(candidate);
      if (className.isPresent()) {
        return className;
      }
    }
    return Optional.empty();
  }

  private static Optional<String> dangerousTypedPayloadClassCandidate(String rawClassName) {
    if (rawClassName == null || rawClassName.isBlank()) {
      return Optional.empty();
    }
    var candidates = new ArrayList<String>();
    String normalized = normalizeJavaTypeName(rawClassName);
    candidates.add(normalized);
    if (normalized.length() > 2 && normalized.startsWith("x") && normalized.endsWith("x")) {
      candidates.add(normalized.substring(1, normalized.length() - 1));
    }
    for (String candidate : candidates) {
      String className = normalizeJavaTypeName(candidate);
      if (REQUEST_TYPED_PARAMETER_CLASS.matcher(className).matches()
          && dangerousPolymorphicType(className)) {
        return Optional.of(className);
      }
    }
    return Optional.empty();
  }

  private static Optional<XmlPolymorphicGadgetPayloadMatch> xmlPolymorphicGadgetPayload(
      RequestContext request) {
    if (request == null || !request.active() || request.body().isBlank()) {
      return Optional.empty();
    }
    String body = request.body();
    String contentType = lower(request.header("content-type").orElse(""));
    for (String variant : decodedVariants(body)) {
      if (!looksLikeXmlPayload(variant, contentType)) {
        continue;
      }
      XmlPolymorphicGadgetPayloadMatch best = null;
      int bestPriority = Integer.MAX_VALUE;
      for (XmlTypeCandidate candidate : xmlTypeCandidates(variant)) {
        Optional<String> className = dangerousTypedPayloadClassCandidate(candidate.className());
        if (className.isPresent()) {
          String matchedClass = className.orElseThrow();
          int priority = xmlGadgetClassPriority(matchedClass);
          if (priority < bestPriority) {
            bestPriority = priority;
            best =
                new XmlPolymorphicGadgetPayloadMatch(
                    matchedClass, candidate.source(), body.length());
            if (bestPriority == 0) {
              return Optional.of(best);
            }
          }
        }
      }
      if (best != null) {
        return Optional.of(best);
      }
    }
    return Optional.empty();
  }

  private static boolean looksLikeXmlPayload(String value, String contentType) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String trimmed = value.stripLeading();
    if (!trimmed.startsWith("<")) {
      return false;
    }
    return contentType.isBlank()
        || contentType.contains("xml")
        || trimmed.startsWith("<?xml")
        || trimmed.regionMatches(true, 0, "<map", 0, "<map".length())
        || trimmed.regionMatches(true, 0, "<list", 0, "<list".length())
        || trimmed.regionMatches(true, 0, "<set", 0, "<set".length())
        || trimmed.regionMatches(true, 0, "<object", 0, "<object".length());
  }

  private static List<XmlTypeCandidate> xmlTypeCandidates(String xml) {
    if (xml == null || xml.isBlank()) {
      return List.of();
    }
    var candidates = new ArrayList<XmlTypeCandidate>();
    var attributeMatcher = XML_PAYLOAD_CLASS_ATTRIBUTE.matcher(xml);
    while (attributeMatcher.find()) {
      candidates.add(new XmlTypeCandidate(attributeMatcher.group(1), "xml-class-attribute"));
    }
    var elementMatcher = XML_PAYLOAD_CLASS_ELEMENT.matcher(xml);
    while (elementMatcher.find()) {
      candidates.add(new XmlTypeCandidate(elementMatcher.group(1), "xml-class-element"));
    }
    var tagMatcher = XML_PAYLOAD_JAVA_TYPE_TAG.matcher(xml);
    while (tagMatcher.find()) {
      candidates.add(new XmlTypeCandidate(tagMatcher.group(1), "xml-java-tag"));
    }
    return List.copyOf(candidates);
  }

  private static Optional<String> typedPayloadTrigger(String value) {
    Optional<String> namingScheme = remoteNamingUrlScheme(value);
    if (namingScheme.isPresent()) {
      return Optional.of("jndi:" + namingScheme.orElseThrow());
    }
    String normalized = lower(value);
    if (normalized.contains("hexasciiserializedmap") || normalized.contains("aced0005")) {
      return Optional.of("serialized");
    }
    if (h2JdbcInitConfig(value)) {
      return Optional.of("jdbc-h2-init");
    }
    return Optional.empty();
  }

  private static Optional<String> remoteNamingUrlScheme(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    var matcher = TYPED_PAYLOAD_REMOTE_NAMING_URL.matcher(value);
    while (matcher.find()) {
      String scheme = lower(matcher.group(1));
      if (JNDI_LOOKUP_PROTOCOLS.contains(scheme)) {
        return Optional.of(scheme);
      }
    }
    return Optional.empty();
  }

  private static RequestContext redactTypedPayloadDeserializationRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    typedPayloadValue(value).isPresent() ? "[redacted]" : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTypedPayloadDeserializationQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactTypedPayloadDeserializationQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String value = parts[i].substring(separator + 1);
      if (typedPayloadValue(percentDecode(value)).isPresent()) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }
}
