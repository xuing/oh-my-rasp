package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/** Recognize and redact serialized client state in an HTTP request. */
final class SerializedRequestState {
  private SerializedRequestState() {}

  private static final Set<String> CLIENT_STATE_PARAMETER_NAMES =
      Set.of(
          "javax.faces.viewstate",
          "jakarta.faces.viewstate",
          "viewstate",
          "facesviewstate",
          "clientstate");

  static Optional<Detection> serializedClientStateFinding(RequestContext request) {
    Optional<SerializedClientStateMatch> serializedClientState = serializedClientState(request);
    if (serializedClientState.isPresent()) {
      SerializedClientStateMatch match = serializedClientState.orElseThrow();
      RequestContext redactedRequest = redactSerializedClientStateRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_serialized_client_state",
              92,
              "Client-side state parameter carries a Java serialized object stream",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "encoding", match.encoding(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "payloadLength", String.valueOf(match.payloadLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  private record SerializedClientStateMatch(
      String parameter, String encoding, int valueLength, int payloadLength) {}

  private record SerializedClientStatePayload(String encoding, int payloadLength) {}

  static boolean startsWithJavaSerializationStream(byte[] plaintext) {
    return plaintext.length >= 4
        && (plaintext[0] & 0xff) == 0xac
        && (plaintext[1] & 0xff) == 0xed
        && plaintext[2] == 0
        && plaintext[3] == 5;
  }

  private static Optional<SerializedClientStateMatch> serializedClientState(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isClientStateParameterName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<SerializedClientStatePayload> payload = serializedClientStatePayload(value);
        if (payload.isPresent()) {
          SerializedClientStatePayload match = payload.orElseThrow();
          return Optional.of(
              new SerializedClientStateMatch(
                  entry.getKey(),
                  match.encoding(),
                  value == null ? 0 : value.length(),
                  match.payloadLength()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean isClientStateParameterName(String name) {
    String normalized = normalizeParameterName(name);
    return CLIENT_STATE_PARAMETER_NAMES.contains(normalized) || normalized.endsWith(".viewstate");
  }

  private static Optional<SerializedClientStatePayload> serializedClientStatePayload(
      String value) {
    if (value == null || value.isBlank() || value.length() > 262_144) {
      return Optional.empty();
    }
    Optional<byte[]> decoded = base64DecodeState(percentDecode(value.trim()));
    if (decoded.isEmpty()) {
      return Optional.empty();
    }
    byte[] bytes = decoded.orElseThrow();
    if (startsWithJavaSerializationStream(bytes)) {
      return Optional.of(new SerializedClientStatePayload("base64", bytes.length));
    }
    if (!startsWithGzip(bytes)) {
      return Optional.empty();
    }
    Optional<byte[]> decompressed = gunzipBounded(bytes, 262_144);
    if (decompressed.isEmpty()) {
      return Optional.empty();
    }
    byte[] payload = decompressed.orElseThrow();
    if (startsWithJavaSerializationStream(payload)) {
      return Optional.of(new SerializedClientStatePayload("base64+gzip", payload.length));
    }
    return Optional.empty();
  }

  private static Optional<byte[]> base64DecodeState(String value) {
    if (value == null) {
      return Optional.empty();
    }
    String compact = value.replaceAll("\\s+", "");
    if (compact.length() < 8) {
      return Optional.empty();
    }
    int remainder = compact.length() % 4;
    if (remainder > 0) {
      compact = compact + "=".repeat(4 - remainder);
    }
    try {
      return Optional.of(Base64.getDecoder().decode(compact));
    } catch (IllegalArgumentException e) {
      try {
        return Optional.of(Base64.getUrlDecoder().decode(compact));
      } catch (IllegalArgumentException ignored) {
        return Optional.empty();
      }
    }
  }

  private static boolean startsWithGzip(byte[] bytes) {
    return bytes.length >= 2 && (bytes[0] & 0xff) == 0x1f && (bytes[1] & 0xff) == 0x8b;
  }

  private static Optional<byte[]> gunzipBounded(byte[] bytes, int maxBytes) {
    try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(bytes));
        ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      byte[] buffer = new byte[512];
      int read;
      while ((read = gzip.read(buffer)) >= 0) {
        if (output.size() + read > maxBytes) {
          return Optional.empty();
        }
        output.write(buffer, 0, read);
      }
      return Optional.of(output.toByteArray());
    } catch (IOException | RuntimeException e) {
      return Optional.empty();
    }
  }

  private static RequestContext redactSerializedClientStateRequest(RequestContext request) {
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
                    isClientStateParameterName(name)
                            && serializedClientStatePayload(value).isPresent()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactSerializedClientStateQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactSerializedClientStateQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      String name = separator < 0 ? parts[i] : parts[i].substring(0, separator);
      if (isClientStateParameterName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }
}
