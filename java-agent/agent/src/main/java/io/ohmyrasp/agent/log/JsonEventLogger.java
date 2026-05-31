package io.ohmyrasp.agent.log;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;

public final class JsonEventLogger {
  private static final JsonEventLogger INSTANCE = new JsonEventLogger();

  private final Path logPath;

  private JsonEventLogger() {
    String configured = System.getProperty("ohmyrasp.log");
    if (configured == null || configured.isBlank()) {
      configured = System.getenv("OHMYRASP_LOG");
    }
    if (configured == null || configured.isBlank()) {
      configured = "/tmp/ohmyrasp-events.jsonl";
    }
    logPath = Path.of(configured);
  }

  public static JsonEventLogger get() {
    return INSTANCE;
  }

  public synchronized void log(Detection detection) {
    String json = toJson(detection);
    try {
      Path parent = logPath.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      Files.writeString(
          logPath,
          json + System.lineSeparator(),
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE,
          StandardOpenOption.APPEND);
    } catch (IOException e) {
      System.err.println("[OHMYRASP] failed to write event log: " + e);
    }
    System.out.println("[OHMYRASP] " + json);
  }

  private static String toJson(Detection detection) {
    var builder = new StringBuilder(512);
    builder.append('{');
    field(builder, "timestamp", detection.timestamp().toString()).append(',');
    field(builder, "hook", detection.hook()).append(',');
    field(builder, "algorithm", detection.algorithm()).append(',');
    field(builder, "action", detection.action()).append(',');
    numberField(builder, "confidence", detection.confidence()).append(',');
    field(builder, "message", detection.message()).append(',');
    builder.append("\"request\":");
    request(builder, detection.request());
    builder.append(',');
    builder.append("\"details\":");
    stringMap(builder, detection.details());
    builder.append('}');
    return builder.toString();
  }

  private static void request(StringBuilder builder, RequestContext request) {
    RequestContext current = request == null ? RequestContext.empty() : request;
    builder.append('{');
    field(builder, "method", current.method()).append(',');
    field(builder, "uri", current.uri()).append(',');
    field(builder, "query", current.query()).append(',');
    builder.append("\"parameters\":");
    listMap(builder, current.parameters());
    builder.append(',');
    builder.append("\"headers\":");
    stringMap(builder, current.headers());
    builder.append('}');
  }

  private static StringBuilder field(StringBuilder builder, String name, String value) {
    return builder.append('"').append(escape(name)).append("\":\"").append(escape(value)).append('"');
  }

  private static StringBuilder numberField(StringBuilder builder, String name, int value) {
    return builder.append('"').append(escape(name)).append("\":").append(value);
  }

  private static void stringMap(StringBuilder builder, Map<String, String> map) {
    builder.append('{');
    boolean first = true;
    for (var entry : map.entrySet()) {
      if (!first) {
        builder.append(',');
      }
      first = false;
      field(builder, entry.getKey(), entry.getValue());
    }
    builder.append('}');
  }

  private static void listMap(StringBuilder builder, Map<String, List<String>> map) {
    builder.append('{');
    boolean firstEntry = true;
    for (var entry : map.entrySet()) {
      if (!firstEntry) {
        builder.append(',');
      }
      firstEntry = false;
      builder.append('"').append(escape(entry.getKey())).append("\":[");
      boolean firstValue = true;
      for (String value : entry.getValue()) {
        if (!firstValue) {
          builder.append(',');
        }
        firstValue = false;
        builder.append('"').append(escape(value)).append('"');
      }
      builder.append(']');
    }
    builder.append('}');
  }

  private static String escape(String value) {
    if (value == null) {
      return "";
    }
    var builder = new StringBuilder(value.length() + 16);
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> builder.append("\\\"");
        case '\\' -> builder.append("\\\\");
        case '\b' -> builder.append("\\b");
        case '\f' -> builder.append("\\f");
        case '\n' -> builder.append("\\n");
        case '\r' -> builder.append("\\r");
        case '\t' -> builder.append("\\t");
        default -> {
          if (ch < 0x20) {
            builder.append(String.format("\\u%04x", (int) ch));
          } else {
            builder.append(ch);
          }
        }
      }
    }
    return builder.toString();
  }
}
