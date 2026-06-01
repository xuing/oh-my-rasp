package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.detect.DetectorEngine;
import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.File;
import java.lang.StackWalker.StackFrame;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public final class OhMyRaspHooks {
  private static final DetectorEngine DETECTORS = new DetectorEngine();
  private static final ThreadLocal<RequestContext> REQUEST =
      ThreadLocal.withInitial(RequestContext::empty);
  private static final ThreadLocal<Object> RESPONSE = new ThreadLocal<>();
  private static final StackWalker STACK_WALKER =
      StackWalker.getInstance(
          Set.of(StackWalker.Option.RETAIN_CLASS_REFERENCE, StackWalker.Option.SHOW_REFLECT_FRAMES));

  private OhMyRaspHooks() {}

  public static void enterHttpRequest(Object request, Object response) {
    try {
      RequestContext context = buildRequestContext(request);
      REQUEST.set(context);
      RESPONSE.set(response);
      emit(DETECTORS.detectRequest(context), false);
    } catch (OhMyRaspBlockException blocked) {
      REQUEST.remove();
      RESPONSE.remove();
      throw blocked;
    } catch (Throwable throwable) {
      quiet("enterHttpRequest", throwable);
    }
  }

  public static void beforeSyntheticHttpRequest(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers) {
    try {
      RequestContext context = new RequestContext(method, uri, query, parameters, headers);
      emit(DETECTORS.detectRequest(context));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticHttpRequest", throwable);
    }
  }

  public static void exitHttpRequest() {
    REQUEST.remove();
    RESPONSE.remove();
  }

  public static void beforeProcessBuilderStart(ProcessBuilder processBuilder) {
    beforeProcessBuilderStart(processBuilder, stackTraceClassNames());
  }

  public static void beforeProcessBuilderStart(
      ProcessBuilder processBuilder, List<String> stackClassNames) {
    try {
      emit(DETECTORS.detectCommand(processBuilder.command(), currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeProcessBuilderStart", throwable);
    }
  }

  public static void beforeSql(String query) {
    try {
      emit(DETECTORS.detectSql(query, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSql", throwable);
    }
  }

  public static void beforeSqlException(
      String server, String errorCode, String errorState, String errorMessage, String query) {
    try {
      emit(
          DETECTORS.detectSqlException(
              server, errorCode, errorState, errorMessage, query, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSqlException", throwable);
    }
  }

  public static void beforeSqlRegex(String query, String regex) {
    try {
      emit(DETECTORS.detectSqlRegex(query, regex, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSqlRegex", throwable);
    }
  }

  public static void beforeUrlOpen(Object url) {
    try {
      String raw = url instanceof URL typed ? typed.toExternalForm() : String.valueOf(url);
      emit(DETECTORS.detectUrl(raw, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeUrlOpen", throwable);
    }
  }

  public static void beforeDnsLookup(String host) {
    try {
      emit(DETECTORS.detectDns(host, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeDnsLookup", throwable);
    }
  }

  public static void beforeJndiLookup(Object name) {
    try {
      emit(DETECTORS.detectJndi(String.valueOf(name), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJndiLookup", throwable);
    }
  }

  public static void beforeFileRead(String path) {
    try {
      emit(DETECTORS.detectFileRead(path, currentRequest(), isXmlParserStack()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileRead", throwable);
    }
  }

  public static void beforeFileReadObject(Object file) {
    beforeFileRead(pathFrom(file));
  }

  public static void beforeFileWrite(String path) {
    beforeFileWrite(path, stackTraceClassNames());
  }

  public static void beforeFileWrite(String path, List<String> stackClassNames) {
    try {
      emit(DETECTORS.detectFileWrite(path, currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileWrite", throwable);
    }
  }

  public static void beforeFileWriteObject(Object file) {
    beforeFileWrite(pathFrom(file));
  }

  public static void beforeFileDelete(Object file) {
    try {
      emit(DETECTORS.detectFileDelete(pathFrom(file), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileDelete", throwable);
    }
  }

  public static void beforeDirectoryList(Object file) {
    beforeDirectoryList(file, stackTraceClassNames());
  }

  public static void beforeDirectoryList(Object file, List<String> stackClassNames) {
    try {
      emit(DETECTORS.detectDirectoryList(pathFrom(file), currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeDirectoryList", throwable);
    }
  }

  public static void beforeInclude(String url, String realPath, String function) {
    try {
      emit(DETECTORS.detectInclude(url, realPath, function, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeInclude", throwable);
    }
  }

  public static void beforeFileUpload(String filename) {
    try {
      emit(DETECTORS.detectFileUpload(filename, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileUpload", throwable);
    }
  }

  public static void beforeWebdavUpload(String source, String destination, String method) {
    try {
      emit(DETECTORS.detectWebdavUpload(source, destination, method, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebdavUpload", throwable);
    }
  }

  public static void beforeRename(String source, String destination) {
    try {
      emit(DETECTORS.detectRename(source, destination, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeRename", throwable);
    }
  }

  public static void beforeLink(String source, String destination, String type) {
    try {
      emit(DETECTORS.detectLink(source, destination, type, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeLink", throwable);
    }
  }

  public static void beforePathRead(Object path) {
    beforeFileRead(pathFrom(path));
  }

  public static void beforePathWrite(Object path) {
    beforeFileWrite(pathFrom(path));
  }

  public static void beforePathWrite(Object path, List<String> stackClassNames) {
    beforeFileWrite(pathFrom(path), stackClassNames);
  }

  public static void beforePathDelete(Object path) {
    beforeFileDelete(path);
  }

  public static void beforeXmlEntity(String name, Object source) {
    try {
      String systemId = invokeString(source, "getSystemId").orElse(String.valueOf(source));
      emit(DETECTORS.detectXxeEntity(name, systemId, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXmlEntity", throwable);
    }
  }

  public static void beforeXxeFileRead(String path) {
    try {
      emit(DETECTORS.detectFileRead(path, currentRequest(), true));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXxeFileRead", throwable);
    }
  }

  public static void beforeDeserializationClass(String className) {
    try {
      emit(DETECTORS.detectDeserialization(className, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeDeserializationClass", throwable);
    }
  }

  public static void beforeOgnl(String expression) {
    try {
      emit(DETECTORS.detectOgnl(expression, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeOgnl", throwable);
    }
  }

  public static void beforeEval(String function, String code) {
    try {
      emit(DETECTORS.detectEval(function, code, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeEval", throwable);
    }
  }

  public static void beforeLoadLibrary(String function, String path, boolean windows) {
    try {
      emit(DETECTORS.detectLoadLibrary(function, path, windows, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeLoadLibrary", throwable);
    }
  }

  public static void beforeResponseDataLeak(String contentType, String content) {
    try {
      emit(DETECTORS.detectResponseDataLeak(contentType, content, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeResponseDataLeak", throwable);
    }
  }

  public static void beforeXssEcho(String content) {
    try {
      emit(DETECTORS.detectXssEcho(content, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXssEcho", throwable);
    }
  }

  public static void beforeWebshellEval(String function, String code) {
    try {
      emit(DETECTORS.detectWebshellEval(function, code, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellEval", throwable);
    }
  }

  public static void beforeWebshellCommand(String command) {
    try {
      emit(DETECTORS.detectWebshellCommand(List.of(command), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellCommand", throwable);
    }
  }

  public static void beforeWebshellFileWrite(String path, String content) {
    try {
      emit(DETECTORS.detectWebshellFileWrite(path, content, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellFileWrite", throwable);
    }
  }

  public static void beforeWebshellCallable(String function) {
    try {
      emit(DETECTORS.detectWebshellCallable(function, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellCallable", throwable);
    }
  }

  public static void beforeWebshellLdPreload(String name, String value) {
    try {
      emit(DETECTORS.detectWebshellLdPreload(name, value, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellLdPreload", throwable);
    }
  }

  public static RequestContext currentRequest() {
    return REQUEST.get();
  }

  private static RequestContext buildRequestContext(Object request) throws ReflectiveOperationException {
    if (request == null) {
      return RequestContext.empty();
    }
    String method = invokeString(request, "getMethod").orElse("");
    String uri = invokeString(request, "getRequestURI").orElse("");
    String query = invokeString(request, "getQueryString").orElse("");
    Map<String, List<String>> parameters = readParameterMap(request);
    Map<String, String> headers = readHeaders(request);
    return new RequestContext(method, uri, query, parameters, headers);
  }

  private static Map<String, List<String>> readParameterMap(Object request)
      throws ReflectiveOperationException {
    Object raw = request.getClass().getMethod("getParameterMap").invoke(request);
    if (!(raw instanceof Map<?, ?> map)) {
      return Map.of();
    }
    var copy = new LinkedHashMap<String, List<String>>();
    map.forEach((key, value) -> copy.put(String.valueOf(key), toStringList(value)));
    return copy;
  }

  private static Map<String, String> readHeaders(Object request) {
    try {
      Method namesMethod = request.getClass().getMethod("getHeaderNames");
      Object names = namesMethod.invoke(request);
      if (!(names instanceof Enumeration<?> enumeration)) {
        return Map.of();
      }
      Method headerMethod = request.getClass().getMethod("getHeader", String.class);
      var headers = new LinkedHashMap<String, String>();
      while (enumeration.hasMoreElements()) {
        String name = String.valueOf(enumeration.nextElement());
        String value = String.valueOf(headerMethod.invoke(request, name));
        headers.put(name.toLowerCase(Locale.ROOT), value);
      }
      return headers;
    } catch (ReflectiveOperationException | RuntimeException e) {
      return Map.of();
    }
  }

  private static List<String> toStringList(Object value) {
    if (value == null) {
      return List.of();
    }
    if (value instanceof String string) {
      return List.of(string);
    }
    if (value instanceof Iterable<?> iterable) {
      var items = new ArrayList<String>();
      for (Object item : iterable) {
        items.add(String.valueOf(item));
      }
      return items;
    }
    if (value.getClass().isArray()) {
      int length = Array.getLength(value);
      var items = new ArrayList<String>(length);
      for (int i = 0; i < length; i++) {
        items.add(String.valueOf(Array.get(value, i)));
      }
      return items;
    }
    return List.of(String.valueOf(value));
  }

  private static Optional<String> invokeString(Object target, String methodName) {
    try {
      Object value = target.getClass().getMethod(methodName).invoke(target);
      return value == null ? Optional.empty() : Optional.of(String.valueOf(value));
    } catch (ReflectiveOperationException | RuntimeException e) {
      return Optional.empty();
    }
  }

  private static String pathFrom(Object value) {
    if (value == null) {
      return "";
    }
    if (value instanceof File file) {
      return file.getPath();
    }
    return String.valueOf(value);
  }

  private static boolean isXmlParserStack() {
    try {
      return STACK_WALKER.walk(OhMyRaspHooks::containsXmlParser);
    } catch (Throwable ignored) {
      return false;
    }
  }

  private static List<String> stackTraceClassNames() {
    try {
      return STACK_WALKER.walk(
          frames -> frames.map(frame -> frame.getDeclaringClass().getName()).limit(48).toList());
    } catch (Throwable ignored) {
      return Collections.emptyList();
    }
  }

  private static boolean containsXmlParser(Stream<StackFrame> frames) {
    return frames
        .map(frame -> frame.getDeclaringClass().getName())
        .anyMatch(name -> name.startsWith("com.sun.org.apache.xerces") || name.contains(".xerces."));
  }

  private static void emit(Optional<Detection> detection) {
    emit(detection, true);
  }

  private static void emit(Optional<Detection> detection, boolean throwOnBlock) {
    if (detection.isEmpty()) {
      return;
    }
    Detection value = detection.orElseThrow();
    boolean willBlock = blockEnabled() && value.request() != null && value.request().active();
    Detection event = willBlock ? value.withAction("block") : value;
    JsonEventLogger.get().log(event);
    if (willBlock) {
      redirectToBlockPage(event);
      if (throwOnBlock) {
        throw new OhMyRaspBlockException(event);
      }
    }
  }

  private static boolean blockEnabled() {
    return Boolean.getBoolean("ohmyrasp.block")
        || "true".equalsIgnoreCase(System.getenv("OHMYRASP_BLOCK"));
  }

  private static void redirectToBlockPage(Detection detection) {
    Object response = RESPONSE.get();
    if (response == null) {
      return;
    }
    String location =
        "/rasp/blocked?hook="
            + encode(detection.hook())
            + "&algorithm="
            + encode(detection.algorithm())
            + "&message="
            + encode(detection.message());
    try {
      Method sendRedirect = response.getClass().getMethod("sendRedirect", String.class);
      sendRedirect.invoke(response, location);
    } catch (ReflectiveOperationException | RuntimeException e) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP] redirect failed: " + e);
      }
    }
  }

  private static String encode(String value) {
    return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
  }

  private static void quiet(String hook, Throwable throwable) {
    if (Boolean.getBoolean("ohmyrasp.debug")) {
      System.err.println("[OHMYRASP] hook failure in " + hook + ": " + throwable);
    }
  }
}
