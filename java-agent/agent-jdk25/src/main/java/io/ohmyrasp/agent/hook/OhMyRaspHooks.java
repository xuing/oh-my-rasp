package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.detect.DetectorEngine;
import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.policy.AgentPolicy;
import io.ohmyrasp.agent.policy.PolicyEvaluation;
import io.ohmyrasp.agent.runtime.AgentRuntime;
import io.ohmyrasp.agent.runtime.DetectionMode;
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
import java.util.zip.ZipEntry;

public final class OhMyRaspHooks {
  private static final DetectorEngine DETECTORS = new DetectorEngine();
  private static volatile AgentPolicy POLICY = AgentPolicy.absent();
  private static volatile String POLICY_AGENT_KEY = "";
  private static final ThreadLocal<RequestContext> REQUEST =
      ThreadLocal.withInitial(RequestContext::empty);
  private static final ThreadLocal<Object> RESPONSE = new ThreadLocal<>();
  private static final ThreadLocal<String> ARCHIVE_ENTRY = new ThreadLocal<>();
  private static final StackWalker STACK_WALKER =
      StackWalker.getInstance(
          Set.of(StackWalker.Option.RETAIN_CLASS_REFERENCE, StackWalker.Option.SHOW_REFLECT_FRAMES));

  private OhMyRaspHooks() {}

  public static void installPolicy(AgentPolicy policy, String agentKey) {
    POLICY = policy == null ? AgentPolicy.empty() : policy;
    POLICY_AGENT_KEY = agentKey == null ? "" : agentKey;
  }

  public static void enterHttpRequest(Object request, Object response) {
    if (detectionDisabled()) {
      return;
    }
    // Time the full agent cost added to this request entry so the daemon's
    // business-latency panel reflects real (usually benign) traffic, not just
    // the rare attack path. Sampled inside sampleHookLatency.
    long started = System.nanoTime();
    try {
      RequestContext context = buildRequestContext(request);
      REQUEST.set(context);
      RESPONSE.set(response);
      emit(DETECTORS.detectRequest(context), false);
      emit(
          DETECTORS.detectServletIncludeAttributes(
              readServletIncludeAttributes(request), context, stackTraceClassNames()),
          false);
    } catch (OhMyRaspBlockException blocked) {
      REQUEST.remove();
      RESPONSE.remove();
      throw blocked;
    } catch (Throwable throwable) {
      quiet("enterHttpRequest", throwable);
    }
    JsonEventLogger.get().sampleHookLatency("http_request", elapsedMicros(started));
  }

  public static void beforeSyntheticHttpRequest(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers) {
    if (detectionDisabled()) {
      return;
    }
    try {
      RequestContext context = new RequestContext(method, uri, query, parameters, headers);
      emit(DETECTORS.detectRequest(context));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticHttpRequest", throwable);
    }
  }

  public static void beforeSyntheticHttpRequestWithBody(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers,
      String body) {
    if (detectionDisabled()) {
      return;
    }
    try {
      RequestContext context = new RequestContext(method, uri, query, parameters, headers, body);
      emit(DETECTORS.detectRequest(context));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticHttpRequestWithBody", throwable);
    }
  }

  public static void beforeSyntheticJaasConfig(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers,
      String body,
      Object config,
      String mechanism) {
    if (detectionDisabled()) {
      return;
    }
    try {
      RequestContext context = new RequestContext(method, uri, query, parameters, headers, body);
      String hook = mechanism == null || mechanism.isBlank() ? "JAAS" : mechanism;
      emit(DETECTORS.detectJaasConfig(String.valueOf(config), hook, context));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticJaasConfig", throwable);
    }
  }

  public static void beforeSyntheticJwtVerificationFailure(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers,
      String mechanism,
      String exceptionClass,
      String message) {
    if (detectionDisabled()) {
      return;
    }
    try {
      RequestContext context = new RequestContext(method, uri, query, parameters, headers);
      emit(DETECTORS.detectJwtVerificationFailure(mechanism, exceptionClass, message, context));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticJwtVerificationFailure", throwable);
    }
  }

  public static void beforeServletIncludeAttributes(
      Map<String, String> attributes, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectServletIncludeAttributes(attributes, currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeServletIncludeAttributes", throwable);
    }
  }

  public static void beforeSyntheticServletIncludeAttributes(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers,
      Map<String, String> attributes,
      List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    try {
      RequestContext context = new RequestContext(method, uri, query, parameters, headers);
      emit(DETECTORS.detectServletIncludeAttributes(attributes, context, stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticServletIncludeAttributes", throwable);
    }
  }

  public static void beforeRemoteJobSubmission(String mechanism, String descriptor) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectRemoteJobSubmission(mechanism, descriptor, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeRemoteJobSubmission", throwable);
    }
  }

  public static void beforeRmiRegistryBind(String operation, String bindingName, Object remote) {
    if (detectionDisabled()) {
      return;
    }
    beforeRmiRegistryBind(operation, bindingName, remote, stackTraceClassNames());
  }

  public static void beforeRmiRegistryBind(
      String operation, String bindingName, Object remote, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    try {
      String remoteClassName = remote == null ? "" : remote.getClass().getName();
      emit(
          DETECTORS.detectRmiRegistryBind(
              operation, bindingName, remoteClassName, currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeRmiRegistryBind", throwable);
    }
  }

  public static void beforeSyntheticRmiRegistryBind(
      String operation, String bindingName, String remoteClassName, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(
          DETECTORS.detectRmiRegistryBind(
              operation, bindingName, remoteClassName, currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticRmiRegistryBind", throwable);
    }
  }

  public static void exitHttpRequest() {
    REQUEST.remove();
    RESPONSE.remove();
    ARCHIVE_ENTRY.remove();
  }

  public static void beforeProcessBuilderStart(ProcessBuilder processBuilder) {
    if (detectionDisabled()) {
      return;
    }
    beforeProcessBuilderStart(processBuilder, stackTraceClassNames());
  }

  public static void beforeProcessBuilderStart(
      ProcessBuilder processBuilder, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectCommand(processBuilder.command(), currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeProcessBuilderStart", throwable);
    }
  }

  public static void beforeRuntimeExecString(String command) {
    if (detectionDisabled()) {
      return;
    }
    try {
      List<String> items = command == null ? List.of() : List.of(command);
      emit(DETECTORS.detectCommand(items, currentRequest(), stackTraceClassNames()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeRuntimeExecString", throwable);
    }
  }

  public static void beforeRuntimeExecArray(String[] command) {
    if (detectionDisabled()) {
      return;
    }
    try {
      var items = new ArrayList<String>();
      if (command != null) {
        Collections.addAll(items, command);
      }
      emit(DETECTORS.detectCommand(items, currentRequest(), stackTraceClassNames()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeRuntimeExecArray", throwable);
    }
  }

  public static void beforeSql(String query) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectSql(query, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSql", throwable);
    }
  }

  public static void beforeJdbcConnect(String url) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectJdbcUrl(url, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJdbcConnect", throwable);
    }
  }

  public static void beforeSyntheticJdbcConnect(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers,
      String body,
      String url) {
    if (detectionDisabled()) {
      return;
    }
    try {
      RequestContext context = new RequestContext(method, uri, query, parameters, headers, body);
      emit(DETECTORS.detectJdbcUrl(url, context));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticJdbcConnect", throwable);
    }
  }

  public static void beforeSqlException(
      String server, String errorCode, String errorState, String errorMessage, String query) {
    if (detectionDisabled()) {
      return;
    }
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
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectSqlRegex(query, regex, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSqlRegex", throwable);
    }
  }

  public static void beforeUrlOpen(Object url) {
    if (detectionDisabled()) {
      return;
    }
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
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectDns(host, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeDnsLookup", throwable);
    }
  }

  public static void beforeJndiLookup(Object name) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectJndi(String.valueOf(name), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJndiLookup", throwable);
    }
  }

  public static void beforeJaasConfig(Object config) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectJaasConfig(String.valueOf(config), "JAAS", currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJaasConfig", throwable);
    }
  }

  public static void beforeJaasConfigEntry(Object loginModuleName, Object options) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectJaasConfig(jaasConfigFrom(loginModuleName, options), "JAAS", currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJaasConfigEntry", throwable);
    }
  }

  public static void beforeClassLoaderUrl(Object url) {
    if (detectionDisabled()) {
      return;
    }
    beforeClassLoaderSources("URLClassLoader", url);
  }

  public static void beforeClassLoaderUrls(Object urls) {
    if (detectionDisabled()) {
      return;
    }
    beforeClassLoaderSources("URLClassLoader", urls);
  }

  public static void beforeRmiClassLoaderCodebase(String codebase) {
    if (detectionDisabled()) {
      return;
    }
    beforeClassLoaderSources("RMIClassLoader", codebase);
  }

  public static void beforeSpringConfigLocation(Object location) {
    if (detectionDisabled()) {
      return;
    }
    beforeSpringConfigLocations("SpringConfig", location);
  }

  public static void beforeSpringConfigLocations(Object locations) {
    if (detectionDisabled()) {
      return;
    }
    beforeSpringConfigLocations("SpringConfig", locations);
  }

  private static void beforeSpringConfigLocations(String mechanism, Object locations) {
    try {
      for (String location : classLoaderSources(locations)) {
        emit(DETECTORS.detectSpringConfigLocation(location, mechanism, currentRequest()));
      }
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSpringConfigLocations", throwable);
    }
  }

  private static void beforeClassLoaderSources(String mechanism, Object sources) {
    try {
      for (String source : classLoaderSources(sources)) {
        emit(DETECTORS.detectClassLoaderUrl(source, mechanism, currentRequest()));
      }
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeClassLoaderSources", throwable);
    }
  }

  public static void beforeJmxMBeanInvoke(Object mbeanName, String operationName, Object arguments) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(
          DETECTORS.detectJmxMBeanInvoke(
              String.valueOf(mbeanName), operationName, toStringList(arguments), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJmxMBeanInvoke", throwable);
    }
  }

  public static void beforeArgumentFileExpansion(Object arguments) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(
          DETECTORS.detectArgumentFileExpansion(
              "args4j", toStringList(arguments), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeArgumentFileExpansion", throwable);
    }
  }

  public static void beforeFileRead(String path) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectFileRead(path, currentRequest(), isXmlParserStack()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileRead", throwable);
    }
  }

  public static void beforeFileReadObject(Object file) {
    if (detectionDisabled()) {
      return;
    }
    beforeFileRead(pathFrom(file));
  }

  public static void beforeFileWrite(String path) {
    if (detectionDisabled()) {
      return;
    }
    beforeFileWrite(path, stackTraceClassNames());
  }

  public static void beforeFileWrite(String path, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    String archiveEntry = ARCHIVE_ENTRY.get();
    try {
      emit(DETECTORS.detectArchiveExtraction(archiveEntry, path, currentRequest()));
      emit(DETECTORS.detectFileWrite(path, currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileWrite", throwable);
    } finally {
      if (archiveEntry != null) {
        ARCHIVE_ENTRY.remove();
      }
    }
  }

  public static void beforeFileWriteObject(Object file) {
    if (detectionDisabled()) {
      return;
    }
    beforeFileWrite(pathFrom(file));
  }

  public static void beforeFileDelete(Object file) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectFileDelete(pathFrom(file), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileDelete", throwable);
    }
  }

  public static void beforeDirectoryList(Object file) {
    if (detectionDisabled()) {
      return;
    }
    beforeDirectoryList(file, stackTraceClassNames());
  }

  public static void beforeDirectoryList(Object file, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectDirectoryList(pathFrom(file), currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeDirectoryList", throwable);
    }
  }

  public static void beforeInclude(String url, String realPath, String function) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectInclude(url, realPath, function, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeInclude", throwable);
    }
  }

  public static void beforeFileUpload(String filename) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectFileUpload(filename, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileUpload", throwable);
    }
  }

  public static void beforeWebdavUpload(String source, String destination, String method) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectWebdavUpload(source, destination, method, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebdavUpload", throwable);
    }
  }

  public static void beforeRename(String source, String destination) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectRename(source, destination, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeRename", throwable);
    }
  }

  public static void beforeLink(String source, String destination, String type) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectLink(source, destination, type, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeLink", throwable);
    }
  }

  public static void beforePathRead(Object path) {
    if (detectionDisabled()) {
      return;
    }
    beforeFileRead(pathFrom(path));
  }

  public static void beforePathWrite(Object path) {
    if (detectionDisabled()) {
      return;
    }
    beforeFileWrite(pathFrom(path));
  }

  public static void beforePathWrite(Object path, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    beforeFileWrite(pathFrom(path), stackClassNames);
  }

  public static void beforeGeneratedScriptFileWrite(Object path, Object content) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(
          DETECTORS.detectGeneratedScriptFileWrite(
              pathFrom(path), contentFrom(content), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeGeneratedScriptFileWrite", throwable);
    }
  }

  public static void beforePathDelete(Object path) {
    if (detectionDisabled()) {
      return;
    }
    beforeFileDelete(path);
  }

  public static void afterArchiveEntry(Object entry) {
    try {
      String name = archiveEntryName(entry);
      if (name.isBlank()) {
        ARCHIVE_ENTRY.remove();
      } else {
        ARCHIVE_ENTRY.set(name);
      }
    } catch (Throwable throwable) {
      quiet("afterArchiveEntry", throwable);
    }
  }

  public static void clearArchiveEntry() {
    ARCHIVE_ENTRY.remove();
  }

  public static void beforeXmlEntity(String name, Object source) {
    if (detectionDisabled()) {
      return;
    }
    try {
      String systemId = invokeString(source, "getSystemId").orElse(String.valueOf(source));
      emit(DETECTORS.detectXxeEntity(name, systemId, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXmlEntity", throwable);
    }
  }

  public static void beforeUrlDataSource(Object url) {
    if (detectionDisabled()) {
      return;
    }
    try {
      List<String> stackClassNames = stackTraceClassNames();
      String mechanism = stackLooksCxfAegisAttachment(stackClassNames) ? "cxf-aegis-xop" : "";
      String raw = url instanceof URL typed ? typed.toExternalForm() : String.valueOf(url);
      emit(DETECTORS.detectXmlAttachmentReference(mechanism, raw, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeUrlDataSource", throwable);
    }
  }

  public static void beforeXmlAttachmentReference(String mechanism, String href) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectXmlAttachmentReference(mechanism, href, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXmlAttachmentReference", throwable);
    }
  }

  public static void beforeXxeFileRead(String path) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectFileRead(path, currentRequest(), true));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXxeFileRead", throwable);
    }
  }

  public static void beforeJwtVerificationFailure(String mechanism, Object failure) {
    if (detectionDisabled()) {
      return;
    }
    try {
      String exceptionClass = failure == null ? "" : failure.getClass().getName();
      String message = failure instanceof Throwable throwable ? throwable.getMessage() : "";
      emit(DETECTORS.detectJwtVerificationFailure(mechanism, exceptionClass, message, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJwtVerificationFailure", throwable);
    }
  }

  public static void beforeDeserializationClass(String className) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectDeserialization(className, currentRequest(), stackTraceClassNames()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeDeserializationClass", throwable);
    }
  }

  public static void beforeSyntheticDeserializationClass(
      String className, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectDeserialization(className, currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSyntheticDeserializationClass", throwable);
    }
  }

  public static void beforeObjectInputStream(Object inputStream) {
    if (detectionDisabled()) {
      return;
    }
    try {
      String streamClassName = inputStream == null ? "" : inputStream.getClass().getName();
      emit(
          DETECTORS.detectHttpObjectStreamDeserialization(
              streamClassName, currentRequest(), stackTraceClassNames()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeObjectInputStream", throwable);
    }
  }

  public static void beforeSessionDeserialization(String sessionId, String mechanism) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectSessionDeserialization(sessionId, mechanism, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSessionDeserialization", throwable);
    }
  }

  public static void beforePolymorphicType(String parser, String className) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectPolymorphicType(parser, className, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforePolymorphicType", throwable);
    }
  }

  public static void beforeProtocolClassInstantiation(
      String protocol, String className, Object arguments) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(
          DETECTORS.detectProtocolClassInstantiation(
              protocol, className, toStringList(arguments), currentRequest()),
          true,
          true);
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeProtocolClassInstantiation", throwable);
    }
  }

  public static void beforeHttpInvokerDeserialization(String mechanism) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectHttpInvokerDeserialization(mechanism, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeHttpInvokerDeserialization", throwable);
    }
  }

  public static void beforeHessianType(String type) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectHessianType(type, currentRequest()), true, true);
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeHessianType", throwable);
    }
  }

  public static void beforeXmlRpcSerializableValue(String mechanism) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectXmlRpcSerializableValue(mechanism, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXmlRpcSerializableValue", throwable);
    }
  }

  public static void beforeJavaBeansStatement(Object statement) {
    if (detectionDisabled()) {
      return;
    }
    try {
      Object target = invoke(statement, "getTarget").orElse(null);
      String methodName = invokeString(statement, "getMethodName").orElse("");
      Object arguments = invoke(statement, "getArguments").orElse(new Object[0]);
      emit(
          DETECTORS.detectXmlDecoderExpression(
              javaBeansTargetType(target),
              methodName,
              javaBeansArguments(target, arguments),
              currentRequest(),
              stackTraceClassNames()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJavaBeansStatement", throwable);
    }
  }

  public static void rethrowIfOhMyRaspBlock(Object throwable) {
    Throwable current = throwable instanceof Throwable value ? value : null;
    while (current != null) {
      if (current instanceof OhMyRaspBlockException blocked) {
        throw blocked;
      }
      current = current.getCause();
    }
  }

  public static void beforeOgnl(String expression) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectOgnl(expression, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeOgnl", throwable);
    }
  }

  public static void beforeExpressionEvaluation(String engine, Object expression) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectExpression(engine, expressionText(expression), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeExpressionEvaluation", throwable);
    }
  }

  public static void beforeJavaCompilationSource(String compiler, Object source) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectJavaCompilation(compiler, javaSourceText(source), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJavaCompilationSource", throwable);
    }
  }

  public static void beforeJavaCompilationUnits(Object units) {
    if (detectionDisabled()) {
      return;
    }
    beforeJavaCompilationUnits("javac", units);
  }

  public static void beforeJavaCompilationUnits(String compiler, Object units) {
    if (detectionDisabled()) {
      return;
    }
    try {
      for (String source : javaSourceTexts(units)) {
        emit(DETECTORS.detectJavaCompilation(compiler, source, currentRequest()));
      }
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeJavaCompilationUnits", throwable);
    }
  }

  public static void beforeEval(String function, String code) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectEval(function, code, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeEval", throwable);
    }
  }

  public static void beforeLoadLibrary(String function, String path, boolean windows) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectLoadLibrary(function, path, windows, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeLoadLibrary", throwable);
    }
  }

  public static void beforeResponseDataLeak(String contentType, String content) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectResponseDataLeak(contentType, content, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeResponseDataLeak", throwable);
    }
  }

  public static void beforeXssEcho(String content) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectXssEcho(content, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXssEcho", throwable);
    }
  }

  public static void beforeWebshellEval(String function, String code) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectWebshellEval(function, code, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellEval", throwable);
    }
  }

  public static void beforeWebshellCommand(String command) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectWebshellCommand(List.of(command), currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellCommand", throwable);
    }
  }

  public static void beforeWebshellFileWrite(String path, String content) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectWebshellFileWrite(path, content, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellFileWrite", throwable);
    }
  }

  public static void beforeWebshellCallable(String function) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectWebshellCallable(function, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeWebshellCallable", throwable);
    }
  }

  public static void beforeWebshellLdPreload(String name, String value) {
    if (detectionDisabled()) {
      return;
    }
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

  private static Map<String, String> readServletIncludeAttributes(Object request) {
    if (request == null) {
      return Map.of();
    }
    try {
      Method namesMethod = request.getClass().getMethod("getAttributeNames");
      Object names = namesMethod.invoke(request);
      if (!(names instanceof Enumeration<?> enumeration)) {
        return Map.of();
      }
      Method attributeMethod = request.getClass().getMethod("getAttribute", String.class);
      var attributes = new LinkedHashMap<String, String>();
      while (enumeration.hasMoreElements()) {
        String name = String.valueOf(enumeration.nextElement());
        String normalized = name.toLowerCase(Locale.ROOT);
        if (!normalized.startsWith("javax.servlet.include.")
            && !normalized.startsWith("jakarta.servlet.include.")) {
          continue;
        }
        Object value = attributeMethod.invoke(request, name);
        if (value != null) {
          attributes.put(name, String.valueOf(value));
        }
      }
      return attributes;
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

  private static List<String> classLoaderSources(Object value) {
    var sources = new ArrayList<String>();
    for (String item : toStringList(value)) {
      if (item == null || item.isBlank()) {
        continue;
      }
      String trimmed = item.trim();
      for (String part : trimmed.split("\\s+")) {
        if (!part.isBlank()) {
          sources.add(part);
        }
      }
    }
    return sources;
  }

  private static String jaasConfigFrom(Object loginModuleName, Object options) {
    StringBuilder builder = new StringBuilder(String.valueOf(loginModuleName));
    if (options instanceof Map<?, ?> map) {
      map.forEach((key, value) -> builder.append(' ').append(key).append('=').append(value));
    } else if (options != null) {
      builder.append(' ').append(options);
    }
    return builder.toString();
  }

  private static Optional<String> invokeString(Object target, String methodName) {
    try {
      Object value = target.getClass().getMethod(methodName).invoke(target);
      return value == null ? Optional.empty() : Optional.of(String.valueOf(value));
    } catch (ReflectiveOperationException | RuntimeException e) {
      return Optional.empty();
    }
  }

  private static Optional<Object> invoke(Object target, String methodName) {
    try {
      if (target == null) {
        return Optional.empty();
      }
      return Optional.ofNullable(target.getClass().getMethod(methodName).invoke(target));
    } catch (ReflectiveOperationException | RuntimeException e) {
      return Optional.empty();
    }
  }

  private static String javaBeansTargetType(Object target) {
    if (target instanceof Class<?> clazz) {
      return clazz.getName();
    }
    return target == null ? "" : target.getClass().getName();
  }

  private static List<String> javaBeansArguments(Object target, Object arguments) {
    var items = new ArrayList<String>();
    addJavaBeansArgument(items, arguments);
    if (target instanceof ProcessBuilder processBuilder) {
      items.addAll(processBuilder.command());
    }
    return items;
  }

  private static void addJavaBeansArgument(List<String> items, Object value) {
    if (value == null) {
      return;
    }
    if (value instanceof Iterable<?> iterable) {
      for (Object item : iterable) {
        addJavaBeansArgument(items, item);
      }
      return;
    }
    if (value.getClass().isArray()) {
      int length = Array.getLength(value);
      for (int i = 0; i < length; i++) {
        addJavaBeansArgument(items, Array.get(value, i));
      }
      return;
    }
    items.add(String.valueOf(value));
  }

  private static String expressionText(Object expression) {
    if (expression == null) {
      return "";
    }
    if (expression instanceof CharSequence text) {
      return text.toString();
    }
    Optional<String> expressionString = invokeString(expression, "getExpressionString");
    if (expressionString.isPresent()) {
      return expressionString.orElseThrow();
    }
    Optional<String> ast = invokeString(expression, "toStringAST");
    if (ast.isPresent()) {
      return ast.orElseThrow();
    }
    return String.valueOf(expression);
  }

  private static List<String> javaSourceTexts(Object units) {
    if (units == null) {
      return List.of();
    }
    if (units instanceof Iterable<?> iterable) {
      var sources = new ArrayList<String>();
      for (Object unit : iterable) {
        String source = javaSourceText(unit);
        if (!source.isBlank()) {
          sources.add(source);
        }
      }
      return sources;
    }
    String source = javaSourceText(units);
    return source.isBlank() ? List.of() : List.of(source);
  }

  private static String javaSourceText(Object unit) {
    if (unit == null) {
      return "";
    }
    if (unit instanceof CharSequence text) {
      return text.toString();
    }
    try {
      Object content = unit.getClass().getMethod("getCharContent", boolean.class).invoke(unit, true);
      if (content != null) {
        return String.valueOf(content);
      }
    } catch (ReflectiveOperationException | RuntimeException e) {
      // Fall through to a conservative string representation.
    }
    return String.valueOf(unit);
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

  private static String contentFrom(Object value) {
    if (value == null) {
      return "";
    }
    if (value instanceof CharSequence text) {
      return text.toString();
    }
    if (value instanceof byte[] bytes) {
      int length = Math.min(bytes.length, 8192);
      return new String(bytes, 0, length, StandardCharsets.UTF_8);
    }
    if (value instanceof char[] chars) {
      return new String(chars, 0, Math.min(chars.length, 8192));
    }
    if (value instanceof Iterable<?> iterable) {
      StringBuilder builder = new StringBuilder();
      for (Object item : iterable) {
        if (builder.length() > 8192) {
          break;
        }
        if (builder.length() > 0) {
          builder.append('\n');
        }
        builder.append(String.valueOf(item));
      }
      return builder.toString();
    }
    if (value.getClass().isArray()) {
      StringBuilder builder = new StringBuilder();
      int length = Math.min(Array.getLength(value), 256);
      for (int i = 0; i < length && builder.length() <= 8192; i++) {
        if (builder.length() > 0) {
          builder.append('\n');
        }
        builder.append(String.valueOf(Array.get(value, i)));
      }
      return builder.toString();
    }
    return String.valueOf(value);
  }

  private static String archiveEntryName(Object entry) {
    if (entry == null) {
      return "";
    }
    if (entry instanceof ZipEntry zipEntry) {
      return zipEntry.getName() == null ? "" : zipEntry.getName();
    }
    return invokeString(entry, "getName").orElse("");
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

  private static boolean stackLooksCxfAegisAttachment(List<String> classNames) {
    for (String className : classNames) {
      if ("org.apache.cxf.aegis.type.mtom.AttachmentUtil".equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static void emit(Optional<Detection> detection) {
    emit(detection, true);
  }

  private static void emit(Optional<Detection> detection, boolean throwOnBlock) {
    emit(detection, throwOnBlock, false);
  }

  private static void emit(
      Optional<Detection> detection, boolean throwOnBlock, boolean allowNonRequestBlock) {
    if (detection.isEmpty()) {
      return;
    }
    long started = System.nanoTime();
    Detection value = detection.orElseThrow();
    // Local runtime controls (mode + per-algorithm switches), hot-reloaded from
    // the daemon/operator control file. Unset mode keeps legacy behavior.
    AgentRuntime runtime = AgentRuntime.get();
    if (!runtime.detectionEnabled() || !runtime.isAlgorithmEnabled(value.algorithm())) {
      return;
    }
    long ruleEvaluationStarted = System.nanoTime();
    PolicyEvaluation policyEvaluation = POLICY.evaluate(value, POLICY_AGENT_KEY);
    long ruleEvaluationUs = elapsedMicros(ruleEvaluationStarted);
    if (policyEvaluation.ignored()) {
      return;
    }
    Detection event = policyEvaluation.detection();
    if (!policyEvaluation.controlled() && legacyBlockEnabled() && activeRequest(value)) {
      event = value.withAction("block");
    }
    if (forceBlockEnabled() && activeRequest(value)) {
      event = event.withAction("block");
    }
    boolean willBlock =
        runtime.blockingAllowed()
            && "block".equalsIgnoreCase(event.action())
            && (activeRequest(event) || allowNonRequestBlock);
    // In MONITOR (record) mode a would-be block is observed, not enforced — record
    // it truthfully so the log/console don't claim a block that never happened.
    // Strictly gated on MONITOR, so unset/legacy (acceptance) behavior is unchanged.
    Detection recorded = event;
    if (!willBlock
        && runtime.mode() == DetectionMode.MONITOR
        && "block".equalsIgnoreCase(event.action())) {
      recorded = event.withAction("monitor");
    }
    JsonEventLogger.get().record(recorded, elapsedMicros(started), ruleEvaluationUs);
    if (willBlock) {
      redirectToBlockPage(event);
      if (throwOnBlock) {
        throw new OhMyRaspBlockException(event);
      }
    }
  }

  private static boolean activeRequest(Detection detection) {
    return detection != null && detection.request() != null && detection.request().active();
  }

  /**
   * True when detection is turned OFF. A single volatile read, used to
   * short-circuit hook entry points before any detector runs — so OFF mode
   * actually removes the hot-path cost rather than just suppressing the result.
   * Cleanup/accessor hooks intentionally do not consult this.
   */
  private static boolean detectionDisabled() {
    return AgentRuntime.get().mode() == DetectionMode.OFF;
  }

  private static long elapsedMicros(long startedNanos) {
    return Math.max(0, (System.nanoTime() - startedNanos) / 1_000);
  }

  private static boolean legacyBlockEnabled() {
    return Boolean.getBoolean("ohmyrasp.block")
        || "true".equalsIgnoreCase(System.getenv("OHMYRASP_BLOCK"));
  }

  private static boolean forceBlockEnabled() {
    return Boolean.getBoolean("ohmyrasp.force_block")
        || "true".equalsIgnoreCase(System.getenv("OHMYRASP_FORCE_BLOCK"));
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
    JsonEventLogger.get().reportError(hook, throwable);
    if (Boolean.getBoolean("ohmyrasp.debug")) {
      System.err.println("[OHMYRASP] hook failure in " + hook + ": " + throwable);
    }
  }
}
