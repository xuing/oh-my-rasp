package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.file.HostReadPath;
import io.ohmyrasp.agent.file.HostFileSystem;
import io.ohmyrasp.agent.file.ArchiveEntryContext;
import io.ohmyrasp.agent.file.WindowsDataStream;
import io.ohmyrasp.agent.file.HostDirectory;
import io.ohmyrasp.agent.jmx.JmxDispatch;
import io.ohmyrasp.agent.jmx.JmxWriteScope;
import io.ohmyrasp.agent.detect.DetectorEngine;
import io.ohmyrasp.agent.http.ArchiveUploadPolicy;
import io.ohmyrasp.agent.http.MultipartFilename;
import io.ohmyrasp.agent.http.ServletDispatchScope;
import io.ohmyrasp.agent.net.HttpTransportObservation;
import io.ohmyrasp.agent.sql.MyBatisSqlTrace;
import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.policy.AgentPolicy;
import io.ohmyrasp.agent.policy.PolicyEvaluation;
import io.ohmyrasp.agent.process.PosixShellCommand;
import io.ohmyrasp.agent.runtime.AgentRuntime;
import io.ohmyrasp.agent.runtime.DetectionMode;
import io.ohmyrasp.agent.xml.XmlCatalogResolution;
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
  private static final ArchiveEntryContext ARCHIVE_ENTRY = new ArchiveEntryContext();
  private static final ServletDispatchScope<RequestContext, Object> DISPATCH =
      new ServletDispatchScope<>(REQUEST, RESPONSE, ARCHIVE_ENTRY);
  private static final StackWalker STACK_WALKER =
      StackWalker.getInstance(
          Set.of(StackWalker.Option.RETAIN_CLASS_REFERENCE, StackWalker.Option.SHOW_REFLECT_FRAMES));

  private OhMyRaspHooks() {}

  public static void installPolicy(AgentPolicy policy, String agentKey) {
    POLICY = policy == null ? AgentPolicy.empty() : policy;
    POLICY_AGENT_KEY = agentKey == null ? "" : agentKey;
  }

  public static void enterHttpRequest(Object request, Object response) {
    DISPATCH.enter(request);
    try {
      inspectHttpRequest(request, response);
      DISPATCH.enteredApplication();
    } catch (RuntimeException | Error failure) {
      DISPATCH.exit();
      throw failure;
    }
  }

  private static void inspectHttpRequest(Object request, Object response) {
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
      inspectRequest(context, false);
      emit(
          DETECTORS.detectServletIncludeAttributes(
              readServletIncludeAttributes(request), context, stackTraceClassNames()),
          false);
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("enterHttpRequest", throwable);
    }
    JsonEventLogger.get().sampleHookLatency("http_request", elapsedMicros(started));
  }

  private static void inspectRequest(RequestContext request, boolean throwOnBlock) {
    emit(DETECTORS.detectRequest(request), throwOnBlock);
    AgentPolicy policy = POLICY;
    if (policy.loaded() && !request.body().isBlank()) {
      for (Detection candidate : DETECTORS.sqlRequestMetadata(request, policy::selectsAlgorithm)) {
        emit(Optional.of(candidate), throwOnBlock);
      }
    }
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
      inspectRequest(context, true);
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
      inspectRequest(context, true);
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
    DISPATCH.exit();
  }

  public static void beforeProcessLaunch(String[] argv) {
    if (detectionDisabled()) return;
    try {
      var finding = DETECTORS.detectCommand(java.util.Arrays.asList(argv), currentRequest(), stackTraceClassNames(),
          POLICY.selectsAlgorithm("command_reflect"));
      if (finding.isEmpty()) return;
      String api = io.ohmyrasp.agent.process.ProcessLaunch.api();
      if (api == null) return;
      Detection event = finding.get();
      var details = new java.util.LinkedHashMap<>(event.details());
      details.put("process_operation", "ProcessImpl.start");
      details.put("argument_count", Integer.toString(argv.length));
      details.put("process_api", api);
      emit(Optional.of(new Detection(event.timestamp(), event.hook(), event.algorithm(), event.action(),
          event.confidence(), event.message(), event.request(), details)));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable failure) {
      quiet("beforeProcessLaunch", failure);
    }
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
      emit(DETECTORS.detectCommand(processBuilder.command(), currentRequest(), stackClassNames, POLICY.selectsAlgorithm("command_reflect")));
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
      List<String> items = List.of(PosixShellCommand.runtimeArguments(command));
      emit(DETECTORS.detectCommand(items, currentRequest(), stackTraceClassNames(), POLICY.selectsAlgorithm("command_reflect")));
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
      emit(DETECTORS.detectCommand(items, currentRequest(), stackTraceClassNames(), POLICY.selectsAlgorithm("command_reflect")));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeRuntimeExecArray", throwable);
    }
  }

  public static void observeMyBatisSubstitution(StringBuilder builder, String value, Object handler, String expression) {
    if (!detectionDisabled()) MyBatisSqlTrace.substitution(builder, value, handler, expression);
  }

  public static void beforeSql(String query) {
    inspectSql(null, query);
  }

  public static void beforeSql(Object jdbcReceiver, String query) {
    if (jdbcReceiver != null) inspectSql(jdbcReceiver, query);
  }

  private static void inspectSql(Object jdbcReceiver, String query) {
    if (detectionDisabled()) {
      return;
    }
    try {
      RequestContext request = currentRequest();
      String reason = MyBatisSqlTrace.controlAtJdbc(query, jdbcReceiver);
      if (reason != null && AgentRuntime.get().isAlgorithmEnabled("sql_identifier_injection")) {
        var redacted = new RequestContext(request.method(), request.uri(), "", Map.of(), Map.of());
        var finding = Detection.log("sql", "sql_identifier_injection", 95,
            "A raw mapper substitution introduced SQL control at JDBC", redacted,
            Map.of("source", "MyBatis", "reason", reason, "decision_basis", "mapper_substitution_at_jdbc"));
        emit(Optional.of(finding), true, true, algorithm -> MyBatisSqlTrace.repeatedObservation(query, algorithm));
        // A managed policy may independently select the existing JDBC classifier.
        if (!POLICY.loaded()) return;
      }
      emit(DETECTORS.detectSql(query, request, jdbcReceiver), true, true,
          algorithm -> MyBatisSqlTrace.repeatedObservation(query, algorithm));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeSql", throwable);
    }
  }

  public static void beforeBase64Decode(
      byte[] src, int sp, int sl, boolean isURL, boolean isMIME) {
    // Pure arithmetic fast path first so benign Base64 decoding never triggers
    // class initialization or allocates on the hot path.
    if (!DetectorEngine.isBase64TailUnderflowCandidate(src, sp, sl, isURL, isMIME)) {
      return;
    }
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectBase64Decode(src, sp, sl, isURL, isMIME, currentRequest()), true, true);
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeBase64Decode", throwable);
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

  private static final HttpTransportObservation.Submissions<RequestContext> HTTP_SUBMISSIONS =
      new HttpTransportObservation.Submissions<>();

  public static void captureHttpSubmission(Object exchange, java.net.URI uri) {
    if (detectionDisabled()) return;
    RequestContext request = currentRequest();
    if (request.active()) {
      HTTP_SUBMISSIONS.capture(exchange, request);
      if (uri != null && DETECTORS.requestSuppliesHttpUrl(uri, HttpTransportObservation.address(uri), uri.getHost(), request)) {
        HttpTransportObservation.selectedSubmission(exchange, uri);
      }
    }
  }

  public static void finishHttpSubmission(java.util.concurrent.CompletableFuture<?> future, Object exchange) {
    HTTP_SUBMISSIONS.finishedWhen(future, exchange);
  }

  public static void beforeHttpExchange(Object exchange, Object requestObject, java.net.URI uri) {
    if (detectionDisabled() || uri == null || !("http".equalsIgnoreCase(uri.getScheme())
        || "https".equalsIgnoreCase(uri.getScheme()))) return;
    HttpTransportObservation.bindExchange(requestObject, exchange, uri);
    inspectHttpExchange(exchange, uri, null);
  }

  public static void beforeResolvedHttpExchange(Object requestObject, java.net.URI uri, java.net.InetSocketAddress address,
      java.net.InetSocketAddress proxy) {
    if (detectionDisabled()) return;
    String peer = HttpTransportObservation.directAddress(uri, address, proxy);
    if (peer != null) {
      Object exchange = HttpTransportObservation.submittedExchange(requestObject);
      if (exchange != null) inspectHttpExchange(exchange, uri, peer);
    }
  }

  private static void inspectHttpExchange(Object exchange, java.net.URI uri, String peer) {
    try {
      RequestContext origin = HTTP_SUBMISSIONS.origin(exchange);
      RequestContext request = origin == null ? RequestContext.empty() : origin;
      var finding = DETECTORS.classifyHttpTransport(uri, request, POLICY.loaded(), peer, HttpTransportObservation.changedOrigin(exchange, uri));
      if (finding.isEmpty()) return;
      var observed = transportEvidence(finding.get(), peer == null ? "http_exchange_acquire" : "http_resolved_route", peer);
      emit(Optional.of(observed), true, false, null, origin != null && origin == currentRequest());
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable failure) {
      quiet("beforeHttpExchange", failure);
    }
  }

  private static Detection transportEvidence(Detection value, String basis, String peer) {
    var details = new java.util.LinkedHashMap<>(value.details());
    details.put("decision_basis", basis);
    if (peer != null) details.put("resolved_address", peer);
    return new Detection(value.timestamp(), value.hook(), value.algorithm(), value.action(),
        value.confidence(), value.message(), value.request(), details);
  }

  public static void beforeUrlConnectionFactory(URL url) {
    if (!HttpTransportObservation.isHttp(url)) beforeUrlOpen(url);
  }

  public static void captureHttpRedirect(Object connection, URL to, URL from) {
    if (detectionDisabled() || !HttpTransportObservation.isHttp(from) || !HttpTransportObservation.isHttp(to)) return;
    String source = HttpTransportObservation.address(from);
    boolean supplied = DETECTORS.requestSuppliesHttpUrl(HttpTransportObservation.comparisonUri(from, source),
        source, from.getHost(), currentRequest());
    HttpTransportObservation.selectedRedirect(connection, from, to, supplied);
  }

  public static void beginHttpRoute(Object client, URL url, java.net.Proxy proxy) {
    HttpTransportObservation.beginRoute(client, detectionDisabled() ? null : url, proxy);
  }

  public static void beforeHttpDial(Object client, java.net.SocketAddress destination) {
    if (detectionDisabled()) return;
    URL url = HttpTransportObservation.dialTarget(client, destination);
    if (url != null) inspectHttpTransport(client, url, false, HttpTransportObservation.peer(client, url), "http_direct_connect", HttpTransportObservation.dialingRedirect(url));
  }

  public static void beforeHttpWrite(Object client, Object connection, URL url) {
    if (detectionDisabled()) return;
    String peer = HttpTransportObservation.peer(client, url);
    inspectHttpTransport(peer == null ? connection : client, url, true, peer, "http_request_write",
        HttpTransportObservation.redirected(connection, url));
  }

  public static void beforeHttpTransport(Object connection, URL url, boolean write) {
    inspectHttpTransport(connection, url, write, null, write ? "http_request_write" : "http_transport_acquire",
        HttpTransportObservation.redirected(connection, url));
  }

  private static void inspectHttpTransport(Object connection, URL url, boolean write, String peer, String basis, boolean redirected) {
    if (detectionDisabled() || url == null) return;
    try {
      RequestContext request = currentRequest();
      var finding = DETECTORS.classifyHttpTransport(url, request, POLICY.loaded(), peer, redirected);
      if (finding.isEmpty()) return;
      Detection observed = transportEvidence(finding.get(), basis, peer);
      emit(Optional.of(observed), true, false,
          algorithm -> HttpTransportObservation.repeated(connection, url, request, algorithm, write));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable failure) {
      quiet("beforeHttpTransport", failure);
    }
  }

  public static void beforeUrlOpen(Object url) {
    if (detectionDisabled()) {
      return;
    }
    try {
      String raw = url instanceof URL typed ? typed.toExternalForm() : String.valueOf(url);
      emit(DETECTORS.detectUrl(raw, currentRequest(), POLICY.loaded()));
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

  public static void beforeJmxStreamWrite(String path, int write) {
    JmxWriteScope scope = write != 0 ? JmxWriteScope.current() : null;
    if (scope != null && !detectionDisabled())
      emit(DETECTORS.detectJmxFileWrite(path, scope, "stream_open", currentRequest()));
  }

  public static void beforeUnixChannelWrite(java.nio.file.Path path, int directoryFd, boolean write) {
    if (!write) return;
    var open = ARCHIVE_ENTRY.atChannelOpen(path, directoryFd);
    if (open != null && !detectionDisabled()) emit(DETECTORS.detectArchiveExtraction(open, currentRequest()));
    beforeJmxChannelWrite(path, directoryFd, true);
  }

  public static void beforeJmxChannelWrite(java.nio.file.Path path, int directoryFd, boolean write) {
    JmxWriteScope scope = write ? JmxWriteScope.current() : null;
    if (scope != null && !detectionDisabled() && (directoryFd < 0 || path.isAbsolute()))
      emit(DETECTORS.detectJmxFileWrite(path.toString(), scope, "channel_open", currentRequest()));
  }

  public static void beforeJmxMBeanInvoke(Object mbeanName, String operationName, Object arguments) {
    inspectJmxInvoke(mbeanName, operationName, arguments, false);
  }

  public static void beforeResolvedJmxInvoke(Object mbeanName, String operationName, Object arguments) {
    inspectJmxInvoke(mbeanName, operationName, arguments, true);
  }

  private static void inspectJmxInvoke(Object mbeanName, String operationName, Object arguments, boolean resolved) {
    if (detectionDisabled()) {
      return;
    }
    try {
      RequestContext request = currentRequest();
      if (!request.active()) return;
      String bean = JmxDispatch.name(mbeanName);
      List<String> text = JmxDispatch.strings(arguments);
      emit(DETECTORS.detectJmxMBeanInvoke(bean, operationName, text, request));
      if (resolved) JmxWriteScope.select(bean, operationName, text);
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

  public static void beforeStreamFileRead(String path, String hook) {
    inspectFileRead(path, HostReadPath.OpenPolicy.FOLLOW, hook);
  }

  public static void beforeFileRead(String path) {
    inspectFileRead(path, HostReadPath.OpenPolicy.PATH_ONLY, null);
  }

  private static void inspectFileRead(String path, HostReadPath.OpenPolicy links, String operation) {
    if (detectionDisabled()) {
      return;
    }
    try {
      if (io.ohmyrasp.agent.xml.AttachmentFileRead.selected(path)) {
        Object origin = io.ohmyrasp.agent.xml.AttachmentFileRead.origin();
        RequestContext request = origin instanceof RequestContext source ? source : RequestContext.empty();
        emit(Optional.of(Detection.log("ssrf", "ssrf_protocol", 95, "External attachment reference opened a host file",
            request, Map.of("scheme", "file", "mechanism", "cxf-aegis-xop", "path", path,
                "decision_basis", "attachment_file_open"))), true, true, ignored -> io.ohmyrasp.agent.xml.AttachmentFileRead.repeated(),
            request.active() && request == currentRequest());
      } else {
        var finding = DETECTORS.detectFileRead(path, currentRequest(), OhMyRaspHooks::isXmlParserStack, POLICY.loaded(), links);
        if (finding.isPresent()) {
          Detection observed = finding.get();
          String basis = observed.details().getOrDefault("decision_basis", "");
          if (operation != null) {
            var details = new java.util.LinkedHashMap<>(observed.details());
            details.put("file_operation", operation);
            observed = new Detection(observed.timestamp(), observed.hook(), observed.algorithm(), observed.action(),
                observed.confidence(), observed.message(), observed.request(), details);
          }
          emit(Optional.of(observed), true, false, algorithm -> HostReadPath.repeated(path, algorithm + ":" + basis));
        }
      }
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
    String archiveEntry = ARCHIVE_ENTRY.take();
    try {
      emit(DETECTORS.detectArchiveExtraction(archiveEntry, path, currentRequest()));
      if (java.io.File.separatorChar != '\\' || WindowsDataStream.parse(path) == null)
        emit(DETECTORS.detectFileWrite(path, currentRequest(), stackClassNames));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFileWrite", throwable);
    }
  }

  public static void beforeWindowsStreamWrite(String path, int writeAccess) {
    if (writeAccess == 0 || java.io.File.separatorChar != '\\') return;
    WindowsDataStream stream = WindowsDataStream.parse(path);
    if (stream == null || detectionDisabled()) return;
    try {
      emit(DETECTORS.detectWindowsStreamWrite(stream, currentRequest(),
          stream.name().isEmpty() ? stackTraceClassNames() : List.of(), POLICY.selectsAlgorithm("writeFile_NTFS")));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable failure) {
      quiet("beforeWindowsStreamWrite", failure);
    }
  }

  public static void beforeFileWriteObject(Object file) {
    if (detectionDisabled()) {
      return;
    }
    if (ARCHIVE_ENTRY.hostDestination(file)) beforeFileWrite(pathFrom(file));
  }

  public static void beforeFileDelete(Object file) {
    if (detectionDisabled()) return;
    try {
      if (HostReadPath.isHostPath(file)) beforeFileDeletePath(pathFrom(file), "file_api_delete");
    } catch (OhMyRaspBlockException denied) {
      throw denied;
    } catch (Throwable failure) {
      quiet("beforeFileDelete", failure);
    }
  }

  public static void beforeFileDeletePath(String value, String operation) {
    if (detectionDisabled() || value == null || value.isEmpty()) return;
    try {
      inspectDelete(java.nio.file.Paths.get(value), null, -1, false, operation);
    } catch (java.nio.file.InvalidPathException ignored) {
      // The JDK retains its normal failure behavior for invalid names.
    }
  }

  public static void captureDirectoryWalk(Object walker, java.nio.file.Path path) {
    RequestContext request = currentRequest();
    if (!detectionDisabled() && request.active() && path != null && HostReadPath.isHostPath(path)) {
      HostDirectory.submitted(walker, request, DETECTORS.requestSelectsDirectory(path.toString(), request, false));
    }
  }

  public static void beginDirectoryVisit(Object walker, java.nio.file.Path path) {
    HostDirectory.visiting(walker, path, currentRequest().active());
  }

  public static void beforeDirectoryList(Object file) {
    if (!detectionDisabled() && HostReadPath.isHostPath(file))
      inspectDirectory(pathFrom(file), null, false, false, null, OhMyRaspHooks::stackTraceClassNames);
  }

  public static void beforeDirectoryList(Object file, List<String> stackClassNames) {
    if (!detectionDisabled() && HostReadPath.isHostPath(file))
      inspectDirectory(pathFrom(file), null, false, false, null, () -> stackClassNames);
  }

  public static void afterFileList(String[] entries, String path) {
    if (entries != null && !detectionDisabled()) inspectDirectory(path, null, false, true, null, OhMyRaspHooks::stackTraceClassNames);
  }

  public static void afterDirectoryOpen(java.nio.file.DirectoryStream<?> opened, java.nio.file.Path path, boolean relativeApi) {
    if (opened == null || detectionDisabled()) return;
    try {
      inspectDirectory(path.toString(), opened, relativeApi && !path.isAbsolute(), true, HostDirectory.origin(path), OhMyRaspHooks::stackTraceClassNames);
    } catch (OhMyRaspBlockException denied) {
      HostDirectory.closeDenied(opened, denied);
      throw denied;
    }
  }

  private static void inspectDirectory(String path, java.nio.file.DirectoryStream<?> opened, boolean relative,
      boolean observed, HostDirectory.Walk walk, java.util.function.Supplier<List<String>> stack) {
    try {
      RequestContext current = currentRequest();
      RequestContext origin = walk == null ? current : walk.origin instanceof RequestContext source ? source : RequestContext.empty();
      for (Detection finding : DETECTORS.directoryListings(path, origin, opened, relative, observed,
          walk != null && walk.selected, POLICY::selectsAlgorithm, stack)) {
        if (observed) {
          var details = new java.util.LinkedHashMap<>(finding.details());
          details.put("directory_operation", opened == null ? "file_list" : relative ? "descriptor_relative_open" : "stream_open");
          finding = new Detection(finding.timestamp(), finding.hook(), finding.algorithm(), finding.action(),
              finding.confidence(), finding.message(), finding.request(), details);
        }
        emit(Optional.of(finding), true, false, null, origin == current);
      }
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable failure) {
      quiet("inspectDirectory", failure);
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

  public static void afterMultipartAccess(Object source, Object result, boolean iterator) {
    DISPATCH.multipartAccess(source, result, iterator);
  }

  public static void afterMultipartLookup(Object result, Object request, int kind, boolean bulk) {
    DISPATCH.multipartResult(request, result, kind, bulk);
  }

  public static void inspectMultipartFilename(String filename, boolean archiveOnly) {
    if (MultipartFilename.eligible() && (!archiveOnly || DISPATCH.deliveredPart(MultipartFilename.receiver()))) {
      inspectFileUpload(filename, archiveOnly);
    }
  }

  public static void beforeFileUpload(String filename) { inspectFileUpload(filename, false); }

  private static void inspectFileUpload(String filename, boolean archiveOnly) {
    if (detectionDisabled() || DISPATCH.inspectingRequest()) {
      return;
    }
    try {
      ArchiveUploadPolicy.Evaluation evaluation = ArchiveUploadPolicy.isArchive(filename)
          ? ArchiveUploadPolicy.inspect(DISPATCH.servletRequest()) : ArchiveUploadPolicy.UNSPECIFIED;
      ArchiveUploadPolicy.Decision decision = evaluation.decision;
      var finding = archiveOnly ? DETECTORS.deniedArchiveUpload(filename, currentRequest(), decision)
          : DETECTORS.detectFileUpload(filename, currentRequest(), decision, POLICY.loaded());
      if (finding.isPresent()) {
        Detection event = finding.get();
        String basis = event.details().getOrDefault("decision_basis", "");
        if (evaluation.policyDigest != null && "fileUpload_java_archive".equals(event.algorithm())
            && basis.equals(decision.denialBasis())) {
          var details = new java.util.LinkedHashMap<>(event.details());
          details.put("archive_policy_sha256", evaluation.policyDigest);
          if (DISPATCH.deliveredPart(MultipartFilename.receiver())) details.put("multipart_source", "active_request_lookup");
          event = new Detection(event.timestamp(), event.hook(), event.algorithm(), event.action(), event.confidence(),
              event.message(), event.request(), details);
        }
        emit(Optional.of(event), true, false, algorithm -> MultipartFilename.repeated(
            DISPATCH.servletRequest(), filename, algorithm, basis, evaluation.policyDigest));
      }
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

  public static void beforeUnixFileOpen(java.nio.file.Path path, boolean read, int directoryFd) {
    beforeUnixFileOpen(path, read, directoryFd, false, false);
  }

  public static void beforeUnixFileOpen(java.nio.file.Path path, boolean read, int directoryFd,
      boolean noFollowFinal, boolean creatingNew) {
    if (HostReadPath.nativeRead(path, read && !creatingNew, directoryFd)) {
      inspectFileRead(path.toString(), noFollowFinal ? HostReadPath.OpenPolicy.NOFOLLOW_FINAL : HostReadPath.OpenPolicy.FOLLOW,
          "UnixChannelFactory.open");
    }
  }

  public static void beginNioRead(Object path) {
    HostReadPath.beginFacade(path);
    try {
      if (!detectionDisabled() && HostReadPath.needsFacadeRead(path)) inspectFileRead(pathFrom(path), HostReadPath.OpenPolicy.PATH_ONLY, null);
    } catch (RuntimeException | Error failure) {
      HostReadPath.endFacade();
      throw failure;
    }
  }

  public static void beforePathRead(Object path) {
    if (detectionDisabled()) {
      return;
    }
    if (HostReadPath.isHostPath(path)) inspectFileRead(pathFrom(path), HostReadPath.OpenPolicy.PATH_ONLY, null);
  }

  public static void beforePathWrite(Object path) {
    if (detectionDisabled()) {
      return;
    }
    if (ARCHIVE_ENTRY.hostDestination(path)) beforeFileWrite(pathFrom(path));
  }

  public static void beforePathWrite(Object path, List<String> stackClassNames) {
    if (detectionDisabled()) {
      return;
    }
    if (ARCHIVE_ENTRY.hostDestination(path)) beforeFileWrite(pathFrom(path), stackClassNames);
  }

  public static GeneratedLineWrite beginGeneratedLines(Object target) {
    if (detectionDisabled() || !currentRequest().active() || !(target instanceof java.nio.file.Path) || !HostFileSystem.contains(target)) return null;
    try {
      String path = pathFrom(target);
      return DETECTORS.generatedScriptCandidate(path) ? new GeneratedLineWrite(path) : null;
    } catch (Throwable failure) {
      quiet("beginGeneratedLines", failure);
      return null;
    }
  }

  public static void beforeGeneratedLine(String line, GeneratedLineWrite output) {
    if (output == null || detectionDisabled()) return;
    try {
      String content = output.append(line);
      if (content != null) emit(DETECTORS.detectGeneratedScriptFileWrite(output.path, content, currentRequest()),
          true, false, ignored -> output.repeated());
    } catch (OhMyRaspBlockException denied) {
      throw denied;
    } catch (Throwable failure) {
      quiet("beforeGeneratedLine", failure);
    }
  }

  public static void beforeEncodedScriptWrite(byte[] bytes, Object target, String text, java.nio.charset.Charset charset) {
    // The immediately following Files.write(byte[]) observes a complete small UTF-8 input itself.
    if (text == null || detectionDisabled() || (charset == StandardCharsets.UTF_8 && bytes.length <= 8192)
        || !HostFileSystem.contains(target)) return;
    try {
      String path = pathFrom(target);
      RequestContext request = currentRequest();
      var typed = DETECTORS.detectGeneratedScriptFileWrite(path, text, request);
      if (typed.isEmpty()) return;
      var raw = DETECTORS.detectGeneratedScriptFileWrite(path, contentFrom(bytes), request);
      if (raw.isEmpty() || !raw.get().details().equals(typed.get().details())) emit(typed);
    } catch (OhMyRaspBlockException denied) {
      throw denied;
    } catch (Throwable failure) {
      quiet("beforeEncodedScriptWrite", failure);
    }
  }

  public static void beforeGeneratedScriptFileWrite(Object path, Object content) {
    if (detectionDisabled() || !HostFileSystem.contains(path)) {
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

  public static void beforePortablePathDelete(Object value) {
    if (detectionDisabled() || !(value instanceof java.nio.file.Path path) || !HostReadPath.isHostPath(path)) return;
    if (!io.ohmyrasp.agent.file.UnixDeleteVisitor.usesNativeBoundary(path)) inspectDelete(path, null, -1, false, "file_api_delete");
  }

  public static void beforeHostDelete(java.nio.file.Path path) {
    inspectDelete(path, null, -1, false, "host_entry_removal");
  }

  public static void beforeSecureDelete(int directoryFd, java.nio.file.SecureDirectoryStream<java.nio.file.Path> directory,
      java.nio.file.Path path, int flags) {
    inspectDelete(path, directory, directoryFd, flags != 0, "descriptor_relative_unlink");
  }

  private static void inspectDelete(java.nio.file.Path path, java.nio.file.SecureDirectoryStream<java.nio.file.Path> directory,
      int directoryFd, boolean removeDirectory, String operation) {
    if (detectionDisabled()) return;
    try {
      RequestContext request = currentRequest();
      if (!request.active()) return;
      boolean relative = directory != null && !path.isAbsolute();
      var entry = new io.ohmyrasp.agent.file.HostDelete(path, directoryFd, relative, true);
      var finding = DETECTORS.detectFileDelete(entry, request, POLICY.selectsAlgorithm("deleteFile_userinput"));
      if (finding.isEmpty()) return;
      if (directory != null && !io.ohmyrasp.agent.file.HostDelete.hasEntry(directory, path, removeDirectory)) return;
      if ("file_api_delete".equals(operation) && !java.nio.file.Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return;
      Detection d = finding.get();
      var details = new java.util.LinkedHashMap<>(d.details());
      details.put("file_operation", operation);
      emit(Optional.of(new Detection(d.timestamp(), d.hook(), d.algorithm(), d.action(), d.confidence(), d.message(), d.request(), details)));
    } catch (OhMyRaspBlockException denied) {
      throw denied;
    } catch (Throwable failure) {
      quiet("beforeHostDelete", failure);
    }
  }

  public static void beforePathDelete(Object path) {
    beforeFileDelete(path);
  }

  public static void afterArchiveEntry(Object entry) {
    afterZipEntryRead(entry, null);
  }

  public static void afterZipEntryRead(Object entry, Object reader) {
    if (!(entry instanceof ZipEntry zip)) {
      ARCHIVE_ENTRY.remove();
      return;
    }
    // ZipEntry's copy constructor preserves the stored member metadata. An application's
    // getName override can have side effects or return a different display name.
    ZipEntry metadata = zip.getClass() == ZipEntry.class ? zip : new ZipEntry(zip);
    ARCHIVE_ENTRY.observe(reader, metadata.getName());
  }

  public static void afterZipLookup(Object stream, String selectedName, Object reader) {
    ARCHIVE_ENTRY.observe(reader, stream == null ? null : selectedName);
  }

  public static void closeArchiveReader(Object reader) {
    ARCHIVE_ENTRY.closed(reader);
  }

  public static void clearArchiveEntry() {
    ARCHIVE_ENTRY.remove();
  }

  public static void beforeXmlEntityOpen(URL target, String name, Object parserInput, Object document, String literal) {
    if (target == null || "[xml]".equals(name) || detectionDisabled()) {
      return;
    }
    try {
      if (!XmlCatalogResolution.consumesPackagedDtd(name, target, parserInput, document, literal)) {
        emit(DETECTORS.detectXxeEntity(name, XmlCatalogResolution.transportId(target), currentRequest(), true));
      }
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXmlEntityOpen", throwable);
    }
  }

  public static void beforeXmlEntity(String name, Object source) {
    if (detectionDisabled()) {
      return;
    }
    try {
      if (source instanceof org.xml.sax.InputSource input
          && (input.getByteStream() != null || input.getCharacterStream() != null)) {
        return;
      }
      String systemId = source instanceof String text ? text
          : source instanceof URL target ? target.toExternalForm() : invokeString(source, "getSystemId").orElse("");
      emit(DETECTORS.detectXxeEntity(name, systemId, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXmlEntity", throwable);
    }
  }

  public static void beginAttachmentReference(String id) {
    io.ohmyrasp.agent.xml.AttachmentFileRead.beginReference(detectionDisabled() ? null : id, currentRequest());
  }

  public static void beforeUrlDataSource(Object url) {
    if (detectionDisabled()) {
      return;
    }
    try {
      if (url instanceof URL file && "file".equalsIgnoreCase(file.getProtocol())) return;
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
      emit(DETECTORS.detectFileRead(path, currentRequest(), true, POLICY.loaded()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeXxeFileRead", throwable);
    }
  }

  /** Previously transformed verifier frames have no downstream dispatch evidence. */
  public static void beforeJwtVerificationFailure(String mechanism, Object failure) {}

  public static void beforeDataEaseFilterContinuation(String rejection, Object request) {
    if (rejection == null || detectionDisabled()) return;
    try {
      RequestContext context = new RequestContext(invokeString(request, "getMethod").orElse(""),
          invokeString(request, "getRequestURI").orElse(""), "", Map.of(), Map.of());
      emit(Optional.of(Detection.log("request", "request_jwt_verification_failure", 95,
          "Authentication filter continued the request after rejecting its credential", context,
          Map.of("exception", rejection, "decision_basis", "rejected_token_dispatch",
              "operation", "FilterChain.doFilter"))), true, true);
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable failure) {
      quiet("beforeDataEaseFilterContinuation", failure);
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

  static void beforeSerialFilterClass(String className) {
    if (detectionDisabled()) {
      return;
    }
    // Preserve the serial guard's explicit non-HTTP enforcement scope, but let
    // the same policy and algorithm switches decide both the action and the log.
    boolean outsideRequest = blockingEnabled() && isDangerousDeserialization(className);
    emit(DETECTORS.detectDeserialization(className, currentRequest(), stackTraceClassNames()),
        true, outsideRequest);
  }

  /**
   * Non-emitting check used by {@link DeserializationGuard}: {@code true} when
   * the class is a known-dangerous deserialization gadget. Fail-safe — any
   * internal error is treated as "not dangerous" so the guard never breaks the
   * deserializing application.
   */
  public static boolean isDangerousDeserialization(String className) {
    try {
      return DETECTORS.isDangerousDeserializationType(className);
    } catch (Throwable throwable) {
      return false;
    }
  }

  /**
   * {@code true} when the agent is currently allowed to actively block (as
   * opposed to monitor/off). Used by the serial-filter guard to reject dangerous
   * gadget classes even outside an active HTTP request (RMI, caches, …), where
   * the request-scoped {@link #emit} path cannot enforce.
   */
  public static boolean blockingEnabled() {
    return AgentRuntime.get().blockingAllowed()
        && (legacyBlockEnabled() || forceBlockEnabled());
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

  public static void beforeFastjsonClassResource(String resource) {
    if (detectionDisabled()) {
      return;
    }
    try {
      emit(DETECTORS.detectFastjsonClassResource(resource, currentRequest()));
    } catch (OhMyRaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      quiet("beforeFastjsonClassResource", throwable);
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
    emit(detection, throwOnBlock, allowNonRequestBlock, null);
  }

  private static void emit(Optional<Detection> detection, boolean throwOnBlock,
      boolean allowNonRequestBlock, java.util.function.Predicate<String> repeatedObservation) {
    emit(detection, throwOnBlock, allowNonRequestBlock, repeatedObservation, true);
  }

  private static void emit(Optional<Detection> detection, boolean throwOnBlock,
      boolean allowNonRequestBlock, java.util.function.Predicate<String> repeatedObservation, boolean mayRedirect) {
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
    boolean blockScope = activeRequest(value) || allowNonRequestBlock;
    if (!policyEvaluation.controlled()
        && (legacyBlockEnabled() || runtime.mode() == DetectionMode.BLOCK)
        && blockScope) {
      event = value.withAction("block");
    }
    if (forceBlockEnabled() && blockScope && !value.requiresExplicitRule()) {
      event = event.withAction("block");
    }
    boolean willBlock =
        runtime.blockingAllowed()
            && "block".equalsIgnoreCase(event.action())
            && (activeRequest(event) || allowNonRequestBlock);
    // In MONITOR (record) mode a would-be block is observed, not enforced — record
    // it truthfully so the log/console don't claim a block that never happened.
    // Strictly gated on MONITOR, so unset/legacy (acceptance) behavior is unchanged.
    if (!willBlock && repeatedObservation != null && repeatedObservation.test(event.algorithm())) return;
    Detection recorded = event;
    if (!willBlock
        && runtime.mode() == DetectionMode.MONITOR
        && "block".equalsIgnoreCase(event.action())) {
      recorded = event.withAction("monitor");
    }
    JsonEventLogger.get().record(redactHttpObservation(recorded), elapsedMicros(started), ruleEvaluationUs);
    if (willBlock) {
      if (mayRedirect) redirectToBlockPage(event);
      if (throwOnBlock) {
        throw new OhMyRaspBlockException(event);
      }
    }
  }

  private static Detection redactHttpObservation(Detection event) {
    if (!"ssrf".equals(event.hook())) return event;
    String basis = event.details().get("decision_basis");
    if (!"http_transport_acquire".equals(basis) && !"http_request_write".equals(basis)
        && !"http_exchange_acquire".equals(basis) && !"http_resolved_route".equals(basis)
        && !"http_direct_connect".equals(basis)) return event;
    var details = new java.util.LinkedHashMap<>(event.details());
    details.computeIfPresent("url", (key, value) -> HttpTransportObservation.recordedAddress(value));
    var request = new RequestContext(event.request().method(), event.request().uri(), "", Map.of(), Map.of());
    return new Detection(event.timestamp(), event.hook(), event.algorithm(), event.action(),
        event.confidence(), event.message(), request, details);
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
