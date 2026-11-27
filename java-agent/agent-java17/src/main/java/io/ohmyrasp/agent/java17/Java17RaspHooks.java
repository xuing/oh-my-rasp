package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.backport.BackportHooks;
import io.ohmyrasp.agent.rules.general.PlotWrite;
import java.net.URL;
import java.util.List;

/**
 * The class the Java 17 transformers inject calls to. Each method is a one-line call to the method of the same
 * name in io.ohmyrasp.agent.backport.BackportHooks, which holds the decisions of all three backport lines; the
 * names and descriptors here stay as they are because instrumented classes, and the servlet transformer's
 * reflective path, name them. The line's start initialises this class before any transformer is registered.
 */
public final class Java17RaspHooks {
  private Java17RaspHooks() {}

  public static void beforeHttpRequest(Object request) {
    BackportHooks.beforeHttpRequest(request);
  }

  public static void beforeContainerRequest(Object request) {
    BackportHooks.beforeContainerRequest(request);
  }

  public static void afterHttpRequest() {
    BackportHooks.afterHttpRequest();
  }

  public static Object enterBodyRead() {
    return BackportHooks.enterBodyRead();
  }

  public static void exitBodyRead(int result, Object token) {
    BackportHooks.exitBodyRead(result, token);
  }

  public static void exitBodyRead(int result, Object token, byte[] buffer, int offset) {
    BackportHooks.exitBodyRead(result, token, buffer, offset);
  }

  public static void exitBodyRead(int result, Object token, java.nio.ByteBuffer buffer) {
    BackportHooks.exitBodyRead(result, token, buffer);
  }

  public static void exitBodyRead(byte[] result, Object token, boolean toEnd) {
    BackportHooks.exitBodyRead(result, token, toEnd);
  }

  public static void exitBodyChars(int result, Object token) {
    BackportHooks.exitBodyChars(result, token);
  }

  public static void exitBodyChars(int result, Object token, char[] buffer, int offset) {
    BackportHooks.exitBodyChars(result, token, buffer, offset);
  }

  public static void exitBodyChars(int result, Object token, java.nio.CharBuffer buffer) {
    BackportHooks.exitBodyChars(result, token, buffer);
  }

  public static void exitBodyLine(String result, Object token) {
    BackportHooks.exitBodyLine(result, token);
  }

  public static void afterMultipartAccess(Object source, Object result, boolean iterator) {
    BackportHooks.afterMultipartAccess(source, result, iterator);
  }

  public static void afterMultipartLookup(Object result, Object request, int kind, boolean bulk) {
    BackportHooks.afterMultipartLookup(result, request, kind, bulk);
  }

  public static void inspectMultipartFilename(String filename, boolean archiveOnly) {
    BackportHooks.inspectMultipartFilename(filename, archiveOnly);
  }

  public static void beforeFileUpload(String filename) {
    BackportHooks.beforeFileUpload(filename);
  }

  public static void beforeSparkRestSubmit(String descriptor) {
    BackportHooks.beforeSparkRestSubmit(descriptor);
  }

  public static void beforeSparkSubmitDispatch(boolean creation, Object request, Class<?> requestApi) {
    BackportHooks.beforeSparkSubmitDispatch(creation, request, requestApi);
  }

  public static void beforeYarnApplicationSubmit(Object submission) {
    BackportHooks.beforeYarnApplicationSubmit(submission);
  }

  public static void afterYarnSubmitPrepared(Object prepared, Object request, Class<?> requestApi) {
    BackportHooks.afterYarnSubmitPrepared(prepared, request, requestApi);
  }

  public static void beforeSpringProcessStart(ProcessBuilder builder) {
    BackportHooks.beforeSpringProcessStart(builder);
  }

  public static void beforeProcessLaunch(String[] argv) {
    BackportHooks.beforeProcessLaunch(argv);
  }

  public static void beforeProcessBuilderStart(ProcessBuilder processBuilder) {
    BackportHooks.beforeProcessBuilderStart(processBuilder);
  }

  public static void beforeRuntimeExecString(String command) {
    BackportHooks.beforeRuntimeExecString(command);
  }

  public static void beforeRuntimeExecArray(String[] command) {
    BackportHooks.beforeRuntimeExecArray(command);
  }

  public static void beforeJndiLookup(Object name) {
    BackportHooks.beforeJndiLookup(name);
  }

  public static void beforeJndiProviderLookup(String url, Object provider, String operation) {
    BackportHooks.beforeJndiProviderLookup(url, provider, operation);
  }

  public static void onJndiRoute(String url, String operation) {
    BackportHooks.onJndiRoute(url, operation);
  }

  public static void beforeObjectStreamClassResolve(Object descriptor) {
    BackportHooks.beforeObjectStreamClassResolve(descriptor);
  }

  public static void beforeObjectStreamProxyResolve(String[] interfaceNames) {
    BackportHooks.beforeObjectStreamProxyResolve(interfaceNames);
  }

  public static void beforeOpenWireThrowable(Class<?> selected) {
    BackportHooks.beforeOpenWireThrowable(selected);
  }

  public static void afterObjectStreamClassResolve(Class<?> selected) {
    BackportHooks.afterObjectStreamClassResolve(selected);
  }

  public static void afterObjectStreamProxyResolve(Class<?> selected) {
    BackportHooks.afterObjectStreamProxyResolve(selected);
  }

  public static void beforeHessianType(String type) {
    BackportHooks.beforeHessianType(type);
  }

  public static void beforeHessianAllocation(Class<?> selected, String basis) {
    BackportHooks.beforeHessianAllocation(selected, basis);
  }

  public static void beforeFileRead(Object path) {
    BackportHooks.beforeFileRead(path);
  }

  public static void captureDirectoryWalk(Object walker, java.nio.file.Path path) {
    BackportHooks.captureDirectoryWalk(walker, path);
  }

  public static void beginDirectoryVisit(Object walker, java.nio.file.Path path) {
    BackportHooks.beginDirectoryVisit(walker, path);
  }

  public static void afterFileList(String[] entries, String path) {
    BackportHooks.afterFileList(entries, path);
  }

  public static void afterDirectoryOpen(java.nio.file.DirectoryStream<?> opened, java.nio.file.Path path, boolean relativeApi) {
    BackportHooks.afterDirectoryOpen(opened, path, relativeApi);
  }

  public static void beforeHostDelete(java.nio.file.Path path) {
    BackportHooks.beforeHostDelete(path);
  }

  public static void beforeSecureDelete(int directoryFd, java.nio.file.SecureDirectoryStream<java.nio.file.Path> directory, java.nio.file.Path path, int flags) {
    BackportHooks.beforeSecureDelete(directoryFd, directory, path, flags);
  }

  public static void beforeStreamFileRead(String path, String hook) {
    BackportHooks.beforeStreamFileRead(path, hook);
  }

  public static void beforeRandomFileWrite(String path, int writable) {
    BackportHooks.beforeRandomFileWrite(path, writable);
  }

  public static void beforeFileWrite(Object path) {
    BackportHooks.beforeFileWrite(path);
  }

  @Deprecated
  public static void beforeFileContentWrite(byte[] bytes, int offset, int length) {
    BackportHooks.beforeFileContentWrite(bytes, offset, length);
  }

  public static void inspectPlotWrite(PlotWrite attempt) {
    BackportHooks.inspectPlotWrite(attempt);
  }

  public static void beforeRandomAccessFileOpen(Object path, String mode) {
    BackportHooks.beforeRandomAccessFileOpen(path, mode);
  }

  public static void beforeUnixFileOpen(java.nio.file.Path path, boolean read, int directoryFd) {
    BackportHooks.beforeUnixFileOpen(path, read, directoryFd);
  }

  public static void beforeUnixFileOpen(java.nio.file.Path path, boolean read, int directoryFd, boolean noFollowFinal, boolean creatingNew) {
    BackportHooks.beforeUnixFileOpen(path, read, directoryFd, noFollowFinal, creatingNew);
  }

  public static void beginNioRead(Object path) {
    BackportHooks.beginNioRead(path);
  }

  public static void beginNioChannel(Object path, Object options) {
    BackportHooks.beginNioChannel(path, options);
  }

  public static void beforeNioFileRead(Object path) {
    BackportHooks.beforeNioFileRead(path);
  }

  public static void beforeNioFileWrite(Object path) {
    BackportHooks.beforeNioFileWrite(path);
  }

  public static void beforeNioByteChannelOpen(Object path, Object options) {
    BackportHooks.beforeNioByteChannelOpen(path, options);
  }

  public static void captureHttpSubmission(Object exchange, java.net.URI uri) {
    BackportHooks.captureHttpSubmission(exchange, uri);
  }

  public static void finishHttpSubmission(java.util.concurrent.CompletableFuture<?> future, Object exchange) {
    BackportHooks.finishHttpSubmission(future, exchange);
  }

  public static void beforeHttpExchange(Object exchange, Object requestObject, java.net.URI uri) {
    BackportHooks.beforeHttpExchange(exchange, requestObject, uri);
  }

  public static void beforeResolvedHttpExchange(Object requestObject, java.net.URI uri, java.net.InetSocketAddress address, java.net.InetSocketAddress proxy) {
    BackportHooks.beforeResolvedHttpExchange(requestObject, uri, address, proxy);
  }

  public static void beforeUrlConnectionFactory(URL url) {
    BackportHooks.beforeUrlConnectionFactory(url);
  }

  public static void captureHttpRedirect(Object connection, URL to, URL from) {
    BackportHooks.captureHttpRedirect(connection, to, from);
  }

  public static void beginHttpRoute(Object client, URL url, java.net.Proxy proxy) {
    BackportHooks.beginHttpRoute(client, url, proxy);
  }

  public static void beforeHttpDial(Object client, java.net.SocketAddress destination) {
    BackportHooks.beforeHttpDial(client, destination);
  }

  public static void beforeHttpWrite(Object client, Object connection, URL url) {
    BackportHooks.beforeHttpWrite(client, connection, url);
  }

  public static void beforeHttpTransport(Object connection, URL url, boolean write) {
    BackportHooks.beforeHttpTransport(connection, url, write);
  }

  public static void beforeUrlOpen(Object url) {
    BackportHooks.beforeUrlOpen(url);
  }

  public static void beforeFastjsonClassResource(String resource) {
    BackportHooks.beforeFastjsonClassResource(resource);
  }

  public static void afterArchiveEntryName(String name) {
    BackportHooks.afterArchiveEntryName(name);
  }

  public static void beforeJdbcConnection(String url) {
    BackportHooks.beforeJdbcConnection(url);
  }

  public static void beforeH2JdbcConnection(String url) {
    BackportHooks.beforeH2JdbcConnection(url);
  }

  public static void beforeSqlIdentifier(String value) {
    BackportHooks.beforeSqlIdentifier(value);
  }

  public static void beforeSqlIdentifier(String value, String source, String parameter) {
    BackportHooks.beforeSqlIdentifier(value, source, parameter);
  }

  public static void beforeMyBatisBoundSql(String sql, Object ignored) {
    BackportHooks.beforeMyBatisBoundSql(sql, ignored);
  }

  public static void observeMyBatisSubstitution(StringBuilder builder, String value, Object handler, String expression) {
    BackportHooks.observeMyBatisSubstitution(builder, value, handler, expression);
  }

  public static void beforeSqlStatement(String sql) {
    BackportHooks.beforeSqlStatement(sql);
  }

  public static void beforeSqlStatement(Object receiver, String sql, String hook) {
    BackportHooks.beforeSqlStatement(receiver, sql, hook);
  }

  public static void beforeBase64Decode(byte[] src, int sp, int sl, boolean isURL, boolean isMIME) {
    BackportHooks.beforeBase64Decode(src, sp, sl, isURL, isMIME);
  }

  public static void beforeClassLoaderUrl(Object url) {
    BackportHooks.beforeClassLoaderUrl(url);
  }

  public static void beforeClassLoaderUrls(Object urls) {
    BackportHooks.beforeClassLoaderUrls(urls);
  }

  public static void onClassResourceRead(java.net.URLConnection connection, Object resource) {
    BackportHooks.onClassResourceRead(connection, resource);
  }

  public static void beforeClassDefinition(java.net.URL origin, Object handler, Object resource) {
    BackportHooks.beforeClassDefinition(origin, handler, resource);
  }

  public static void onClassDefinitionSource(String source) {
    BackportHooks.onClassDefinitionSource(source);
  }

  public static void beforeRmiClassLoaderCodebase(String codebase) {
    BackportHooks.beforeRmiClassLoaderCodebase(codebase);
  }

  public static void beforeRmiCodebaseLoader(URL[] urls) {
    BackportHooks.beforeRmiCodebaseLoader(urls);
  }

  public static void beforeScriptEval(String script) {
    BackportHooks.beforeScriptEval(script);
  }

  public static void beforeJexlExpression(Object expression) {
    BackportHooks.beforeJexlExpression(expression);
  }

  public static void beforeElExpression(Object expression) {
    BackportHooks.beforeElExpression(expression);
  }

  public static void beforeJavaCompilationSource(String compiler, Object source) {
    BackportHooks.beforeJavaCompilationSource(compiler, source);
  }

  public static void beforeJavaCompilationUnits(String compiler, Object units) {
    BackportHooks.beforeJavaCompilationUnits(compiler, units);
  }

  public static void beforeJaasConfigEntry(Object loginModuleName, Object options) {
    BackportHooks.beforeJaasConfigEntry(loginModuleName, options);
  }

  public static void beforeJmxStreamWrite(String path, int write) {
    BackportHooks.beforeJmxStreamWrite(path, write);
  }

  public static void beforeUnixChannelWrite(java.nio.file.Path path, int directoryFd, boolean write) {
    BackportHooks.beforeUnixChannelWrite(path, directoryFd, write);
  }

  public static void beforeJmxChannelWrite(java.nio.file.Path path, int directoryFd, boolean write) {
    BackportHooks.beforeJmxChannelWrite(path, directoryFd, write);
  }

  public static void beforeResolvedJmxInvoke(Object bean, String operation, Object arguments) {
    BackportHooks.beforeResolvedJmxInvoke(bean, operation, arguments);
  }

  public static void beforeJmxMBeanInvoke(Object bean, String operation, Object arguments) {
    BackportHooks.beforeJmxMBeanInvoke(bean, operation, arguments);
  }

  public static void beforeJwtVerificationFailure(Object token, Throwable failure) {
    BackportHooks.beforeJwtVerificationFailure(token, failure);
  }

  public static void beforeDataEaseFilterContinuation(String rejection, Object request) {
    BackportHooks.beforeDataEaseFilterContinuation(rejection, request);
  }

  public static void beforeJavaBeansStatement(Object statement) {
    BackportHooks.beforeJavaBeansStatement(statement);
  }

  static void beforeJavaBeansStatement(Object statement, List<String> stackClassNames) {
    BackportHooks.beforeJavaBeansStatement(statement, stackClassNames);
  }

  public static void rethrowIfJava17RaspBlock(Object throwable) {
    BackportHooks.rethrowIfBlock(throwable);
  }

  public static void beginAttachmentReference(String id) {
    BackportHooks.beginAttachmentReference(id);
  }

  public static void beforeXmlEntity(String name, Object source) {
    BackportHooks.beforeXmlEntity(name, source);
  }

  public static void beforeXmlEntityOpen(URL target, String name, Object parserInput, Object document, String literal) {
    BackportHooks.beforeXmlEntityOpen(target, name, parserInput, document, literal);
  }

  public static Object jmxAttributeDisplayReceiver(Object value) {
    return BackportHooks.jmxAttributeDisplayReceiver(value);
  }

  public static boolean enforceElasticLz4Bounds() {
    return BackportHooks.enforceElasticLz4Bounds();
  }
}
