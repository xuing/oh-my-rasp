package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.file.EscapingPath;
import io.ohmyrasp.agent.file.ArchiveEntryContext;
import io.ohmyrasp.agent.file.HostReadPath;
import io.ohmyrasp.agent.file.HostDirectory;
import io.ohmyrasp.agent.jmx.JmxDispatch;
import io.ohmyrasp.agent.rules.product.spark.SparkSubmitRole;
import io.ohmyrasp.agent.serialization.StreamTypeNames;
import io.ohmyrasp.agent.rules.product.beanshell.BeanShellTypes;
import io.ohmyrasp.agent.rules.general.PlotWrite;
import io.ohmyrasp.agent.jmx.JmxWriteScope;
import io.ohmyrasp.agent.file.HostDelete;
import io.ohmyrasp.agent.http.ArchiveUploadPolicy;
import io.ohmyrasp.agent.http.PercentEncodedText;
import io.ohmyrasp.agent.http.MultipartFilename;
import io.ohmyrasp.agent.http.ServletDispatchScope;
import io.ohmyrasp.agent.http.ServletQueryParameters;
import io.ohmyrasp.agent.net.HttpTransportObservation;
import io.ohmyrasp.agent.net.NetworkHost;
import io.ohmyrasp.agent.process.PosixShellCommand;
import io.ohmyrasp.agent.process.ProcessLaunchIndicators;
import io.ohmyrasp.agent.process.ShellControlSource;
import io.ohmyrasp.agent.rules.product.solr.SolrExecutableListener;
import io.ohmyrasp.agent.sql.SqlStatement;
import io.ohmyrasp.agent.sql.MyBatisSqlTrace;
import io.ohmyrasp.agent.xml.XmlCatalogResolution;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Java17RaspHooks {
  private static final Pattern SHELL =
      Pattern.compile(
          "(?i)(?:^|[/\\\\])(?:sh|bash|dash|ash|zsh|ksh|cmd(?:\\.exe)?|powershell(?:\\.exe)?|pwsh(?:\\.exe)?)$");
  private static final Pattern SHELL_META =
      Pattern.compile("[;&|`$<>]|\\$\\{?IFS\\}?");
  private static final Pattern EXPLOIT_COMMAND =
      Pattern.compile(
          "(?is)(?:cat\\s+/etc/(?:passwd|shadow)|/proc/self/environ|bash\\s+-i\\b|/dev/tcp/|nc\\b.{0,60}\\s-e\\s+/bin/(?:ba)?sh|curl\\b.{0,160}\\|\\s*(?:sh|bash)|wget\\b.{0,160}\\|\\s*(?:sh|bash)|\\{echo,.{10,500}\\}\\|\\{base64,-d\\})|(?:^|\\s)(?:cat|more|less|head|tail)\\s+/(?:etc/(?:passwd|shadow)|proc/self/environ)(?:\\s|$)");
  private static final byte[] SHIRO_DEFAULT_REMEMBERME_KEY =
      decodeBase64OrEmpty("kPH+bIxk5D2deZiIxcaaaA==");
  private static final int MAX_DEFAULT_CRYPTO_COOKIE_LENGTH = 12000;
  private static final List<String> FILE_READERS = java.util.Arrays.asList("cat", "more", "less", "head", "tail");
  private static final List<String> SENSITIVE_PATHS = java.util.Arrays.asList("/etc/passwd", "/etc/shadow", "/proc/self/environ");
  private static final Pattern REMOTE_JNDI_LOOKUP =
      Pattern.compile("(?is)^\\s*(ldap|ldaps|rmi|iiop|corbaname|corbaloc)://[^\\s\\u0000]{1,2048}");
  private static final Pattern JAAS_REMOTE_PROVIDER =
      Pattern.compile(
          "(?is)(?:^|[\\s,{])(?:user|group)\\.provider\\.url\\s*[=:]\\s*[\"']?((?:ldap|ldaps|rmi|iiop|corbaname|corbaloc)://[^\"'\\s,;}]{1,2048})");
  private static final Pattern TYPED_PAYLOAD_CLASS_ATTRIBUTE =
      Pattern.compile("(?is)(?:\\btype|\\bclass)\\s*=\\s*[\"']([^\"'<>\\s]{1,256})[\"']");
  private static final Pattern TYPED_PAYLOAD_JSON_TYPE =
      Pattern.compile("(?is)[\"']@type[\"']\\s*:\\s*[\"']([^\"']{1,256})[\"']");
  private static final Pattern TYPED_PAYLOAD_YAML_TAG =
      Pattern.compile("(?m)(?:^|[\\s\\[{,])!!([a-zA-Z_$][\\w$]*(?:\\.[a-zA-Z_$][\\w$]*)+)");
  private static final Pattern TYPED_PAYLOAD_REMOTE_NAMING_URL =
      Pattern.compile("(?is)\\b(ldap|ldaps|rmi|iiop|corbaname|corbaloc)://[^\\s\"'<>\\u0000]{1,2048}");
  private static final Pattern TYPED_PAYLOAD_H2_INIT =
      Pattern.compile("(?is)jdbc:h2:[^\\s\"'<>]{0,4096}\\bINIT\\s*=");
  private static final Pattern SENSITIVE_FILE_READ =
      Pattern.compile(
          "^/(?:etc/(?:passwd|shadow|issue)|proc/self/(?:environ|cmdline)|root/\\.ssh/(?:id_rsa|authorized_keys)|home/[^/]+/\\.ssh/id_rsa)$");
  private static final Pattern SCRIPT_FILE_WRITE =
      Pattern.compile(
          "(?i).+\\.(?:jsp|jspx|jspf|war|class|jar|php|asp|aspx|ashx|cer|asa|sh|bash|cmd|bat|ps1)$");
  private static final Pattern MULTIPART_SCRIPT_UPLOAD_FILE =
      Pattern.compile(
          "(?i)(?:.+\\.(?:jsp|jspx|jspf|php|asp|aspx|ashx|cer|asa)|(?:^|.*/)(?:\\.htaccess|\\.user\\.ini))$");
  private static final Pattern MULTIPART_HTML_UPLOAD_FILE =
      Pattern.compile("(?i).+\\.(?:html?|shtml|xhtml|svg)$");
  private static final Pattern MULTIPART_EXECUTABLE_UPLOAD_FILE =
      Pattern.compile("(?i).+\\.(?:exe|dll|so|dylib|msi|scr|com|bat|cmd|ps1|sh|bash)$");
  private static final Pattern MULTIPART_EXPRESSION_UPLOAD_FILE =
      Pattern.compile(
          "(?is)(?:%\\{|\\$\\{|#(?:context|application|session|request|response)|\\b(?:ognl|freemarker|execute)\\b|\\x00)");
  private static final Pattern MULTIPART_TRAVERSAL_UPLOAD_FILE =
      Pattern.compile("(?i)(?:^|/|%2f|%5c)\\.\\.(?:/|$|%2f|%5c)");
  private static final Pattern WEBROOT_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:webapps?|webroot|ROOT|www|wwwroot|htdocs|html|public|static|uploads?)(?:/|$)");
  private static final Pattern LOOPBACK_ADMIN_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:actuator|jolokia|manager|host-manager|admin|console|webtools|solr/admin|_cat|debug|server-status)(?:[/?#;]|$)");
  private static final Pattern SENSITIVE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:auth|admin|user|users|role|roles|permission|permissions|ops|manage|management|console)(?:/|$)");
  private static final Pattern INTERNAL_FORWARD_JSP_SUFFIX =
      Pattern.compile("(?i);\\s*\\.jspx?(?:$|[/?#])");
  private static final Pattern INTERNAL_FORWARD_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:auth|admin|user|users|role|roles|permission|permissions|token|tokens|debug|config|ops|manage|management|console)(?:/|$)");
  private static final Pattern JWT_HMAC_ALGORITHM =
      Pattern.compile("\"alg\"\\s*:\\s*\"(HS(?:256|384|512))\"");
  private static final Pattern PROTECTED_WEB_RESOURCE_PATH =
      Pattern.compile("(?i)(?:^|/)(?:WEB-INF|META-INF)(?:/|$)");
  private static final Pattern TEMPLATE_SOURCE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|administrator|adminapi|ajax|cfc|control|filemanager|include|includes|macro|preview|render|resource|resources|template|templates|tinymce|view|views)(?:[!;/]|/|$)");
  private static final Pattern REMOTE_TEMPLATE_SOURCE_URL =
      Pattern.compile("(?is)^\\s*(?:https?|ftp|ldap|rmi)://[^\\s\\u0000]{1,2048}");
  private static final Pattern OGC_REQUEST_CONTROL_PATH =
      Pattern.compile("(?i)(?:^|/)(?:ows|wfs|wms|wps)(?:[;/]|/|$)");
  private static final Pattern OGC_FILTER_SQL_INJECTION_VALUE =
      Pattern.compile(
          "(?is)(?:--|/\\*|\\bunion\\s+(?:all\\s+)?select\\b|\\bcast\\s*\\(\\s*\\(?\\s*\\(?\\s*select\\b|\\bselect\\b.{0,160}\\b(?:version|current_database|database|user)\\s*\\(|\\b(?:pg_sleep|sleep|benchmark)\\s*\\()");
  private static final Pattern SAFE_SQL_IDENTIFIER =
      Pattern.compile("(?i)^[a-z0-9_.$-]{1,256}$");
  private static final Pattern SQL_IDENTIFIER_KEYWORD_CONTROL =
      Pattern.compile(
          "(?is)(?:^|\\s)(?:where|join|union|select|insert|update|delete|drop|alter|create|merge|call|case|when|then|else|sleep|benchmark|order|group|having|limit|and|or)\\b");
  private static final Pattern SCRIPT_LITERAL_EXECUTE =
      Pattern.compile("(?is)[\"'][^\"'\\r\\n]{1,200}[\"']\\s*\\.\\s*execute\\s*\\(");
  private static final ThreadLocal<String> LAST_LOGGED_REQUEST = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_REMOTE_JOB = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_COMMAND = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JNDI = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_HESSIAN_TYPE = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_FILE_READ = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_FILE_WRITE = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_FILE_UPLOAD = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_URL = new ThreadLocal<String>();
  private static final ThreadLocal<List<String>> CURRENT_REQUEST_URLS =
      new ThreadLocal<List<String>>();
  private static final ThreadLocal<RequestSnapshot> CURRENT_REQUEST =
      new ThreadLocal<RequestSnapshot>();
  private static final ArchiveEntryContext ARCHIVE_ENTRY = new ArchiveEntryContext();
  private static final ServletDispatchScope<RequestSnapshot, List<String>> DISPATCH =
      new ServletDispatchScope<RequestSnapshot, List<String>>(CURRENT_REQUEST, CURRENT_REQUEST_URLS, ARCHIVE_ENTRY);
  private static final ThreadLocal<String> LAST_LOGGED_ARCHIVE = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JDBC = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_SQL_IDENTIFIER = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_SQL_STATEMENT = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_BASE64 = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_CLASSLOADER = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_SCRIPT = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JEXL = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_EL = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JAVA_COMPILE = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JAAS = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JMX = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_XML_DECODER = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_XXE = new ThreadLocal<String>();
  private static final String HUGEGRAPH_DEFAULT_JWT_SECRET = "FXQXbJtbCLxODc6tGci732pkH1cyf8Qg";

  private Java17RaspHooks() {}

  public static void beforeHttpRequest(Object request) {
    beforeHttpRequest(request, false);
  }

  public static void beforeContainerRequest(Object request) {
    beforeHttpRequest(request, true);
  }

  private static void beforeHttpRequest(Object request, boolean beforeServlet) {
    long started = System.nanoTime();
    DISPATCH.enter(beforeServlet ? null : request);
    try {
      try {
        beforeHttpRequestImpl(request, beforeServlet);
        DISPATCH.enteredApplication();
      } finally {
        RaspRuntime.sampleLatency((System.nanoTime() - started) / 1000L);
      }
    } catch (RuntimeException | Error failure) {
      DISPATCH.exit();
      throw failure;
    }
  }

  private static void beforeHttpRequestImpl(Object request, boolean beforeServlet) {
    // Parameter-map access can consume a multipart body before lazy servlet initialization.
    boolean deferMultipart = beforeServlet
        && requestHeader(request, "Content-Type").trim().regionMatches(true, 0, "multipart/", 0, 10);
    Object raw = deferMultipart ? ServletQueryParameters.parse(requestQuery(request))
        : invoke(request, "getParameterMap");
    Map<?, ?> parameters = raw instanceof Map<?, ?> ? (Map<?, ?>) raw : null;
    CURRENT_REQUEST.set(new RequestSnapshot(parameters));
    captureRequestControlledUrls(parameters);
    Finding finding = classifyHttpRequest(request, parameters);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_REQUEST.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_REQUEST.set(finding.detailValue);
    appendEvent(finding, "HttpServlet.service", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious request path");
    }
  }

  public static void afterHttpRequest() {
    DISPATCH.exit();
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
    if (RaspRuntime.detectionOff() || DISPATCH.inspectingRequest()) return;
    Finding finding = archiveOnly ? classifyArchiveUpload(filename) : classifyFileUpload(filename);
    if (finding == null) return;
    String action = shouldBlock() ? "block" : "log";
    if (MultipartFilename.eligible()) {
      if (!"block".equals(action) && MultipartFilename.repeated(DISPATCH.servletRequest(), filename,
          finding.algorithm, finding.decisionBasis == null ? "" : finding.decisionBasis, finding.policyDigest)) return;
    } else {
      RequestSnapshot request = CURRENT_REQUEST.get();
      String previous = request == null ? LAST_LOGGED_FILE_UPLOAD.get() : request.lastUpload;
      if (!"block".equals(action) && finding.detailValue.equals(previous)) return;
      if (request == null) LAST_LOGGED_FILE_UPLOAD.set(finding.detailValue);
      else request.lastUpload = finding.detailValue;
    }
    appendEvent(finding, "MultipartUpload.filename", action);
    if ("block".equals(action)) throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious file upload");
  }

  /** Previously transformed handlers supplied only descriptor text. */
  public static void beforeSparkRestSubmit(String descriptor) {}

  public static void beforeSparkSubmitDispatch(boolean creation, Object request, Class<?> requestApi) {
    if (RaspRuntime.detectionOff() || !SparkSubmitRole.denied(creation, request, requestApi)) return;
    Finding finding = new Finding("java17_request_remote_job_submission", 95,
        "Spark job submission lacks the deployment's required role", "operation", "handleSubmit", "required_submit_role_denied");
    boolean block = shouldBlock();
    appendEvent(finding, "SparkRest.handleSubmit", block ? "block" : "log");
    if (block) throw new Java17RaspBlockException("OhMyRASP blocked unauthorized Spark submission");
  }

  public static void beforeYarnApplicationSubmit(Object submission) {
    Finding finding = classifyYarnApplicationSubmission(submission);
    emitRemoteJobFinding(finding, "RMWebServices.submitApplication");
  }

  public static void beforeProcessLaunch(String[] argv) {
    if (RaspRuntime.detectionOff()) return;
    Finding finding = classifyCommand(argv);
    if (finding == null) return;
    String api = io.ohmyrasp.agent.process.ProcessLaunch.api();
    if (api == null) return;
    boolean block = shouldBlock();
    appendEvent(finding, api, block ? "block" : "log", null, argv.length);
    if (block) throw new Java17RaspBlockException("OhMyRASP blocked a process launch");
  }

  public static void beforeProcessBuilderStart(ProcessBuilder processBuilder) {
    if (processBuilder == null) {
      return;
    }
    inspectCommand(toArray(processBuilder.command()), "ProcessBuilder.start");
  }

  public static void beforeRuntimeExecString(String command) {
    if (command == null) {
      return;
    }
    inspectCommand(PosixShellCommand.runtimeArguments(command), "Runtime.exec(String)");
  }

  public static void beforeRuntimeExecArray(String[] command) {
    inspectCommand(command, "Runtime.exec(String[])");
  }

  public static void beforeJndiLookup(Object name) {
    if (name == null) {
      return;
    }
    Finding finding = classifyJndiLookup(String.valueOf(name).trim());
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_JNDI.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_JNDI.set(finding.detailValue);
    appendEvent(finding, "InitialContext.lookup", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious JNDI lookup");
    }
  }

  /** Legacy entry hooks precede class resolution and have no selected type. */
  public static void beforeObjectStreamClassResolve(Object descriptor) {}
  public static void beforeObjectStreamProxyResolve(String[] interfaceNames) {}

  public static void afterObjectStreamClassResolve(Class<?> selected) {
    inspectResolvedType(selected, "ObjectInputStream.resolveClass", "resolved_class");
  }

  public static void afterObjectStreamProxyResolve(Class<?> selected) {
    if (selected == null || RaspRuntime.detectionOff() || !java.lang.reflect.Proxy.isProxyClass(selected)) return;
    for (Class<?> iface : selected.getInterfaces()) {
      if (inspectResolvedType(iface, "ObjectInputStream.resolveProxyClass", "resolved_proxy_interface")) return;
    }
  }

  private static boolean inspectResolvedType(Class<?> selected, String hook, String basis) {
    if (selected == null || RaspRuntime.detectionOff()) return false;
    String name = selected.getName();
    if (!StreamTypeNames.listed(name) || !BeanShellTypes.permitsTypeCheck(selected)) return false;
    Finding finding = new Finding("java17_deserialization_gadget_class", deserializationConfidence(name),
        "Stream resolver selected a listed serialization type", "class", name, basis);
    boolean block = shouldBlock();
    appendEvent(finding, hook, block ? "block" : "log");
    if (block) throw new Java17RaspBlockException("OhMyRASP blocked a listed serialization type");
    return true;
  }

  public static void beforeHessianType(String type) {
    Finding finding = classifyHessianType(type);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_HESSIAN_TYPE.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_HESSIAN_TYPE.set(finding.detailValue);
    appendEvent(finding, "Hessian.SerializerFactory.getDeserializer", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious Hessian deserialization type");
    }
  }

  public static void beforeFileRead(Object path) {
    if (!HostReadPath.isHostPath(path)) return;
    Finding finding = classifyFileRead(pathValue(path), HostReadPath.OpenPolicy.PATH_ONLY);
    emitFileFinding(finding, LAST_LOGGED_FILE_READ, "FileInputStream.open");
  }

  public static void captureDirectoryWalk(Object walker, java.nio.file.Path path) {
    RequestSnapshot request = CURRENT_REQUEST.get();
    if (RaspRuntime.detectionOff() || request == null || path == null || !HostReadPath.isHostPath(path)) return;
    List<String> inputs = request.parameterValues == null ? java.util.Collections.<String>emptyList() : request.parameterValues;
    HostDirectory.submitted(walker, inputs, HostDirectory.selected(path.toString(), inputs, false));
  }

  public static void beginDirectoryVisit(Object walker, java.nio.file.Path path) {
    HostDirectory.visiting(walker, path, CURRENT_REQUEST.get() != null);
  }

  public static void afterFileList(String[] entries, String path) {
    if (entries != null) inspectListedDirectory(path, null, false, null);
  }

  public static void afterDirectoryOpen(java.nio.file.DirectoryStream<?> opened, java.nio.file.Path path, boolean relativeApi) {
    if (opened == null) return;
    try { inspectListedDirectory(path.toString(), opened, relativeApi && !path.isAbsolute(), HostDirectory.origin(path)); }
    catch (Java17RaspBlockException denied) { HostDirectory.closeDenied(opened, denied); throw denied; }
  }

  @SuppressWarnings("unchecked")
  private static void inspectListedDirectory(String path, java.nio.file.DirectoryStream<?> opened, boolean relative, HostDirectory.Walk walk) {
    if (RaspRuntime.detectionOff()) return;
    RequestSnapshot request = CURRENT_REQUEST.get();
    List<String> inputs = walk != null ? (List<String>) walk.origin : request != null ? request.parameterValues : null;
    boolean direct = HostDirectory.selected(path, inputs, relative);
    if (!direct && (walk == null || !walk.selected)) return;
    String root = HostDirectory.protectedRoot(path, opened, relative);
    if (root.isEmpty()) return;
    Finding finding = new Finding("java17_directory_userinput", 90, "Request selected a protected directory listing",
        "path", root, direct ? "selected_directory" : "selected_directory_walk");
    boolean block = shouldBlock();
    String operation = opened == null ? "FileSystem.list" : relative ? "SecureDirectoryStream.open" : "DirectoryStream.open";
    appendEvent(finding, operation, block ? "block" : "log");
    if (block) throw new Java17RaspBlockException("OhMyRASP blocked a directory listing");
  }

  public static void beforeHostDelete(java.nio.file.Path path) {
    inspectDelete(path, null, -1, false);
  }

  public static void beforeSecureDelete(int directoryFd, java.nio.file.SecureDirectoryStream<java.nio.file.Path> directory,
      java.nio.file.Path path, int flags) {
    inspectDelete(path, directory, directoryFd, flags != 0);
  }

  private static void inspectDelete(java.nio.file.Path path, java.nio.file.SecureDirectoryStream<java.nio.file.Path> directory,
      int directoryFd, boolean removeDirectory) {
    if (RaspRuntime.detectionOff()) return;
    RequestSnapshot request = CURRENT_REQUEST.get();
    if (request == null || request.parameterValues == null) return;
    HostDelete entry = new HostDelete(path, directoryFd, directory != null, true);
    for (String input : request.parameterValues) {
      if (entry.match(input) != HostDelete.Basis.ESCAPING_ENTRY) continue;
      if (directory != null && !HostDelete.hasEntry(directory, path, removeDirectory)) return;
      Finding finding = new Finding("deleteFile_userinput", 85, "Request selected an entry outside the base directory",
          "path", entry.path(), "escaping_entry");
      boolean block = shouldBlock();
      appendEvent(finding, directory == null ? "host_entry_removal" : "descriptor_relative_unlink", block ? "block" : "log");
      if (block) throw new Java17RaspBlockException("OhMyRASP blocked a file removal");
      return;
    }
  }

  public static void beforeStreamFileRead(String path, String hook) {
    if (!RaspRuntime.detectionOff()) emitFileFinding(classifyFileRead(path, HostReadPath.OpenPolicy.FOLLOW), null, hook);
  }

  public static void beforeRandomFileWrite(String path, int writable) {
    if (writable != 0) beforeFileWrite(path);
  }

  public static void beforeFileWrite(Object path) {
    if (!ARCHIVE_ENTRY.hostDestination(path)) return;
    String rawPath = pathValue(path);
    String normalizedPath = normalizePath(rawPath);
    String entry = ARCHIVE_ENTRY.take();
    if (entry != null) {
      emitFileFinding(classifyArchiveWrite(entry, rawPath, null), LAST_LOGGED_ARCHIVE, "ArchiveEntry.write");
    }
    if (isTomcatWarExpansionStack() || isTomcatJspCompilationStack()) {
      return;
    }
    Finding finding = classifyFileWrite(normalizedPath);
    emitFileFinding(finding, LAST_LOGGED_FILE_WRITE, "FileOutputStream.open");
  }

  /** Previously transformed callers have no receiver identity for this callback. */
  @Deprecated public static void beforeFileContentWrite(byte[] bytes, int offset, int length) {}

  public static void inspectPlotWrite(PlotWrite attempt) {
    if (attempt == null) return;
    try {
      if (!attempt.hasDirective() || RaspRuntime.detectionOff()) return;
      Finding finding = new Finding("java17_file_generated_plot_script_command", 91,
          "A plot directive reached its open output stream", "path", attempt.path(), "plot_stream_write");
      boolean block = shouldBlock();
      appendEvent(finding, "FileOutputStream.write", block ? "block" : "log");
      if (block) throw new Java17RaspBlockException("OhMyRASP blocked a plot directive");
    } catch (RuntimeException | Error failure) {
      PlotWrite.cancelled(attempt);
      throw failure;
    }
  }

  public static void beforeRandomAccessFileOpen(Object path, String mode) {
    if (mode != null && mode.toLowerCase(Locale.ROOT).indexOf('w') >= 0) {
      beforeFileWrite(path);
    } else {
      beforeFileRead(path);
    }
  }

  public static void beforeUnixFileOpen(java.nio.file.Path path, boolean read, int directoryFd) {
    beforeUnixFileOpen(path, read, directoryFd, false, false);
  }

  public static void beforeUnixFileOpen(java.nio.file.Path path, boolean read, int directoryFd,
      boolean noFollowFinal, boolean creatingNew) {
    if (HostReadPath.nativeRead(path, read && !creatingNew, directoryFd) && !RaspRuntime.detectionOff()) {
      HostReadPath.OpenPolicy links = noFollowFinal ? HostReadPath.OpenPolicy.NOFOLLOW_FINAL : HostReadPath.OpenPolicy.FOLLOW;
      emitFileFinding(classifyFileRead(path.toString(), links), null, "UnixChannelFactory.open");
    }
  }

  public static void beginNioRead(Object path) {
    HostReadPath.beginFacade(path);
    try { beforeNioFileRead(path); }
    catch (RuntimeException | Error failure) { HostReadPath.endFacade(); throw failure; }
  }

  public static void beginNioChannel(Object path, Object options) {
    HostReadPath.beginFacade(path);
    try { beforeNioByteChannelOpen(path, options); }
    catch (RuntimeException | Error failure) { HostReadPath.endFacade(); throw failure; }
  }

  public static void beforeNioFileRead(Object path) {
    if (HostReadPath.needsFacadeRead(path)) {
      emitFileFinding(classifyFileRead(pathValue(path), HostReadPath.OpenPolicy.PATH_ONLY), LAST_LOGGED_FILE_READ, "FileInputStream.open");
    }
  }

  public static void beforeNioFileWrite(Object path) {
    beforeFileWrite(path);
  }

  public static void beforeNioByteChannelOpen(Object path, Object options) {
    if (nioOptionsContainWrite(options)) {
      beforeFileWrite(path);
    } else {
      beforeNioFileRead(path);
    }
  }

  private static final HttpTransportObservation.Submissions<List<String>> HTTP_SUBMISSIONS =
      new HttpTransportObservation.Submissions<List<String>>();

  public static void captureHttpSubmission(Object exchange, java.net.URI uri) {
    if (RaspRuntime.detectionOff()) return;
    List<String> urls = CURRENT_REQUEST_URLS.get();
    HTTP_SUBMISSIONS.capture(exchange, urls);
    if (urls != null && uri != null && urls.contains(urlParts(uri).comparisonKey)) {
      HttpTransportObservation.selectedSubmission(exchange, uri);
    }
  }

  public static void finishHttpSubmission(java.util.concurrent.CompletableFuture<?> future, Object exchange) {
    HTTP_SUBMISSIONS.finishedWhen(future, exchange);
  }

  public static void beforeHttpExchange(Object exchange, Object requestObject, java.net.URI uri) {
    if (RaspRuntime.detectionOff() || uri == null || !("http".equalsIgnoreCase(uri.getScheme())
        || "https".equalsIgnoreCase(uri.getScheme()))) return;
    HttpTransportObservation.bindExchange(requestObject, exchange, uri);
    inspectHttpExchange(exchange, uri, null);
  }

  public static void beforeResolvedHttpExchange(Object requestObject, java.net.URI uri, java.net.InetSocketAddress address,
      java.net.InetSocketAddress proxy) {
    if (RaspRuntime.detectionOff()) return;
    String peer = HttpTransportObservation.directAddress(uri, address, proxy);
    if (peer != null) {
      Object exchange = HttpTransportObservation.submittedExchange(requestObject);
      if (exchange != null) inspectHttpExchange(exchange, uri, peer);
    }
  }

  private static void inspectHttpExchange(Object exchange, java.net.URI uri, String peer) {
    Finding finding = classifyUrlOpen(uri, HTTP_SUBMISSIONS.origin(exchange), peer, HttpTransportObservation.changedOrigin(exchange, uri));
    if (finding != null) emitHttpDestination(finding, "HTTP.acquireExchange",
        peer == null ? "http_exchange_acquire" : "http_resolved_route", shouldBlock(), peer);
  }

  public static void beforeUrlConnectionFactory(URL url) {
    if (!HttpTransportObservation.isHttp(url)) beforeUrlOpen(url);
  }

  public static void captureHttpRedirect(Object connection, URL to, URL from) {
    if (RaspRuntime.detectionOff() || !HttpTransportObservation.isHttp(from) || !HttpTransportObservation.isHttp(to)) return;
    List<String> inputs = CURRENT_REQUEST_URLS.get();
    HttpTransportObservation.selectedRedirect(connection, from, to, inputs != null && inputs.contains(urlComparisonKey(from)));
  }

  public static void beginHttpRoute(Object client, URL url, java.net.Proxy proxy) {
    HttpTransportObservation.beginRoute(client, RaspRuntime.detectionOff() ? null : url, proxy);
  }

  public static void beforeHttpDial(Object client, java.net.SocketAddress destination) {
    if (RaspRuntime.detectionOff()) return;
    URL url = HttpTransportObservation.dialTarget(client, destination);
    if (url != null) inspectHttpTransport(client, url, false, HttpTransportObservation.peer(client, url), "http_direct_connect", HttpTransportObservation.dialingRedirect(url));
  }

  public static void beforeHttpWrite(Object client, Object connection, URL url) {
    if (RaspRuntime.detectionOff()) return;
    String peer = HttpTransportObservation.peer(client, url);
    inspectHttpTransport(peer == null ? connection : client, url, true, peer, "http_request_write",
        HttpTransportObservation.redirected(connection, url));
  }

  public static void beforeHttpTransport(Object connection, URL url, boolean write) {
    inspectHttpTransport(connection, url, write, null, write ? "http_request_write" : "http_transport_acquire",
        HttpTransportObservation.redirected(connection, url));
  }

  private static void inspectHttpTransport(Object connection, URL url, boolean write, String peer, String basis, boolean redirected) {
    if (RaspRuntime.detectionOff()) return;
    Finding finding = classifyUrlOpen(url, CURRENT_REQUEST_URLS.get(), peer, redirected);
    if (finding == null) return;
    boolean block = shouldBlock();
    if (!block && HttpTransportObservation.repeated(connection, url, CURRENT_REQUEST.get(), finding.algorithm, write)) return;
    emitHttpDestination(finding, write ? "HTTP.writeRequest" : (peer == null ? "HTTP.acquireTransport" : "HTTP.connect"), basis, block, peer);
  }

  private static void emitHttpDestination(Finding finding, String hook, String basis, boolean block, String peer) {
    Finding observed = new Finding(finding.algorithm, finding.confidence, finding.message,
        finding.detailKey, HttpTransportObservation.recordedAddress(finding.detailValue), basis);
    appendEvent(observed, hook, block ? "block" : "log", peer);
    if (block) throw new Java17RaspBlockException("OhMyRASP blocked an outbound HTTP destination");
  }

  public static void beforeUrlOpen(Object url) {
    Finding finding = classifyUrlOpen(url);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_URL.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_URL.set(finding.detailValue);
    appendEvent(finding, "URL.openConnection", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious URL access");
    }
  }

  public static void beforeFastjsonClassResource(String resource) {
    Finding finding = classifyFastjsonClassResource(resource);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    appendEvent(finding, "ParserConfig.checkAutoType.getResourceAsStream", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException(
          "OhMyRASP Java 17 blocked a Fastjson URL-shaped class resource");
    }
  }

  public static void afterArchiveEntryName(String name) {
    ARCHIVE_ENTRY.observe(name);
  }

  public static void beforeJdbcConnection(String url) {
    inspectJdbcConnection(url, "DriverManager.getConnection");
  }

  public static void beforeH2JdbcConnection(String url) {
    inspectJdbcConnection(url, "org.h2.jdbc.JdbcConnection.<init>");
  }

  public static void beforeSqlIdentifier(String value) {
    Finding finding =
        classifySqlIdentifier(
            value, "SkyWalking.H2LogQueryDAO.queryLogs", "metricName");
    inspectSqlIdentifierFinding(finding, "SQL.identifier");
  }

  /** Binary compatibility with previously transformed BoundSql constructors. */
  public static void beforeMyBatisBoundSql(String sql, Object ignored) {
    MyBatisSqlTrace.compiled(null, sql);
  }

  public static void observeMyBatisSubstitution(StringBuilder builder, String value, Object handler, String expression) {
    if (!RaspRuntime.detectionOff()) MyBatisSqlTrace.substitution(builder, value, handler, expression);
  }

  public static void beforeSqlStatement(String sql) {
    beforeSqlStatement(null, sql, "Statement.execute");
  }

  public static void beforeSqlStatement(Object receiver, String sql, String hook) {
    if (RaspRuntime.detectionOff()) return;
    Finding finding = classifySqlStatement(receiver, sql);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    if ("mapper_substitution_at_jdbc".equals(finding.decisionBasis)) {
      if (!"block".equals(action) && MyBatisSqlTrace.repeatedObservation(sql, finding.algorithm)) return;
    } else {
      String previous = LAST_LOGGED_SQL_STATEMENT.get();
      if (!"block".equals(action) && finding.detailValue.equals(previous)) return;
      LAST_LOGGED_SQL_STATEMENT.set(finding.detailValue);
    }
    appendEvent(finding, hook, action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious SQL statement");
    }
  }

  public static void beforeBase64Decode(
      byte[] src, int sp, int sl, boolean isURL, boolean isMIME) {
    // Pure arithmetic fast path first so benign Base64 decoding never triggers
    // class initialization or allocates on the hot path.
    if (!isBase64TailUnderflowCandidate(src, sp, sl, isURL, isMIME)) {
      return;
    }
    int length = sl - sp;
    int remainder = length & 63;
    int padding = 0;
    while (padding < 3 && src[sl - 1 - padding] == '=') {
      padding++;
    }
    Finding finding =
        new Finding(
            "java17_base64_avx512_tail_underflow",
            99,
            "Base64.Decoder.decode0 rejected x64 AVX-512 tail-underflow candidate (CVE-2026-114938)",
            "candidate",
            "length="
                + length
                + ",padding="
                + padding
                + ",remainder="
                + remainder
                + ",alphabet="
                + (isURL ? "URL-safe" : "standard")
                + ",cve=CVE-2026-114938");
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_BASE64.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_BASE64.set(finding.detailValue);
    appendEvent(finding, "Base64.Decoder.decode0", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException(
          "OhMyRASP Java 17 blocked Base64 x64 tail-underflow candidate");
    }
  }

  private static boolean isBase64TailUnderflowCandidate(
      byte[] src, int sp, int sl, boolean isURL, boolean isMIME) {
    if (isMIME || src == null || sp < 0 || sl < sp || sl > src.length) {
      return false;
    }
    int length = sl - sp;
    if (length < 65) {
      return false;
    }
    int remainder = length & 63;
    if (remainder < 1 || remainder > 3) {
      return false;
    }
    int padding = 0;
    while (padding < 3 && src[sl - 1 - padding] == '=') {
      padding++;
    }
    if (padding < 1 || padding > 2 || padding > remainder) {
      return false;
    }
    for (int i = sp; i < sl - padding; i++) {
      int c = src[i] & 0xff;
      if (!((c >= 'A' && c <= 'Z')
          || (c >= 'a' && c <= 'z')
          || (c >= '0' && c <= '9')
          || (isURL ? (c == '-' || c == '_') : (c == '+' || c == '/')))) {
        return false;
      }
    }
    return true;
  }

  private static Finding classifySqlStatement(Object receiver, String sql) {
    if (sql == null || sql.trim().length() == 0) {
      return null;
    }
    SqlStatement statement = SqlStatement.fromJdbc(sql, receiver);
    String mapperControl = MyBatisSqlTrace.controlAtJdbc(statement);
    if (mapperControl != null) {
      return new Finding("java17_sql_identifier_injection", 95,
          "A raw mapper substitution introduced SQL control at JDBC",
          "identifier", "source=MyBatis reason=" + mapperControl, "mapper_substitution_at_jdbc");
    }
    RequestSnapshot snapshot = CURRENT_REQUEST.get();
    boolean structural = statement.hasTruncatedLiteral()
        || (statement.hasConstantDisjunction()
            && (snapshot == null || snapshot.sqlInputs.stream().noneMatch(statement::isSubmittedConsoleSelect)));
    if (!structural && !statement.matchesSinkPolicy()
        && (snapshot == null || !snapshot.sqlInputs.stream().anyMatch(statement::matchesStructureFrom))) {
      return null;
    }
    return new Finding(
        "java17_sql_statement_injection",
        structural ? 90 : 85,
        "Suspicious SQL injection pattern reached a Java 17 JDBC Statement sink",
        "query",
        abbreviate(sql, 1200));
  }

  private static void inspectSqlIdentifierFinding(Finding finding, String hook) {
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_SQL_IDENTIFIER.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_SQL_IDENTIFIER.set(finding.detailValue);
    appendEvent(finding, hook, action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious SQL identifier");
    }
  }

  private static void inspectJdbcConnection(String url, String hook) {
    Finding finding = classifyJdbcUrl(url);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_JDBC.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_JDBC.set(finding.detailValue);
    appendEvent(finding, hook, action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious JDBC URL");
    }
  }

  public static void beforeClassLoaderUrl(Object url) {
    emitClassLoaderFindings(url, "URLClassLoader");
  }

  public static void beforeClassLoaderUrls(Object urls) {
    emitClassLoaderFindings(urls, "URLClassLoader");
  }

  public static void beforeRmiClassLoaderCodebase(String codebase) {
    emitClassLoaderFindings(codebase, "RMIClassLoader");
  }

  public static void beforeScriptEval(String script) {
    Finding finding = classifyScriptEval(script);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_SCRIPT.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_SCRIPT.set(finding.detailValue);
    appendEvent(finding, "ScriptEngine.eval", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious script evaluation");
    }
  }

  public static void beforeJexlExpression(Object expression) {
    Finding finding = classifyJexlExpression(jexlSourceText(expression));
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_JEXL.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_JEXL.set(finding.detailValue);
    appendEvent(finding, "CommonsJEXL.evaluate", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious JEXL evaluation");
    }
  }

  public static void beforeElExpression(Object expression) {
    Finding finding = classifyElExpression(elSourceText(expression));
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_EL.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_EL.set(finding.detailValue);
    appendEvent(finding, "UnifiedEL.evaluate", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious EL evaluation");
    }
  }

  public static void beforeJavaCompilationSource(String compiler, Object source) {
    emitJavaCompilationFinding(classifyJavaCompilation(compiler, javaSourceText(source)));
  }

  public static void beforeJavaCompilationUnits(String compiler, Object units) {
    List<String> sources = javaSourceTexts(units);
    for (String source : sources) {
      emitJavaCompilationFinding(classifyJavaCompilation(compiler, source));
    }
  }

  public static void beforeJaasConfigEntry(Object loginModuleName, Object options) {
    Finding finding = classifyJaasConfig(loginModuleName, options);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_JAAS.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_JAAS.set(finding.detailValue);
    appendEvent(finding, "AppConfigurationEntry.<init>", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious JAAS configuration");
    }
  }

  public static void beforeJmxStreamWrite(String path, int write) {
    if (write != 0 && JmxWriteScope.current() != null) inspectJmxFileWrite(path, "stream_open");
  }

  public static void beforeUnixChannelWrite(java.nio.file.Path path, int directoryFd, boolean write) {
    if (!write) return;
    ArchiveEntryContext.ChannelWrite open = ARCHIVE_ENTRY.atChannelOpen(path, directoryFd);
    if (open != null && !RaspRuntime.detectionOff())
      emitFileFinding(classifyArchiveWrite(open.member, open.target, open.basis), null, "ArchiveEntry.write");
    beforeJmxChannelWrite(path, directoryFd, true);
  }

  public static void beforeJmxChannelWrite(java.nio.file.Path path, int directoryFd, boolean write) {
    if (write && JmxWriteScope.current() != null && (directoryFd < 0 || path.isAbsolute()))
      inspectJmxFileWrite(path.toString(), "channel_open");
  }

  private static void inspectJmxFileWrite(String path, String operation) {
    JmxWriteScope scope = JmxWriteScope.current();
    if (RaspRuntime.detectionOff() || !SCRIPT_FILE_WRITE.matcher(normalizePath(path)).matches() || !scope.selects(path)) return;
    Finding finding = new Finding("java17_jmx_script_file_write", 90,
        "A managed operation opens its selected script destination for writing", "path", path, "selected_write_open");
    boolean block = shouldBlock();
    appendEvent(finding, operation, block ? "block" : "log");
    if (block) throw new Java17RaspBlockException("OhMyRASP blocked a managed file write");
  }

  public static void beforeResolvedJmxInvoke(Object bean, String operation, Object arguments) {
    inspectJmxInvoke(bean, operation, arguments, true);
  }

  public static void beforeJmxMBeanInvoke(Object bean, String operation, Object arguments) {
    inspectJmxInvoke(bean, operation, arguments, false);
  }

  private static void inspectJmxInvoke(Object mbeanName, String operationName, Object arguments, boolean resolved) {
    if (RaspRuntime.detectionOff()) return;
    List<String> values = JmxDispatch.strings(arguments);
    String bean = JmxDispatch.name(mbeanName);
    emitJmxInvoke(classifyJmxMBeanInvoke(bean, operationName, values));
    if (resolved) JmxWriteScope.select(bean, operationName, values);
  }

  private static void emitJmxInvoke(Finding finding) {
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_JMX.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_JMX.set(finding.detailValue);
    appendEvent(finding, "JmxMBeanServer.invoke", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious JMX MBean invocation");
    }
  }

  /** Previously transformed verifier frames have no downstream dispatch evidence. */
  public static void beforeJwtVerificationFailure(Object token, Throwable failure) {}

  public static void beforeDataEaseFilterContinuation(String rejection, Object request) {
    if (rejection == null || RaspRuntime.detectionOff()) return;
    Finding finding = new Finding("java17_request_jwt_verification_failure", 95,
        "Authentication filter continued the request after rejecting its credential",
        "exception", rejection, "rejected_token_dispatch");
    boolean block = shouldBlock();
    appendEvent(finding, "FilterChain.doFilter", block ? "block" : "log");
    if (block) throw new Java17RaspBlockException("OhMyRASP blocked continuation after credential rejection");
  }

  public static void beforeJavaBeansStatement(Object statement) {
    beforeJavaBeansStatement(statement, stackTraceClassNames());
  }

  static void beforeJavaBeansStatement(Object statement, List<String> stackClassNames) {
    try {
      Object target = invoke(statement, "getTarget");
      String methodName = invokeString(statement, "getMethodName");
      Object arguments = invoke(statement, "getArguments");
      Finding finding =
          classifyXmlDecoderExpression(
              javaBeansTargetType(target),
              methodName,
              javaBeansArguments(target, arguments),
              stackClassNames);
      emitXmlDecoderFinding(finding);
    } catch (Java17RaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] JavaBeans hook failed: " + throwable);
      }
    }
  }

  public static void rethrowIfJava17RaspBlock(Object throwable) {
    Throwable current = throwable instanceof Throwable ? (Throwable) throwable : null;
    int depth = 0;
    while (current != null && depth < 16) {
      if (current instanceof Java17RaspBlockException) {
        throw (Java17RaspBlockException) current;
      }
      current = current.getCause();
      depth++;
    }
  }

  public static void beginAttachmentReference(String id) {
    io.ohmyrasp.agent.xml.AttachmentFileRead.beginReference(RaspRuntime.detectionOff() ? null : id, null);
  }

  public static void beforeXmlEntity(String name, Object source) {
    inspectXmlEntity(name, xmlEntitySystemId(source), null);
  }

  public static void beforeXmlEntityOpen(URL target, String name, Object parserInput, Object document, String literal) {
    if (target != null && !"[xml]".equals(name) && !RaspRuntime.detectionOff()
        && !XmlCatalogResolution.consumesPackagedDtd(name, target, parserInput, document, literal)) {
      inspectXmlEntity(name, XmlCatalogResolution.transportId(target), "parser_url_open");
    }
  }

  private static void inspectXmlEntity(String name, String systemId, String basis) {
    Finding finding = classifyXxeEntity(name, systemId, basis);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_XXE.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_XXE.set(finding.detailValue);
    appendEvent(finding, "XMLEntityManager.setupCurrentEntity", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious XML external entity");
    }
  }

  private static void inspectCommand(String[] command, String hook) {
    Finding finding = classifyCommand(command);
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_COMMAND.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_COMMAND.set(finding.detailValue);
    appendEvent(finding, hook, action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious command execution");
    }
  }

  private static Finding classifyCommand(String[] command) {
    if (command == null || command.length == 0) {
      return null;
    }
    String joined = join(command);
    if (joined.length() == 0) {
      return null;
    }
    if (isBenignLocalBrowserLaunchCommand(command)) {
      return null;
    }
    if (isBenignSystemInventoryCommand(command)) {
      return null;
    }
    if (isTeamCityMetadataVerifierCommand(command)) {
      return null;
    }
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    if (isTikaExternalParserVersionCheckStack(stack) && isTikaExternalParserAvailabilityProbe(command)) {
      return null;
    }
    if (isOfficeProcessCleanupStack(stack) && isOfficeProcessCleanupCommand(command, joined)) {
      return null;
    }
    if (SolrExecutableListener.onStack(stack)) {
      return new Finding(
          "java17_command_execution_exploit_primitive",
          93,
          "Solr RunExecutableListener reached a Java 17 process sink",
          "command",
          joined, "configured_listener");
    }
    if (isExpressionLanguageRuntimeStack(stack)) {
      return new Finding(
          "java17_command_execution_exploit_primitive",
          93,
          "Dynamic expression evaluation reached a Java 17 process sink",
          "command",
          joined, "expression_evaluation");
    }
    if (isJiffleRuntimeCommandStack(stack)) {
      return new Finding(
          "java17_command_execution_exploit_primitive",
          94,
          "Jiffle runtime reached a Java 17 process sink",
          "command",
          joined, "expression_evaluation");
    }
    if (isDatabaseJavaRoutineCommandStack(stack)) {
      return new Finding(
          "java17_command_execution_exploit_primitive",
          93,
          "Database Java routine reached a Java 17 process sink",
          "command",
          joined, "database_stack");
    }
    if (isSpringBeanInitializationRuntimeStack(stack)) {
      if (isBenignSpringIdentityProbeCommand(command)) {
        return null;
      }
      return new Finding(
          "java17_command_execution_exploit_primitive",
          92,
          "Spring bean initialization reached a Java 17 process sink",
          "command",
          joined, "bean_initialization");
    }
    if (isJavaDeserializationCommandStack(stack)) {
      return new Finding(
          "java17_command_execution_exploit_primitive",
          95,
          "Java deserialization reached a Java 17 process sink",
          "command",
          joined, "object_deserialization");
    }
    if (isXStreamDeserializationCommandStack(stack)) {
      return new Finding(
          "java17_command_execution_exploit_primitive",
          94,
          "XML polymorphic deserialization reached a Java 17 process sink",
          "command",
          joined, "xml_deserialization");
    }
    String executable = command[0] == null ? "" : command[0].trim();
    boolean shell = SHELL.matcher(executable).matches();
    String firstArgument = command.length > 1 ? command[1] : "";
    if (shell && isSchedulerScriptExecutionStack(stack) && isScriptFilePath(firstArgument)) {
      return new Finding(
          "java17_command_execution_shell_meta",
          90,
          "Scheduler script job reached a Java 17 shell script process sink",
          "command",
          joined, "scheduled_script");
    }
    List<String> argv = java.util.Arrays.asList(command);
    PosixShellCommand posix = PosixShellCommand.from(argv);
    if (ProcessLaunchIndicators.matches(argv, posix, EXPLOIT_COMMAND, FILE_READERS, SENSITIVE_PATHS)) {
      return new Finding(
          "java17_command_execution_exploit_primitive",
          95,
          "Suspicious command execution reached a Java 17 process sink",
          "command",
          joined, "command_arguments");
    }
    if (posix != null) {
      RequestSnapshot request = CURRENT_REQUEST.get();
      ShellControlSource source = ShellControlSource.classify(
          posix, request == null ? null : request.parameterValues, stack);
      if (source != null) {
        return new Finding("java17_command_execution_shell_meta", 85, source.message,
            "command", joined, source.basis);
      }
    } else if (shell && !PosixShellCommand.isShell(executable)
        && command.length >= 3 && isShellCommandFlag(command[1])) {
      String script = command[2] == null ? "" : command[2];
      if (SHELL_META.matcher(script).find()) {
        return new Finding(
            "java17_command_execution_shell_meta",
            85,
            "Suspicious shell metacharacter command reached a Java 17 shell command",
            "command",
            joined, "shell_arguments");
      }
    }
    return null;
  }

  private static boolean isExpressionLanguageRuntimeStack(StackTraceElement[] stack) {
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if (className.startsWith("org.mvel2.")
          || className.startsWith("org.elasticsearch.common.mvel2.")
          || className.startsWith("org.elasticsearch.script.mvel.")
          || className.startsWith("ognl.")
          || className.startsWith("groovy.")
          || className.startsWith("org.codehaus.groovy.")
          || (className.startsWith("org.apache.commons.jexl.") || className.startsWith("org.apache.commons.jexl2.")
              || className.startsWith("org.apache.commons.jexl3."))
          || className.startsWith("org.springframework.expression.")
          || className.startsWith("org.springframework.webflow.expression.")) {
        return true;
      }
    }
    return false;
  }

  private static boolean isJiffleRuntimeCommandStack(StackTraceElement[] stack) {
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if (className.startsWith("it.geosolutions.jaiext.jiffle.")
          || className.startsWith("it.geosolutions.jaiext.jiffleop.")
          || className.startsWith("org.jaitools.jiffle.")
          || "org.geotools.process.raster.JiffleProcess".equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isDatabaseJavaRoutineCommandStack(StackTraceElement[] stack) {
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if (className.startsWith("org.apache.derby.")
          || className.startsWith("org.h2.")
          || className.startsWith("org.hsqldb.")) {
        return true;
      }
    }
    return false;
  }

  private static boolean isSpringBeanInitializationRuntimeStack(StackTraceElement[] stack) {
    boolean beanInitialization = false;
    boolean applicationContextRefresh = false;
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if ("org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory"
          .equals(className)) {
        beanInitialization = true;
      }
      if (className.startsWith("org.springframework.context.support.")) {
        applicationContextRefresh = true;
      }
    }
    return beanInitialization && applicationContextRefresh;
  }

  private static boolean isJavaDeserializationCommandStack(StackTraceElement[] stack) {
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if ("java.io.ObjectInputStream".equals(className)
          || "org.apache.axis2.context.externalize.SafeObjectInputStream".equals(className)
          || className.startsWith("flex.messaging.io.amf.")
          || className.startsWith("flex.messaging.endpoints.amf.")) {
        return true;
      }
    }
    return false;
  }

  private static boolean isBenignSpringIdentityProbeCommand(String[] command) {
    if (command == null || command.length != 2) {
      return false;
    }
    String executable = command[0] == null ? "" : command[0].trim().replace('\\', '/');
    int slash = executable.lastIndexOf('/');
    String fileName = slash >= 0 ? executable.substring(slash + 1) : executable;
    if (!"id".equals(fileName)) {
      return false;
    }
    String subject = command[1] == null ? "" : command[1].trim();
    return subject.matches("[A-Za-z0-9_.@-]{1,128}");
  }

  private static boolean isXStreamDeserializationCommandStack(StackTraceElement[] stack) {
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if (className.startsWith("com.thoughtworks.xstream.")
          || "org.apache.struts2.rest.handler.XStreamHandler".equals(className)
          || "org.apache.struts2.rest.ContentTypeInterceptor".equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isSchedulerScriptExecutionStack(StackTraceElement[] stack) {
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if ("com.xxl.job.core.handler.impl.ScriptJobHandler".equals(className)
          || "com.xxl.job.core.util.ScriptUtil".equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isOfficeProcessCleanupStack(StackTraceElement[] stack) {
    for (StackTraceElement element : stack) {
      if ("cn.keking.service.OfficePluginManager".equals(element.getClassName())) {
        return true;
      }
    }
    return false;
  }

  private static boolean isTikaExternalParserVersionCheckStack(StackTraceElement[] stack) {
    for (StackTraceElement element : stack) {
      if ("org.apache.tika.parser.external.ExternalParser".equals(element.getClassName())
          && "check".equals(element.getMethodName())) {
        return true;
      }
    }
    return false;
  }

  private static boolean isTikaExternalParserAvailabilityProbe(String[] command) {
    if (command == null || command.length == 0 || command.length > 2) {
      return false;
    }
    String executable = command[0] == null ? "" : command[0].trim();
    if (!isKnownTikaExternalParserExecutable(executable)) {
      return false;
    }
    if (command.length == 1) {
      return true;
    }
    String argument = command[1] == null ? "" : command[1].trim().toLowerCase(Locale.ROOT);
    return "-version".equals(argument) || "--version".equals(argument) || "-ver".equals(argument);
  }

  private static boolean isKnownTikaExternalParserExecutable(String value) {
    if (value.length() == 0) {
      return false;
    }
    String normalized = value.replace('\\', '/');
    int slash = normalized.lastIndexOf('/');
    String fileName = lower(slash >= 0 ? normalized.substring(slash + 1) : normalized);
    return "ffmpeg".equals(fileName) || "exiftool".equals(fileName) || "tesseract".equals(fileName);
  }

  private static boolean isOfficeProcessCleanupCommand(String[] command, String joined) {
    String script = joined;
    if (command != null && command.length >= 3 && isShellCommandFlag(command[1])) {
      script = command[2] == null ? "" : command[2];
    }
    String compact = script.toLowerCase(Locale.ROOT).replaceAll("\\s+", "");
    return "ps-ef|grepsoffice.bin".equals(compact)
        || "ps-ef|grepsoffice.bin|grep-vgrep|wc-l".equals(compact)
        || "ps-ef|grepsoffice.bin|grep-vgrep|awk'{print\"kill-9\"$2}'|sh".equals(compact)
        || "kill-15`ps-ef|grepsoffice.bin|awk'nr==1{print$2}'`".equals(compact);
  }

  private static boolean isBenignSystemInventoryCommand(String[] command) {
    if (command == null) {
      return false;
    }
    String joined = lower(join(command)).replace('\\', '/').replaceAll("\\s+", " ").trim();
    String joinedNoPipeSpaces = joined.replace(" | ", "|");
    if ("cat /etc/os-release|grep ^id".equals(joinedNoPipeSpaces)
        || "/bin/cat /etc/os-release|grep ^id".equals(joinedNoPipeSpaces)
        || "/usr/bin/cat /etc/os-release|grep ^id".equals(joinedNoPipeSpaces)) {
      return true;
    }
    if ("ldconfig -p".equals(joined)
        || "/sbin/ldconfig -p".equals(joined)
        || "/usr/sbin/ldconfig -p".equals(joined)) {
      return true;
    }
    if ("uname -o".equals(joined)
        || "/bin/uname -o".equals(joined)
        || "/usr/bin/uname -o".equals(joined)) {
      return true;
    }
    String executable = command[0] == null ? "" : command[0].trim().replace('\\', '/');
    int slash = executable.lastIndexOf('/');
    String fileName = slash >= 0 ? executable.substring(slash + 1) : executable;
    if (command.length == 2
        && "getconf".equals(fileName)
        && isBenignGetconfVariable(command[1])) {
      return true;
    }
    if (command.length == 2 && "vcgencmd".equals(fileName) && "measure_temp".equals(command[1])) {
      return true;
    }
    if (command.length == 3
        && "dmidecode".equals(fileName)
        && "-t".equals(command[1])
        && "4".equals(command[2])) {
      return true;
    }
    if (command.length == 2 && "cpuid".equals(fileName) && "-1r".equals(command[1])) {
      return true;
    }
    return command.length == 2 && "lscpu".equals(fileName) && "-p=cpu,node".equals(command[1]);
  }

  private static boolean isBenignGetconfVariable(String value) {
    return "CLK_TCK".equals(value) || "PAGE_SIZE".equals(value) || "PAGESIZE".equals(value);
  }

  private static boolean isTeamCityMetadataVerifierCommand(String[] command) {
    if (command == null || command.length < 4) {
      return false;
    }
    String executable = command[0] == null ? "" : lower(normalizePath(command[0].trim()));
    if (!"java".equals(executable) && !executable.endsWith("/java")) {
      return false;
    }
    boolean teamCityClasspath = false;
    boolean verifierMain = false;
    boolean metadataCachePath = false;
    for (int i = 1; i < command.length; i++) {
      String value = command[i] == null ? "" : command[i].trim();
      String lowerValue = lower(normalizePath(value));
      if (("-classpath".equals(value) || "-cp".equals(value)) && i + 1 < command.length) {
        String classpath = lower(normalizePath(command[i + 1]));
        teamCityClasspath =
            classpath.indexOf("/opt/teamcity/webapps/root/web-inf/lib/server-core.jar") >= 0
                || classpath.indexOf("/opt/teamcity/webapps/root/web-inf/lib/server.jar") >= 0
                || classpath.indexOf("/teamcity/webapps/root/web-inf/lib/server-core.jar") >= 0
                || classpath.indexOf("/teamcity/webapps/root/web-inf/lib/server.jar") >= 0;
      }
      if ("jetbrains.buildServer.serverSide.metadata.impl.cache.DatabaseConnectionVerifier"
          .equals(value)) {
        verifierMain = true;
      }
      if (lowerValue.indexOf("/teamcity_server/datadir/system/caches/buildsmetadata") >= 0) {
        metadataCachePath = true;
      }
    }
    return teamCityClasspath && verifierMain && metadataCachePath;
  }

  private static boolean isBenignLocalBrowserLaunchCommand(String[] command) {
    if (command == null || command.length < 3 || !isShellCommandFlag(command[1])) {
      return false;
    }
    String script = lower(command[2] == null ? "" : command[2].trim());
    if (script.indexOf(';') >= 0
        || script.indexOf('&') >= 0
        || script.indexOf('`') >= 0
        || script.indexOf('$') >= 0
        || script.indexOf('>') >= 0
        || script.indexOf('<') >= 0) {
      return false;
    }
    String[] parts = script.split("\\s*\\|\\|\\s*");
    if (parts.length == 0) {
      return false;
    }
    for (String part : parts) {
      String[] tokens = part.trim().split("\\s+");
      if (tokens.length != 2 || !isKnownLocalBrowserCommand(tokens[0]) || !isLocalBrowserUrl(tokens[1])) {
        return false;
      }
    }
    return true;
  }

  private static boolean isKnownLocalBrowserCommand(String value) {
    String normalized = value == null ? "" : value.trim().replace('\\', '/');
    int slash = normalized.lastIndexOf('/');
    String fileName = slash >= 0 ? normalized.substring(slash + 1) : normalized;
    return "xdg-open".equals(fileName)
        || "firefox".equals(fileName)
        || "mozilla".equals(fileName)
        || "konqueror".equals(fileName)
        || "opera".equals(fileName);
  }

  private static boolean isLocalBrowserUrl(String value) {
    String normalized = stripQuotes(value == null ? "" : value.trim());
    return normalized.startsWith("http://localhost:")
        || normalized.startsWith("https://localhost:")
        || normalized.startsWith("http://127.0.0.1:")
        || normalized.startsWith("https://127.0.0.1:");
  }

  private static String stripQuotes(String value) {
    if (value.length() >= 2
        && ((value.startsWith("\"") && value.endsWith("\""))
            || (value.startsWith("'") && value.endsWith("'")))) {
      return value.substring(1, value.length() - 1);
    }
    return value;
  }

  private static boolean isScriptFilePath(String value) {
    if (value == null) {
      return false;
    }
    return SCRIPT_FILE_WRITE.matcher(value.trim().replace('\\', '/')).matches();
  }

  private static Finding classifyJndiLookup(String lookup) {
    if (lookup.length() == 0) {
      return null;
    }
    Matcher matcher = REMOTE_JNDI_LOOKUP.matcher(lookup);
    if (!matcher.find()) {
      return null;
    }
    String scheme = matcher.group(1).toLowerCase(Locale.ROOT);
    int confidence = "ldap".equals(scheme) || "rmi".equals(scheme) ? 92 : 88;
    return new Finding(
        "java17_jndi_remote_lookup",
        confidence,
        "Remote JNDI lookup reached a Java 17 naming sink",
        "lookup",
        lookup);
  }

  private static Finding classifyHessianType(String type) {
    String normalized = normalizeJavaTypeName(type);
    if (normalized.length() == 0 || !StreamTypeNames.listed(normalized)) {
      return null;
    }
    return new Finding(
        "java17_deserialization_hessian_type",
        deserializationConfidence(normalized),
        "Hessian deserialization attempted to resolve a dangerous Java 17 type",
        "class",
        normalized);
  }

  private static int deserializationConfidence(String className) {
    String lower = className.toLowerCase(Locale.ROOT);
    if (lower.contains("templatesimpl")
        || lower.contains("jdbcrowsetimpl")
        || lower.contains("processbuilder")) {
      return 95;
    }
    if (lower.contains("invokertransformer")
        || lower.contains("chainedtransformer")
        || lower.contains("beancomparator")
        || lower.startsWith("bsh.")
        || lower.contains("convertedclosure")) {
      return 92;
    }
    return 88;
  }

  private static Finding classifyFileRead(String path, HostReadPath.OpenPolicy links) {
    if (io.ohmyrasp.agent.xml.AttachmentFileRead.selected(path)) {
      return new Finding("java17_file_sensitive_read", 95, "External attachment reference opened a host file",
          "path", path, "attachment_file_open");
    }
    String normalized = HostReadPath.location(path);
    if (normalized.isEmpty()) return null;
    boolean hosts = HostReadPath.isHostsFile(normalized);
    if (!hosts && SENSITIVE_FILE_READ.matcher(normalized).matches() && HostReadPath.confirmsLocation(path)) {
      return new Finding("java17_file_sensitive_read", fileReadConfidence(normalized),
          "Sensitive file read reached a Java 17 file sink", "path", normalized,
          path.equals(normalized) ? null : "normalized_read_location");
    }
    RequestSnapshot request = CURRENT_REQUEST.get();
    if (request == null || !HostReadPath.selected(path, request.parameterValues)) return null;
    if (hosts && HostReadPath.confirmsLocation(path)) {
      return new Finding("java17_file_sensitive_read", fileReadConfidence(normalized),
          "Request selected the system hosts file", "path", normalized, "request_selected_hosts");
    }
    String resolved = links.resolvedLocation(path);
    if (resolved.equals(normalized) || !(SENSITIVE_FILE_READ.matcher(resolved).matches() || HostReadPath.isHostsFile(resolved))) {
      return null;
    }
    return new Finding("java17_file_sensitive_read", fileReadConfidence(resolved),
        "Request-selected path resolves to a protected host file", "path", resolved, "resolved_request_file");
  }

  private static Finding classifyFileWrite(String path) {
    String normalized = normalizePath(path);
    if (normalized.length() == 0 || !SCRIPT_FILE_WRITE.matcher(normalized).matches()) {
      return null;
    }
    if (isWebInfDeploymentArtifact(normalized)) {
      return null;
    }
    if (isTeamCityPluginStartupWrite(normalized)) {
      return null;
    }
    if (isMavenRepositoryArtifactWrite(normalized)) {
      return null;
    }
    if (!WEBROOT_PATH.matcher(normalized).find() && normalized.indexOf("../") < 0) {
      return null;
    }
    return new Finding(
        "java17_file_script_write",
        90,
        "Script or executable file write reached a Java 17 file sink",
        "path",
        normalized);
  }

  private static Finding classifyFileUpload(String filename) {
    String normalized = normalizePath(filename);
    if (normalized.length() == 0) {
      return null;
    }
    if (MULTIPART_TRAVERSAL_UPLOAD_FILE.matcher(normalized).find()) {
      return new Finding(
          "fileUpload_path_traversal",
          93,
          "Multipart upload filename contains path traversal",
          "filename",
          normalized);
    }
    if (MULTIPART_EXPRESSION_UPLOAD_FILE.matcher(normalized).find()) {
      return new Finding(
          "fileUpload_multipart_expression",
          91,
          "Multipart upload filename contains an expression payload",
          "filename",
          normalized);
    }
    if (MULTIPART_SCRIPT_UPLOAD_FILE.matcher(normalized).matches()) {
      return new Finding(
          "fileUpload_multipart_script",
          92,
          "Multipart upload contains a server-side script filename",
          "filename",
          normalized);
    }
    if (MULTIPART_HTML_UPLOAD_FILE.matcher(normalized).matches()) {
      return new Finding(
          "fileUpload_multipart_html",
          82,
          "Multipart upload contains an active HTML document filename",
          "filename",
          normalized);
    }
    if (MULTIPART_EXECUTABLE_UPLOAD_FILE.matcher(normalized).matches()) {
      return new Finding(
          "fileUpload_multipart_exe",
          88,
          "Multipart upload contains an executable filename",
          "filename",
          normalized);
    }
    return classifyArchiveUpload(filename);
  }

  private static Finding classifyArchiveUpload(String filename) {
    if (!ArchiveUploadPolicy.isArchive(filename)) return null;
    ArchiveUploadPolicy.Evaluation evaluation = ArchiveUploadPolicy.inspect(DISPATCH.servletRequest());
    String basis = evaluation.decision.denialBasis();
    if (basis == null) return null;
    return new Finding(
        "fileUpload_java_archive",
        90,
        "Java archive upload conflicts with the application's deployment policy",
        "filename",
        normalizePath(filename), basis, evaluation.policyDigest);
  }

  private static Finding classifyArchiveWrite(String entry, String path, String basis) {
    if (!EscapingPath.matches(entry, path)) {
      return null;
    }
    return new Finding(
        "java17_archive_entry_traversal_write",
        92,
        "Archive entry traversal reached a Java 17 file write sink",
        "entry",
        entry + " -> " + path, basis);
  }

  private static Finding classifyJdbcUrl(String url) {
    if (url == null) {
      return null;
    }
    String normalized = url.trim();
    if (normalized.length() == 0) {
      return null;
    }
    String lower = normalized.toLowerCase(Locale.ROOT);
    String relaxed = relaxJdbcSyntax(lower);
    if (relaxed.startsWith("jdbc:h2:") && isDangerousH2JdbcUrl(relaxed)) {
      return new Finding(
          "java17_jdbc_h2_code_execution",
          h2JdbcConfidence(relaxed),
          "H2 JDBC URL code execution primitive reached a Java 17 JDBC sink",
          "jdbc_url",
          normalized);
    }
    if (relaxed.startsWith("jdbc:derby:") && isDangerousDerbyJdbcUrl(relaxed)) {
      return new Finding(
          "java17_jdbc_derby_code_loading",
          90,
          "Derby JDBC URL Java code loading primitive reached a Java 17 JDBC sink",
          "jdbc_url",
          normalized);
    }
    if (relaxed.startsWith("jdbc:mysql:") && isDangerousMysqlJdbcUrl(relaxed)) {
      return new Finding(
          "java17_jdbc_mysql_deserialization",
          92,
          "MySQL JDBC deserialization primitive reached a Java 17 JDBC sink",
          "jdbc_url",
          normalized);
    }
    return null;
  }

  private static Finding classifySqlIdentifier(String value, String source, String parameter) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    if (trimmed.length() == 0 || SAFE_SQL_IDENTIFIER.matcher(trimmed).matches()) {
      return null;
    }
    String reason = sqlIdentifierControlReason(trimmed);
    if (reason.length() == 0) {
      return null;
    }
    return new Finding(
        "java17_sql_identifier_injection",
        90,
        "SQL identifier argument contains control syntax before a Java 17 SQL sink",
        "identifier",
        abbreviate(
            "source="
                + source
                + " parameter="
                + parameter
                + " reason="
                + reason
                + " valueLength="
                + String.valueOf(trimmed.length()),
            1200));
  }

  private static String sqlIdentifierControlReason(String value) {
    String lower = lower(value);
    if (lower.indexOf("--") >= 0 || lower.indexOf("/*") >= 0 || lower.indexOf("*/") >= 0) {
      return "sql-comment";
    }
    if (lower.indexOf(';') >= 0) {
      return "statement-separator";
    }
    if (lower.indexOf('\'') >= 0 || lower.indexOf('"') >= 0 || lower.indexOf('`') >= 0) {
      return "quoted-identifier-control";
    }
    if (lower.indexOf('(') >= 0 || lower.indexOf(')') >= 0) {
      return "call-or-expression";
    }
    if (lower.indexOf('=') >= 0 || lower.indexOf('<') >= 0 || lower.indexOf('>') >= 0) {
      return "boolean-or-comparison";
    }
    if (lower.indexOf('/') >= 0 || lower.indexOf('\\') >= 0 || lower.indexOf('|') >= 0) {
      return "operator-or-separator";
    }
    if (SQL_IDENTIFIER_KEYWORD_CONTROL.matcher(value).find()) {
      return "sql-keyword-control";
    }
    return "";
  }

  private static boolean isDangerousH2JdbcUrl(String lower) {
    if (!containsJdbcOption(lower, "init")) {
      return false;
    }
    return lower.indexOf("runscript") >= 0
        || lower.indexOf("create alias") >= 0
        || lower.indexOf("create trigger") >= 0
        || lower.indexOf("scriptengine") >= 0
        || lower.indexOf("runtime.getruntime") >= 0
        || lower.indexOf("java.lang.runtime") >= 0
        || lower.indexOf("processbuilder") >= 0
        || lower.indexOf("javax.naming.initialcontext") >= 0
        || lower.indexOf("urlclassloader") >= 0;
  }

  private static int h2JdbcConfidence(String lower) {
    if (lower.indexOf("runtime.getruntime") >= 0
        || lower.indexOf("processbuilder") >= 0
        || lower.indexOf("javax.naming.initialcontext") >= 0) {
      return 96;
    }
    if (lower.indexOf("create alias") >= 0 || lower.indexOf("runscript") >= 0) {
      return 94;
    }
    return 90;
  }

  private static boolean isDangerousDerbyJdbcUrl(String lower) {
    return lower.indexOf("sqlj.install_jar") >= 0
        || lower.indexOf("sqlj.replace_jar") >= 0
        || lower.indexOf("derby.database.classpath") >= 0
        || lower.indexOf("external name") >= 0
        || lower.indexOf("parameter style java") >= 0
        || lower.indexOf("language java") >= 0;
  }

  private static boolean isDangerousMysqlJdbcUrl(String lower) {
    if (!isJdbcOptionEnabled(lower, "autodeserialize")) {
      return false;
    }
    return lower.indexOf("statementinterceptors") >= 0
        || lower.indexOf("queryinterceptors") >= 0
        || lower.indexOf("detectcustomcollations=true") >= 0
        || lower.indexOf("detectcustomcollations=1") >= 0
        || lower.indexOf("detectcustomcollations=yes") >= 0;
  }

  private static void emitRemoteJobFinding(Finding finding, String hook) {
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_REMOTE_JOB.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_REMOTE_JOB.set(finding.detailValue);
    appendEvent(finding, hook, action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious remote job submission");
    }
  }

  private static Finding classifyYarnApplicationSubmission(Object submission) {
    Object container = invoke(submission, "getContainerLaunchContextInfo");
    List<String> commands = yarnCommandTexts(invoke(container, "getCommands"));
    if (commands.isEmpty()) {
      return null;
    }
    String joined = joinList(commands);
    String applicationType = invokeString(submission, "getApplicationType");
    if (applicationType.length() == 0) {
      applicationType = "YARN";
    }
    return new Finding(
        "java17_request_remote_job_submission",
        90,
        "YARN ResourceManager REST request submits an application master command",
        "submission",
        "YARN ResourceManager type="
            + abbreviate(applicationType, 64)
            + " commands="
            + commands.size()
            + " commandHash="
            + Integer.toHexString(joined.hashCode()));
  }

  private static List<String> yarnCommandTexts(Object commands) {
    List<String> values = new ArrayList<String>();
    collectYarnCommandTexts(values, commands);
    return values;
  }

  private static void collectYarnCommandTexts(List<String> values, Object commands) {
    if (commands == null || values.size() >= 32) {
      return;
    }
    if (commands instanceof Iterable<?>) {
      for (Object command : (Iterable<?>) commands) {
        collectYarnCommandTexts(values, command);
        if (values.size() >= 32) {
          break;
        }
      }
      return;
    }
    Class<?> type = commands.getClass();
    if (type.isArray()) {
      int length = Array.getLength(commands);
      for (int index = 0; index < length && values.size() < 32; index++) {
        collectYarnCommandTexts(values, Array.get(commands, index));
      }
      return;
    }
    String text = String.valueOf(commands).trim();
    if (text.length() > 0) {
      values.add(abbreviate(text, 2048));
    }
  }

  private static void emitClassLoaderFindings(Object sources, String mechanism) {
    List<String> values = classLoaderSources(sources);
    for (String value : values) {
      Finding finding = classifyClassLoaderSource(value, mechanism);
      if (finding == null) {
        continue;
      }
      String action = shouldBlock() ? "block" : "log";
      String previous = LAST_LOGGED_CLASSLOADER.get();
      if (!"block".equals(action) && finding.detailValue.equals(previous)) {
        continue;
      }
      LAST_LOGGED_CLASSLOADER.set(finding.detailValue);
      appendEvent(finding, mechanism, action);
      if ("block".equals(action)) {
        throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious remote classloader codebase");
      }
    }
  }

  private static Finding classifyClassLoaderSource(String source, String mechanism) {
    if (source == null) {
      return null;
    }
    String normalized = source.trim();
    if (normalized.length() == 0) {
      return null;
    }
    String scheme = remoteClassLoaderScheme(normalized);
    if (scheme.length() == 0) {
      return null;
    }
    if (isFelixExtensionClassLoaderSource(normalized, scheme)) {
      return null;
    }
    int confidence = "RMIClassLoader".equals(mechanism) ? 94 : 90;
    return new Finding(
        "java17_classloader_remote_codebase",
        confidence,
        "Remote classloader codebase reached a Java 17 class loading sink",
        "codebase",
        mechanism + " " + scheme + " " + normalized);
  }

  private static Finding classifyScriptEval(String script) {
    if (script == null) {
      return null;
    }
    String normalized = script.trim();
    if (normalized.length() == 0) {
      return null;
    }
    String compact = normalized.toLowerCase(Locale.ROOT).replaceAll("\\s+", "");
    boolean runtimeExec =
        compact.indexOf("runtime") >= 0
            && compact.indexOf("getruntime") >= 0
            && compact.indexOf("exec") >= 0;
    boolean reflectiveRuntimeExec =
        compact.indexOf("java.lang.runtime") >= 0
            && (compact.indexOf("getmethod") >= 0 || compact.indexOf("getmethods") >= 0)
            && compact.indexOf("invoke") >= 0
            && compact.indexOf("exec") >= 0;
    boolean processBuilder =
        compact.indexOf("processbuilder") >= 0
            && (compact.indexOf(".start") >= 0
                || compact.indexOf("newprocessbuilder") >= 0
                || compact.indexOf("newjava.lang.processbuilder") >= 0);
    boolean nestedScriptEval =
        compact.indexOf("scriptenginemanager") >= 0 && compact.indexOf(".eval") >= 0;
    boolean literalExecute = SCRIPT_LITERAL_EXECUTE.matcher(normalized).find();
    if (!runtimeExec && !reflectiveRuntimeExec && !processBuilder && !nestedScriptEval && !literalExecute) {
      return null;
    }
    return new Finding(
        "java17_script_engine_runtime_execution",
        scriptConfidence(runtimeExec, processBuilder, reflectiveRuntimeExec, nestedScriptEval),
        "Script engine evaluation reached a Java 17 runtime execution primitive",
        "script",
        normalized);
  }

  private static Finding classifyJexlExpression(String expression) {
    if (expression == null) {
      return null;
    }
    String normalized = expression.trim();
    if (normalized.length() == 0) {
      return null;
    }
    String compact = normalized.toLowerCase(Locale.ROOT).replaceAll("\\s+", "");
    boolean runtimeExec =
        compact.indexOf("runtime") >= 0
            && compact.indexOf("getruntime") >= 0
            && compact.indexOf("exec") >= 0;
    boolean reflectiveRuntimeExec =
        compact.indexOf("java.lang.runtime") >= 0
            && compact.indexOf("forname") >= 0
            && compact.indexOf("getruntime") >= 0
            && compact.indexOf("exec") >= 0;
    boolean processBuilder =
        compact.indexOf("processbuilder") >= 0
            && (compact.indexOf(".start") >= 0
                || compact.indexOf("newprocessbuilder") >= 0
                || compact.indexOf("newjava.lang.processbuilder") >= 0);
    boolean nestedScriptEval =
        compact.indexOf("scriptenginemanager") >= 0 && compact.indexOf(".eval") >= 0;
    if (!runtimeExec && !reflectiveRuntimeExec && !processBuilder && !nestedScriptEval) {
      return null;
    }
    return new Finding(
        "java17_jexl_runtime_execution",
        runtimeExec || processBuilder || reflectiveRuntimeExec ? 90 : 86,
        "Commons JEXL evaluation reached a Java 17 runtime execution primitive",
        "expression",
        "engine=jexl expressionLength=" + normalized.length());
  }

  private static Finding classifyElExpression(String expression) {
    if (expression == null) {
      return null;
    }
    String normalized = expression.trim();
    if (normalized.length() == 0) {
      return null;
    }
    String compact = normalized.toLowerCase(Locale.ROOT).replaceAll("\\s+", "");
    boolean runtimeExec =
        compact.indexOf("runtime") >= 0
            && compact.indexOf("getruntime") >= 0
            && compact.indexOf("exec") >= 0;
    boolean reflectiveRuntimeExec =
        compact.indexOf("java.lang.runtime") >= 0
            && compact.indexOf("forname") >= 0
            && compact.indexOf("exec") >= 0
            && (compact.indexOf("getruntime") >= 0
                || compact.indexOf("getmethod") >= 0
                || compact.indexOf("getmethods") >= 0
                || compact.indexOf("getdeclaredmethod") >= 0
                || compact.indexOf("getdeclaredmethods") >= 0)
            && compact.indexOf("invoke") >= 0;
    boolean processBuilder =
        compact.indexOf("processbuilder") >= 0
            && (compact.indexOf(".start") >= 0
                || compact.indexOf("start(") >= 0
                || compact.indexOf("newprocessbuilder") >= 0
                || compact.indexOf("newjava.lang.processbuilder") >= 0);
    boolean nestedScriptEval =
        compact.indexOf("scriptenginemanager") >= 0 && compact.indexOf(".eval") >= 0;
    if (!runtimeExec && !reflectiveRuntimeExec && !processBuilder && !nestedScriptEval) {
      return null;
    }
    return new Finding(
        "java17_el_runtime_execution",
        runtimeExec || processBuilder || reflectiveRuntimeExec ? 90 : 86,
        "Unified EL evaluation reached a Java 17 runtime execution primitive",
        "expression",
        "engine=el expressionLength=" + normalized.length());
  }

  private static Finding classifyJavaCompilation(String compiler, String source) {
    if (source == null) {
      return null;
    }
    String normalized = source.trim();
    if (normalized.length() == 0) {
      return null;
    }
    String compact = normalized.toLowerCase(Locale.ROOT).replaceAll("\\s+", "");
    boolean runtimeExec =
        compact.indexOf("runtime.getruntime().exec") >= 0
            || (compact.indexOf("java.lang.runtime") >= 0
                && compact.indexOf("getruntime") >= 0
                && compact.indexOf(".exec") >= 0);
    boolean processBuilder =
        compact.indexOf("processbuilder") >= 0
            && (compact.indexOf(".start(") >= 0
                || compact.indexOf("getmethod(\"start\"") >= 0
                || compact.indexOf("getmethod('start'") >= 0);
    boolean scriptEngineEval =
        compact.indexOf("scriptenginemanager") >= 0 && compact.indexOf(".eval(") >= 0;
    if (!runtimeExec && !processBuilder && !scriptEngineEval) {
      return null;
    }
    String normalizedCompiler = compiler == null || compiler.trim().length() == 0 ? "java" : compiler.trim();
    return new Finding(
        "java17_java_compile_runtime_execution",
        runtimeExec || processBuilder ? 94 : 88,
        "Java source compilation reached a Java 17 runtime execution primitive",
        "source",
        normalizedCompiler + " " + abbreviate(normalized, 1200));
  }

  private static void emitJavaCompilationFinding(Finding finding) {
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_JAVA_COMPILE.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_JAVA_COMPILE.set(finding.detailValue);
    appendEvent(finding, "JavaCompiler.getTask", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious Java compilation");
    }
  }

  private static Finding classifyJaasConfig(Object loginModuleName, Object options) {
    if (loginModuleName == null) {
      return null;
    }
    String loginModule = String.valueOf(loginModuleName).trim();
    if (loginModule.length() == 0 || !loginModule.toLowerCase(Locale.ROOT).contains("jndiloginmodule")) {
      return null;
    }
    String config = loginModule + " " + jaasOptionsText(options);
    Matcher matcher = JAAS_REMOTE_PROVIDER.matcher(config);
    if (!matcher.find()) {
      return null;
    }
    String providerUrl = matcher.group(1);
    return new Finding(
        "java17_jaas_jndi_remote_provider",
        remoteJaasConfidence(providerUrl),
        "JAAS JNDI login module reached a Java 17 remote provider configuration sink",
        "config",
        loginModule + " " + providerUrl);
  }

  private static Finding classifyJmxMBeanInvoke(
      String bean, String operationName, List<String> values) {
    String operation = operationName == null ? "" : operationName.trim();
    if (operation.length() == 0 || !isMutatingJmxOperation(operation)) {
      return null;
    }
    for (String value : values) {
      if (looksLikeRemoteJmxConfig(value)) {
        return new Finding(
            "java17_jmx_remote_config_source",
            jmxRemoteConfigConfidence(value),
            "MBean invocation argument names a remote configuration source",
            "invoke",
            abbreviate(bean + " " + operation + " " + value, 1200));
      }
    }
    return null;
  }

  private static Finding classifyXmlDecoderExpression(
      String targetType, String methodName, List<String> arguments, List<String> stackClassNames) {
    if (!isXmlDecoderStack(stackClassNames)) {
      return null;
    }
    String normalizedTarget = normalizeJavaTypeName(targetType);
    String normalizedMethod = lower(methodName);
    List<String> safeArguments = arguments == null ? new ArrayList<String>() : arguments;
    String joinedArguments = joinList(safeArguments);

    boolean processBuilderStart =
        "java.lang.ProcessBuilder".equals(normalizedTarget) && "start".equals(normalizedMethod);
    boolean runtimeExec =
        "java.lang.Runtime".equals(normalizedTarget) && normalizedMethod.startsWith("exec");
    boolean reflectiveInvoke =
        "java.lang.reflect.Method".equals(normalizedTarget) && "invoke".equals(normalizedMethod);
    if (processBuilderStart || runtimeExec || reflectiveInvoke) {
      return new Finding(
          "java17_xml_decoder_runtime_execution",
          95,
          "XMLDecoder object graph reached a Java 17 runtime execution primitive",
          "expression",
          abbreviate(normalizedTarget + " " + methodName + " " + joinedArguments, 1200));
    }

    boolean writerConstruction =
        ("java.io.PrintWriter".equals(normalizedTarget)
                || "java.io.FileWriter".equals(normalizedTarget)
                || "java.io.FileOutputStream".equals(normalizedTarget))
            && ("new".equals(normalizedMethod) || "newinstance".equals(normalizedMethod));
    if (writerConstruction) {
      for (String argument : safeArguments) {
        String path = normalizePath(argument);
        if (SCRIPT_FILE_WRITE.matcher(path).matches()) {
          return new Finding(
              "java17_xml_decoder_script_file_write",
              95,
              "XMLDecoder object graph reached a Java 17 server-side script writer",
              "expression",
              abbreviate(normalizedTarget + " " + methodName + " " + path, 1200));
        }
      }
    }
    return null;
  }

  private static void emitXmlDecoderFinding(Finding finding) {
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_XML_DECODER.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_XML_DECODER.set(finding.detailValue);
    appendEvent(finding, "XMLDecoder.Statement", action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious XMLDecoder object graph");
    }
  }

  private static boolean isXmlDecoderStack(List<String> stackClassNames) {
    if (stackClassNames == null || stackClassNames.isEmpty()) {
      return false;
    }
    for (String className : stackClassNames) {
      if (className == null) {
        continue;
      }
      if ("java.beans.XMLDecoder".equals(className)
          || className.startsWith("com.sun.beans.decoder.")) {
        return true;
      }
    }
    return false;
  }

  private static Finding classifyXxeEntity(String name, String systemId, String basis) {
    if ("[xml]".equals(name)) {
      return null;
    }
    String value = systemId == null ? "" : systemId.trim();
    if (value.length() == 0) {
      return null;
    }
    if (value.startsWith("\\\\") || value.startsWith("//")) {
      return new Finding(
          "java17_xxe_external_entity_protocol",
          96,
          "XML external entity reached a Java 17 parser with SMB/UNC source",
          "entity",
          String.valueOf(name) + " " + value, basis);
    }
    String scheme = uriScheme(value);
    if (scheme.length() == 0 || !isXxeExternalScheme(scheme)) {
      return null;
    }
    return new Finding(
        "java17_xxe_external_entity_protocol",
        xxeConfidence(scheme),
        "XML external entity reached a Java 17 parser with protocol " + scheme,
        "entity",
        String.valueOf(name) + " " + abbreviate(value, 1200), basis);
  }

  private static String xmlEntitySystemId(Object source) {
    if (source == null) {
      return "";
    }
    if (source instanceof String || source instanceof URL) {
      return source.toString();
    }
    if (invoke(source, "getCharacterStream") != null || invoke(source, "getByteStream") != null) {
      return "";
    }
    Object systemId = invoke(source, "getSystemId");
    if (systemId != null) {
      return String.valueOf(systemId);
    }
    systemId = invoke(source, "getExpandedSystemId");
    if (systemId != null) {
      return String.valueOf(systemId);
    }
    systemId = invoke(source, "getLiteralSystemId");
    if (systemId != null) {
      return String.valueOf(systemId);
    }
    return "";
  }

  private static Finding classifyHttpRequest(Object request, Map<?, ?> parameters) {
    if (request == null) {
      return null;
    }
    String uri = requestUri(request);
    String query = requestQuery(request);
    if (uri.length() == 0) {
      return null;
    }
    Finding cryptoCookie = classifyDefaultCryptoCookie(request);
    if (cryptoCookie != null) {
      return cryptoCookie;
    }
    Finding internalIdentity = classifyInternalIdentityRequest(request, uri);
    if (internalIdentity != null) {
      return internalIdentity;
    }
    Finding defaultJwt = classifyDefaultJwtSecret(request, uri);
    if (defaultJwt != null) {
      return defaultJwt;
    }
    Finding typedPayload = classifyTypedPayloadDeserializationRequest(parameters, uri);
    if (typedPayload != null) {
      return typedPayload;
    }
    Finding debugProcessLaunch = classifyDebugProcessLaunchRequest(request, uri, query, parameters);
    if (debugProcessLaunch != null) {
      return debugProcessLaunch;
    }
    Finding ogcFilterSqlInjection = classifyOgcFilterSqlInjectionRequest(parameters, uri);
    if (ogcFilterSqlInjection != null) {
      return ogcFilterSqlInjection;
    }
    Finding templateSource = classifyTemplateSourceRequest(parameters, uri);
    if (templateSource != null) {
      return templateSource;
    }
    Finding forgedInclude = classifyForgedIncludeRequest(request, uri);
    if (forgedInclude != null) {
      return forgedInclude;
    }
    Finding internalForward = classifyInternalForwardRequest(parameters, uri);
    if (internalForward != null) {
      return internalForward;
    }
    Finding sessionFile = classifySessionFileDeserializationRequest(request, uri);
    if (sessionFile != null) {
      return sessionFile;
    }
    if (isTeamCityInstallLinksFragmentPath(uri)) {
      return null;
    }
    String inspected = query.length() == 0 ? uri : uri + "?" + query;
    String confusingPath = confusingRequestPath(inspected);
    if (confusingPath.length() == 0) {
      return null;
    }
    return new Finding(
        "java17_request_path_confusion",
        90,
        "HTTP request URI contains Java 17 path normalization confusion",
        "uri",
        abbreviate(uri + " -> " + confusingPath, 1200));
  }

  private static Finding classifyInternalIdentityRequest(Object request, String uri) {
    String userAgent = lower(requestHeader(request, "User-Agent").trim());
    if (!isInternalServiceUserAgent(userAgent)) {
      return null;
    }
    String path = uri == null ? "" : uri;
    if (isBenignInternalServicePath(path)) {
      return null;
    }
    if (!SENSITIVE_CONTROL_PATH.matcher(path).find()) {
      return null;
    }
    return new Finding(
        "java17_request_internal_identity",
        90,
        "Internal service identity reached a Java 17 sensitive control path",
        "request",
        abbreviate("user-agent=" + userAgent + " uri=" + path, 1200));
  }

  private static Finding classifyTypedPayloadDeserializationRequest(Map<?, ?> parameters, String uri) {
    if (parameters == null) {
      return null;
    }
    for (Map.Entry<?, ?> entry : parameters.entrySet()) {
      String name = String.valueOf(entry.getKey());
      List<String> values = new ArrayList<String>();
      collectParameterValues(values, entry.getValue());
      for (String value : values) {
        TypedPayloadMatch match = typedPayloadMatch(value);
        if (match == null) {
          continue;
        }
        return new Finding(
            "java17_request_typed_payload_deserialization",
            92,
            "Request parameter carries a Java 17 dangerous typed payload",
            "payload",
            abbreviate(
                "uri="
                    + uri
                    + " parameter="
                    + name
                    + " class="
                    + match.className
                    + " trigger="
                    + match.trigger
                    + " valueLength="
                    + String.valueOf(value == null ? 0 : value.length())
                    + " value=[redacted]",
                1200));
      }
    }
    return null;
  }

  private static boolean isInternalServiceUserAgent(String userAgent) {
    return "nacos-server".equals(userAgent) || userAgent.startsWith("nacos-server/");
  }

  private static boolean isBenignInternalServicePath(String path) {
    String normalized = lower(path == null ? "" : path);
    return normalized.equals("/nacos/v1/cs/ops/data/removal")
        || normalized.startsWith("/nacos/v1/cs/ops/data/removal/");
  }

  private static TypedPayloadMatch typedPayloadMatch(String value) {
    if (value == null || value.trim().length() == 0) {
      return null;
    }
    String inspected = value.length() > 8192 ? value.substring(0, 8192) : value;
    List<String> variants = new ArrayList<String>();
    variants.add(inspected);
    String decoded = percentDecode(inspected);
    if (!decoded.equals(inspected)) {
      variants.add(decoded);
      String decodedTwice = percentDecode(decoded);
      if (!decodedTwice.equals(decoded)) {
        variants.add(decodedTwice);
      }
    }
    for (String variant : variants) {
      if (!typedPayloadBindingSyntax(variant)) {
        continue;
      }
      String className = typedPayloadDangerousClass(variant);
      if (className.length() == 0) {
        continue;
      }
      String trigger = typedPayloadTrigger(variant);
      if (trigger.length() > 0) {
        return new TypedPayloadMatch(className, trigger);
      }
    }
    return null;
  }

  private static boolean typedPayloadBindingSyntax(String value) {
    String normalized = lower(value);
    return normalized.indexOf("<wddxpacket") >= 0
        || normalized.indexOf("<struct") >= 0
        || TYPED_PAYLOAD_CLASS_ATTRIBUTE.matcher(value).find()
        || TYPED_PAYLOAD_JSON_TYPE.matcher(value).find()
        || TYPED_PAYLOAD_YAML_TAG.matcher(value).find()
        || normalized.indexOf("@type") >= 0
        || normalized.indexOf("!!") >= 0;
  }

  private static String typedPayloadDangerousClass(String value) {
    List<String> candidates = new ArrayList<String>();
    Matcher attributeMatcher = TYPED_PAYLOAD_CLASS_ATTRIBUTE.matcher(value);
    while (attributeMatcher.find()) {
      candidates.add(attributeMatcher.group(1));
    }
    Matcher jsonMatcher = TYPED_PAYLOAD_JSON_TYPE.matcher(value);
    while (jsonMatcher.find()) {
      candidates.add(jsonMatcher.group(1));
    }
    Matcher yamlMatcher = TYPED_PAYLOAD_YAML_TAG.matcher(value);
    while (yamlMatcher.find()) {
      candidates.add(yamlMatcher.group(1));
    }
    for (String candidate : candidates) {
      String className = typedPayloadDangerousClassCandidate(candidate);
      if (className.length() > 0) {
        return className;
      }
    }
    return "";
  }

  private static String typedPayloadDangerousClassCandidate(String rawClassName) {
    if (rawClassName == null || rawClassName.trim().length() == 0) {
      return "";
    }
    List<String> candidates = new ArrayList<String>();
    String normalized = normalizeJavaTypeName(rawClassName);
    candidates.add(normalized);
    if (normalized.length() > 2 && normalized.startsWith("x") && normalized.endsWith("x")) {
      candidates.add(normalized.substring(1, normalized.length() - 1));
    }
    for (String candidate : candidates) {
      String className = normalizeJavaTypeName(candidate);
      if (StreamTypeNames.listed(className)
          || "org.h2.jdbc.JdbcConnection".equals(className)) {
        return className;
      }
    }
    return "";
  }

  private static String typedPayloadTrigger(String value) {
    Matcher namingMatcher = TYPED_PAYLOAD_REMOTE_NAMING_URL.matcher(value);
    if (namingMatcher.find()) {
      return "jndi:" + lower(namingMatcher.group(1));
    }
    String normalized = lower(value);
    if (normalized.indexOf("hexasciiserializedmap") >= 0 || normalized.indexOf("aced0005") >= 0) {
      return "serialized";
    }
    if (TYPED_PAYLOAD_H2_INIT.matcher(value).find()) {
      return "jdbc-h2-init";
    }
    return "";
  }

  private static Finding classifyDebugProcessLaunchRequest(
      Object request, String uri, String query, Map<?, ?> parameters) {
    if (!isDebugProcessLaunchContext(request, uri)) {
      return null;
    }
    if (parameters != null) {
      for (Map.Entry<?, ?> entry : parameters.entrySet()) {
        String name = String.valueOf(entry.getKey());
        if (!isDebugProcessLaunchParameter(name)) {
          continue;
        }
        List<String> values = new ArrayList<String>();
        collectParameterValues(values, entry.getValue());
        for (String value : values) {
          if (value != null && value.trim().length() > 0) {
            return debugProcessLaunchFinding(uri, name, value.length());
          }
        }
      }
    }
    return classifyDebugProcessLaunchQuery(uri, query);
  }

  private static Finding classifyDebugProcessLaunchQuery(String uri, String query) {
    if (query == null || query.trim().length() == 0) {
      return null;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = percentDecode(parts[i].substring(0, separator));
      if (!isDebugProcessLaunchParameter(name)) {
        continue;
      }
      String value = percentDecode(parts[i].substring(separator + 1));
      if (value.trim().length() > 0) {
        return debugProcessLaunchFinding(uri, name, value.length());
      }
    }
    return null;
  }

  private static Finding debugProcessLaunchFinding(String uri, String parameter, int length) {
    return new Finding(
        "java17_request_debug_process_launch",
        88,
        "Request invokes a Java 17 debug process launch endpoint",
        "process",
        abbreviate(
            "uri="
                + uri
                + " parameter="
                + parameter
                + " commandLength="
                + String.valueOf(length)
                + " value=[redacted]",
            1200));
  }

  private static boolean isDebugProcessLaunchContext(Object request, String uri) {
    String method = lower(invokeString(request, "getMethod")).replaceAll("[^a-z]", "");
    if (!"post".equals(method) && !"put".equals(method) && !"patch".equals(method)) {
      return false;
    }
    String path = lower(percentDecode(uri == null ? "" : uri)).replace('\\', '/');
    return (path.contains("/debug/") || path.endsWith("/debug"))
        && (path.contains("/process") || path.contains("/processes"));
  }

  private static boolean isDebugProcessLaunchParameter(String name) {
    String normalized = normalizeParameterName(name);
    return "exepath".equals(normalized)
        || "executable".equals(normalized)
        || "executablepath".equals(normalized)
        || "command".equals(normalized)
        || "commandline".equals(normalized)
        || "cmd".equals(normalized);
  }

  private static Finding classifyOgcFilterSqlInjectionRequest(Map<?, ?> parameters, String uri) {
    if (!isOgcRequest(parameters, uri)) {
      return null;
    }
    if (parameters == null) {
      return null;
    }
    for (Map.Entry<?, ?> entry : parameters.entrySet()) {
      String name = String.valueOf(entry.getKey());
      if (!isOgcFilterSqlParameter(name)) {
        continue;
      }
      List<String> values = new ArrayList<String>();
      collectParameterValues(values, entry.getValue());
      for (String value : values) {
        if (!dangerousOgcFilterSqlValue(value)) {
          continue;
        }
        return new Finding(
            "java17_request_ogc_filter_sql_injection",
            95,
            "OGC filter parameter contains Java 17 SQL injection primitives",
            "filter",
            abbreviate(
                "uri="
                    + uri
                    + " parameter="
                    + name
                    + " valueLength="
                    + String.valueOf(value == null ? 0 : value.length())
                    + " value=[redacted]",
                1200));
      }
    }
    return null;
  }

  private static boolean isOgcRequest(Map<?, ?> parameters, String uri) {
    if (OGC_REQUEST_CONTROL_PATH.matcher(uri == null ? "" : uri).find()) {
      return true;
    }
    if (parameters == null) {
      return false;
    }
    for (Map.Entry<?, ?> entry : parameters.entrySet()) {
      String name = normalizeParameterName(String.valueOf(entry.getKey()));
      List<String> values = new ArrayList<String>();
      collectParameterValues(values, entry.getValue());
      for (String value : values) {
        String normalizedValue = normalizeParameterName(value);
        if ("service".equals(name) && isOgcServiceValue(normalizedValue)) {
          return true;
        }
        if ("request".equals(name) && isOgcRequestValue(normalizedValue)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean isOgcServiceValue(String value) {
    return "wfs".equals(value) || "wms".equals(value) || "wps".equals(value);
  }

  private static boolean isOgcRequestValue(String value) {
    return "getfeature".equals(value)
        || "getmap".equals(value)
        || "getpropertyvalue".equals(value)
        || "describefeaturetype".equals(value);
  }

  private static boolean isOgcFilterSqlParameter(String name) {
    String normalized = normalizeParameterName(name);
    return "cqlfilter".equals(normalized)
        || "ecqlfilter".equals(normalized)
        || "filter".equals(normalized);
  }

  private static boolean dangerousOgcFilterSqlValue(String value) {
    if (value == null || value.trim().length() == 0) {
      return false;
    }
    return OGC_FILTER_SQL_INJECTION_VALUE.matcher(percentDecode(value)).find();
  }

  private static Finding classifyTemplateSourceRequest(Map<?, ?> parameters, String uri) {
    if (!TEMPLATE_SOURCE_CONTROL_PATH.matcher(uri == null ? "" : uri).find()) {
      return null;
    }
    if (parameters == null) {
      return null;
    }
    for (Map.Entry<?, ?> entry : parameters.entrySet()) {
      String name = String.valueOf(entry.getKey());
      if (!isTemplateSourceParameterName(name)) {
        continue;
      }
      List<String> values = new ArrayList<String>();
      collectParameterValues(values, entry.getValue());
      for (String value : values) {
        if (REMOTE_TEMPLATE_SOURCE_URL.matcher(value == null ? "" : value).find()) {
          return new Finding(
              "java17_request_template_source",
              88,
              "Request selects a remote template or decorator source",
              "source",
              abbreviate(
                  "uri="
                      + uri
                      + " parameter="
                      + name
                      + " target=remote-url valueLength="
                      + String.valueOf(value == null ? 0 : value.length()),
                  1200));
        }
      }
    }
    return null;
  }

  private static Finding classifyForgedIncludeRequest(Object request, String uri) {
    IncludeAttributes include = servletIncludeAttributes(request, "javax.servlet.include.", "javax");
    if (!include.present) {
      include = servletIncludeAttributes(request, "jakarta.servlet.include.", "jakarta");
    }
    if (!include.present || isLegitimateRequestDispatcherInclude()) {
      return null;
    }
    if (isKnownLiferayPortalInclude(uri, include)) {
      return null;
    }
    List<String> candidates = new ArrayList<String>();
    addIncludeCandidate(candidates, include.pathInfo);
    addIncludeCandidate(candidates, include.servletPath);
    addIncludeCandidate(candidates, include.requestUri);
    addIncludeCandidate(candidates, joinIncludePath(include.servletPath, include.pathInfo));
    addIncludeCandidate(candidates, joinIncludePath(include.requestUri, include.pathInfo));
    for (int i = 0; i < candidates.size(); i++) {
      String target = forgedIncludeTarget(candidates.get(i));
      if (target.length() > 0) {
        return new Finding(
            "java17_request_forged_include_attribute",
            90,
            "Forged servlet include attributes reached a Java 17 request",
            "include",
            abbreviate("uri=" + uri + " namespace=" + include.namespace + " target=" + target, 1200));
      }
    }
    return null;
  }

  private static Finding classifyInternalForwardRequest(Map<?, ?> parameters, String uri) {
    if (parameters == null) {
      return null;
    }
    for (Map.Entry<?, ?> entry : parameters.entrySet()) {
      String name = String.valueOf(entry.getKey());
      if (!isInternalForwardParameter(name)) {
        continue;
      }
      List<String> values = new ArrayList<String>();
      collectParameterValues(values, entry.getValue());
      for (String value : values) {
        String target = internalForwardTarget(value);
        if (target.length() > 0) {
          return new Finding(
              "java17_request_internal_forward",
              90,
              "Request parameter attempts internal forwarding to a Java 17 sensitive control path",
              "forward",
              abbreviate("uri=" + uri + " parameter=" + name + " target=" + target, 1200));
        }
      }
    }
    return null;
  }

  private static boolean isInternalForwardParameter(String name) {
    if (name == null || name.trim().length() == 0) {
      return false;
    }
    String normalized =
        lower(name).replace("-", "").replace("_", "").replace(".", "");
    return "jsp".equals(normalized)
        || "view".equals(normalized)
        || "viewname".equals(normalized)
        || "forward".equals(normalized)
        || "forwardto".equals(normalized)
        || "dispatch".equals(normalized)
        || "dispatcher".equals(normalized)
        || "template".equals(normalized);
  }

  private static String internalForwardTarget(String value) {
    if (value == null || value.trim().length() == 0) {
      return "";
    }
    for (String variant : pathVariants(value.trim())) {
      String normalized = variant.trim().replace('\\', '/');
      if (!normalized.startsWith("/") || !INTERNAL_FORWARD_JSP_SUFFIX.matcher(normalized).find()) {
        continue;
      }
      String path = normalized.split("[?#]", 2)[0];
      String stripped = stripServletPathParameters(path);
      if (INTERNAL_FORWARD_CONTROL_PATH.matcher(stripped).find()) {
        return normalized;
      }
    }
    return "";
  }

  private static Finding classifySessionFileDeserializationRequest(Object request, String uri) {
    Object cookies = invoke(request, "getCookies");
    if (cookies == null || !cookies.getClass().isArray()) {
      return null;
    }
    int length = Array.getLength(cookies);
    for (int i = 0; i < length; i++) {
      Object cookie = Array.get(cookies, i);
      String name = invokeString(cookie, "getName");
      if (!"JSESSIONID".equalsIgnoreCase(name)) {
        continue;
      }
      String value = invokeString(cookie, "getValue");
      String reason = sessionFileSessionIdReason(value);
      if (reason.length() == 0) {
        continue;
      }
      return new Finding(
          "java17_request_session_file_deserialization",
          90,
          "Filesystem-shaped JSESSIONID reached a Java 17 request",
          "session",
          abbreviate("uri=" + uri + " cookie=JSESSIONID reason=" + reason, 1200));
    }
    return null;
  }

  private static String sessionFileSessionIdReason(String value) {
    if (value == null) {
      return "";
    }
    String trimmed = value.trim();
    if (trimmed.length() == 0) {
      return "";
    }
    String lower = lower(trimmed);
    if (trimmed.startsWith(".")) {
      return "hidden-file-session-id";
    }
    if (trimmed.indexOf('/') >= 0 || trimmed.indexOf('\\') >= 0) {
      return "path-separator-session-id";
    }
    if (trimmed.indexOf("..") >= 0) {
      return "dotdot-session-id";
    }
    if (lower.indexOf("%2f") >= 0
        || lower.indexOf("%5c") >= 0
        || lower.indexOf("%252f") >= 0
        || lower.indexOf("%255c") >= 0) {
      return "encoded-separator-session-id";
    }
    return "";
  }

  private static IncludeAttributes servletIncludeAttributes(
      Object request, String prefix, String namespace) {
    return new IncludeAttributes(
        namespace,
        requestAttribute(request, prefix + "request_uri"),
        requestAttribute(request, prefix + "path_info"),
        requestAttribute(request, prefix + "servlet_path"));
  }

  private static void addIncludeCandidate(List<String> candidates, String value) {
    if (value == null || value.trim().length() == 0 || candidates.contains(value)) {
      return;
    }
    candidates.add(value);
  }

  private static String joinIncludePath(String base, String path) {
    if (!hasText(base)) {
      return path;
    }
    if (!hasText(path)) {
      return base;
    }
    String trimmedBase = base.trim();
    String trimmedPath = path.trim();
    if (trimmedPath.startsWith("/")) {
      return trimmedPath;
    }
    if (trimmedBase.endsWith("/")) {
      return trimmedBase + trimmedPath;
    }
    return trimmedBase + "/" + trimmedPath;
  }

  private static boolean isKnownLiferayPortalInclude(String uri, IncludeAttributes include) {
    String normalizedUri = normalizePath(uri == null ? "" : uri);
    if (!("/".equals(normalizedUri)
        || normalizedUri.startsWith("/c/portal/")
        || normalizedUri.startsWith("/o/"))) {
      return false;
    }
    List<String> candidates = new ArrayList<String>();
    addIncludeCandidate(candidates, include.pathInfo);
    addIncludeCandidate(candidates, include.servletPath);
    addIncludeCandidate(candidates, include.requestUri);
    addIncludeCandidate(candidates, joinIncludePath(include.servletPath, include.pathInfo));
    addIncludeCandidate(candidates, joinIncludePath(include.requestUri, include.pathInfo));
    for (int i = 0; i < candidates.size(); i++) {
      List<String> variants = pathVariants(candidates.get(i));
      for (int j = 0; j < variants.size(); j++) {
        String normalized = normalizePath(stripServletPathParameters(variants.get(j)));
        if (isKnownLiferayInternalIncludePath(normalizedUri, normalized)) {
          return true;
        }
        String canonical = collapsePathDotSegments(normalized);
        if (isKnownLiferayInternalIncludePath(normalizedUri, canonical)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean isKnownLiferayInternalIncludePath(String uri, String path) {
    if (path == null) {
      return false;
    }
    if (path.startsWith("/html/portal/")
        || path.startsWith("/html/common/")
        || path.startsWith("/html/taglib/")) {
      return true;
    }
    if (uri != null
        && uri.startsWith("/c/portal/")
        && path.startsWith("/dynamic_include/")) {
      return true;
    }
    return uri != null
        && uri.startsWith("/o/")
        && ("/view.jsp".equals(path)
            || path.endsWith("/view.jsp")
            || path.startsWith("/search/bar/"));
  }

  private static String forgedIncludeTarget(String value) {
    if (value == null || value.trim().length() == 0) {
      return "";
    }
    List<String> variants = decodedPathVariants(value);
    int decodedCount = variants.size();
    addLowByteVariants(variants, value);
    for (int i = 0; i < variants.size(); i++) {
      String normalized = normalizePath(stripServletPathParameters(variants.get(i)));
      if (PROTECTED_WEB_RESOURCE_PATH.matcher(normalized).find()) {
        return normalized;
      }
      if (SCRIPT_FILE_WRITE.matcher(normalized).matches()) {
        return normalized;
      }
      if (hasConfusingDotSegment(normalized) || (i < decodedCount && hasPathControlCharacter(normalized))) {
        return normalized;
      }
      String canonicalProtectedPath = canonicalProtectedWebResourcePath(normalized);
      if (canonicalProtectedPath.length() > 0) {
        return canonicalProtectedPath;
      }
    }
    return "";
  }

  private static boolean isLegitimateRequestDispatcherInclude() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i < stack.length; i++) {
      String className = stack[i].getClassName();
      String methodName = stack[i].getMethodName();
      if (!"include".equals(methodName) && !"doInclude".equals(methodName)) {
        continue;
      }
      if (className.endsWith("ApplicationDispatcher")
          || "org.eclipse.jetty.server.Dispatcher".equals(className)
          || "io.undertow.servlet.spec.RequestDispatcherImpl".equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isTemplateSourceParameterName(String name) {
    String normalized = normalizeParameterName(name);
    if (normalized.length() == 0) {
      return false;
    }
    if ("class".equals(normalized)
        || "classname".equals(normalized)
        || "locale".equals(normalized)
        || "resource".equals(normalized)
        || "resourcefile".equals(normalized)
        || "resourcepath".equals(normalized)
        || "resourceurl".equals(normalized)
        || "template".equals(normalized)
        || "templatepath".equals(normalized)
        || "templatefile".equals(normalized)
        || "templateurl".equals(normalized)
        || "templatesource".equals(normalized)
        || "templatesourceurl".equals(normalized)
        || "templatesourcepath".equals(normalized)) {
      return true;
    }
    return (normalized.contains("decorator") && normalized.contains("location"))
        || (normalized.contains("screen") && normalized.contains("location"))
        || (normalized.contains("template")
            && (normalized.contains("source")
                || normalized.contains("path")
                || normalized.contains("file")
                || normalized.contains("url")));
  }

  private static String normalizeParameterName(String name) {
    String value = lower(name == null ? "" : name);
    StringBuilder normalized = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        normalized.append(c);
      }
    }
    return normalized.toString();
  }

  private static void collectParameterValues(List<String> values, Object value) {
    if (value == null || values.size() >= 32) {
      return;
    }
    if (value instanceof Iterable<?>) {
      for (Object item : (Iterable<?>) value) {
        if (values.size() >= 32) {
          break;
        }
        collectParameterValues(values, item);
      }
      return;
    }
    Class<?> valueClass = value.getClass();
    if (valueClass.isArray()) {
      int length = Array.getLength(value);
      for (int i = 0; i < length && values.size() < 32; i++) {
        collectParameterValues(values, Array.get(value, i));
      }
      return;
    }
    values.add(String.valueOf(value));
  }

  private static Finding classifyDefaultJwtSecret(Object request, String uri) {
    String authorization = requestHeader(request, "Authorization").trim();
    if (!authorization.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
      return null;
    }
    String token = authorization.substring("Bearer ".length()).trim();
    if (token.length() == 0 || token.length() > 8192) {
      return null;
    }
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3
        || parts[0].length() == 0
        || parts[1].length() == 0
        || parts[2].length() == 0) {
      return null;
    }
    String algorithm = jwtHmacAlgorithm(parts[0]);
    if (algorithm.length() == 0) {
      return null;
    }
    byte[] signature = decodeBase64UrlOrEmpty(parts[2]);
    if (signature.length == 0) {
      return null;
    }
    byte[] expected = jwtHmac(parts[0] + "." + parts[1], algorithm, HUGEGRAPH_DEFAULT_JWT_SECRET);
    if (expected.length == 0 || !MessageDigest.isEqual(signature, expected)) {
      return null;
    }
    return new Finding(
        "java17_request_default_jwt_secret",
        95,
        "Bearer JWT is signed with a known Java 17 default HMAC secret",
        "jwt",
        abbreviate("key=hugegraph-default-token-secret alg=" + algorithm + " uri=" + uri, 1200));
  }

  private static String jwtHmacAlgorithm(String headerPart) {
    byte[] headerBytes = decodeBase64UrlOrEmpty(headerPart);
    if (headerBytes.length == 0) {
      return "";
    }
    String header = new String(headerBytes, StandardCharsets.UTF_8);
    Matcher matcher = JWT_HMAC_ALGORITHM.matcher(header);
    return matcher.find() ? matcher.group(1) : "";
  }

  private static byte[] jwtHmac(String signingInput, String jwtAlgorithm, String secret) {
    String macAlgorithm = "";
    if ("HS256".equals(jwtAlgorithm)) {
      macAlgorithm = "HmacSHA256";
    } else if ("HS384".equals(jwtAlgorithm)) {
      macAlgorithm = "HmacSHA384";
    } else if ("HS512".equals(jwtAlgorithm)) {
      macAlgorithm = "HmacSHA512";
    }
    if (macAlgorithm.length() == 0) {
      return new byte[0];
    }
    try {
      Mac mac = Mac.getInstance(macAlgorithm);
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlgorithm));
      return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
    } catch (Exception ignored) {
      return new byte[0];
    }
  }

  private static Finding classifyDefaultCryptoCookie(Object request) {
    Object cookies = invoke(request, "getCookies");
    if (cookies == null || !cookies.getClass().isArray()) {
      return null;
    }
    int length = Array.getLength(cookies);
    for (int i = 0; i < length; i++) {
      Object cookie = Array.get(cookies, i);
      String name = invokeString(cookie, "getName");
      if (!"rememberMe".equals(name)) {
        continue;
      }
      String value = invokeString(cookie, "getValue");
      if (isDefaultEncryptedSerializedCookie(value)) {
        return new Finding(
            "java17_request_default_crypto_cookie",
            94,
            "Default-key encrypted Java serialization cookie reached a Java 17 request",
            "cookie",
            "rememberMe shiro-default-aes-cbc");
      }
    }
    return null;
  }

  private static boolean isDefaultEncryptedSerializedCookie(String value) {
    if (value == null) {
      return false;
    }
    String trimmed = value.trim();
    if (trimmed.length() < 44 || trimmed.length() > MAX_DEFAULT_CRYPTO_COOKIE_LENGTH) {
      return false;
    }
    try {
      byte[] encrypted = Base64.getDecoder().decode(trimmed);
      if (encrypted.length < 32 || ((encrypted.length - 16) % 16) != 0) {
        return false;
      }
      byte[] iv = new byte[16];
      System.arraycopy(encrypted, 0, iv, 0, iv.length);
      byte[] ciphertext = new byte[encrypted.length - iv.length];
      System.arraycopy(encrypted, iv.length, ciphertext, 0, ciphertext.length);
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(SHIRO_DEFAULT_REMEMBERME_KEY, "AES"),
          new IvParameterSpec(iv));
      byte[] plaintext = cipher.doFinal(ciphertext);
      return plaintext.length >= 4
          && (plaintext[0] & 0xff) == 0xac
          && (plaintext[1] & 0xff) == 0xed
          && plaintext[2] == 0
          && plaintext[3] == 5;
    } catch (Exception ignored) {
      return false;
    }
  }

  private static String confusingRequestPath(String uri) {
    if (uri == null || uri.trim().length() == 0) {
      return "";
    }
    String path = uri.split("\\?", 2)[0];
    boolean sensitiveControlPath = SENSITIVE_CONTROL_PATH.matcher(path).find();
    List<String> variants = decodedPathVariants(path);
    int decodedCount = variants.size();
    addLowByteVariants(variants, path);
    for (int i = 0; i < variants.size(); i++) {
      String normalized = variants.get(i).replace('\\', '/');
      if (hasConfusingDotSegment(normalized)
          || (sensitiveControlPath && i < decodedCount && hasPathControlCharacter(normalized))) {
        return normalized;
      }
      String canonicalControlPath = canonicalSensitiveControlPath(normalized);
      if (canonicalControlPath.length() > 0) {
        return canonicalControlPath;
      }
      String canonicalProtectedPath = canonicalProtectedWebResourcePath(normalized);
      if (canonicalProtectedPath.length() > 0) {
        return canonicalProtectedPath;
      }
    }
    return "";
  }

  private static boolean isTeamCityInstallLinksFragmentPath(String uri) {
    if (uri == null || uri.trim().length() == 0) {
      return false;
    }
    String path = uri.split("\\?", 2)[0].replace('\\', '/');
    return "/admin/../installlinks.jspf".equals(lower(path));
  }

  private static String canonicalSensitiveControlPath(String path) {
    if (path == null || path.trim().length() == 0) {
      return "";
    }
    String normalized = stripServletPathParameters(path.replace('\\', '/'));
    if (!hasSingleDotSegment(normalized) && normalized.indexOf("//") < 0) {
      return "";
    }
    String canonical = collapsePathDotSegments(normalized);
    if (canonical.equals(normalized) || !SENSITIVE_CONTROL_PATH.matcher(canonical).find()) {
      return "";
    }
    return canonical;
  }

  private static String canonicalProtectedWebResourcePath(String path) {
    if (path == null || path.trim().length() == 0) {
      return "";
    }
    String normalized = stripServletPathParameters(path.replace('\\', '/'));
    if (!hasSingleDotSegment(normalized) && normalized.indexOf("//") < 0) {
      return "";
    }
    String canonical = collapsePathDotSegments(normalized);
    if (canonical.equals(normalized) || !PROTECTED_WEB_RESOURCE_PATH.matcher(canonical).find()) {
      return "";
    }
    return canonical;
  }

  private static List<String> pathVariants(String path) {
    List<String> variants = decodedPathVariants(path);
    addLowByteVariants(variants, path);
    return variants;
  }

  private static List<String> decodedPathVariants(String path) {
    List<String> variants = new ArrayList<String>();
    addVariant(variants, path);
    addOverlongUtf8Variants(variants, path);
    String once = PercentEncodedText.decode(path, false);
    addVariant(variants, once);
    addVariant(variants, decodeUnicodeEscapes(once));
    addLenientPercentVariants(variants, once);
    addOverlongUtf8Variants(variants, once);
    String twice = PercentEncodedText.decode(once, false);
    addVariant(variants, twice);
    addVariant(variants, decodeUnicodeEscapes(twice));
    addLenientPercentVariants(variants, twice);
    addOverlongUtf8Variants(variants, twice);
    addLenientPercentVariants(variants, path);
    return variants;
  }

  private static void addLowByteVariants(List<String> variants, String path) {
    String ghost = lowByteUnicodeDecode(path);
    if (!ghost.equals(path)) {
      addVariant(variants, ghost);
      addVariant(variants, decodeUnicodeEscapes(ghost));
      addOverlongUtf8Variants(variants, ghost);
      String decodedGhost = PercentEncodedText.decode(ghost, false);
      addVariant(variants, decodedGhost);
      addVariant(variants, decodeUnicodeEscapes(decodedGhost));
      addLenientPercentVariants(variants, decodedGhost);
      addOverlongUtf8Variants(variants, decodedGhost);
    }
  }

  private static void addOverlongUtf8Variants(List<String> variants, String value) {
    String overlong = overlongUtf8Decode(value);
    if (!overlong.equals(value)) {
      addVariant(variants, overlong);
      addVariant(variants, decodeUnicodeEscapes(overlong));
    }
  }

  private static void addLenientPercentVariants(List<String> variants, String value) {
    String lenient = jettyLenientPercentDecode(value);
    if (!lenient.equals(value)) {
      addVariant(variants, lenient);
      addVariant(variants, decodeUnicodeEscapes(lenient));
    }
  }

  private static void addVariant(List<String> variants, String value) {
    if (value == null || value.trim().length() == 0) {
      return;
    }
    if (!variants.contains(value)) {
      variants.add(value);
    }
  }

  private static boolean hasConfusingDotSegment(String path) {
    String[] segments = path.split("/+");
    for (int i = 0; i < segments.length; i++) {
      String segment = segments[i];
      if (segment.length() == 0) {
        continue;
      }
      int semicolon = segment.indexOf(';');
      if (semicolon >= 0) {
        segment = segment.substring(0, semicolon);
      }
      if ("..".equals(segment)) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasSingleDotSegment(String path) {
    String[] segments = path.split("/", -1);
    for (int i = 0; i < segments.length; i++) {
      if (".".equals(segments[i])) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasPathControlCharacter(String path) {
    for (int i = 0; i < path.length(); i++) {
      if (Character.isISOControl(path.charAt(i))) {
        return true;
      }
    }
    return false;
  }

  private static String collapsePathDotSegments(String path) {
    boolean absolute = path.startsWith("/");
    List<String> segments = new ArrayList<String>();
    String[] rawSegments = path.split("/+", -1);
    for (int i = 0; i < rawSegments.length; i++) {
      String segment = rawSegments[i];
      if (segment.trim().length() == 0 || ".".equals(segment)) {
        continue;
      }
      if ("..".equals(segment)) {
        if (!segments.isEmpty()) {
          segments.remove(segments.size() - 1);
        }
        continue;
      }
      segments.add(segment);
    }
    String collapsed = joinPathSegments(segments);
    if (absolute) {
      collapsed = "/" + collapsed;
    }
    return collapsed.trim().length() == 0 ? "/" : collapsed;
  }

  private static String joinPathSegments(List<String> segments) {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < segments.size(); i++) {
      if (i > 0) {
        builder.append('/');
      }
      builder.append(segments.get(i));
    }
    return builder.toString();
  }

  private static String stripServletPathParameters(String path) {
    String[] segments = path.split("/", -1);
    StringBuilder stripped = new StringBuilder(path.length());
    for (int i = 0; i < segments.length; i++) {
      if (i > 0) {
        stripped.append('/');
      }
      String segment = segments[i];
      int semicolon = segment.indexOf(';');
      stripped.append(semicolon >= 0 ? segment.substring(0, semicolon) : segment);
    }
    return stripped.toString();
  }

  private static String percentDecode(String value) {
    if (value == null || value.indexOf('%') < 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '%' && i + 2 < value.length()) {
        int high = Character.digit(value.charAt(i + 1), 16);
        int low = Character.digit(value.charAt(i + 2), 16);
        if (high >= 0 && low >= 0) {
          decoded.append((char) ((high << 4) + low));
          i += 2;
          continue;
        }
      }
      decoded.append(ch);
    }
    return decoded.toString();
  }

  private static String jettyLenientPercentDecode(String value) {
    return PercentEncodedText.decode(value, true);
  }

  private static String overlongUtf8Decode(String value) {
    if (value == null || value.trim().length() == 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    boolean changed = false;
    for (int i = 0; i < value.length(); i++) {
      int first = encodedByteValue(value, i);
      int firstNext = encodedByteNextIndex(value, i);
      if (first >= 0xc0 && first <= 0xdf && firstNext < value.length()) {
        int second = encodedByteValue(value, firstNext);
        int secondNext = encodedByteNextIndex(value, firstNext);
        if ((second & 0xc0) == 0x80) {
          int codepoint = ((first & 0x1f) << 6) | (second & 0x3f);
          if (overlongPathCharacter(codepoint)) {
            decoded.append((char) codepoint);
            i = secondNext - 1;
            changed = true;
            continue;
          }
        }
      }
      if (first == 0xe0 && firstNext < value.length()) {
        int second = encodedByteValue(value, firstNext);
        int secondNext = encodedByteNextIndex(value, firstNext);
        if ((second & 0xc0) == 0x80 && secondNext < value.length()) {
          int third = encodedByteValue(value, secondNext);
          int thirdNext = encodedByteNextIndex(value, secondNext);
          if ((third & 0xc0) == 0x80) {
            int codepoint =
                ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
            if (overlongPathCharacter(codepoint)) {
              decoded.append((char) codepoint);
              i = thirdNext - 1;
              changed = true;
              continue;
            }
          }
        }
      }
      decoded.append(value.charAt(i));
    }
    return changed ? decoded.toString() : value;
  }

  private static boolean overlongPathCharacter(int codepoint) {
    return codepoint == '.' || codepoint == '/' || codepoint == '\\';
  }

  private static int encodedByteValue(String value, int index) {
    if (index < 0 || index >= value.length()) {
      return -1;
    }
    char ch = value.charAt(index);
    if (ch == '%' && index + 2 < value.length()) {
      int high = Character.digit(value.charAt(index + 1), 16);
      int low = Character.digit(value.charAt(index + 2), 16);
      if (high >= 0 && low >= 0) {
        return (high << 4) + low;
      }
    }
    return ch <= 0xff ? ch : -1;
  }

  private static int encodedByteNextIndex(String value, int index) {
    if (index < 0 || index >= value.length()) {
      return value.length();
    }
    char ch = value.charAt(index);
    if (ch == '%'
        && index + 2 < value.length()
        && Character.digit(value.charAt(index + 1), 16) >= 0
        && Character.digit(value.charAt(index + 2), 16) >= 0) {
      return index + 3;
    }
    return index + 1;
  }

  private static String decodeUnicodeEscapes(String value) {
    if (value == null || lower(value).indexOf("%u") < 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '%'
          && i + 5 < value.length()
          && (value.charAt(i + 1) == 'u' || value.charAt(i + 1) == 'U')) {
        int codepoint = 0;
        boolean valid = true;
        for (int offset = 2; offset < 6; offset++) {
          int digit = Character.digit(value.charAt(i + offset), 16);
          if (digit < 0) {
            valid = false;
            break;
          }
          codepoint = (codepoint << 4) + digit;
        }
        if (valid) {
          decoded.append((char) codepoint);
          i += 5;
          continue;
        }
      }
      decoded.append(ch);
    }
    return decoded.toString();
  }

  private static String lowByteUnicodeDecode(String value) {
    if (value == null || value.trim().length() == 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    boolean changed = false;
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch > 0x7f) {
        decoded.append((char) (ch & 0xff));
        changed = true;
      } else {
        decoded.append(ch);
      }
    }
    return changed ? decoded.toString() : value;
  }

  private static String uriScheme(String value) {
    int colon = value.indexOf(':');
    if (colon <= 0 || colon > 24) {
      return "";
    }
    String scheme = value.substring(0, colon).toLowerCase(Locale.ROOT);
    for (int i = 0; i < scheme.length(); i++) {
      char ch = scheme.charAt(i);
      if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')) {
        return "";
      }
    }
    return scheme;
  }

  private static boolean isXxeExternalScheme(String scheme) {
    return "file".equals(scheme)
        || "jar".equals(scheme)
        || "http".equals(scheme)
        || "https".equals(scheme)
        || "ftp".equals(scheme)
        || "ldap".equals(scheme)
        || "ldaps".equals(scheme)
        || "rmi".equals(scheme)
        || "iiop".equals(scheme)
        || "corbaname".equals(scheme)
        || "corbaloc".equals(scheme)
        || "gopher".equals(scheme)
        || "dict".equals(scheme);
  }

  private static int xxeConfidence(String scheme) {
    if ("file".equals(scheme) || "jar".equals(scheme)) {
      return 95;
    }
    if ("http".equals(scheme) || "https".equals(scheme) || "ftp".equals(scheme)) {
      return 92;
    }
    return 90;
  }

  private static boolean isWebInfDeploymentArtifact(String path) {
    String normalized = normalizePath(path);
    String lower = lower(normalized);
    if (!(lower.indexOf("/web-inf/classes/") >= 0
        || lower.indexOf("/web-inf/cfclasses/") >= 0
        || lower.indexOf("/web-inf/lib/") >= 0)) {
      return false;
    }
    return lower.endsWith(".class") || lower.endsWith(".jar");
  }

  private static boolean isMavenRepositoryArtifactWrite(String path) {
    String lower = lower(normalizePath(path));
    return lower.indexOf("/.m2/repository/") >= 0
        && lower.indexOf("../") < 0
        && lower.endsWith(".jar");
  }

  private static boolean isTeamCityPluginStartupWrite(String path) {
    String lowerPath = lower(normalizePath(path));
    if (!isTeamCityPluginStartupWritePath(lowerPath)) {
      return false;
    }
    boolean startupStack = false;
    boolean bundledPluginUnpackStack = false;
    boolean pluginResourceUnpackStack = false;
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if ("jetbrains.buildServer.plugins.files.PluginFilesUtil".equals(className)
          || className.startsWith("jetbrains.buildServer.web.plugins.files.")) {
        bundledPluginUnpackStack = true;
      }
      if ("jetbrains.buildServer.util.ArchiveUtil".equals(className)
          || "jetbrains.buildServer.web.impl.Unpacker".equals(className)
          || "jetbrains.buildServer.web.impl.WatchingResourceUnpackerState".equals(className)
          || "jetbrains.buildServer.web.impl.InitializingResourceUnpacker".equals(className)
          || "jetbrains.buildServer.web.impl.WebResourcesUnpacker".equals(className)) {
        pluginResourceUnpackStack = true;
      }
      if ("jetbrains.buildServer.web.impl.BuildServerConfigurator".equals(className)
          || "jetbrains.buildServer.serverSide.impl.BuildServerLifecycleProcessor"
              .equals(className)
          || className.startsWith("jetbrains.buildServer.maintenance.StartupProcessor")) {
        startupStack = true;
      }
    }
    return startupStack && (bundledPluginUnpackStack || pluginResourceUnpackStack);
  }

  private static boolean isTeamCityPluginStartupWritePath(String lowerPath) {
    if (lowerPath.endsWith(".jar") && lowerPath.indexOf("/web-inf/plugins/.unpacked/") >= 0) {
      return true;
    }
    return lowerPath.indexOf("/webapps/root/plugins/") >= 0
        && SCRIPT_FILE_WRITE.matcher(lowerPath).matches();
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
    String normalized = lower(argument == null ? "" : argument.trim());
    if (normalized.length() == 0 || !containsRemoteProtocol(normalized) || !JmxDispatch.isLocationArgument(argument)) {
      return false;
    }
    return normalized.indexOf("brokerconfig=") >= 0
        || normalized.indexOf("xbean:") >= 0
        || normalized.indexOf("spring:") >= 0
        || (normalized.indexOf("config") >= 0 && normalized.indexOf(".xml") >= 0);
  }

  private static boolean containsRemoteProtocol(String value) {
    String normalized = lower(value);
    return normalized.indexOf("http://") >= 0
        || normalized.indexOf("https://") >= 0
        || normalized.indexOf("ftp://") >= 0
        || normalized.indexOf("ldap://") >= 0
        || normalized.indexOf("ldaps://") >= 0
        || normalized.indexOf("rmi://") >= 0
        || normalized.indexOf("iiop://") >= 0
        || normalized.indexOf("corbaname://") >= 0
        || normalized.indexOf("corbaloc://") >= 0;
  }

  private static int jmxRemoteConfigConfidence(String value) {
    String normalized = lower(value);
    if (normalized.indexOf("brokerconfig=") >= 0 || normalized.indexOf("xbean:") >= 0) {
      return 94;
    }
    if (normalized.indexOf("spring:") >= 0) {
      return 92;
    }
    return 88;
  }

  private static Object invoke(Object target, String methodName) {
    if (target == null) {
      return null;
    }
    try {
      return target.getClass().getMethod(methodName).invoke(target);
    } catch (Exception ignored) {
      try {
        Method method = target.getClass().getDeclaredMethod(methodName);
        method.setAccessible(true);
        return method.invoke(target);
      } catch (Exception alsoIgnored) {
        return null;
      }
    }
  }

  private static String invokeString(Object target, String methodName) {
    Object value = invoke(target, methodName);
    return value == null ? "" : String.valueOf(value);
  }

  private static String jexlSourceText(Object expression) {
    String source = invokeString(expression, "getSourceText");
    if (source.length() > 0) {
      return source;
    }
    source = invokeString(expression, "getParsedText");
    if (source.length() > 0) {
      return source;
    }
    return expression == null ? "" : String.valueOf(expression);
  }

  private static String elSourceText(Object expression) {
    String source = invokeString(expression, "getExpressionString");
    if (source.length() > 0) {
      return source;
    }
    source = invokeString(expression, "getExpression");
    if (source.length() > 0) {
      return source;
    }
    return expression == null ? "" : String.valueOf(expression);
  }

  private static String requestUri(Object request) {
    String uri = invokeString(request, "getRequestURI");
    if (uri.length() > 0) {
      return uri;
    }
    Object requestUri = invoke(request, "getRequestUri");
    if (requestUri == null) {
      return "";
    }
    String rawPath = invokeString(requestUri, "getRawPath");
    if (rawPath.length() > 0) {
      return rawPath;
    }
    String path = invokeString(requestUri, "getPath");
    return path.length() > 0 ? path : String.valueOf(requestUri);
  }

  private static String requestQuery(Object request) {
    String query = invokeString(request, "getQueryString");
    if (query.length() > 0) {
      return query;
    }
    Object requestUri = invoke(request, "getRequestUri");
    if (requestUri == null) {
      return "";
    }
    return invokeString(requestUri, "getRawQuery");
  }

  private static String requestHeader(Object request, String headerName) {
    if (request == null || headerName == null) {
      return "";
    }
    try {
      Object value = request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
      return value == null ? "" : String.valueOf(value);
    } catch (Exception ignored) {
      try {
        Object value =
            request.getClass().getMethod("getHeaderString", String.class).invoke(request, headerName);
        return value == null ? "" : String.valueOf(value);
      } catch (Exception alsoIgnored) {
        try {
          Method method = request.getClass().getDeclaredMethod("getHeader", String.class);
          method.setAccessible(true);
          Object value = method.invoke(request, headerName);
          return value == null ? "" : String.valueOf(value);
        } catch (Exception thirdIgnored) {
          return "";
        }
      }
    }
  }

  private static String requestAttribute(Object request, String attributeName) {
    if (request == null || attributeName == null) {
      return "";
    }
    try {
      Object value = request.getClass().getMethod("getAttribute", String.class).invoke(request, attributeName);
      return value == null ? "" : String.valueOf(value);
    } catch (Exception ignored) {
      try {
        Method method = request.getClass().getDeclaredMethod("getAttribute", String.class);
        method.setAccessible(true);
        Object value = method.invoke(request, attributeName);
        return value == null ? "" : String.valueOf(value);
      } catch (Exception alsoIgnored) {
        return "";
      }
    }
  }

  private static byte[] decodeBase64OrEmpty(String value) {
    try {
      return Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException ignored) {
      return new byte[0];
    }
  }

  private static byte[] decodeBase64UrlOrEmpty(String value) {
    try {
      return Base64.getUrlDecoder().decode(value);
    } catch (IllegalArgumentException ignored) {
      return new byte[0];
    }
  }

  private static String javaBeansTargetType(Object target) {
    if (target instanceof Class<?>) {
      return ((Class<?>) target).getName();
    }
    return target == null ? "" : target.getClass().getName();
  }

  private static List<String> javaBeansArguments(Object target, Object arguments) {
    List<String> values = new ArrayList<String>();
    collectJavaBeansArguments(values, arguments, 0);
    if (target instanceof ProcessBuilder) {
      List<String> command = ((ProcessBuilder) target).command();
      for (String item : command) {
        if (values.size() >= 64) {
          break;
        }
        if (item != null && item.trim().length() > 0) {
          values.add(item.trim());
        }
      }
    }
    return values;
  }

  private static void collectJavaBeansArguments(List<String> values, Object value, int depth) {
    if (value == null || depth > 3 || values.size() >= 64) {
      return;
    }
    if (value instanceof Iterable<?>) {
      for (Object item : (Iterable<?>) value) {
        if (values.size() >= 64) {
          break;
        }
        collectJavaBeansArguments(values, item, depth + 1);
      }
      return;
    }
    Class<?> valueClass = value.getClass();
    if (valueClass.isArray()) {
      int length = Array.getLength(value);
      for (int i = 0; i < length && values.size() < 64; i++) {
        collectJavaBeansArguments(values, Array.get(value, i), depth + 1);
      }
      return;
    }
    String text = String.valueOf(value).trim();
    if (text.length() > 0) {
      values.add(text);
    }
  }

  private static String normalizeJavaTypeName(String className) {
    if (className == null) {
      return "";
    }
    String normalized = className.trim().replace('/', '.');
    while (normalized.startsWith("[")) {
      normalized = normalized.startsWith("[L") ? normalized.substring(2) : normalized.substring(1);
    }
    if (normalized.endsWith(";")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized;
  }

  private static List<String> stackTraceClassNames() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    List<String> names = new ArrayList<String>(stack.length);
    for (int i = 0; i < stack.length; i++) {
      names.add(stack[i].getClassName());
    }
    return names;
  }

  private static String joinList(List<String> values) {
    StringBuilder builder = new StringBuilder();
    if (values == null) {
      return "";
    }
    for (String value : values) {
      if (value == null || value.trim().length() == 0) {
        continue;
      }
      if (builder.length() > 0) {
        builder.append(' ');
      }
      builder.append(value.trim());
    }
    return builder.toString();
  }

  private static int remoteJaasConfidence(String providerUrl) {
    String lower = providerUrl == null ? "" : providerUrl.toLowerCase(Locale.ROOT);
    if (lower.startsWith("ldap://") || lower.startsWith("ldaps://") || lower.startsWith("rmi://")) {
      return 94;
    }
    return 88;
  }

  private static String jaasOptionsText(Object options) {
    if (options == null) {
      return "";
    }
    if (options instanceof Map<?, ?>) {
      StringBuilder builder = new StringBuilder();
      Map<?, ?> map = (Map<?, ?>) options;
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (builder.length() > 0) {
          builder.append(' ');
        }
        builder.append(String.valueOf(entry.getKey())).append('=').append(String.valueOf(entry.getValue()));
      }
      return builder.toString();
    }
    return String.valueOf(options);
  }

  private static int scriptConfidence(
      boolean runtimeExec, boolean processBuilder, boolean reflectiveRuntimeExec, boolean nestedScriptEval) {
    if (runtimeExec || processBuilder) {
      return 94;
    }
    if (reflectiveRuntimeExec || nestedScriptEval) {
      return 90;
    }
    return 86;
  }

  private static List<String> javaSourceTexts(Object value) {
    List<String> sources = new ArrayList<String>();
    if (value == null) {
      return sources;
    }
    if (value instanceof Iterable<?>) {
      for (Object item : (Iterable<?>) value) {
        String source = javaSourceText(item);
        if (source.length() > 0) {
          sources.add(source);
        }
      }
      return sources;
    }
    if (value instanceof Object[]) {
      Object[] values = (Object[]) value;
      for (int i = 0; i < values.length; i++) {
        String source = javaSourceText(values[i]);
        if (source.length() > 0) {
          sources.add(source);
        }
      }
      return sources;
    }
    String source = javaSourceText(value);
    if (source.length() > 0) {
      sources.add(source);
    }
    return sources;
  }

  private static String javaSourceText(Object value) {
    if (value == null) {
      return "";
    }
    if (value instanceof CharSequence) {
      return String.valueOf(value);
    }
    try {
      Method method = value.getClass().getMethod("getCharContent", boolean.class);
      method.setAccessible(true);
      Object content = method.invoke(value, Boolean.TRUE);
      if (content != null) {
        return String.valueOf(content);
      }
    } catch (Exception ignored) {
      // Fall through to String.valueOf for compiler implementations without source access.
    }
    return String.valueOf(value);
  }

  private static String abbreviate(String value, int maxLength) {
    if (value == null) {
      return "";
    }
    if (value.length() <= maxLength) {
      return value;
    }
    return value.substring(0, maxLength) + "...";
  }

  private static String remoteClassLoaderScheme(String source) {
    String inspected = source.trim().toLowerCase(Locale.ROOT);
    if (inspected.startsWith("jar:")) {
      inspected = inspected.substring("jar:".length());
      int bang = inspected.indexOf("!/");
      if (bang >= 0) {
        inspected = inspected.substring(0, bang);
      }
    }
    int colon = inspected.indexOf(':');
    if (colon <= 0 || colon > 16) {
      return "";
    }
    String scheme = inspected.substring(0, colon);
    if ("http".equals(scheme)
        || "https".equals(scheme)
        || "ftp".equals(scheme)
        || "ldap".equals(scheme)
        || "rmi".equals(scheme)) {
      return scheme;
    }
    return "";
  }

  private static boolean isFelixExtensionClassLoaderSource(String source, String scheme) {
    if (!"http".equals(scheme) && !"https".equals(scheme)) {
      return false;
    }
    String inspected = source.trim();
    if (inspected.regionMatches(true, 0, "jar:", 0, "jar:".length())) {
      inspected = inspected.substring("jar:".length());
      int bang = inspected.indexOf("!/");
      if (bang >= 0) {
        inspected = inspected.substring(0, bang);
      }
    }
    int schemeSeparator = inspected.indexOf(':');
    if (schemeSeparator <= 0 || inspected.length() <= schemeSeparator + 3) {
      return false;
    }
    if (inspected.charAt(schemeSeparator + 1) != '/'
        || inspected.charAt(schemeSeparator + 2) != '/') {
      return false;
    }
    int authorityStart = schemeSeparator + 3;
    int authorityEnd = inspected.length();
    for (int i = authorityStart; i < inspected.length(); i++) {
      char value = inspected.charAt(i);
      if (value == '/' || value == '?' || value == '#') {
        authorityEnd = i;
        break;
      }
    }
    String authority = inspected.substring(authorityStart, authorityEnd);
    int at = authority.lastIndexOf('@');
    if (at >= 0) {
      authority = authority.substring(at + 1);
    }
    int portSeparator = authority.lastIndexOf(':');
    if (portSeparator <= 0 || portSeparator == authority.length() - 1) {
      return false;
    }
    String host = authority.substring(0, portSeparator);
    String port = authority.substring(portSeparator + 1);
    if (!"felix.extensions".equalsIgnoreCase(host)) {
      return false;
    }
    for (int i = 0; i < port.length(); i++) {
      if (!Character.isDigit(port.charAt(i))) {
        return false;
      }
    }
    return true;
  }

  private static List<String> classLoaderSources(Object value) {
    List<String> sources = new ArrayList<String>();
    if (value == null) {
      return sources;
    }
    if (value instanceof URL[]) {
      URL[] urls = (URL[]) value;
      for (int i = 0; i < urls.length; i++) {
        if (urls[i] != null) {
          sources.add(String.valueOf(urls[i]));
        }
      }
      return sources;
    }
    if (value instanceof Object[]) {
      Object[] values = (Object[]) value;
      for (int i = 0; i < values.length; i++) {
        if (values[i] != null) {
          addClassLoaderSourceText(sources, String.valueOf(values[i]));
        }
      }
      return sources;
    }
    addClassLoaderSourceText(sources, String.valueOf(value));
    return sources;
  }

  private static void addClassLoaderSourceText(List<String> sources, String value) {
    if (value == null) {
      return;
    }
    String trimmed = value.trim();
    if (trimmed.length() == 0) {
      return;
    }
    String[] parts = trimmed.split("\\s+");
    for (int i = 0; i < parts.length; i++) {
      if (parts[i].length() > 0) {
        sources.add(parts[i]);
      }
    }
  }

  private static boolean containsJdbcOption(String lower, String option) {
    return lower.indexOf(";" + option + "=") >= 0
        || lower.indexOf("&" + option + "=") >= 0
        || lower.indexOf("?" + option + "=") >= 0;
  }

  private static boolean isJdbcOptionEnabled(String lower, String option) {
    return lower.indexOf(option + "=true") >= 0
        || lower.indexOf(option + "=1") >= 0
        || lower.indexOf(option + "=yes") >= 0;
  }

  private static String relaxJdbcSyntax(String value) {
    return value
        .replace('+', ' ')
        .replace("%20", " ")
        .replace("%09", " ")
        .replace("%0a", " ")
        .replace("%0d", " ")
        .replace("%22", "\"")
        .replace("%27", "'")
        .replace("%26", "&")
        .replace("%28", "(")
        .replace("%29", ")")
        .replace("%2b", "+")
        .replace("%2c", ",")
        .replace("%2f", "/")
        .replace("%3b", ";")
        .replace("%3d", "=");
  }

  private static Finding classifyUrlOpen(Object url) {
    return classifyUrlOpen(url, CURRENT_REQUEST_URLS.get(), null, false);
  }

  private static Finding classifyUrlOpen(Object url, List<String> requestUrls, String peer, boolean redirected) {
    UrlParts parts = urlParts(url);
    if (parts == null || parts.host.length() == 0) {
      return null;
    }
    if (NetworkHost.isMetadata(parts.host) || (peer != null && NetworkHost.isMetadata(peer))) {
      return new Finding(
          "java17_ssrf_cloud_metadata",
          95,
          "Cloud metadata URL reached a Java 17 URL sink",
          "url",
          parts.fullUrl);
    }
    boolean supplied = redirected || !requestControlledUrlMatch(parts.comparisonKey, requestUrls).isEmpty();
    if ((isLoopbackHost(parts.host) || (peer != null && isLoopbackHost(peer))) && LOOPBACK_ADMIN_PATH.matcher(parts.path).find()
        && (supplied || (requestUrls != null && requestUrls.contains(parts.path)))) {
      return new Finding(
          "java17_ssrf_loopback_admin",
          88,
          "Loopback administrative URL reached a Java 17 URL sink",
          "url",
          parts.fullUrl);
    }
    if (supplied && (NetworkHost.isInternal(parts.host) || (peer != null && NetworkHost.isInternal(peer)))) {
      return new Finding(
          "java17_ssrf_request_parameter_url",
          92,
          "Request parameter controlled outbound URL reached a Java 17 URL sink",
          "url",
          abbreviate(parts.fullUrl, 1200));
    }
    return null;
  }

  private static Finding classifyFastjsonClassResource(String resource) {
    String mechanism = fastjsonClassResourceMechanism(resource);
    if (mechanism.length() == 0) {
      return null;
    }
    return new Finding(
        "java17_deserialization_fastjson_resource_url",
        100,
        "Fastjson autoType attempted to resolve a URL-shaped class resource",
        "resource",
        abbreviate(resource, 1200));
  }

  private static String fastjsonClassResourceMechanism(String resource) {
    if (resource == null || resource.trim().length() == 0) {
      return "";
    }
    String normalized = lower(resource.trim());
    if (normalized.startsWith("http://")) {
      return "http";
    }
    if (normalized.startsWith("https://")) {
      return "https";
    }
    if (normalized.startsWith("jar:http://")) {
      return "jar:http";
    }
    if (normalized.startsWith("jar:https://")) {
      return "jar:https";
    }
    if (normalized.startsWith("jar:file:/proc/self/fd/")) {
      return "jar:file:proc-fd";
    }
    return "";
  }

  private static UrlParts urlParts(Object value) {
    if (value == null) {
      return null;
    }
    if (value instanceof java.net.URI) {
      java.net.URI uri = (java.net.URI) value;
      String protocol = lower(uri.getScheme());
      String host = normalizeHost(uri.getHost());
      String rawPath = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
      int port = uri.getPort() < 0 ? ("https".equals(protocol) ? 443 : 80) : uri.getPort();
      String query = uri.getRawQuery();
      return new UrlParts(protocol, host, rawPath, HttpTransportObservation.address(uri),
          protocol + "://" + NetworkHost.destinationKey(host) + ":" + port + rawPath + (query == null ? "" : "?" + query));
    }
    if (value instanceof URL) {
      URL url = (URL) value;
      return new UrlParts(
          lower(url.getProtocol()),
          normalizeHost(url.getHost()),
          url.getPath() == null || url.getPath().length() == 0 ? "/" : url.getPath(),
          HttpTransportObservation.isHttp(url) ? HttpTransportObservation.address(url) : String.valueOf(url),
          urlComparisonKey(url));
    }
    try {
      URL url = new URL(String.valueOf(value));
      return new UrlParts(
          lower(url.getProtocol()),
          normalizeHost(url.getHost()),
          url.getPath() == null || url.getPath().length() == 0 ? "/" : url.getPath(),
          HttpTransportObservation.isHttp(url) ? HttpTransportObservation.address(url) : String.valueOf(url),
          urlComparisonKey(url));
    } catch (Exception ignored) {
      return null;
    }
  }

  private static void captureRequestControlledUrls(Map<?, ?> parameters) {
    List<String> values = requestControlledUrls(parameters);
    if (values.isEmpty()) {
      CURRENT_REQUEST_URLS.remove();
    } else {
      CURRENT_REQUEST_URLS.set(values);
    }
  }

  private static List<String> requestControlledUrls(Map<?, ?> parameters) {
    List<String> urls = new ArrayList<String>();
    if (parameters == null) {
      return urls;
    }
    for (Map.Entry<?, ?> entry : parameters.entrySet()) {
      collectRequestControlledUrl(urls, String.valueOf(entry.getKey()), entry.getValue());
      if (urls.size() >= 16) {
        break;
      }
    }
    return urls;
  }

  private static void collectRequestControlledUrl(List<String> urls, String name, Object value) {
    if (!isUrlParameterName(name) || value == null || urls.size() >= 16) {
      return;
    }
    Class<?> type = value.getClass();
    if (type.isArray()) {
      int length = Array.getLength(value);
      for (int i = 0; i < length && urls.size() < 16; i++) {
        addRequestControlledUrl(urls, Array.get(value, i));
      }
      return;
    }
    if (value instanceof Iterable<?>) {
      for (Object element : (Iterable<?>) value) {
        addRequestControlledUrl(urls, element);
        if (urls.size() >= 16) {
          return;
        }
      }
      return;
    }
    addRequestControlledUrl(urls, value);
  }

  private static boolean isUrlParameterName(String name) {
    String lower = lower(name == null ? "" : name);
    return lower.indexOf("url") >= 0
        || lower.indexOf("uri") >= 0
        || lower.indexOf("href") >= 0
        || lower.indexOf("endpoint") >= 0
        || lower.indexOf("target") >= 0
        || lower.indexOf("callback") >= 0
        || lower.indexOf("webhook") >= 0 || lower.equals("path") || lower.equals("route");
  }

  private static void addRequestControlledUrl(List<String> urls, Object value) {
    if (value instanceof String) {
      String path = (String) value;
      if (path.startsWith("/") && !path.startsWith("//") && LOOPBACK_ADMIN_PATH.matcher(path).find()) {
        if (!urls.contains(path)) urls.add(path);
        return;
      }
    }
    String key = urlComparisonKey(value);
    if (key.length() > 0 && !urls.contains(key)) {
      urls.add(key);
    }
  }

  private static String requestControlledUrlMatch(String key, List<String> urls) {
    if (key == null || key.length() == 0) {
      return "";
    }
    if (urls == null || urls.isEmpty()) {
      return "";
    }
    return urls.contains(key) ? key : "";
  }

  private static String urlComparisonKey(Object value) {
    if (value == null) {
      return "";
    }
    try {
      URL url = value instanceof URL ? (URL) value : new URL(String.valueOf(value).trim());
      String protocol = lower(url.getProtocol());
      if (!"http".equals(protocol) && !"https".equals(protocol)) {
        return "";
      }
      String host = NetworkHost.destinationKey(url.getHost());
      if (host.length() == 0) {
        return "";
      }
      int port = url.getPort();
      if (port < 0) {
        port = "https".equals(protocol) ? 443 : 80;
      }
      String path = url.getPath() == null || url.getPath().length() == 0 ? "/" : url.getPath();
      String query = url.getQuery();
      return protocol + "://" + host + ":" + port + path + (query == null ? "" : "?" + query);
    } catch (Exception ignored) {
      return "";
    }
  }

  private static String normalizeHost(String host) {
    return NetworkHost.normalize(host);
  }

  private static String lower(String value) {
    return value == null ? "" : value.toLowerCase(Locale.ROOT);
  }

  private static boolean isLoopbackHost(String host) {
    return NetworkHost.isLoopback(host);
  }

  private static int fileReadConfidence(String path) {
    String lower = path.toLowerCase(Locale.ROOT);
    if (lower.endsWith("/etc/shadow") || lower.endsWith("/proc/self/environ")) {
      return 95;
    }
    if (lower.endsWith("/id_rsa") || lower.endsWith("/authorized_keys")) {
      return 94;
    }
    return 90;
  }

  private static boolean isTomcatWarExpansionStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i < stack.length; i++) {
      if ("org.apache.catalina.startup.ExpandWar".equals(stack[i].getClassName())) {
        return true;
      }
    }
    return false;
  }

  private static boolean isTomcatJspCompilationStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i < stack.length; i++) {
      String className = stack[i].getClassName();
      if ("org.apache.jasper.compiler.Compiler".equals(className)
          || "org.apache.jasper.compiler.JDTCompiler".equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static boolean nioOptionsContainWrite(Object options) {
    if (options == null) {
      return false;
    }
    if (options instanceof Iterable<?>) {
      for (Object option : (Iterable<?>) options) {
        if (isNioWriteOption(option)) {
          return true;
        }
      }
      return false;
    }
    Class<?> type = options.getClass();
    if (type.isArray()) {
      int length = Array.getLength(options);
      for (int i = 0; i < length; i++) {
        if (isNioWriteOption(Array.get(options, i))) {
          return true;
        }
      }
      return false;
    }
    return isNioWriteOption(options);
  }

  private static boolean isNioWriteOption(Object option) {
    return option == java.nio.file.StandardOpenOption.WRITE || option == java.nio.file.StandardOpenOption.APPEND
        || (option instanceof String && ("WRITE".equalsIgnoreCase((String) option)
            || "APPEND".equalsIgnoreCase((String) option)));
  }

  private static void emitFileFinding(
      Finding finding, ThreadLocal<String> lastLoggedPath, String hook) {
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    if ("attachment_file_open".equals(finding.decisionBasis)) {
      if (!"block".equals(action) && io.ohmyrasp.agent.xml.AttachmentFileRead.repeated()) return;
    } else if ((lastLoggedPath == LAST_LOGGED_FILE_READ || lastLoggedPath == null)
        && !"block".equals(action) && HostReadPath.repeated(finding.detailValue, finding.algorithm)) {
      return;
    } else if (lastLoggedPath != null) {
      if (!"block".equals(action) && finding.detailValue.equals(lastLoggedPath.get())) return;
      lastLoggedPath.set(finding.detailValue);
    }
    appendEvent(finding, hook, action);
    if ("block".equals(action)) {
      throw new Java17RaspBlockException("OhMyRASP Java 17 blocked suspicious file access");
    }
  }

  private static String pathValue(Object path) {
    if (path == null) {
      return "";
    }
    if (path instanceof File) {
      return ((File) path).getPath();
    }
    return String.valueOf(path);
  }

  private static final class UrlParts {
    final String protocol;
    final String host;
    final String path;
    final String fullUrl;
    final String comparisonKey;

    UrlParts(String protocol, String host, String path, String fullUrl, String comparisonKey) {
      this.protocol = protocol;
      this.host = host;
      this.path = path;
      this.fullUrl = fullUrl;
      this.comparisonKey = comparisonKey;
    }
  }

  private static final class RequestSnapshot {
    String lastUpload;
    final List<String> sqlInputs;
    final List<String> parameterValues;

    RequestSnapshot(Map<?, ?> parameters) {
      sqlInputs = new ArrayList<String>();
      if (parameters != null) {
        // Snapshot values at request entry. Framework-owned parameter arrays can change later.
        parameterValues = new ArrayList<String>();
        for (Object value : parameters.values()) {
          if (value instanceof String[]) {
            java.util.Collections.addAll(parameterValues, (String[]) value);
          } else {
            List<String> items = new ArrayList<String>();
            collectParameterValues(items, value);
            parameterValues.addAll(items);
          }
        }
        for (String item : parameterValues) {
          if (SqlStatement.mayControlStructure(item)) {
            sqlInputs.add(item);
          }
        }
      } else {
        parameterValues = null;
      }
    }
  }

  private static final class IncludeAttributes {
    final String namespace;
    final String requestUri;
    final String pathInfo;
    final String servletPath;
    final boolean present;

    IncludeAttributes(String namespace, String requestUri, String pathInfo, String servletPath) {
      this.namespace = namespace;
      this.requestUri = requestUri;
      this.pathInfo = pathInfo;
      this.servletPath = servletPath;
      this.present = hasText(requestUri) || hasText(pathInfo) || hasText(servletPath);
    }
  }



  private static String normalizePath(String path) {
    if (path == null) {
      return "";
    }
    String normalized = path.trim().replace('\\', '/');
    while (normalized.indexOf("//") >= 0) {
      normalized = normalized.replace("//", "/");
    }
    return normalized;
  }

  private static boolean isShellCommandFlag(String value) {
    if (value == null) {
      return false;
    }
    String normalized = value.toLowerCase(Locale.ROOT);
    return "-c".equals(normalized) || "/c".equals(normalized);
  }

  private static String[] toArray(List<String> command) {
    if (command == null) {
      return new String[0];
    }
    List<String> values = new ArrayList<String>(command.size());
    for (String item : command) {
      values.add(item);
    }
    return values.toArray(new String[values.size()]);
  }

  private static String join(String[] command) {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < command.length; i++) {
      if (command[i] == null || command[i].trim().length() == 0) {
        continue;
      }
      if (builder.length() > 0) {
        builder.append(' ');
      }
      builder.append(command[i].trim());
    }
    return builder.toString();
  }

  private static boolean shouldBlock() {
    String property = System.getProperty("ohmyrasp.java17.block");
    if (property == null || property.trim().length() == 0) {
      property = System.getenv("OHMYRASP_JAVA17_BLOCK");
    }
    boolean legacy =
        "true".equalsIgnoreCase(property)
            || "1".equals(property)
            || "yes".equalsIgnoreCase(property);
    return RaspRuntime.blockingAllowed(legacy);
  }

  private static void appendEvent(Finding finding, String hook, String action) {
    appendEvent(finding, hook, action, null);
  }

  private static void appendEvent(Finding finding, String hook, String action, String resolvedAddress) {
    appendEvent(finding, hook, action, resolvedAddress, -1);
  }

  private static void appendEvent(Finding finding, String hook, String action, String resolvedAddress, int argc) {
    if (RaspRuntime.detectionOff()) {
      return;
    }
    String logPath = RaspRuntime.resolveLogPath();
    String event =
        "{"
            + "\"event\":\"ohmyrasp-detection\","
            + "\"timestamp\":"
            + System.currentTimeMillis()
            + ","
            + "\"hook\":\""
            + json(hook)
            + "\","
            + "\"algorithm\":\""
            + json(finding.algorithm)
            + "\","
            + "\"action\":\""
            + json(action)
            + "\","
            + "\"confidence\":"
            + finding.confidence
            + ","
            + "\"message\":\""
            + json(finding.message)
            + "\","
            + "\"details\":{\""
            + json(finding.detailKey)
            + "\":\""
            + json(finding.detailValue)
            + "\""
            + (argc < 0 ? "" : ",\"process_operation\":\"ProcessImpl.start\",\"argument_count\":\"" + argc + "\"")
            + (resolvedAddress == null ? "" : ",\"resolved_address\":\"" + json(resolvedAddress) + "\"")
            + (finding.policyDigest != null && DISPATCH.deliveredPart(MultipartFilename.receiver())
                ? ",\"multipart_source\":\"active_request_lookup\"" : "")
            + (finding.policyDigest == null ? "" : ",\"archive_policy_sha256\":\"" + finding.policyDigest + "\"")
            + (finding.decisionBasis == null ? "" : ",\"decision_basis\":\"" + json(finding.decisionBasis) + "\"")
            + "}"
            + "}";
    RaspRuntime.writeEvent(logPath, event);
  }

  private static boolean hasText(String value) {
    return value != null && value.trim().length() > 0;
  }

  private static String json(String value) {
    StringBuilder builder = new StringBuilder(value.length() + 16);
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"':
          builder.append("\\\"");
          break;
        case '\\':
          builder.append("\\\\");
          break;
        case '\b':
          builder.append("\\b");
          break;
        case '\f':
          builder.append("\\f");
          break;
        case '\n':
          builder.append("\\n");
          break;
        case '\r':
          builder.append("\\r");
          break;
        case '\t':
          builder.append("\\t");
          break;
        default:
          if (ch < 0x20) {
            builder.append(String.format("\\u%04x", Integer.valueOf(ch)));
          } else {
            builder.append(ch);
          }
      }
    }
    return builder.toString();
  }

  private static final class TypedPayloadMatch {
    final String className;
    final String trigger;

    TypedPayloadMatch(String className, String trigger) {
      this.className = className;
      this.trigger = trigger;
    }
  }

  private static final class Finding {
    final String algorithm;
    final int confidence;
    final String message;
    final String detailKey;
    final String detailValue;
    final String decisionBasis;
    final String policyDigest;

    Finding(String algorithm, int confidence, String message, String detailKey, String detailValue) {
      this(algorithm, confidence, message, detailKey, detailValue, null);
    }

    Finding(String algorithm, int confidence, String message, String detailKey, String detailValue,
        String decisionBasis) {
      this(algorithm, confidence, message, detailKey, detailValue, decisionBasis, null);
    }

    Finding(String algorithm, int confidence, String message, String detailKey, String detailValue,
        String decisionBasis, String policyDigest) {
      this.policyDigest = policyDigest;
      this.decisionBasis = decisionBasis;
      this.algorithm = algorithm;
      this.confidence = confidence;
      this.message = message;
      this.detailKey = detailKey;
      this.detailValue = detailValue;
    }
  }
}
