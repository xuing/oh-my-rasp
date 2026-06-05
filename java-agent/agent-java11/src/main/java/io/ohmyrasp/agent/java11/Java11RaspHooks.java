package io.ohmyrasp.agent.java11;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectStreamClass;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Java11RaspHooks {
  private static final Pattern SHELL =
      Pattern.compile(
          "(?i)(?:^|[/\\\\])(?:sh|bash|dash|ash|zsh|ksh|cmd(?:\\.exe)?|powershell(?:\\.exe)?|pwsh(?:\\.exe)?)$");
  private static final Pattern SHELL_META =
      Pattern.compile("[;&|`$<>]|\\$\\{?IFS\\}?");
  private static final Pattern EXPLOIT_COMMAND =
      Pattern.compile(
          "(?is)(?:cat\\s+/etc/(?:passwd|shadow)|/proc/self/environ|bash\\s+-i\\b|/dev/tcp/|nc\\b.{0,60}\\s-e\\s+/bin/(?:ba)?sh|curl\\b.{0,160}\\|\\s*(?:sh|bash)|wget\\b.{0,160}\\|\\s*(?:sh|bash)|\\{echo,.{10,500}\\}\\|\\{base64,-d\\})");
  private static final byte[] SHIRO_DEFAULT_REMEMBERME_KEY =
      decodeBase64OrEmpty("kPH+bIxk5D2deZiIxcaaaA==");
  private static final int MAX_DEFAULT_CRYPTO_COOKIE_LENGTH = 12000;
  private static final Pattern SENSITIVE_DIRECT_READ =
      Pattern.compile(
          "(?is)(?:^|\\s)(?:cat|more|less|head|tail)\\s+/(?:etc/(?:passwd|shadow)|proc/self/environ)(?:\\s|$)");
  private static final Pattern REMOTE_JNDI_LOOKUP =
      Pattern.compile("(?is)^\\s*(ldap|ldaps|rmi|iiop|corbaname|corbaloc)://[^\\s\\u0000]{1,2048}");
  private static final Pattern JAAS_REMOTE_PROVIDER =
      Pattern.compile(
          "(?is)(?:^|[\\s,{])(?:user|group)\\.provider\\.url\\s*[=:]\\s*[\"']?((?:ldap|ldaps|rmi|iiop|corbaname|corbaloc)://[^\"'\\s,;}]{1,2048})");
  private static final Pattern DESERIALIZATION_GADGET_CLASS =
      Pattern.compile(
          "(?i)^(?:"
              + "com\\.sun\\.org\\.apache\\.xalan\\.internal\\.xsltc\\.trax\\.TemplatesImpl|"
              + "org\\.apache\\.xalan\\.xsltc\\.trax\\.TemplatesImpl|"
              + "com\\.sun\\.rowset\\.JdbcRowSetImpl|"
              + "java\\.lang\\.ProcessBuilder|"
              + "javax\\.script\\.ScriptEngineManager|"
              + "bsh\\.(?:XThis(?:\\$Handler)?|This|NameSpace|Interpreter|BSH[A-Za-z0-9_$]+)|"
              + "org\\.apache\\.commons\\.collections(?:4)?\\.functors\\.(?:Invoker|Instantiate|Chained|Constant)Transformer|"
              + "org\\.codehaus\\.groovy\\.runtime\\.(?:ConvertedClosure|MethodClosure)|"
              + "org\\.springframework\\.beans\\.factory\\.config\\.(?:PropertyPathFactoryBean|MethodInvokingFactoryBean)"
              + ")$");
  private static final Pattern SENSITIVE_FILE_READ =
      Pattern.compile(
          "(?i)(?:^|/)(?:etc/(?:passwd|shadow|issue|hosts)|proc/self/(?:environ|cmdline)|root/\\.ssh/(?:id_rsa|authorized_keys)|home/[^/]+/\\.ssh/id_rsa|windows/system32/drivers/etc/hosts)$");
  private static final Pattern SCRIPT_FILE_WRITE =
      Pattern.compile(
          "(?i).+\\.(?:jsp|jspx|jspf|war|class|jar|php|asp|aspx|ashx|cer|asa|sh|bash|cmd|bat|ps1)$");
  private static final Pattern GENERATED_PLOT_SCRIPT_FILE =
      Pattern.compile("(?i).+\\.(?:gnuplot|gp|plt|plot)$");
  private static final Pattern GENERATED_PLOT_COMMAND =
      Pattern.compile(
          "(?is)(?:\\b(?:yrange|y2range|xrange|x2range|key)\\b[^\\r\\n]{0,300}\\b(?:system|shell)\\s*\\(|\\bkey\\b[^\\r\\n]{0,300};\\s*system\\b|;\\s*system\\s*[\"'])");
  private static final Pattern SCRIPT_FILE_TOKEN =
      Pattern.compile(
          "(?is)(?:[a-z]:)?(?:[./][^\\s\"'<>;,)]*)?[^\\s\"'<>;,)]*\\.(?:jspx?|jspf|war|class|jar|php|asp|aspx|ashx|cer|asa|sh|bash|cmd|bat|ps1)\\.?");
  private static final Pattern WEBROOT_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:webapps|ROOT|www|wwwroot|htdocs|html|public|static|uploads?)(?:/|$)");
  private static final Pattern LOOPBACK_ADMIN_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:actuator|jolokia|manager|host-manager|admin|console|webtools|solr/admin|_cat|debug|server-status)(?:[/?#;]|$)");
  private static final Pattern SENSITIVE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:auth|admin|user|users|role|roles|permission|permissions|ops|manage|management|console)(?:/|$)");
  private static final Pattern PROTECTED_WEB_RESOURCE_PATH =
      Pattern.compile("(?i)(?:^|/)(?:WEB-INF|META-INF)(?:/|$)");
  private static final Pattern SCRIPT_LITERAL_EXECUTE =
      Pattern.compile("(?is)[\"'][^\"'\\r\\n]{1,200}[\"']\\s*\\.\\s*execute\\s*\\(");
  private static final Pattern WINDOWS_ABSOLUTE_PATH = Pattern.compile("(?i)^[a-z]:/.*");
  private static final Pattern REMOTE_JOB_ARTIFACT =
      Pattern.compile(
          "(?is)\"(?:appResource|spark\\.jars)\"\\s*:\\s*\"((?:https?|ftp)://[^\"\\s]{1,2048}\\.(?:jar|zip|py))\"");
  private static final Pattern REMOTE_JOB_MAIN_CLASS =
      Pattern.compile("(?is)\"mainClass\"\\s*:\\s*\"[^\"\\r\\n]{1,512}\"");
  private static final ThreadLocal<String> LAST_LOGGED_REQUEST = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_REMOTE_JOB = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_COMMAND = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JNDI = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_DESERIALIZATION = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_FILE_READ = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_FILE_WRITE = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_PLOT_SCRIPT = new ThreadLocal<String>();
  private static final ThreadLocal<String> CURRENT_PLOT_SCRIPT_WRITE = new ThreadLocal<String>();
  private static final ThreadLocal<String> CURRENT_PLOT_SCRIPT_CONTENT = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_URL = new ThreadLocal<String>();
  private static final ThreadLocal<List<String>> CURRENT_REQUEST_URLS =
      new ThreadLocal<List<String>>();
  private static final ThreadLocal<String> ARCHIVE_ENTRY = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_ARCHIVE = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JDBC = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_CLASSLOADER = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_SCRIPT = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JAVA_COMPILE = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JAAS = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_JMX = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_XML_DECODER = new ThreadLocal<String>();
  private static final ThreadLocal<String> LAST_LOGGED_XXE = new ThreadLocal<String>();

  private Java11RaspHooks() {}

  public static void beforeHttpRequest(Object request) {
    captureRequestControlledUrls(request);
    Finding finding = classifyHttpRequest(request);
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
      CURRENT_REQUEST_URLS.remove();
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious request path");
    }
  }

  public static void afterHttpRequest() {
    CURRENT_REQUEST_URLS.remove();
  }

  public static void beforeSparkRestSubmit(String descriptor) {
    Finding finding = classifyRemoteJobSubmission("Spark REST", descriptor);
    emitRemoteJobFinding(finding, "SparkRest.handleSubmit");
  }

  public static void beforeYarnApplicationSubmit(Object submission) {
    Finding finding = classifyYarnApplicationSubmission(submission);
    emitRemoteJobFinding(finding, "RMWebServices.submitApplication");
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
    inspectCommand(new String[] {command}, "Runtime.exec(String)");
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious JNDI lookup");
    }
  }

  public static void beforeObjectStreamClassResolve(Object descriptor) {
    if (!(descriptor instanceof ObjectStreamClass)) {
      return;
    }
    Finding finding = classifyDeserializationClass(((ObjectStreamClass) descriptor).getName());
    emitDeserializationFinding(finding);
  }

  public static void beforeObjectStreamProxyResolve(String[] interfaceNames) {
    if (interfaceNames == null) {
      return;
    }
    for (String interfaceName : interfaceNames) {
      Finding finding = classifyDeserializationClass(interfaceName);
      if (finding != null) {
        emitDeserializationFinding(finding);
        return;
      }
    }
  }

  public static void beforeFileRead(Object path) {
    Finding finding = classifyFileRead(pathValue(path));
    emitFileFinding(finding, LAST_LOGGED_FILE_READ, "FileInputStream.open");
  }

  public static void beforeFileWrite(Object path) {
    String normalizedPath = normalizePath(pathValue(path));
    trackGeneratedPlotScriptWrite(normalizedPath);
    Finding archiveFinding = classifyArchiveWrite(normalizedPath);
    if (archiveFinding != null) {
      ARCHIVE_ENTRY.remove();
    }
    try {
      emitFileFinding(archiveFinding, LAST_LOGGED_ARCHIVE, "ArchiveEntry.write");
    } finally {
      if (ARCHIVE_ENTRY.get() != null) {
        ARCHIVE_ENTRY.remove();
      }
    }
    if (isTomcatWarExpansionStack() || isTomcatJspCompilationStack()) {
      return;
    }
    Finding finding = classifyFileWrite(normalizedPath);
    emitFileFinding(finding, LAST_LOGGED_FILE_WRITE, "FileOutputStream.open");
  }

  public static void beforeFileContentWrite(byte[] bytes, int offset, int length) {
    String path = CURRENT_PLOT_SCRIPT_WRITE.get();
    if (path == null || path.length() == 0) {
      return;
    }
    String content = appendPlotScriptContent(bytesToString(bytes, offset, length));
    Finding finding = classifyGeneratedPlotScriptWrite(path, content);
    emitFileFinding(finding, LAST_LOGGED_PLOT_SCRIPT, "FileOutputStream.write");
  }

  public static void beforeRandomAccessFileOpen(Object path, String mode) {
    if (mode != null && mode.toLowerCase(Locale.ROOT).indexOf('w') >= 0) {
      beforeFileWrite(path);
    } else {
      beforeFileRead(path);
    }
  }

  public static void beforeNioFileRead(Object path) {
    beforeFileRead(path);
  }

  public static void beforeNioFileWrite(Object path) {
    beforeFileWrite(path);
  }

  public static void beforeNioByteChannelOpen(Object path, Object options) {
    if (nioOptionsContainWrite(options)) {
      beforeFileWrite(path);
    } else {
      beforeFileRead(path);
    }
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious URL access");
    }
  }

  public static void afterArchiveEntryName(String name) {
    String normalized = normalizePath(name);
    if (isDangerousArchiveEntry(normalized)) {
      ARCHIVE_ENTRY.set(normalized);
    } else {
      ARCHIVE_ENTRY.remove();
    }
  }

  public static void beforeJdbcConnection(String url) {
    inspectJdbcConnection(url, "DriverManager.getConnection");
  }

  public static void beforeH2JdbcConnection(String url) {
    inspectJdbcConnection(url, "org.h2.jdbc.JdbcConnection.<init>");
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious JDBC URL");
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious script evaluation");
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious JAAS configuration");
    }
  }

  public static void beforeJmxMBeanInvoke(Object mbeanName, String operationName, Object arguments) {
    Finding finding = classifyJmxMBeanInvoke(mbeanName, operationName, arguments);
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious JMX MBean invocation");
    }
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
    } catch (Java11RaspBlockException blocked) {
      throw blocked;
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA11] JavaBeans hook failed: " + throwable);
      }
    }
  }

  public static void rethrowIfJava11RaspBlock(Object throwable) {
    Throwable current = throwable instanceof Throwable ? (Throwable) throwable : null;
    int depth = 0;
    while (current != null && depth < 16) {
      if (current instanceof Java11RaspBlockException) {
        throw (Java11RaspBlockException) current;
      }
      current = current.getCause();
      depth++;
    }
  }

  public static void beforeXmlEntity(String name, Object source) {
    String systemId = xmlEntitySystemId(source);
    Finding finding = classifyXxeEntity(name, systemId);
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious XML external entity");
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious command execution");
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
    if (isBenignTtyProbeCommand(command, joined)) {
      return null;
    }
    if (isBenignLocalBrowserLaunchCommand(command)) {
      return null;
    }
    if (isBenignSystemInventoryCommand(command)) {
      return null;
    }
    if (isTikaExternalParserVersionCheckStack() && isTikaExternalParserAvailabilityProbe(command)) {
      return null;
    }
    if (isOfficeProcessCleanupStack() && isOfficeProcessCleanupCommand(command, joined)) {
      return null;
    }
    if (isSolrRunExecutableListenerStack()) {
      return new Finding(
          "java11_command_execution_exploit_primitive",
          93,
          "Solr RunExecutableListener reached a Java 11 process sink",
          "command",
          joined);
    }
    if (isExpressionLanguageRuntimeStack()) {
      return new Finding(
          "java11_command_execution_exploit_primitive",
          93,
          "Dynamic expression evaluation reached a Java 11 process sink",
          "command",
          joined);
    }
    if (isDatabaseJavaRoutineCommandStack()) {
      return new Finding(
          "java11_command_execution_exploit_primitive",
          93,
          "Database Java routine reached a Java 11 process sink",
          "command",
          joined);
    }
    if (isSpringBeanInitializationRuntimeStack()) {
      return new Finding(
          "java11_command_execution_exploit_primitive",
          92,
          "Spring bean initialization reached a Java 11 process sink",
          "command",
          joined);
    }
    if (isXStreamDeserializationCommandStack()) {
      return new Finding(
          "java11_command_execution_exploit_primitive",
          94,
          "XML polymorphic deserialization reached a Java 11 process sink",
          "command",
          joined);
    }
    String executable = command[0] == null ? "" : command[0].trim();
    boolean shell = SHELL.matcher(executable).matches();
    boolean exploit = EXPLOIT_COMMAND.matcher(joined).find();
    boolean sensitiveDirectRead = SENSITIVE_DIRECT_READ.matcher(joined).find();
    String firstArgument = command.length > 1 ? command[1] : "";
    if (shell && isSchedulerScriptExecutionStack() && isScriptFilePath(firstArgument)) {
      return new Finding(
          "java11_command_execution_shell_meta",
          90,
          "Scheduler script job reached a Java 11 shell script process sink",
          "command",
          joined);
    }
    if (exploit || sensitiveDirectRead) {
      return new Finding(
          "java11_command_execution_exploit_primitive",
          95,
          "Suspicious command execution reached a Java 11 process sink",
          "command",
          joined);
    }
    if (shell && command.length >= 3 && isShellCommandFlag(command[1])) {
      String script = command[2] == null ? "" : command[2];
      if (SHELL_META.matcher(script).find()) {
        return new Finding(
            "java11_command_execution_shell_meta",
            85,
            "Suspicious shell metacharacter command reached a Java 11 process sink",
            "command",
            joined);
      }
    }
    return null;
  }

  private static boolean isSolrRunExecutableListenerStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement element : stack) {
      if ("org.apache.solr.core.RunExecutableListener".equals(element.getClassName())) {
        return true;
      }
    }
    return false;
  }

  private static boolean isExpressionLanguageRuntimeStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if (className.startsWith("org.mvel2.")
          || className.startsWith("org.elasticsearch.common.mvel2.")
          || className.startsWith("org.elasticsearch.script.mvel.")
          || className.startsWith("ognl.")
          || className.startsWith("groovy.")
          || className.startsWith("org.codehaus.groovy.")
          || className.startsWith("org.apache.commons.jexl")
          || className.startsWith("org.springframework.expression.")
          || className.startsWith("org.springframework.webflow.expression.")) {
        return true;
      }
    }
    return false;
  }

  private static boolean isDatabaseJavaRoutineCommandStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
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

  private static boolean isSpringBeanInitializationRuntimeStack() {
    boolean beanInitialization = false;
    boolean applicationContextRefresh = false;
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
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

  private static boolean isXStreamDeserializationCommandStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
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

  private static boolean isSchedulerScriptExecutionStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if ("com.xxl.job.core.handler.impl.ScriptJobHandler".equals(className)
          || "com.xxl.job.core.util.ScriptUtil".equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isOfficeProcessCleanupStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement element : stack) {
      if ("cn.keking.service.OfficePluginManager".equals(element.getClassName())) {
        return true;
      }
    }
    return false;
  }

  private static boolean isTikaExternalParserVersionCheckStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
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

  private static boolean isBenignTtyProbeCommand(String[] command, String joined) {
    String script = joined;
    if (command != null && command.length >= 3 && isShellCommandFlag(command[1])) {
      script = command[2] == null ? "" : command[2];
    }
    String compact = script.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();
    if (!compact.startsWith("stty ") || !compact.endsWith(" < /dev/tty")) {
      return false;
    }
    String sttyArguments = compact.substring(0, compact.length() - " < /dev/tty".length());
    return sttyArguments.indexOf(';') < 0
        && sttyArguments.indexOf('|') < 0
        && sttyArguments.indexOf('&') < 0
        && sttyArguments.indexOf('`') < 0
        && sttyArguments.indexOf('$') < 0
        && sttyArguments.indexOf('>') < 0
        && sttyArguments.indexOf('<') < 0;
  }

  private static boolean isBenignSystemInventoryCommand(String[] command) {
    if (command == null) {
      return false;
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
    return command.length == 2 && "lscpu".equals(fileName) && "-p=cpu,node".equals(command[1]);
  }

  private static boolean isBenignGetconfVariable(String value) {
    return "CLK_TCK".equals(value) || "PAGE_SIZE".equals(value) || "PAGESIZE".equals(value);
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
        "java11_jndi_remote_lookup",
        confidence,
        "Remote JNDI lookup reached a Java 11 naming sink",
        "lookup",
        lookup);
  }

  private static Finding classifyDeserializationClass(String className) {
    if (className == null) {
      return null;
    }
    String normalized = className.trim();
    if (normalized.length() == 0) {
      return null;
    }
    if (!DESERIALIZATION_GADGET_CLASS.matcher(normalized).matches()) {
      return null;
    }
    return new Finding(
        "java11_deserialization_gadget_class",
        deserializationConfidence(normalized),
        "High-risk gadget class reached a Java 11 deserialization sink",
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
        || lower.startsWith("bsh.")
        || lower.contains("convertedclosure")) {
      return 92;
    }
    return 88;
  }

  private static void emitDeserializationFinding(Finding finding) {
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = LAST_LOGGED_DESERIALIZATION.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    LAST_LOGGED_DESERIALIZATION.set(finding.detailValue);
    appendEvent(finding, "ObjectInputStream.resolveClass", action);
    if ("block".equals(action)) {
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious deserialization class");
    }
  }

  private static Finding classifyFileRead(String path) {
    String normalized = normalizePath(path);
    if (normalized.length() == 0 || !SENSITIVE_FILE_READ.matcher(normalized).find()) {
      return null;
    }
    if (isNettyHostsFileRead(normalized)) {
      return null;
    }
    return new Finding(
        "java11_file_sensitive_read",
        fileReadConfidence(normalized),
        "Sensitive file read reached a Java 11 file sink",
        "path",
        normalized);
  }

  private static Finding classifyFileWrite(String path) {
    String normalized = normalizePath(path);
    if (normalized.length() == 0 || !SCRIPT_FILE_WRITE.matcher(normalized).matches()) {
      return null;
    }
    if (isWebInfDeploymentArtifact(normalized)) {
      return null;
    }
    if (!WEBROOT_PATH.matcher(normalized).find() && normalized.indexOf("../") < 0) {
      return null;
    }
    return new Finding(
        "java11_file_script_write",
        90,
        "Script or executable file write reached a Java 11 file sink",
        "path",
        normalized);
  }

  private static Finding classifyGeneratedPlotScriptWrite(String path, String content) {
    String normalized = normalizePath(path);
    if (!isGeneratedPlotScriptPath(normalized) || content == null || content.length() == 0) {
      return null;
    }
    if (!GENERATED_PLOT_COMMAND.matcher(content).find()) {
      return null;
    }
    return new Finding(
        "java11_file_generated_plot_script_command",
        91,
        "Generated plot script carries a command execution directive",
        "path",
        normalized);
  }

  private static void trackGeneratedPlotScriptWrite(String normalizedPath) {
    if (isGeneratedPlotScriptPath(normalizedPath)) {
      String previous = CURRENT_PLOT_SCRIPT_WRITE.get();
      CURRENT_PLOT_SCRIPT_WRITE.set(normalizedPath);
      if (!normalizedPath.equals(previous)) {
        CURRENT_PLOT_SCRIPT_CONTENT.remove();
      }
      return;
    }
    if (normalizedPath != null && normalizedPath.length() > 0) {
      CURRENT_PLOT_SCRIPT_WRITE.remove();
      CURRENT_PLOT_SCRIPT_CONTENT.remove();
    }
  }

  private static boolean isGeneratedPlotScriptPath(String path) {
    return path != null && GENERATED_PLOT_SCRIPT_FILE.matcher(normalizePath(path)).matches();
  }

  private static String appendPlotScriptContent(String chunk) {
    if (chunk == null || chunk.length() == 0) {
      String current = CURRENT_PLOT_SCRIPT_CONTENT.get();
      return current == null ? "" : current;
    }
    String current = CURRENT_PLOT_SCRIPT_CONTENT.get();
    String combined = current == null ? chunk : current + chunk;
    if (combined.length() > 8192) {
      combined = combined.substring(combined.length() - 8192);
    }
    CURRENT_PLOT_SCRIPT_CONTENT.set(combined);
    return combined;
  }

  private static Finding classifyArchiveWrite(String path) {
    String entry = ARCHIVE_ENTRY.get();
    if (entry == null || entry.length() == 0 || !isDangerousArchiveEntry(entry)) {
      return null;
    }
    if (path == null || path.length() == 0) {
      return null;
    }
    return new Finding(
        "java11_archive_entry_traversal_write",
        92,
        "Archive entry traversal reached a Java 11 file write sink",
        "entry",
        entry + " -> " + path);
  }

  private static boolean isDangerousArchiveEntry(String entry) {
    if (entry == null) {
      return false;
    }
    String normalized = normalizePath(entry);
    return normalized.startsWith("/")
        || normalized.startsWith("../")
        || normalized.indexOf("/../") >= 0
        || normalized.endsWith("/..")
        || WINDOWS_ABSOLUTE_PATH.matcher(normalized).matches();
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
          "java11_jdbc_h2_code_execution",
          h2JdbcConfidence(relaxed),
          "H2 JDBC URL code execution primitive reached a Java 11 JDBC sink",
          "jdbc_url",
          normalized);
    }
    if (relaxed.startsWith("jdbc:derby:") && isDangerousDerbyJdbcUrl(relaxed)) {
      return new Finding(
          "java11_jdbc_derby_code_loading",
          90,
          "Derby JDBC URL Java code loading primitive reached a Java 11 JDBC sink",
          "jdbc_url",
          normalized);
    }
    if (relaxed.startsWith("jdbc:mysql:") && isDangerousMysqlJdbcUrl(relaxed)) {
      return new Finding(
          "java11_jdbc_mysql_deserialization",
          92,
          "MySQL JDBC deserialization primitive reached a Java 11 JDBC sink",
          "jdbc_url",
          normalized);
    }
    return null;
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious remote job submission");
    }
  }

  private static Finding classifyRemoteJobSubmission(String mechanism, String descriptor) {
    String normalized = descriptor == null ? "" : descriptor.trim();
    if (normalized.length() == 0 || normalized.indexOf("CreateSubmissionRequest") < 0) {
      return null;
    }
    Matcher artifact = REMOTE_JOB_ARTIFACT.matcher(normalized);
    if (artifact.find() && REMOTE_JOB_MAIN_CLASS.matcher(normalized).find()) {
      String artifactUrl = artifact.group(1);
      return new Finding(
          "java11_request_remote_job_submission",
          92,
          "Spark REST request submits a remote executable artifact",
          "submission",
          mechanism
              + " "
              + artifactScheme(artifactUrl)
              + " "
              + artifactExtension(artifactUrl)
              + " descriptorHash="
              + Integer.toHexString(normalized.hashCode()));
    }
    return null;
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
        "java11_request_remote_job_submission",
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
        throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious remote classloader codebase");
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
        "java11_classloader_remote_codebase",
        confidence,
        "Remote classloader codebase reached a Java 11 class loading sink",
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
        "java11_script_engine_runtime_execution",
        scriptConfidence(runtimeExec, processBuilder, reflectiveRuntimeExec, nestedScriptEval),
        "Script engine evaluation reached a Java 11 runtime execution primitive",
        "script",
        normalized);
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
        "java11_java_compile_runtime_execution",
        runtimeExec || processBuilder ? 94 : 88,
        "Java source compilation reached a Java 11 runtime execution primitive",
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious Java compilation");
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
        "java11_jaas_jndi_remote_provider",
        remoteJaasConfidence(providerUrl),
        "JAAS JNDI login module reached a Java 11 remote provider configuration sink",
        "config",
        loginModule + " " + providerUrl);
  }

  private static Finding classifyJmxMBeanInvoke(
      Object mbeanName, String operationName, Object arguments) {
    String operation = operationName == null ? "" : operationName.trim();
    if (operation.length() == 0 || !isMutatingJmxOperation(operation)) {
      return null;
    }
    List<String> values = jmxArgumentTexts(arguments);
    for (String value : values) {
      if (looksLikeRemoteJmxConfig(value)) {
        return new Finding(
            "java11_jmx_remote_config_source",
            jmxRemoteConfigConfidence(value),
            "JMX MBean invocation reached a Java 11 remote configuration source sink",
            "invoke",
            abbreviate(String.valueOf(mbeanName) + " " + operation + " " + value, 1200));
      }
    }
    for (String value : values) {
      String target = jmxScriptWriteTarget(value);
      if (target.length() > 0) {
        return new Finding(
            "java11_jmx_script_file_write",
            90,
            "JMX MBean invocation reached a Java 11 server-side script write sink",
            "invoke",
            abbreviate(String.valueOf(mbeanName) + " " + operation + " " + target, 1200));
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
          "java11_xml_decoder_runtime_execution",
          95,
          "XMLDecoder object graph reached a Java 11 runtime execution primitive",
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
              "java11_xml_decoder_script_file_write",
              95,
              "XMLDecoder object graph reached a Java 11 server-side script writer",
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
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious XMLDecoder object graph");
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

  private static Finding classifyXxeEntity(String name, String systemId) {
    if ("[xml]".equals(name)) {
      return null;
    }
    String value = systemId == null ? "" : systemId.trim();
    if (value.length() == 0) {
      return null;
    }
    if ("[dtd]".equals(name) && isLocalRuntimeDtd(value)) {
      return null;
    }
    if (value.startsWith("\\\\") || value.startsWith("//")) {
      return new Finding(
          "java11_xxe_external_entity_protocol",
          96,
          "XML external entity reached a Java 11 parser with SMB/UNC source",
          "entity",
          String.valueOf(name) + " " + value);
    }
    String scheme = uriScheme(value);
    if (scheme.length() == 0 || !isXxeExternalScheme(scheme)) {
      return null;
    }
    return new Finding(
        "java11_xxe_external_entity_protocol",
        xxeConfidence(scheme),
        "XML external entity reached a Java 11 parser with protocol " + scheme,
        "entity",
        String.valueOf(name) + " " + abbreviate(value, 1200));
  }

  private static String xmlEntitySystemId(Object source) {
    if (source == null) {
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
    systemId = invoke(source, "getBaseSystemId");
    if (systemId != null) {
      return String.valueOf(systemId);
    }
    return String.valueOf(source);
  }

  private static Finding classifyHttpRequest(Object request) {
    if (request == null) {
      return null;
    }
    String uri = invokeString(request, "getRequestURI");
    String query = invokeString(request, "getQueryString");
    if (uri.length() == 0) {
      return null;
    }
    Finding cryptoCookie = classifyDefaultCryptoCookie(request);
    if (cryptoCookie != null) {
      return cryptoCookie;
    }
    String inspected = query.length() == 0 ? uri : uri + "?" + query;
    String confusingPath = confusingRequestPath(inspected);
    if (confusingPath.length() == 0) {
      return null;
    }
    return new Finding(
        "java11_request_path_confusion",
        90,
        "HTTP request URI contains Java 11 path normalization confusion",
        "uri",
        abbreviate(uri + " -> " + confusingPath, 1200));
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
            "java11_request_default_crypto_cookie",
            94,
            "Default-key encrypted Java serialization cookie reached a Java 11 request",
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
    List<String> variants = pathVariants(path);
    for (int i = 0; i < variants.size(); i++) {
      String normalized = variants.get(i).replace('\\', '/');
      if (hasConfusingDotSegment(normalized)
          || (sensitiveControlPath && hasPathControlCharacter(normalized))) {
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
    List<String> variants = new ArrayList<String>();
    addVariant(variants, path);
    addOverlongUtf8Variants(variants, path);
    String once = percentDecode(path);
    addVariant(variants, once);
    addVariant(variants, decodeUnicodeEscapes(once));
    addLenientPercentVariants(variants, once);
    addOverlongUtf8Variants(variants, once);
    String twice = percentDecode(once);
    addVariant(variants, twice);
    addVariant(variants, decodeUnicodeEscapes(twice));
    addLenientPercentVariants(variants, twice);
    addOverlongUtf8Variants(variants, twice);
    addLenientPercentVariants(variants, path);
    String ghost = lowByteUnicodeDecode(path);
    if (!ghost.equals(path)) {
      addVariant(variants, ghost);
      addVariant(variants, decodeUnicodeEscapes(ghost));
      addOverlongUtf8Variants(variants, ghost);
      String decodedGhost = percentDecode(ghost);
      addVariant(variants, decodedGhost);
      addVariant(variants, decodeUnicodeEscapes(decodedGhost));
      addLenientPercentVariants(variants, decodedGhost);
      addOverlongUtf8Variants(variants, decodedGhost);
    }
    return variants;
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
    if (value == null || value.indexOf('%') < 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    boolean changed = false;
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '%' && i + 2 < value.length()) {
        int high = jettyLenientHexDigit(value.charAt(i + 1));
        int low = jettyLenientHexDigit(value.charAt(i + 2));
        if (high >= 0 && low >= 0) {
          decoded.append((char) ((high << 4) + low));
          changed = true;
          i += 2;
          continue;
        }
      }
      decoded.append(ch);
    }
    return changed ? decoded.toString() : value;
  }

  private static int jettyLenientHexDigit(char ch) {
    if (ch > 0x7f) {
      return -1;
    }
    int digit = ((ch & 0x1f) + ((ch >> 6) * 0x19) - 0x10);
    return digit >= 0 && digit <= 15 ? digit : -1;
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

  private static boolean isLocalRuntimeDtd(String value) {
    String normalized = normalizePath(value);
    if (normalized.startsWith("jar:file:") && isTrustedEmbeddedRuntimeDtd(normalized)) {
      return true;
    }
    if (normalized.startsWith("file:") && isTrustedLocalFrameworkConfigXml(normalized)) {
      return true;
    }
    if (!normalized.endsWith(".dtd")) {
      return false;
    }
    if (isTrustedRuntimeDtdUrl(value) || isTrustedRuntimeDtdUrl(normalized)) {
      return true;
    }
    if (normalized.startsWith("jar:file:")) {
      return trustedRuntimeResource(normalized.substring("jar:".length()));
    }
    if (normalized.startsWith("file:")) {
      return trustedRuntimeResource(normalized);
    }
    return false;
  }

  private static boolean isTrustedEmbeddedRuntimeDtd(String value) {
    String normalized = lower(value == null ? "" : value.trim()).replace('\\', '/');
    return normalized.endsWith("!/org/apache/tomcat/util/modeler/mbeans-descriptors.dtd")
        || normalized.endsWith("!/javax/servlet/jsp/resources/web-jsptaglibrary_1_1.dtd")
        || normalized.endsWith("!/javax/servlet/jsp/resources/web-jsptaglibrary_1_2.dtd")
        || normalized.endsWith("!/jakarta/servlet/jsp/resources/web-jsptaglibrary_1_2.dtd")
        || normalized.endsWith("!/struts-default.xml")
        || normalized.endsWith("!/struts-plugin.xml");
  }

  private static boolean isTrustedLocalFrameworkConfigXml(String value) {
    String normalized = lower(value == null ? "" : value.trim()).replace('\\', '/');
    return isTrustedLocalStrutsConfigXml(normalized)
        || isTrustedLocalStrutsValidationXml(normalized)
        || normalized.endsWith("/com/opensymphony/xwork2/validator/validators/default.xml");
  }

  private static boolean isTrustedLocalStrutsConfigXml(String normalized) {
    return isDirectStrutsConfigXml(normalized, "/target/classes/")
        || isDirectStrutsConfigXml(normalized, "/web-inf/classes/");
  }

  private static boolean isDirectStrutsConfigXml(String normalized, String directory) {
    if (!normalized.endsWith(".xml")) {
      return false;
    }
    int index = normalized.lastIndexOf(directory);
    if (index < 0) {
      return false;
    }
    String fileName = normalized.substring(index + directory.length());
    if (fileName.indexOf('/') >= 0 || fileName.indexOf("..") >= 0) {
      return false;
    }
    return fileName.startsWith("struts") || isStrutsXmlConfigurationStack();
  }

  private static boolean isStrutsXmlConfigurationStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i < stack.length; i++) {
      String className = stack[i].getClassName();
      if ("com.opensymphony.xwork2.config.providers.XmlConfigurationProvider".equals(className)
          || "org.apache.struts2.config.StrutsXmlConfigurationProvider".equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isTrustedLocalStrutsValidationXml(String normalized) {
    if (!normalized.endsWith("-validation.xml")) {
      return false;
    }
    if (trustedRuntimeResource(normalized)
        && (normalized.indexOf("/org/apache/struts2/") >= 0
            || normalized.indexOf("/com/opensymphony/xwork2/") >= 0)) {
      return true;
    }
    return isClasspathStrutsValidationXml(normalized, "/target/classes/")
        || isClasspathStrutsValidationXml(normalized, "/web-inf/classes/");
  }

  private static boolean isClasspathStrutsValidationXml(String normalized, String directory) {
    int index = normalized.lastIndexOf(directory);
    if (index < 0) {
      return false;
    }
    String fileName = normalized.substring(index + directory.length());
    return fileName.length() > "-validation.xml".length()
        && fileName.indexOf("..") < 0
        && fileName.endsWith("-validation.xml");
  }

  private static boolean trustedRuntimeResource(String value) {
    String normalized = normalizePath(value);
    String[] trustedRoots =
        new String[] {
          normalizeFileProperty("catalina.home"),
          normalizeFileProperty("catalina.base"),
          normalizeFileProperty("java.home"),
          normalizeFileProperty("jetty.home"),
          normalizeFileProperty("jetty.base"),
          normalizeFileProperty("activemq.home"),
          normalizeFileProperty("karaf.home"),
          normalizeEnvPath("CATALINA_HOME"),
          normalizeEnvPath("CATALINA_BASE"),
          normalizeEnvPath("JETTY_HOME"),
          normalizeEnvPath("JETTY_BASE"),
          normalizeEnvPath("ACTIVEMQ_HOME"),
          normalizeEnvPath("KARAF_HOME")
        };
    for (String trustedRoot : trustedRoots) {
      if (hasTrustedPrefix(normalized, "file:", trustedRoot)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isTrustedRuntimeDtdUrl(String value) {
    String normalized = lower(value == null ? "" : value.trim()).replace('\\', '/').replace("://", ":/");
    return "http:/www.eclipse.org/jetty/configure_9_0.dtd".equals(normalized)
        || "https:/www.eclipse.org/jetty/configure_9_0.dtd".equals(normalized)
        || "http:/www.eclipse.org/jetty/configure_9_3.dtd".equals(normalized)
        || "https:/www.eclipse.org/jetty/configure_9_3.dtd".equals(normalized)
        || "http:/java.sun.com/dtd/web-app_2_2.dtd".equals(normalized)
        || "http:/java.sun.com/dtd/web-app_2_3.dtd".equals(normalized)
        || "http:/java.sun.com/dtd/web-facesconfig_1_1.dtd".equals(normalized)
        || "http:/java.sun.com/dtd/web-jsptaglibrary_1_1.dtd".equals(normalized)
        || "http:/java.sun.com/dtd/web-jsptaglibrary_1_2.dtd".equals(normalized)
        || "http:/mybatis.org/dtd/mybatis-3-config.dtd".equals(normalized)
        || "http:/mybatis.org/dtd/mybatis-3-mapper.dtd".equals(normalized)
        || "http:/www.springframework.org/dtd/spring-beans.dtd".equals(normalized)
        || "https:/java.sun.com/dtd/web-app_2_2.dtd".equals(normalized)
        || "https:/java.sun.com/dtd/web-app_2_3.dtd".equals(normalized)
        || "https:/java.sun.com/dtd/web-facesconfig_1_1.dtd".equals(normalized)
        || "https:/java.sun.com/dtd/web-jsptaglibrary_1_1.dtd".equals(normalized)
        || "https:/java.sun.com/dtd/web-jsptaglibrary_1_2.dtd".equals(normalized)
        || "https:/mybatis.org/dtd/mybatis-3-config.dtd".equals(normalized)
        || "https:/mybatis.org/dtd/mybatis-3-mapper.dtd".equals(normalized)
        || "https:/www.springframework.org/dtd/spring-beans.dtd".equals(normalized);
  }

  private static String normalizeFileProperty(String name) {
    String value = System.getProperty(name);
    if (value == null || value.trim().length() == 0) {
      return "";
    }
    return normalizePath(new File(value).getAbsolutePath());
  }

  private static String normalizeEnvPath(String name) {
    String value = System.getenv(name);
    if (value == null || value.trim().length() == 0) {
      return "";
    }
    return normalizePath(new File(value).getAbsolutePath());
  }

  private static boolean hasTrustedPrefix(String value, String uriPrefix, String trustedPath) {
    if (trustedPath.length() == 0) {
      return false;
    }
    return value.startsWith(uriPrefix + trustedPath + "/")
        || value.startsWith(uriPrefix + "/" + trustedPath + "/");
  }

  private static boolean isWebInfDeploymentArtifact(String path) {
    String normalized = normalizePath(path);
    String lower = lower(normalized);
    if (!(lower.indexOf("/web-inf/classes/") >= 0 || lower.indexOf("/web-inf/lib/") >= 0)) {
      return false;
    }
    return lower.endsWith(".class") || lower.endsWith(".jar");
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
    if (normalized.length() == 0 || !containsRemoteProtocol(normalized)) {
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

  private static String jmxScriptWriteTarget(String argument) {
    if (argument == null || argument.trim().length() == 0) {
      return "";
    }
    Matcher matcher = SCRIPT_FILE_TOKEN.matcher(argument);
    while (matcher.find()) {
      String target = normalizePath(matcher.group());
      if (SCRIPT_FILE_WRITE.matcher(target).matches()) {
        return target;
      }
    }
    return "";
  }

  private static List<String> jmxArgumentTexts(Object arguments) {
    List<String> values = new ArrayList<String>();
    collectJmxArgumentTexts(values, arguments, 0);
    return values;
  }

  private static void collectJmxArgumentTexts(List<String> values, Object value, int depth) {
    if (value == null || depth > 3 || values.size() >= 32) {
      return;
    }
    if (value instanceof Object[]) {
      Object[] array = (Object[]) value;
      for (int i = 0; i < array.length && values.size() < 32; i++) {
        collectJmxArgumentTexts(values, array[i], depth + 1);
      }
      return;
    }
    if (value instanceof Iterable<?>) {
      for (Object item : (Iterable<?>) value) {
        if (values.size() >= 32) {
          break;
        }
        collectJmxArgumentTexts(values, item, depth + 1);
      }
      return;
    }
    if (value instanceof Map<?, ?>) {
      Map<?, ?> map = (Map<?, ?>) value;
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (values.size() >= 32) {
          break;
        }
        collectJmxArgumentTexts(
            values,
            String.valueOf(entry.getKey()) + "=" + String.valueOf(entry.getValue()),
            depth + 1);
      }
      return;
    }
    String text = String.valueOf(value).trim();
    if (text.length() > 0) {
      values.add(text);
    }
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

  private static byte[] decodeBase64OrEmpty(String value) {
    try {
      return Base64.getDecoder().decode(value);
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
    UrlParts parts = urlParts(url);
    if (parts == null || parts.host.length() == 0) {
      return null;
    }
    if (isCloudMetadataHost(parts.host)) {
      return new Finding(
          "java11_ssrf_cloud_metadata",
          95,
          "Cloud metadata URL reached a Java 11 URL sink",
          "url",
          parts.fullUrl);
    }
    if (isLoopbackHost(parts.host) && LOOPBACK_ADMIN_PATH.matcher(parts.path).find()) {
      return new Finding(
          "java11_ssrf_loopback_admin",
          88,
          "Loopback administrative URL reached a Java 11 URL sink",
          "url",
          parts.fullUrl);
    }
    String requestControlledUrl = requestControlledUrlMatch(parts.comparisonKey);
    if (requestControlledUrl.length() > 0) {
      return new Finding(
          "java11_ssrf_request_parameter_url",
          92,
          "Request parameter controlled outbound URL reached a Java 11 URL sink",
          "url",
          abbreviate(requestControlledUrl, 1200));
    }
    return null;
  }

  private static UrlParts urlParts(Object value) {
    if (value == null) {
      return null;
    }
    if (value instanceof URL) {
      URL url = (URL) value;
      return new UrlParts(
          lower(url.getProtocol()),
          normalizeHost(url.getHost()),
          url.getPath() == null || url.getPath().length() == 0 ? "/" : url.getPath(),
          String.valueOf(url),
          urlComparisonKey(url));
    }
    try {
      URL url = new URL(String.valueOf(value));
      return new UrlParts(
          lower(url.getProtocol()),
          normalizeHost(url.getHost()),
          url.getPath() == null || url.getPath().length() == 0 ? "/" : url.getPath(),
          String.valueOf(url),
          urlComparisonKey(url));
    } catch (Exception ignored) {
      return null;
    }
  }

  private static void captureRequestControlledUrls(Object request) {
    List<String> values = requestControlledUrls(request);
    if (values.isEmpty()) {
      CURRENT_REQUEST_URLS.remove();
    } else {
      CURRENT_REQUEST_URLS.set(values);
    }
  }

  private static List<String> requestControlledUrls(Object request) {
    List<String> urls = new ArrayList<String>();
    if (request == null) {
      return urls;
    }
    Object parameterMap = invoke(request, "getParameterMap");
    if (!(parameterMap instanceof Map<?, ?>)) {
      return urls;
    }
    for (Map.Entry<?, ?> entry : ((Map<?, ?>) parameterMap).entrySet()) {
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
        || lower.indexOf("webhook") >= 0;
  }

  private static void addRequestControlledUrl(List<String> urls, Object value) {
    String key = urlComparisonKey(value);
    if (key.length() > 0 && !urls.contains(key)) {
      urls.add(key);
    }
  }

  private static String requestControlledUrlMatch(String key) {
    if (key == null || key.length() == 0) {
      return "";
    }
    List<String> urls = CURRENT_REQUEST_URLS.get();
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
      String host = normalizeHost(url.getHost());
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
    if (host == null) {
      return "";
    }
    String normalized = host.trim().toLowerCase(Locale.ROOT);
    if (normalized.startsWith("[") && normalized.endsWith("]")) {
      normalized = normalized.substring(1, normalized.length() - 1);
    }
    if (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized;
  }

  private static String lower(String value) {
    return value == null ? "" : value.toLowerCase(Locale.ROOT);
  }

  private static String artifactScheme(String value) {
    int index = value == null ? -1 : value.indexOf(':');
    if (index <= 0) {
      return "unknown";
    }
    return lower(value.substring(0, index));
  }

  private static String artifactExtension(String value) {
    if (value == null) {
      return "unknown";
    }
    String normalized = value;
    int query = normalized.indexOf('?');
    if (query >= 0) {
      normalized = normalized.substring(0, query);
    }
    int fragment = normalized.indexOf('#');
    if (fragment >= 0) {
      normalized = normalized.substring(0, fragment);
    }
    int dot = normalized.lastIndexOf('.');
    if (dot < 0 || dot == normalized.length() - 1) {
      return "unknown";
    }
    return lower(normalized.substring(dot + 1));
  }

  private static boolean isCloudMetadataHost(String host) {
    return "169.254.169.254".equals(host)
        || "169.254.169.253".equals(host)
        || "169.254.170.2".equals(host)
        || "100.100.100.200".equals(host)
        || "metadata.google.internal".equals(host)
        || "fd00:ec2::254".equals(host);
  }

  private static boolean isLoopbackHost(String host) {
    return "localhost".equals(host)
        || host.startsWith("127.")
        || "::1".equals(host)
        || "0:0:0:0:0:0:0:1".equals(host);
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

  private static boolean isNettyHostsFileRead(String path) {
    String lower = path.toLowerCase(Locale.ROOT);
    if (!lower.endsWith("/etc/hosts") && !lower.endsWith("/windows/system32/drivers/etc/hosts")) {
      return false;
    }
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i < stack.length; i++) {
      String className = stack[i].getClassName();
      if ("io.netty.resolver.HostsFileEntriesProvider$ParserImpl".equals(className)
          || "io.netty.resolver.DefaultHostsFileEntriesResolver".equals(className)) {
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
    if (option == null) {
      return false;
    }
    String value = String.valueOf(option).toUpperCase(Locale.ROOT);
    return "WRITE".equals(value)
        || "APPEND".equals(value)
        || "CREATE".equals(value)
        || "CREATE_NEW".equals(value)
        || "TRUNCATE_EXISTING".equals(value);
  }

  private static void emitFileFinding(
      Finding finding, ThreadLocal<String> lastLoggedPath, String hook) {
    if (finding == null) {
      return;
    }
    String action = shouldBlock() ? "block" : "log";
    String previous = lastLoggedPath.get();
    if (!"block".equals(action) && finding.detailValue.equals(previous)) {
      return;
    }
    lastLoggedPath.set(finding.detailValue);
    appendEvent(finding, hook, action);
    if ("block".equals(action)) {
      throw new Java11RaspBlockException("OhMyRASP Java 11 blocked suspicious file access");
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

  private static String bytesToString(byte[] bytes, int offset, int length) {
    if (bytes == null || length <= 0) {
      return "";
    }
    int safeOffset = Math.max(0, Math.min(offset, bytes.length));
    int safeLength = Math.max(0, Math.min(length, bytes.length - safeOffset));
    if (safeLength <= 0) {
      return "";
    }
    return new String(bytes, safeOffset, safeLength, StandardCharsets.UTF_8);
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
    String property = System.getProperty("ohmyrasp.java11.block");
    if (property == null || property.trim().length() == 0) {
      property = System.getenv("OHMYRASP_JAVA11_BLOCK");
    }
    return "true".equalsIgnoreCase(property)
        || "1".equals(property)
        || "yes".equalsIgnoreCase(property);
  }

  private static void appendEvent(Finding finding, String hook, String action) {
    String logPath =
        firstNonBlank(
            System.getProperty("ohmyrasp.java11.log"),
            System.getProperty("ohmyrasp.log"),
            System.getenv("OHMYRASP_LOG"));
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
            + "\"}"
            + "}";
    if (logPath == null) {
      System.err.println(event);
      return;
    }
    appendLine(logPath, event);
  }

  private static String firstNonBlank(String first, String second, String third) {
    if (hasText(first)) {
      return first;
    }
    if (hasText(second)) {
      return second;
    }
    if (hasText(third)) {
      return third;
    }
    return null;
  }

  private static boolean hasText(String value) {
    return value != null && value.trim().length() > 0;
  }

  private static void appendLine(String logPath, String message) {
    File target = new File(logPath);
    File parent = target.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      System.err.println("[OHMYRASP-JAVA11] could not create log directory: " + parent);
      return;
    }
    FileWriter writer = null;
    try {
      writer = new FileWriter(target, true);
      writer.write(message);
      writer.write(System.lineSeparator());
    } catch (IOException e) {
      System.err.println("[OHMYRASP-JAVA11] could not write detection event: " + e);
    } finally {
      if (writer != null) {
        try {
          writer.close();
        } catch (IOException ignored) {
          // Nothing useful to do during sink protection.
        }
      }
    }
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

  private static final class Finding {
    final String algorithm;
    final int confidence;
    final String message;
    final String detailKey;
    final String detailValue;

    Finding(String algorithm, int confidence, String message, String detailKey, String detailValue) {
      this.algorithm = algorithm;
      this.confidence = confidence;
      this.message = message;
      this.detailKey = detailKey;
      this.detailValue = detailValue;
    }
  }
}
