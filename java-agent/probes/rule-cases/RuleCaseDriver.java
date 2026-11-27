import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.naming.InitialContext;
import javax.servlet.DispatcherType;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Performs one rule case in a JVM started with the packaged agent, and reports how it ended.
 *
 * The case arrives on stdin as key=hex(UTF-8 value) lines written by check.py. The last stdout line
 * starting with "RULECASE" says whether the handler ran, whether the operation ran, and how each ended:
 * Beside them it reports the line the launcher says it started (system property ohmyrasp.agent.line, which
 * it publishes once a line is installed and nothing reads), and the length of the event file just before
 * the operation and just after it, so that check.py attributes only the events the operation wrote.
 * "blocked" when the agent's block exception is in the cause chain (or, at request entry, the primary
 * redirected to its block page and skipped the handler), "ran" when the operation completed or ended
 * with the exception the case declares in completes_with, "error" for any other failure.
 */
public class RuleCaseDriver extends HttpServlet {
  private static final Map<String, String> SPEC = new LinkedHashMap<String, String>();
  private static final Map<String, String> RESULT = new LinkedHashMap<String, String>();
  private static int port;
  private static boolean redirected;

  public static void main(String[] args) throws Exception {
    readSpec();
    ServerSocket listener = new ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"));
    port = listener.getLocalPort();
    Thread server = new Thread(new Listener(listener), "rule-case-listener");
    server.setDaemon(true);
    server.start();
    // Outbound HTTP to anything but loopback goes to the listener, so a sink the agent lets through
    // never leaves the machine. Loopback stays direct (the default http.nonProxyHosts).
    System.setProperty("http.proxyHost", "127.0.0.1");
    System.setProperty("http.proxyPort", String.valueOf(port));
    DriverManager.registerDriver(new StubDriver());

    String via = spec("via");
    RESULT.put("handler", "n/a");
    RESULT.put("entry", "n/a");
    RESULT.put("op", "not-run");
    RESULT.put("ending", "");
    RESULT.put("log_start", String.valueOf(logLength()));
    mark("OperationStart");
    if ("sink".equals(via)) {
      perform();
    } else {
      RuleCaseDriver servlet = new RuleCaseDriver();
      RESULT.put("handler", "no");
      try {
        servlet.service((ServletRequest) request(), (ServletResponse) response());
        RESULT.put("entry", "passed");
      } catch (Throwable thrown) {
        RESULT.put("entry", blockedBy(thrown) ? "blocked" : "error");
        RESULT.put("entry_ending", describe(thrown));
      }
      if ("no".equals(RESULT.get("handler")) && redirected) RESULT.put("entry", "blocked-redirect");
    }
    mark("OperationEnd");
    RESULT.put("log_end", String.valueOf(logLength()));
    RESULT.put("agent_line", System.getProperty("ohmyrasp.agent.line", ""));
    StringBuilder line = new StringBuilder("RULECASE");
    for (Map.Entry<String, String> entry : RESULT.entrySet()) {
      line.append('\t').append(entry.getKey()).append('=').append(clean(entry.getValue()));
    }
    // The report goes to a file when the probe names one. On Java 8, -verbose:class writes to standard
    // output too, and a class-load line can land in the middle of a line printed here.
    String report = System.getProperty("rulecase.report");
    if (report == null) {
      System.out.println(line);
      System.out.flush();
    } else {
      java.io.OutputStream out = new java.io.FileOutputStream(report);
      try {
        out.write(line.append('\n').toString().getBytes("UTF-8"));
      } finally {
        out.close();
      }
    }
    System.exit(0);
  }

  /**
   * Loads the marker class {@code RuleCaseDriver$<name>}, so the JVM's class-load log shows where the operation
   * starts and ends: check.py fails a case when a class of the agent loads between the two marks, since that load
   * happened inside a hook (or a transformer) during the operation.
   */
  private static void mark(String name) throws ClassNotFoundException {
    Class.forName(RuleCaseDriver.class.getName() + "$" + name, true, RuleCaseDriver.class.getClassLoader());
  }

  /** Marker classes for {@link #mark}: nothing else loads them. */
  static final class OperationStart {}

  static final class OperationEnd {}

  /** Bytes in the agent's event file now: the agent writes inline (ohmyrasp.log.sync=true), so this is a line boundary. */
  private static long logLength() {
    String path = System.getProperty("ohmyrasp.log");
    return path == null ? 0 : new File(path).length();
  }

  // ---- the servlet ------------------------------------------------------------------------

  @Override protected void service(HttpServletRequest request, HttpServletResponse response)
      throws javax.servlet.ServletException, IOException {
    if ("PATCH".equals(request.getMethod())) handle(); // HttpServlet has no doPatch
    else super.service(request, response);
  }

  @Override protected void doGet(HttpServletRequest request, HttpServletResponse response) { handle(); }
  @Override protected void doPost(HttpServletRequest request, HttpServletResponse response) { handle(); }
  @Override protected void doPut(HttpServletRequest request, HttpServletResponse response) { handle(); }
  @Override protected void doDelete(HttpServletRequest request, HttpServletResponse response) { handle(); }

  private static void handle() {
    RESULT.put("handler", "yes");
    readBody();
    if ("request-sink".equals(spec("via"))) {
      perform();
      String ending = RESULT.get("op");
      if ("blocked".equals(ending)) {
        // An application does not catch the agent's exception: let it reach the container.
        throw BLOCK_SEEN[0] instanceof RuntimeException ? (RuntimeException) BLOCK_SEEN[0] : new IllegalStateException(BLOCK_SEEN[0]);
      }
    }
  }

  private static final Throwable[] BLOCK_SEEN = new Throwable[1];

  /** The request the handler was given: the stub servlet request, which carries the case's body when it has one. */
  private static HttpServletRequest current;

  /**
   * The handler reads the case's request body the way an application does: from the input stream or the reader,
   * one unit at a time, or with array reads when the case sets a chunk; to end of stream, exactly Content-Length
   * bytes (never asking past them, as a JSON parser that knows the length does), or not at all.
   */
  private static void readBody() {
    if (!SPEC.containsKey("request.body") || current == null) return;
    String mode = SPEC.containsKey("request.bodyRead") ? SPEC.get("request.bodyRead") : "all";
    if ("none".equals(mode)) {
      RESULT.put("body", "not read");
      return;
    }
    boolean arrays = SPEC.containsKey("request.bodyChunk") || "content-length".equals(mode);
    long read = 0;
    try {
      if ("reader".equals(SPEC.get("request.bodyApi"))) {
        BufferedReader reader = current.getReader();
        if (arrays) {
          char[] buffer = new char[64];
          for (int n; (n = reader.read(buffer, 0, buffer.length)) >= 0; ) read += n;
        } else {
          while (reader.read() >= 0) read++;
        }
      } else {
        InputStream in = current.getInputStream();
        long limit = "content-length".equals(mode) ? current.getContentLengthLong() : Long.MAX_VALUE;
        if (arrays) {
          byte[] buffer = new byte[4096];
          while (read < limit) {
            int n = in.read(buffer, 0, (int) Math.min(buffer.length, limit - read));
            if (n < 0) break;
            read += n;
          }
        } else {
          while (in.read() >= 0) read++;
        }
      }
      RESULT.put("body", "read " + read);
    } catch (IOException unreadable) {
      RESULT.put("body", "unreadable");
    } catch (RuntimeException thrown) {
      // The agent's exception from inside the application's read: the application does not catch it.
      if (blockedBy(thrown)) RESULT.put("body", "blocked after " + read + " read");
      throw thrown;
    }
  }

  // ---- the operation ----------------------------------------------------------------------

  private static void perform() {
    try {
      performOperation();
    } finally {
      // A file the operation creates: check.py fails a block that left it behind, and a run that did not.
      if (SPEC.containsKey("witness")) RESULT.put("witness", new File(spec("witness")).exists() ? "present" : "absent");
    }
  }

  private static void performOperation() {
    String op = spec("op");
    try {
      String detail = run(op);
      RESULT.put("op", "ran");
      RESULT.put("ending", detail);
    } catch (Throwable thrown) {
      if (blockedBy(thrown)) {
        BLOCK_SEEN[0] = thrown;
        RESULT.put("op", "blocked");
      } else {
        boolean expected = false;
        if (SPEC.containsKey("completes_with")) {
          for (String name : SPEC.get("completes_with").split(",")) expected |= endsWith(thrown, name);
        }
        // An exception the case accepts that the agent itself threw is not the operation's own ending.
        String agentFrame = thrownByAgent(thrown);
        if (agentFrame != null) {
          expected = false;
          RESULT.put("op", "error");
          RESULT.put("ending", "thrown by the agent (" + agentFrame + "): " + describe(thrown));
          return;
        }
        RESULT.put("op", expected ? "ran" : "error");
      }
      RESULT.put("ending", describe(thrown));
    }
  }

  private static String run(String op) throws Exception {
    if ("process.exec".equals(op)) return processExec();
    if ("file.read".equals(op)) return fileRead(spec("path"));
    if ("file.write".equals(op)) return fileWrite(spec("path"), SPEC.containsKey("content") ? SPEC.get("content") : "x");
    if ("file.list".equals(op)) return fileList(spec("path"));
    if ("file.delete".equals(op)) return fileDelete(spec("path"));
    if ("jndi.lookup".equals(op)) return "returned " + typeOf(new InitialContext().lookup(spec("name")));
    if ("net.open".equals(op)) return netOpen(spec("url"));
    if ("classloader.remote".equals(op)) return classLoad(spec("url"), spec("class"));
    if ("deserialize".equals(op)) return deserialize(spec("class"));
    if ("xml.parse".equals(op)) return xmlParse(spec("document"));
    if ("archive.extract".equals(op)) return archiveExtract(spec("entry"), spec("path"));
    if ("base64.decode".equals(op)) return base64Decode(spec("input"));
    if ("jdbc.connect".equals(op)) return "connected " + typeOf(DriverManager.getConnection(spec("url")));
    if ("sql.execute".equals(op)) return "executed " + typeOf(new StubStatement().executeQuery(spec("sql")));
    if ("beans.decode".equals(op)) return beansDecode(spec("document"));
    if ("java.compile".equals(op)) return javaCompile(spec("source"));
    if ("xpath.evaluate".equals(op)) {
      return "evaluated to \"" + javax.xml.xpath.XPathFactory.newInstance().newXPath().evaluate(spec("expression"),
          new org.xml.sax.InputSource(new StringReader("<r><item>weekly</item></r>"))) + "\"";
    }
    throw new IllegalArgumentException("unknown op " + op);
  }

  private static String processExec() throws Exception {
    List<String> argv = list("argv");
    Process process;
    String api = SPEC.containsKey("api") ? SPEC.get("api") : "ProcessBuilder";
    if ("Runtime.exec".equals(api)) process = Runtime.getRuntime().exec(argv.toArray(new String[0]));
    else if ("ProcessBuilder".equals(api)) process = new ProcessBuilder(argv).redirectErrorStream(true).start();
    else throw new IllegalArgumentException("process api " + api);
    drain(process.getInputStream());
    return "exit " + process.waitFor();
  }

  private static String fileRead(String path) throws IOException {
    String api = SPEC.containsKey("api") ? SPEC.get("api") : "FileInputStream";
    if ("Files.readAllBytes".equals(api)) return "read " + Files.readAllBytes(Paths.get(path)).length + " bytes";
    if (!"FileInputStream".equals(api)) throw new IllegalArgumentException("file api " + api);
    InputStream in = new FileInputStream(path);
    try { return "read " + drain(in) + " bytes"; } finally { in.close(); }
  }

  private static String fileWrite(String path, String content) throws Exception {
    File target = new File(path);
    File parent = target.getAbsoluteFile().getParentFile();
    if (parent != null) parent.mkdirs();
    String api = SPEC.containsKey("api") ? SPEC.get("api") : "FileOutputStream";
    byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
    if ("Files.write".equals(api)) Files.write(target.toPath(), bytes);
    else if ("reflection".equals(api)) {
      OutputStream out = (OutputStream) FileOutputStream.class.getConstructor(String.class).newInstance(path);
      try { out.write(bytes); } finally { out.close(); }
    }
    else if ("FileOutputStream".equals(api)) {
      OutputStream out = new FileOutputStream(target);
      try { out.write(bytes); } finally { out.close(); }
    } else throw new IllegalArgumentException("file api " + api);
    if (!target.isFile()) throw new IOException("file not written: " + path);
    return "wrote " + bytes.length + " bytes";
  }

  private static String fileList(String path) throws IOException {
    String api = SPEC.containsKey("api") ? SPEC.get("api") : "File.list";
    if ("Files.newDirectoryStream".equals(api)) {
      int count = 0;
      DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get(path));
      try { for (Path ignored : stream) count++; } finally { stream.close(); }
      return "listed " + count + " entries";
    }
    if (!"File.list".equals(api)) throw new IllegalArgumentException("list api " + api);
    String[] names = new File(path).list();
    if (names == null) throw new IOException("not a readable directory: " + path);
    return "listed " + names.length + " entries";
  }

  private static String fileDelete(String path) throws IOException {
    String api = SPEC.containsKey("api") ? SPEC.get("api") : "Files.delete";
    if ("File.delete".equals(api)) {
      if (!new File(path).delete()) throw new IOException("not deleted: " + path);
    } else if ("Files.delete".equals(api)) {
      Files.delete(Paths.get(path));
    } else throw new IllegalArgumentException("delete api " + api);
    return "deleted";
  }

  private static String netOpen(String url) throws IOException {
    java.net.URLConnection connection = new URL(url).openConnection();
    connection.setConnectTimeout(5000);
    connection.setReadTimeout(5000);
    InputStream in = connection.getInputStream();
    try {
      long read = drain(in);
      return connection instanceof HttpURLConnection
          ? "status " + ((HttpURLConnection) connection).getResponseCode() : "read " + read + " bytes";
    } finally {
      in.close();
    }
  }

  private static String classLoad(String url, String name) throws Exception {
    URLClassLoader loader = new URLClassLoader(new URL[]{new URL(url)}, null);
    try { return "loaded " + loader.loadClass(name).getName(); } finally { loader.close(); }
  }

  /** A stream holding one object of the named class, described with its local serialVersionUID and no fields. */
  private static String deserialize(String className) throws Exception {
    Class<?> local = Class.forName(className, false, RuleCaseDriver.class.getClassLoader());
    ObjectStreamClass descriptor = ObjectStreamClass.lookup(local);
    if (descriptor == null) throw new IllegalArgumentException(className + " is not serializable");
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(bytes);
    out.writeShort(0xACED);
    out.writeShort(5);
    out.writeByte(0x73);            // TC_OBJECT
    out.writeByte(0x72);            // TC_CLASSDESC
    out.writeUTF(className);
    out.writeLong(descriptor.getSerialVersionUID());
    out.writeByte(0x02);            // SC_SERIALIZABLE
    out.writeShort(0);              // no fields
    out.writeByte(0x78);            // TC_ENDBLOCKDATA
    out.writeByte(0x70);            // TC_NULL: no superclass descriptor
    out.flush();
    ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()));
    try { return "read " + typeOf(in.readObject()); } finally { in.close(); }
  }

  private static String xmlParse(String document) throws Exception {
    javax.xml.parsers.DocumentBuilder builder = javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder();
    org.w3c.dom.Document parsed = builder.parse(new org.xml.sax.InputSource(new StringReader(document)));
    return "parsed <" + parsed.getDocumentElement().getNodeName() + "> text length "
        + parsed.getDocumentElement().getTextContent().length();
  }

  private static String archiveExtract(String entryName, String destination) throws IOException {
    ByteArrayOutputStream zipped = new ByteArrayOutputStream();
    ZipOutputStream zip = new ZipOutputStream(zipped);
    zip.putNextEntry(new ZipEntry(entryName));
    zip.write("x".getBytes(StandardCharsets.UTF_8));
    zip.closeEntry();
    zip.close();
    new File(destination).mkdirs();
    ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(zipped.toByteArray()));
    try {
      ZipEntry entry = in.getNextEntry();
      File target = new File(destination, entry.getName());
      target.getAbsoluteFile().getParentFile().mkdirs();
      OutputStream out = new FileOutputStream(target);
      try {
        byte[] buffer = new byte[64];
        int n;
        while ((n = in.read(buffer)) > 0) out.write(buffer, 0, n);
      } finally {
        out.close();
      }
      return "extracted " + entry.getName();
    } finally {
      in.close();
    }
  }

  private static String beansDecode(String document) {
    final Exception[] failure = new Exception[1];
    java.beans.XMLDecoder decoder = new java.beans.XMLDecoder(
        new ByteArrayInputStream(document.getBytes(StandardCharsets.UTF_8)), null, new java.beans.ExceptionListener() {
          @Override public void exceptionThrown(Exception e) { if (failure[0] == null) failure[0] = e; }
        });
    try {
      Object value = decoder.readObject();
      if (failure[0] != null) throw new IllegalStateException("decoder reported", failure[0]);
      return "decoded " + typeOf(value);
    } finally {
      decoder.close();
    }
  }

  /** A source unit held in memory, written the way the javax.tools documentation shows it. */
  public static final class StringSource extends javax.tools.SimpleJavaFileObject {
    private final String source;
    public StringSource(String source) {
      super(java.net.URI.create("string:///Generated.java"), javax.tools.JavaFileObject.Kind.SOURCE);
      this.source = source;
    }
    @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) { return source; }
  }

  /** Compiles one source unit into the case directory; the class is never loaded or run. */
  private static String javaCompile(final String source) throws Exception {
    javax.tools.JavaCompiler compiler = javax.tools.ToolProvider.getSystemJavaCompiler();
    if (compiler == null) throw new IllegalStateException("no system Java compiler");
    String api = SPEC.containsKey("api") ? SPEC.get("api") : "public-class";
    javax.tools.JavaFileObject unit;
    if ("public-class".equals(api)) unit = new StringSource(source);
    else if ("anonymous-class".equals(api)) {
      unit = new javax.tools.SimpleJavaFileObject(
          java.net.URI.create("string:///Generated.java"), javax.tools.JavaFileObject.Kind.SOURCE) {
        @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) { return source; }
      };
    } else if ("file-object".equals(api)) {
      // javac's own unit for a file on disk: a class of the jdk.compiler module, which does not open its package.
      File file = new File(spec("tmp"), "Generated.java");
      Files.write(file.toPath(), source.getBytes(StandardCharsets.UTF_8));
      unit = compiler.getStandardFileManager(null, null, null).getJavaFileObjects(file).iterator().next();
    } else throw new IllegalArgumentException("compile api " + api);
    File output = new File(spec("tmp"), "compiled");
    output.mkdirs();
    StringWriter diagnostics = new StringWriter();
    Boolean compiled = compiler.getTask(diagnostics, null, null, java.util.Arrays.asList("-d", output.getPath()), null,
        Collections.singletonList(unit)).call();
    if (!Boolean.TRUE.equals(compiled)) throw new IllegalStateException("compilation failed: " + diagnostics);
    return "compiled";
  }

  private static String base64Decode(String input) {
    String api = SPEC.containsKey("api") ? SPEC.get("api") : "basic";
    Base64.Decoder decoder = "mime".equals(api) ? Base64.getMimeDecoder() : "url".equals(api) ? Base64.getUrlDecoder()
        : Base64.getDecoder();
    return "decoded " + decoder.decode(input.getBytes(StandardCharsets.ISO_8859_1)).length + " bytes";
  }

  // ---- request and response stubs ---------------------------------------------------------

  private static HttpServletRequest request() {
    final String method = spec("request.method");
    final String uri = spec("request.uri");
    final String query = SPEC.get("request.query");
    final Map<String, String[]> parameters = multimap("param");
    final Map<String, String[]> headers = new TreeMap<String, String[]>(String.CASE_INSENSITIVE_ORDER);
    headers.putAll(multimap("header"));
    final Map<String, Object> attributes = new LinkedHashMap<String, Object>();
    attributes.putAll(multimap("attr"));
    for (Map.Entry<String, Object> entry : attributes.entrySet()) entry.setValue(((String[]) entry.getValue())[0]);
    final Map<String, String[]> headerNames = multimap("header");
    final String body = SPEC.containsKey("request.body") ? spec("request.body") : "";
    final byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
    final int chunk = SPEC.containsKey("request.bodyChunk") ? Integer.parseInt(SPEC.get("request.bodyChunk")) : 0;
    InvocationHandler handler = new InvocationHandler() {
      @Override public Object invoke(Object proxy, Method m, Object[] a) {
        String name = m.getName();
        if ("getMethod".equals(name)) return method;
        if ("getRequestURI".equals(name)) return uri;
        if ("getServletPath".equals(name)) return uri;
        if ("getContextPath".equals(name)) return "";
        if ("getPathInfo".equals(name) || "getPathTranslated".equals(name)) return null;
        if ("getQueryString".equals(name)) return query;
        if ("getRequestURL".equals(name)) return new StringBuffer("http://localhost:8080" + uri);
        if ("getProtocol".equals(name)) return "HTTP/1.1";
        if ("getScheme".equals(name)) return "http";
        if ("getServerName".equals(name) || "getLocalName".equals(name) || "getRemoteHost".equals(name)) return "localhost";
        if ("getServerPort".equals(name) || "getLocalPort".equals(name)) return 8080;
        if ("getRemotePort".equals(name)) return 50000;
        if ("getRemoteAddr".equals(name) || "getLocalAddr".equals(name)) return "127.0.0.1";
        if ("getParameterMap".equals(name)) return Collections.unmodifiableMap(parameters);
        if ("getParameterNames".equals(name)) return Collections.enumeration(parameters.keySet());
        if ("getParameterValues".equals(name)) return parameters.get((String) a[0]);
        if ("getParameter".equals(name)) {
          String[] values = parameters.get((String) a[0]);
          return values == null ? null : values[0];
        }
        if ("getHeaderNames".equals(name)) return Collections.enumeration(headerNames.keySet());
        if ("getHeader".equals(name)) {
          String[] values = headers.get((String) a[0]);
          return values == null ? null : values[0];
        }
        if ("getHeaders".equals(name)) {
          String[] values = headers.get((String) a[0]);
          return Collections.enumeration(values == null ? Collections.<String>emptyList() : java.util.Arrays.asList(values));
        }
        if ("getIntHeader".equals(name)) {
          String[] values = headers.get((String) a[0]);
          return values == null ? -1 : Integer.parseInt(values[0].trim());
        }
        if ("getDateHeader".equals(name)) return -1L;
        if ("getContentType".equals(name)) {
          String[] values = headers.get("Content-Type");
          return values == null ? null : values[0];
        }
        if ("getContentLength".equals(name)) return bodyBytes.length;
        if ("getContentLengthLong".equals(name)) return (long) bodyBytes.length;
        if ("getCharacterEncoding".equals(name)) return "UTF-8";
        if ("getAttribute".equals(name)) return attributes.get((String) a[0]);
        if ("getAttributeNames".equals(name)) return Collections.enumeration(new ArrayList<String>(attributes.keySet()));
        if ("setAttribute".equals(name)) { attributes.put((String) a[0], a[1]); return null; }
        if ("removeAttribute".equals(name)) { attributes.remove((String) a[0]); return null; }
        if ("getCookies".equals(name)) return cookies(headers.get("Cookie"));
        if ("getInputStream".equals(name)) return bodyStream(bodyBytes, chunk);
        // A reader over the input stream, as Jetty and Undertow serve getReader(); Tomcat's own reader is covered
        // by the real-container acceptance script, not here.
        if ("getReader".equals(name)) {
          return new BufferedReader(new InputStreamReader(bodyStream(bodyBytes, chunk), StandardCharsets.UTF_8));
        }
        if ("getDispatcherType".equals(name)) return DispatcherType.REQUEST;
        if ("getLocale".equals(name)) return Locale.US;
        if ("getLocales".equals(name)) return Collections.enumeration(Collections.singletonList(Locale.US));
        if ("toString".equals(name)) return "RuleCaseRequest[" + method + " " + uri + "]";
        if ("hashCode".equals(name)) return System.identityHashCode(proxy);
        if ("equals".equals(name)) return proxy == a[0];
        return defaultValue(m.getReturnType());
      }
    };
    current = (HttpServletRequest) Proxy.newProxyInstance(RuleCaseDriver.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class}, handler);
    return current;
  }

  private static HttpServletResponse response() {
    final StringWriter body = new StringWriter();
    final PrintWriter writer = new PrintWriter(body);
    InvocationHandler handler = new InvocationHandler() {
      @Override public Object invoke(Object proxy, Method m, Object[] a) {
        String name = m.getName();
        if ("sendRedirect".equals(name)) { redirected = true; RESULT.put("redirect", String.valueOf(a[0])); return null; }
        if ("sendError".equals(name)) { RESULT.put("status", String.valueOf(a[0])); return null; }
        if ("setStatus".equals(name)) { RESULT.put("status", String.valueOf(a[0])); return null; }
        if ("getWriter".equals(name)) return writer;
        if ("getOutputStream".equals(name)) return discard();
        if ("getStatus".equals(name)) return 200;
        if ("getHeaderNames".equals(name) || "getHeaders".equals(name)) return Collections.<String>emptyList();
        if ("toString".equals(name)) return "RuleCaseResponse";
        if ("hashCode".equals(name)) return System.identityHashCode(proxy);
        if ("equals".equals(name)) return proxy == a[0];
        return defaultValue(m.getReturnType());
      }
    };
    return (HttpServletResponse) Proxy.newProxyInstance(RuleCaseDriver.class.getClassLoader(),
        new Class<?>[]{HttpServletResponse.class}, handler);
  }

  private static Cookie[] cookies(String[] header) {
    if (header == null) return null;
    List<Cookie> cookies = new ArrayList<Cookie>();
    for (String line : header) {
      for (String pair : line.split(";")) {
        int eq = pair.indexOf('=');
        if (eq > 0) cookies.add(new Cookie(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim()));
      }
    }
    return cookies.toArray(new Cookie[0]);
  }

  /** The body as a servlet input stream that returns at most {@code chunk} bytes per array read (0: no limit). */
  private static ServletInputStream bodyStream(final byte[] bytes, final int chunk) {
    return new ServletInputStream() {
      private int position;
      @Override public int read() { return position < bytes.length ? bytes[position++] & 0xff : -1; }
      @Override public int read(byte[] buffer, int offset, int length) {
        if (length == 0) return 0;
        if (position >= bytes.length) return -1;
        int n = Math.min(Math.min(length, bytes.length - position), chunk > 0 ? chunk : length);
        System.arraycopy(bytes, position, buffer, offset, n);
        position += n;
        return n;
      }
      @Override public boolean isFinished() { return position >= bytes.length; }
      @Override public boolean isReady() { return true; }
      @Override public void setReadListener(ReadListener listener) { }
    };
  }

  private static ServletOutputStream discard() {
    return new ServletOutputStream() {
      @Override public void write(int b) { }
      @Override public boolean isReady() { return true; }
      @Override public void setWriteListener(WriteListener listener) { }
    };
  }

  private static Object defaultValue(Class<?> type) {
    if (type == boolean.class) return false;
    if (type == int.class) return 0;
    if (type == long.class) return 0L;
    if (type == short.class) return (short) 0;
    if (type == byte.class) return (byte) 0;
    if (type == char.class) return (char) 0;
    if (type == float.class) return 0f;
    if (type == double.class) return 0d;
    if (type == java.util.Enumeration.class) return Collections.emptyEnumeration();
    if (type == java.util.Collection.class) return Collections.emptyList();
    return null;
  }

  // ---- the loopback listener ---------------------------------------------------------------

  /** Answers every HTTP request: a class file under the remote class directory, a DTD, or "ok". */
  private static final class Listener implements Runnable {
    private final ServerSocket socket;
    Listener(ServerSocket socket) { this.socket = socket; }

    @Override public void run() {
      while (true) {
        try {
          final Socket client = socket.accept();
          Thread worker = new Thread(new Runnable() {
            @Override public void run() { answer(client); }
          }, "rule-case-listener-client");
          worker.setDaemon(true);
          worker.start();
        } catch (IOException closed) {
          return;
        }
      }
    }

    private void answer(Socket client) {
      try {
        BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.ISO_8859_1));
        String requestLine = in.readLine();
        String header;
        while ((header = in.readLine()) != null && !header.isEmpty()) { /* skip */ }
        String target = requestLine == null ? "/" : requestLine.split(" ")[1];
        int slash = target.indexOf("://");
        if (slash >= 0) target = target.substring(target.indexOf('/', slash + 3));
        byte[] payload = "ok".getBytes(StandardCharsets.UTF_8);
        String type = "text/plain";
        String classes = SPEC.get("classes");
        if (target.endsWith(".class") && classes != null) {
          File file = new File(classes, target.substring(target.lastIndexOf('/') + 1));
          if (file.isFile()) {
            payload = Files.readAllBytes(file.toPath());
            type = "application/java-vm";
          }
        } else if (target.endsWith(".dtd")) {
          payload = "<!ENTITY remote \"ok\">".getBytes(StandardCharsets.UTF_8);
          type = "application/xml-dtd";
        }
        OutputStream out = client.getOutputStream();
        out.write(("HTTP/1.1 200 OK\r\nContent-Type: " + type + "\r\nContent-Length: " + payload.length
            + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        out.write(payload);
        out.flush();
        client.close();
      } catch (IOException ignored) {
        // The client gave up; nothing to answer.
      }
    }
  }

  /** Accepts every JDBC URL and returns a connection that does nothing, so no database is needed. */
  public static final class StubDriver implements Driver {
    @Override public Connection connect(String url, Properties info) {
      return (Connection) Proxy.newProxyInstance(RuleCaseDriver.class.getClassLoader(), new Class<?>[]{Connection.class},
          new InvocationHandler() {
            @Override public Object invoke(Object proxy, Method m, Object[] a) {
              if ("toString".equals(m.getName())) return "StubConnection";
              return defaultValue(m.getReturnType());
            }
          });
    }
    @Override public boolean acceptsURL(String url) { return url != null && url.startsWith("jdbc:"); }
    @Override public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) { return new DriverPropertyInfo[0]; }
    @Override public int getMajorVersion() { return 1; }
    @Override public int getMinorVersion() { return 0; }
    @Override public boolean jdbcCompliant() { return false; }
    @Override public Logger getParentLogger() { return Logger.getLogger("rule-cases"); }
  }

  // ---- helpers ------------------------------------------------------------------------------

  private static void readSpec() throws IOException {
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
    String line;
    while ((line = in.readLine()) != null) {
      int eq = line.indexOf('=');
      if (eq <= 0) continue;
      SPEC.put(line.substring(0, eq), unhex(line.substring(eq + 1)));
    }
  }

  private static String spec(String key) {
    String value = SPEC.get(key);
    if (value == null) throw new IllegalArgumentException("case has no " + key);
    return value.replace("{port}", String.valueOf(port));
  }

  private static List<String> list(String prefix) {
    List<String> values = new ArrayList<String>();
    for (int i = 0; SPEC.containsKey(prefix + "." + i); i++) values.add(spec(prefix + "." + i));
    return values;
  }

  /** name/value pairs written as prefix.N.name and prefix.N.value, in order, values of one name together. */
  private static Map<String, String[]> multimap(String prefix) {
    Map<String, List<String>> grouped = new LinkedHashMap<String, List<String>>();
    for (int i = 0; SPEC.containsKey(prefix + "." + i + ".name"); i++) {
      String name = spec(prefix + "." + i + ".name");
      if (!grouped.containsKey(name)) grouped.put(name, new ArrayList<String>());
      grouped.get(name).add(spec(prefix + "." + i + ".value"));
    }
    Map<String, String[]> result = new LinkedHashMap<String, String[]>();
    for (Map.Entry<String, List<String>> entry : grouped.entrySet()) {
      result.put(entry.getKey(), entry.getValue().toArray(new String[0]));
    }
    return result;
  }

  private static String unhex(String hex) {
    byte[] bytes = new byte[hex.length() / 2];
    for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
    return new String(bytes, StandardCharsets.UTF_8);
  }

  private static long drain(InputStream in) throws IOException {
    byte[] buffer = new byte[4096];
    long total = 0;
    int n;
    while ((n = in.read(buffer)) > 0) total += n;
    return total;
  }

  /**
   * The agent's block: its block exception type (Java8RaspBlockException, OhMyRaspBlockException) in the cause
   * chain. The primary blocks a stream class through the JDK serialization filter, which surfaces as
   * InvalidClassException "filter status: REJECTED"; the driver installs no filter, so that rejection is the agent's.
   */
  private static boolean blockedBy(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause() == t ? null : t.getCause()) {
      if (t.getClass().getSimpleName().endsWith("RaspBlockException")) return true;
      if (t instanceof java.io.InvalidClassException && String.valueOf(t.getMessage()).startsWith("filter status: REJECTED")
          && System.getProperty("jdk.serialFilter") == null) return true;
    }
    return false;
  }

  /** The agent class on top of the stack of an exception in the cause chain, or null when none was thrown by agent code. */
  private static String thrownByAgent(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause() == t ? null : t.getCause()) {
      StackTraceElement[] trace = t.getStackTrace();
      if (trace.length > 0 && trace[0].getClassName().startsWith("io.ohmyrasp.agent.")) return trace[0].getClassName();
    }
    return null;
  }

  /** True when a type in the cause chain, or one of its superclasses, has the given simple name. */
  private static boolean endsWith(Throwable thrown, String simpleName) {
    for (Throwable t = thrown; t != null; t = t.getCause() == t ? null : t.getCause()) {
      for (Class<?> type = t.getClass(); type != null; type = type.getSuperclass()) {
        if (type.getSimpleName().equals(simpleName)) return true;
      }
    }
    return false;
  }

  private static String describe(Throwable thrown) {
    StringBuilder chain = new StringBuilder();
    for (Throwable t = thrown; t != null; t = t.getCause() == t ? null : t.getCause()) {
      if (chain.length() > 0) chain.append(" <- ");
      chain.append(t.getClass().getName()).append(": ").append(t.getMessage());
      if (chain.length() > 600) break;
    }
    return chain.toString();
  }

  private static String typeOf(Object value) {
    return value == null ? "null" : value.getClass().getName();
  }

  private static String clean(String value) {
    return value == null ? "" : value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
  }
}
