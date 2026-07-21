package io.ohmyrasp.agent.java8;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

public final class OhMyRaspJava8Agent {
  private OhMyRaspJava8Agent() {}

  public static void premain(String agentArgs, Instrumentation instrumentation) {
    install("premain", agentArgs, instrumentation);
  }

  public static void agentmain(String agentArgs, Instrumentation instrumentation) {
    install("agentmain", agentArgs, instrumentation);
  }

  private static void install(String mode, String agentArgs, Instrumentation instrumentation) {
    appendSelfToBootstrap(instrumentation);
    installTransformer(instrumentation);
    String logPath = firstNonBlank(
        System.getProperty("ohmyrasp.java8.log"),
        System.getProperty("ohmyrasp.log"),
        System.getenv("OHMYRASP_LOG"));
    if (logPath == null) {
      System.err.println(startupMessage(mode, agentArgs, instrumentation));
      return;
    }
    appendLine(logPath, startupMessage(mode, agentArgs, instrumentation));
  }

  private static String startupMessage(
      String mode, String agentArgs, Instrumentation instrumentation) {
    return "{"
        + "\"event\":\"ohmyrasp-java8-agent-start\","
        + "\"mode\":\"" + json(mode) + "\","
        + "\"java_version\":\"" + json(System.getProperty("java.version", "unknown")) + "\","
        + "\"java_vendor\":\"" + json(System.getProperty("java.vendor", "unknown")) + "\","
        + "\"agent_args\":\"" + json(agentArgs == null ? "" : agentArgs) + "\","
        + "\"request_hook\":\"installed\","
        + "\"remote_job_hook\":\"installed\","
        + "\"command_hook\":\"installed\","
        + "\"jndi_hook\":\"installed\","
        + "\"deserialization_hook\":\"installed\","
        + "\"hessian_hook\":\"installed\","
        + "\"file_hook\":\"installed\","
        + "\"upload_hook\":\"installed\","
        + "\"url_hook\":\"installed\","
        + "\"archive_hook\":\"installed\","
        + "\"jdbc_hook\":\"installed\","
        + "\"sql_identifier_hook\":\"installed\","
        + "\"classloader_hook\":\"installed\","
        + "\"script_hook\":\"installed\","
        + "\"jexl_hook\":\"installed\","
        + "\"el_hook\":\"installed\","
        + "\"java_compile_hook\":\"installed\","
        + "\"jaas_hook\":\"installed\","
        + "\"jmx_hook\":\"installed\","
        + "\"jwt_hook\":\"installed\","
        + "\"java_beans_hook\":\"installed\","
        + "\"xxe_hook\":\"installed\","
        + "\"instrumentation\":\"" + (instrumentation == null ? "missing" : "available") + "\""
        + "}";
  }

  private static void appendSelfToBootstrap(Instrumentation instrumentation) {
    if (instrumentation == null) {
      return;
    }
    try {
      if (OhMyRaspJava8Agent.class.getProtectionDomain() == null
          || OhMyRaspJava8Agent.class.getProtectionDomain().getCodeSource() == null
          || OhMyRaspJava8Agent.class.getProtectionDomain().getCodeSource().getLocation() == null) {
        return;
      }
      String path =
          OhMyRaspJava8Agent.class.getProtectionDomain().getCodeSource().getLocation().getPath();
      instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(new File(path)));
    } catch (IOException e) {
      System.err.println("[OHMYRASP-JAVA8] unable to append agent jar to bootstrap search: " + e);
    } catch (RuntimeException e) {
      System.err.println("[OHMYRASP-JAVA8] unable to append agent jar to bootstrap search: " + e);
    }
  }

  private static void installTransformer(Instrumentation instrumentation) {
    if (instrumentation == null) {
      return;
    }
    boolean canRetransform = instrumentation.isRetransformClassesSupported();
    instrumentation.addTransformer(new Java8ServletTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8SparkRestTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8YarnRestTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8ProcessTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8JndiTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8DeserializationTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8FastjsonTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8HessianTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8FileTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8MultipartUploadTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8UrlTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8ArchiveTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8JdbcTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8ClassLoaderTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8ScriptEngineTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8JexlTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8ElTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8JavaCompilationTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8JaasTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8JmxTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8JwtTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8JavaBeansTransformer(), canRetransform);
    instrumentation.addTransformer(new Java8XxeTransformer(), canRetransform);
    if (!canRetransform) {
      return;
    }
    retransformByName(instrumentation, "javax.servlet.http.HttpServlet");
    retransformByName(instrumentation, "jakarta.servlet.http.HttpServlet");
    retransformByName(instrumentation, "org.apache.shiro.web.servlet.AbstractShiroFilter");
    retransformByName(instrumentation, "org.glassfish.jersey.server.ServerRuntime");
    retransformByName(instrumentation, "org.apache.catalina.authenticator.AuthenticatorBase");
    retransformByName(instrumentation, "org.apache.catalina.core.StandardWrapperValve");
    retransformByName(instrumentation, "org.apache.spark.deploy.rest.SubmitRequestServlet");
    retransformByName(instrumentation, "org.apache.spark.deploy.rest.StandaloneSubmitRequestServlet");
    retransformByName(instrumentation, "org.apache.hadoop.yarn.server.resourcemanager.webapp.RMWebServices");
    retransform(instrumentation, ProcessBuilder.class);
    retransform(instrumentation, Runtime.class);
    retransform(instrumentation, javax.naming.InitialContext.class);
    retransform(instrumentation, java.io.ObjectInputStream.class);
    retransformByName(instrumentation, "sun.rmi.server.MarshalInputStream");
    retransformByName(instrumentation, "com.alibaba.fastjson.parser.ParserConfig");
    retransformByName(instrumentation, "com.caucho.hessian.io.SerializerFactory");
    retransform(instrumentation, java.io.File.class);
    retransform(instrumentation, java.io.FileInputStream.class);
    retransform(instrumentation, java.io.FileOutputStream.class);
    retransform(instrumentation, java.io.RandomAccessFile.class);
    retransform(instrumentation, java.nio.file.Files.class);
    retransformByName(instrumentation, "javax.servlet.http.Part");
    retransformByName(instrumentation, "jakarta.servlet.http.Part");
    retransformByName(instrumentation, "org.apache.catalina.core.ApplicationPart");
    retransformByName(instrumentation, "io.undertow.servlet.spec.PartImpl");
    retransformByName(instrumentation, "org.apache.commons.fileupload.disk.DiskFileItem");
    retransformByName(instrumentation, "org.eclipse.jetty.util.MultiPartInputStreamParser$MultiPart");
    retransformByName(instrumentation, "org.eclipse.jetty.server.MultiPartFormInputStream$MultiPart");
    retransformByName(instrumentation, "org.springframework.web.multipart.MultipartFile");
    retransformByName(instrumentation, "org.springframework.web.multipart.commons.CommonsMultipartFile");
    retransformByName(
        instrumentation,
        "org.springframework.web.multipart.support.StandardMultipartHttpServletRequest$StandardMultipartFile");
    retransformByName(instrumentation, "org.springframework.mock.web.MockMultipartFile");
    retransform(instrumentation, java.net.URL.class);
    retransform(instrumentation, java.util.zip.ZipEntry.class);
    retransform(instrumentation, java.sql.DriverManager.class);
    retransformByName(
        instrumentation, "org.apache.skywalking.oap.server.storage.plugin.jdbc.h2.dao.H2LogQueryDAO");
    retransform(instrumentation, java.net.URLClassLoader.class);
    retransform(instrumentation, java.rmi.server.RMIClassLoader.class);
    retransform(instrumentation, javax.script.AbstractScriptEngine.class);
    retransformByName(instrumentation, "org.apache.commons.jexl3.internal.Script");
    retransformByName(instrumentation, "org.apache.commons.jexl2.ExpressionImpl");
    retransformByName(instrumentation, "org.apache.commons.jexl2.ScriptImpl");
    retransformByName(instrumentation, "org.apache.commons.jexl.ExpressionImpl");
    retransformByName(instrumentation, "org.apache.commons.jexl.Script");
    retransformByName(instrumentation, "com.sun.el.ValueExpressionImpl");
    retransformByName(instrumentation, "com.sun.el.MethodExpressionImpl");
    retransformByName(instrumentation, "org.apache.el.ValueExpressionImpl");
    retransformByName(instrumentation, "org.apache.el.MethodExpressionImpl");
    retransformByName(instrumentation, "de.odysseus.el.TreeValueExpression");
    retransformByName(instrumentation, "de.odysseus.el.TreeMethodExpression");
    retransformByName(instrumentation, "org.jboss.el.ValueExpressionImpl");
    retransformByName(instrumentation, "org.jboss.el.MethodExpressionImpl");
    retransform(instrumentation, javax.security.auth.login.AppConfigurationEntry.class);
    retransform(instrumentation, java.beans.Expression.class);
    retransform(instrumentation, java.beans.Statement.class);
    retransformByName(instrumentation, "com.sun.jmx.mbeanserver.JmxMBeanServer");
    retransformByName(instrumentation, "com.auth0.jwt.JWTVerifier");
    retransformByName(instrumentation, "com.auth0.jwt.algorithms.HMACAlgorithm");
    retransformByName(instrumentation, "com.auth0.jwt.algorithms.RSAAlgorithm");
    retransformByName(instrumentation, "com.auth0.jwt.algorithms.ECDSAAlgorithm");
    retransformByName(instrumentation, "com.sun.beans.decoder.DocumentHandler");
    retransformByName(instrumentation, "com.sun.org.apache.xerces.internal.impl.XMLEntityManager");
    retransformByName(instrumentation, "com.sun.tools.javac.api.JavacTool");
  }

  private static void retransform(Instrumentation instrumentation, Class<?> type) {
    try {
      if (instrumentation.isModifiableClass(type)) {
        instrumentation.retransformClasses(type);
      }
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] unable to retransform " + type.getName() + ": " + throwable);
      }
    }
  }

  private static void retransformByName(Instrumentation instrumentation, String className) {
    try {
      Class<?> type = Class.forName(className, false, ClassLoader.getSystemClassLoader());
      retransform(instrumentation, type);
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] unable to find or retransform " + className + ": " + throwable);
      }
    }
  }

  private static void appendLine(String logPath, String message) {
    File target = new File(logPath);
    File parent = target.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      System.err.println("ohmyrasp java8 agent could not create log directory: " + parent);
      return;
    }
    FileWriter writer = null;
    try {
      writer = new FileWriter(target, true);
      writer.write(message);
      writer.write(System.lineSeparator());
    } catch (IOException e) {
      System.err.println("ohmyrasp java8 agent could not write startup event: " + e);
    } finally {
      if (writer != null) {
        try {
          writer.close();
        } catch (IOException ignored) {
          // Nothing useful to do during agent startup.
        }
      }
    }
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
}
