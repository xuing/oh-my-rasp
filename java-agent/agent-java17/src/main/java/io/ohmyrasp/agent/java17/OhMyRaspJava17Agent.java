package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.rules.product.elasticsearch.Lz4TransportVisitor;
import io.ohmyrasp.agent.net.HttpTransportVisitor;
import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import io.ohmyrasp.agent.sql.MyBatisSqlVisitor;
import io.ohmyrasp.agent.xml.XmlEntityOpenVisitor;
import io.ohmyrasp.agent.backport.RaspRuntime;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.RandomAccessFile;
import java.lang.instrument.Instrumentation;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.lang.instrument.ClassFileTransformer;
import java.util.ArrayList;
import java.util.List;

public final class OhMyRaspJava17Agent {
  private OhMyRaspJava17Agent() {}

  public static void premain(String agentArgs, Instrumentation instrumentation) {
    install("premain", agentArgs, instrumentation);
  }

  public static void agentmain(String agentArgs, Instrumentation instrumentation) {
    install("agentmain", agentArgs, instrumentation);
  }

  private static void install(String mode, String agentArgs, Instrumentation instrumentation) {
    Class<?>[] outsideJavaBase = null;
    if (instrumentation != null) {
      // The transformers inject calls that the bootstrap loader resolves: without the JAR on its search the start
      // fails here, before any transformer is registered, and the launcher reports it.
      File agentJar = appendSelfToBootstrap(instrumentation);
      requireBootstrapDefined("io.ohmyrasp.agent.java17.Java17RaspLine", "io.ohmyrasp.agent.backport.BackportLine",
          "io.ohmyrasp.agent.backport.RaspRuntime", "io.ohmyrasp.agent.backport.BackportHooks",
          "io.ohmyrasp.agent.java17.Java17RaspHooks", "io.ohmyrasp.agent.util.Preload");
      // Every class of ours a hook or a transformer can use, loaded and initialised now, not inside a hooked call.
      try {
        io.ohmyrasp.agent.util.Preload.classes(agentJar, "agent-java17", null);
      } catch (IOException e) {
        throw new IllegalStateException("cannot read the preload list of " + agentJar, e);
      }
      outsideJavaBase = typesOutsideJavaBase();
    }
    // Installs the line and starts the shared runtime here, before any transformer, so no hook does it on an app
    // thread. What can fail without a trace is done above; a failure from here on undoes the start.
    boolean startedHere = Java17RaspLine.start();
    List<ClassFileTransformer> registered = new ArrayList<ClassFileTransformer>();
    try {
      String logPath = RaspRuntime.resolveLogPath();
      io.ohmyrasp.agent.xml.SystemArchiveOrigins.initialize(instrumentation);
      installTransformer(instrumentation, outsideJavaBase, registered);
      RaspRuntime.writeStartupLine(logPath, startupMessage(mode, agentArgs, instrumentation));
    } catch (RuntimeException | Error failure) {
      undo(instrumentation, registered, startedHere, failure);
      throw failure;
    }
  }

  /**
   * After a failure that follows the line's start: removes the transformers this start registered and, when this
   * call started the runtime, stops it, so the launcher's start-failed holds (no thread, no transformer, hooks
   * inactive). A failure on the way is added to {@code failure} as suppressed.
   */
  private static void undo(Instrumentation instrumentation, List<ClassFileTransformer> registered, boolean startedHere,
      Throwable failure) {
    for (int i = registered.size() - 1; i >= 0; i--) {
      try {
        instrumentation.removeTransformer(registered.get(i));
      } catch (RuntimeException | Error other) {
        failure.addSuppressed(other);
      }
    }
    if (startedHere) {
      try {
        RaspRuntime.stop();
      } catch (RuntimeException | Error other) {
        failure.addSuppressed(other);
      }
    }
  }

  /**
   * The types outside java.base that the transformers or the retransform list use, resolved before the line starts.
   * A type this JVM cannot link (java.sql is not visible to the bootstrap loader on Java 9 and later) then fails the
   * start before anything is started or registered.
   */
  private static Class<?>[] typesOutsideJavaBase() {
    return new Class<?>[] {
      javax.naming.InitialContext.class,
      java.sql.DriverManager.class,
      javax.script.AbstractScriptEngine.class,
      java.beans.Expression.class,
      java.beans.Statement.class,
    };
  }

  private static void register(Instrumentation instrumentation, List<ClassFileTransformer> registered,
      ClassFileTransformer transformer, boolean canRetransform) {
    instrumentation.addTransformer(transformer, canRetransform);
    registered.add(transformer);
  }

  /** Appends the agent JAR to the bootstrap search and returns it. Throws when it cannot: the start must fail. */
  private static File appendSelfToBootstrap(Instrumentation instrumentation) {
    if (OhMyRaspJava17Agent.class.getProtectionDomain() == null
        || OhMyRaspJava17Agent.class.getProtectionDomain().getCodeSource() == null
        || OhMyRaspJava17Agent.class.getProtectionDomain().getCodeSource().getLocation() == null) {
      throw new IllegalStateException("[OHMYRASP-JAVA17] cannot find the agent JAR to append to the bootstrap search");
    }
    URL location =
        OhMyRaspJava17Agent.class.getProtectionDomain().getCodeSource().getLocation();
    File agentFile;
    try {
      agentFile = new File(location.toURI());
    } catch (URISyntaxException e) {
      agentFile = new File(location.getPath());
    } catch (IllegalArgumentException e) {
      agentFile = new File(location.getPath());
    }
    try {
      instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(agentFile));
    } catch (IOException | RuntimeException e) {
      throw new IllegalStateException(
          "[OHMYRASP-JAVA17] unable to append agent jar to bootstrap search: " + e, e);
    }
    return agentFile;
  }

  /**
   * Throws unless each class, looked up through this entry's own loader as the start is about to use it, is the
   * one the bootstrap loader defined from the appended JAR, which the injected calls reach. A copy that another
   * loader defined first (the agent JAR is also on the application class path and the application used it, or an
   * earlier attach did) would start a runtime that the hooks never see.
   */
  private static void requireBootstrapDefined(String... classNames) {
    ClassLoader own = OhMyRaspJava17Agent.class.getClassLoader();
    for (String className : classNames) {
      Class<?> found;
      try {
        found = Class.forName(className, false, own);
      } catch (ClassNotFoundException e) {
        throw new IllegalStateException(
            "[OHMYRASP-JAVA17] " + className + " is not on the bootstrap search after the append", e);
      }
      if (found.getClassLoader() != null) {
        throw new IllegalStateException("[OHMYRASP-JAVA17] " + className + " is already defined by "
            + found.getClassLoader() + ", not the bootstrap loader: the start would use a runtime the hooks do not");
      }
    }
  }

  private static String startupMessage(
      String mode, String agentArgs, Instrumentation instrumentation) {
    return "{"
        + "\"event\":\"ohmyrasp-java17-agent-start\","
        + "\"mode\":\"" + json(mode) + "\","
        + "\"java_version\":\"" + json(System.getProperty("java.version", "unknown")) + "\","
        + "\"java_vendor\":\"" + json(System.getProperty("java.vendor", "unknown")) + "\","
        + "\"agent_args\":\"" + json(agentArgs == null ? "" : agentArgs) + "\","
        + "\"startup_probe\":\"installed\","
        + "\"request_hook\":\"installed\","
        + "\"remote_job_hook\":\"installed\","
        + "\"command_hook\":\"installed\","
        + "\"jndi_hook\":\"installed\","
        + "\"deserialization_hook\":\"installed\","
        + "\"hessian_hook\":\"installed\","
        + "\"file_hook\":\"installed\","
        + "\"upload_hook\":\"installed\","
        + "\"archive_hook\":\"installed\","
        + "\"url_hook\":\"installed\","
        + "\"classloader_hook\":\"installed\","
        + "\"jdbc_hook\":\"installed\","
        + "\"sql_identifier_hook\":\"installed\","
        + "\"sql_statement_hook\":\"installed\","
        + "\"base64_hook\":\"installed\","
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

  private static void installTransformer(Instrumentation instrumentation, Class<?>[] outsideJavaBase,
      List<ClassFileTransformer> registered) {
    if (instrumentation == null) {
      return;
    }
    Class<?> initialContext = outsideJavaBase[0];
    Class<?> driverManager = outsideJavaBase[1];
    Class<?> scriptEngine = outsideJavaBase[2];
    Class<?> beanExpression = outsideJavaBase[3];
    Class<?> beanStatement = outsideJavaBase[4];
    boolean canRetransform = instrumentation.isRetransformClassesSupported();
    register(instrumentation, registered, new Java17ServletTransformer(), canRetransform);
    register(instrumentation, registered, new Java17SparkRestTransformer(), canRetransform);
    register(instrumentation, registered, new Java17YarnRestTransformer(), canRetransform);
    register(instrumentation, registered, new Java17ProcessTransformer(), canRetransform);
    register(instrumentation, registered, new Java17JndiTransformer(), canRetransform);
    register(instrumentation, registered, new Java17DeserializationTransformer(), canRetransform);
    register(instrumentation, registered, new Java17FastjsonTransformer(), canRetransform);
    register(instrumentation, registered, new Java17HessianTransformer(), canRetransform);
    register(instrumentation, registered, new Java17FileTransformer(), canRetransform);
    register(instrumentation, registered, new Java17MultipartUploadTransformer(), canRetransform);
    register(instrumentation, registered, new Java17ArchiveTransformer(), canRetransform);
    register(instrumentation, registered, new Java17UrlTransformer(), canRetransform);
    register(instrumentation, registered, new Java17ClassLoaderTransformer(), canRetransform);
    register(instrumentation, registered, new Java17JdbcTransformer(), canRetransform);
    register(instrumentation, registered, new Java17ScriptEngineTransformer(), canRetransform);
    register(instrumentation, registered, new Java17JexlTransformer(), canRetransform);
    register(instrumentation, registered, new Java17ElTransformer(), canRetransform);
    register(instrumentation, registered, new Java17JavaCompilationTransformer(), canRetransform);
    register(instrumentation, registered, new Java17JmxTransformer(), canRetransform);
    register(instrumentation, registered, new Java17JwtTransformer(), canRetransform);
    register(instrumentation, registered, new Java17JavaBeansTransformer(), canRetransform);
    register(instrumentation, registered, new Java17XxeTransformer(), canRetransform);
    register(instrumentation, registered, new Java17ElasticLz4Transformer(), canRetransform);
    register(instrumentation, registered, new Java17Base64Transformer(), canRetransform);
    if (!canRetransform) {
      return;
    }
    retransformByName(instrumentation, "javax.servlet.http.HttpServlet");
    retransformByName(instrumentation, "jakarta.servlet.http.HttpServlet");
    retransformByName(instrumentation, "org.apache.shiro.web.servlet.AbstractShiroFilter");
    retransformByName(instrumentation, "org.glassfish.jersey.server.ServerRuntime");
    retransformByName(instrumentation, "org.apache.catalina.authenticator.AuthenticatorBase");
    retransformByName(instrumentation, "org.apache.catalina.core.StandardWrapperValve");
    if (io.ohmyrasp.agent.process.ProcessLaunchVisitor.platformHandoff()) retransformByName(instrumentation, "java.lang.ProcessImpl");
    retransform(instrumentation, ProcessBuilder.class);
    retransform(instrumentation, Runtime.class);
    retransform(instrumentation, initialContext);
    retransform(instrumentation, ObjectInputStream.class);
    retransformByName(instrumentation, "com.alibaba.fastjson.parser.ParserConfig");
    retransform(instrumentation, File.class);
    retransform(instrumentation, FileInputStream.class);
    retransform(instrumentation, FileOutputStream.class);
    retransform(instrumentation, RandomAccessFile.class);
    retransform(instrumentation, java.nio.file.Files.class);
    retransformByName(instrumentation, "sun.nio.fs.UnixChannelFactory");
    retransform(instrumentation, ZipEntry.class);
    retransform(instrumentation, URL.class);
    retransform(instrumentation, URLClassLoader.class);
    retransform(instrumentation, driverManager);
    retransformByName(
        instrumentation, "org.apache.skywalking.oap.server.storage.plugin.jdbc.h2.dao.H2LogQueryDAO");
    retransformByName(
        instrumentation,
        "org.apache.skywalking.oap.server.storage.plugin.jdbc.common.dao.JDBCLogQueryDAO");
    retransform(instrumentation, scriptEngine);
    retransformByName(instrumentation, "org.apache.commons.jexl3.internal.Script");
    retransformByName(instrumentation, "org.apache.commons.jexl2.ExpressionImpl");
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
    retransform(instrumentation, beanExpression);
    retransform(instrumentation, beanStatement);
    retransformByName(instrumentation, "com.sun.tools.javac.api.JavacTool");
    retransformByName(instrumentation, io.ohmyrasp.agent.jmx.JmxDispatchVisitor.TARGET.replace('/', '.'));

    retransformByName(instrumentation, "com.sun.beans.decoder.DocumentHandler");
    Class<?>[] loadedClasses = instrumentation.getAllLoadedClasses();
    java.util.Set<Class<?>> multipartOwners = io.ohmyrasp.agent.http.MultipartFilename.loadedOwners(loadedClasses);
    for (Class<?> loaded : loadedClasses) {
      String internalName = loaded.getName().replace('.', '/');
      if (io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor.matches(internalName)
          || io.ohmyrasp.agent.rules.product.activemq.OpenWireThrowableVisitor.matches(internalName)
          || io.ohmyrasp.agent.rules.product.spring.SpringProcessVisitor.matches(internalName)
          || io.ohmyrasp.agent.loading.CodebaseVisitor.RMI_ROUTER.equals(internalName)
          || io.ohmyrasp.agent.loading.CodebaseVisitor.directoryResource(internalName)
          || io.ohmyrasp.agent.jmx.JmxAttributeReadVisitor.OWNER.equals(internalName)
          || Lz4TransportVisitor.OWNER.equals(internalName)
          || io.ohmyrasp.agent.naming.JndiLookupVisitor.URL_CONTEXT.equals(internalName)
          || io.ohmyrasp.agent.naming.JndiLookupVisitor.LOGIN_MODULE.equals(internalName)
          || io.ohmyrasp.agent.rules.product.yarn.YarnSubmitVisitor.OWNER.equals(internalName)
          || io.ohmyrasp.agent.rules.product.spark.SparkSubmitVisitor.OWNER.equals(internalName)
          || io.ohmyrasp.agent.rules.product.dataease.FilterVerificationVisitor.OWNER.equals(internalName)
          || multipartOwners.contains(loaded) || io.ohmyrasp.agent.http.MultipartFilenameVisitor.known(internalName, true)
          || io.ohmyrasp.agent.file.DirectoryListVisitor.matches(internalName) || io.ohmyrasp.agent.xml.AttachmentFileVisitor.matches(internalName) || XmlEntityOpenVisitor.matches(internalName) || MyBatisSqlVisitor.matches(internalName)
          || (HttpTransportVisitor.matches(internalName) && !"java/net/URL".equals(internalName))
          || JdbcSqlMethod.isJdbcImplementation(loaded)) {
        retransform(instrumentation, loaded);
      }
    }
    retransform(instrumentation, java.util.Base64.Decoder.class);
  }

  private static void retransform(Instrumentation instrumentation, Class<?> type) {
    try {
      if (instrumentation.isModifiableClass(type)) {
        instrumentation.retransformClasses(type);
      }
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] unable to retransform " + type.getName() + ": " + throwable);
      }
    }
  }

  private static void retransformByName(Instrumentation instrumentation, String className) {
    try {
      Class<?> type = Class.forName(className, false, ClassLoader.getSystemClassLoader());
      retransform(instrumentation, type);
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] unable to find or retransform " + className + ": " + throwable);
      }
    }
  }

  private static String json(String value) {
    var builder = new StringBuilder(value.length() + 16);
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> builder.append("\\\"");
        case '\\' -> builder.append("\\\\");
        case '\b' -> builder.append("\\b");
        case '\f' -> builder.append("\\f");
        case '\n' -> builder.append("\\n");
        case '\r' -> builder.append("\\r");
        case '\t' -> builder.append("\\t");
        default -> {
          if (ch < 0x20) {
            builder.append(String.format("\\u%04x", Integer.valueOf(ch)));
          } else {
            builder.append(ch);
          }
        }
      }
    }
    return builder.toString();
  }
}
