package io.ohmyrasp.agent.java8;

import io.ohmyrasp.agent.rules.product.elasticsearch.Lz4TransportVisitor;
import io.ohmyrasp.agent.net.HttpTransportVisitor;
import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import io.ohmyrasp.agent.sql.MyBatisSqlVisitor;
import io.ohmyrasp.agent.xml.XmlEntityOpenVisitor;
import io.ohmyrasp.agent.backport.RaspRuntime;
import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.jar.JarFile;
import java.lang.instrument.ClassFileTransformer;
import java.util.ArrayList;
import java.util.List;

public final class OhMyRaspJava8Agent {
  private OhMyRaspJava8Agent() {}

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
      requireBootstrapDefined("io.ohmyrasp.agent.java8.Java8RaspLine", "io.ohmyrasp.agent.backport.BackportLine",
          "io.ohmyrasp.agent.backport.RaspRuntime", "io.ohmyrasp.agent.backport.BackportHooks",
          "io.ohmyrasp.agent.java8.Java8RaspHooks", "io.ohmyrasp.agent.util.Preload");
      // Every class of ours a hook or a transformer can use, loaded and initialised now, not inside a hooked call.
      try {
        io.ohmyrasp.agent.util.Preload.classes(agentJar, "agent-java8", null);
      } catch (IOException e) {
        throw new IllegalStateException("cannot read the preload list of " + agentJar, e);
      }
      outsideJavaBase = typesOutsideJavaBase();
    }
    // Installs the line and starts the shared runtime here, before any transformer, so no hook does it on an app
    // thread. What can fail without a trace is done above; a failure from here on undoes the start.
    boolean startedHere = Java8RaspLine.start();
    List<ClassFileTransformer> registered = new ArrayList<ClassFileTransformer>();
    boolean hookMisses = false;
    try {
      String logPath = RaspRuntime.resolveLogPath();
      io.ohmyrasp.agent.xml.SystemArchiveOrigins.initialize(instrumentation);
      // The hook-miss report reads its table here, before any transformer: register() wraps each one in it. It is
      // held: misses of classes loaded during the start are queued, and its worker thread is created only once the
      // start has committed, below.
      hookMisses = io.ohmyrasp.agent.backport.BackportHookMisses.start();
      installTransformer(instrumentation, outsideJavaBase, registered);
      RaspRuntime.writeStartupLine(logPath, startupMessage(mode, agentArgs, instrumentation));
    } catch (RuntimeException | Error failure) {
      undo(instrumentation, registered, startedHere, hookMisses, failure);
      throw failure;
    }
    // Committed: nothing from here on can fail the start.
    io.ohmyrasp.agent.hookmiss.HookMisses.release();
  }

  /**
   * After a failure that follows the line's start: turns the hook-miss report off (no miss is taken any more, what
   * was queued is dropped and it never starts a worker), removes the transformers this start registered and, when
   * this call started the runtime, stops it, so the launcher's start-failed holds (no thread, no transformer, hooks
   * inactive). A failure on the way is added to {@code failure} as suppressed.
   */
  private static void undo(Instrumentation instrumentation, List<ClassFileTransformer> registered, boolean startedHere,
      boolean hookMisses, Throwable failure) {
    if (hookMisses) {
      try {
        io.ohmyrasp.agent.hookmiss.HookMisses.stop();
      } catch (RuntimeException | Error other) {
        failure.addSuppressed(other);
      }
    }
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
    ClassFileTransformer watched = io.ohmyrasp.agent.hookmiss.HookMissWatch.wrap(transformer);
    instrumentation.addTransformer(watched, canRetransform);
    registered.add(watched);
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
        + "\"sql_statement_hook\":\"installed\","
        + "\"base64_hook\":\"installed\","
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

  /** Appends the agent JAR to the bootstrap search and returns it. Throws when it cannot: the start must fail. */
  private static File appendSelfToBootstrap(Instrumentation instrumentation) {
    if (OhMyRaspJava8Agent.class.getProtectionDomain() == null
        || OhMyRaspJava8Agent.class.getProtectionDomain().getCodeSource() == null
        || OhMyRaspJava8Agent.class.getProtectionDomain().getCodeSource().getLocation() == null) {
      throw new IllegalStateException("[OHMYRASP-JAVA8] cannot find the agent JAR to append to the bootstrap search");
    }
    URL location =
        OhMyRaspJava8Agent.class.getProtectionDomain().getCodeSource().getLocation();
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
          "[OHMYRASP-JAVA8] unable to append agent jar to bootstrap search: " + e, e);
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
    ClassLoader own = OhMyRaspJava8Agent.class.getClassLoader();
    for (String className : classNames) {
      Class<?> found;
      try {
        found = Class.forName(className, false, own);
      } catch (ClassNotFoundException e) {
        throw new IllegalStateException(
            "[OHMYRASP-JAVA8] " + className + " is not on the bootstrap search after the append", e);
      }
      if (found.getClassLoader() != null) {
        throw new IllegalStateException("[OHMYRASP-JAVA8] " + className + " is already defined by "
            + found.getClassLoader() + ", not the bootstrap loader: the start would use a runtime the hooks do not");
      }
    }
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
    register(instrumentation, registered, new Java8ServletTransformer(), canRetransform);
    register(instrumentation, registered, new Java8SparkRestTransformer(), canRetransform);
    register(instrumentation, registered, new Java8YarnRestTransformer(), canRetransform);
    register(instrumentation, registered, new Java8ProcessTransformer(), canRetransform);
    register(instrumentation, registered, new Java8JndiTransformer(), canRetransform);
    register(instrumentation, registered, new Java8DeserializationTransformer(), canRetransform);
    register(instrumentation, registered, new Java8FastjsonTransformer(), canRetransform);
    register(instrumentation, registered, new Java8HessianTransformer(), canRetransform);
    register(instrumentation, registered, new Java8FileTransformer(), canRetransform);
    register(instrumentation, registered, new Java8MultipartUploadTransformer(), canRetransform);
    register(instrumentation, registered, new Java8RequestBodyTransformer(), canRetransform);
    register(instrumentation, registered, new Java8UrlTransformer(), canRetransform);
    register(instrumentation, registered, new Java8ArchiveTransformer(), canRetransform);
    register(instrumentation, registered, new Java8JdbcTransformer(), canRetransform);
    register(instrumentation, registered, new Java8ClassLoaderTransformer(), canRetransform);
    register(instrumentation, registered, new Java8ScriptEngineTransformer(), canRetransform);
    register(instrumentation, registered, new Java8JexlTransformer(), canRetransform);
    register(instrumentation, registered, new Java8ElTransformer(), canRetransform);
    register(instrumentation, registered, new Java8JavaCompilationTransformer(), canRetransform);
    register(instrumentation, registered, new Java8JmxTransformer(), canRetransform);
    register(instrumentation, registered, new Java8JwtTransformer(), canRetransform);
    register(instrumentation, registered, new Java8JavaBeansTransformer(), canRetransform);
    register(instrumentation, registered, new Java8XxeTransformer(), canRetransform);
    register(instrumentation, registered, new Java8ElasticLz4Transformer(), canRetransform);
    register(instrumentation, registered, new Java8Base64Transformer(), canRetransform);
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
    retransform(instrumentation, java.io.ObjectInputStream.class);
    retransformByName(instrumentation, "com.alibaba.fastjson.parser.ParserConfig");
    retransform(instrumentation, java.io.FileInputStream.class);
    retransform(instrumentation, java.io.FileOutputStream.class);
    retransform(instrumentation, java.io.RandomAccessFile.class);
    retransform(instrumentation, java.nio.file.Files.class);
    retransformByName(instrumentation, "sun.nio.fs.UnixChannelFactory");
    retransform(instrumentation, java.net.URL.class);
    retransform(instrumentation, java.util.zip.ZipEntry.class);
    retransform(instrumentation, driverManager);
    retransformByName(
        instrumentation, "org.apache.skywalking.oap.server.storage.plugin.jdbc.h2.dao.H2LogQueryDAO");
    retransformByName(
        instrumentation,
        "org.apache.skywalking.oap.server.storage.plugin.jdbc.common.dao.JDBCLogQueryDAO");
    retransform(instrumentation, java.net.URLClassLoader.class);
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
          || io.ohmyrasp.agent.http.RequestBodyVisitor.loadedTarget(loaded)
          || io.ohmyrasp.agent.file.ContainerDeploymentVisitor.matches(internalName)
          || io.ohmyrasp.agent.file.DirectoryListVisitor.matches(internalName) || io.ohmyrasp.agent.xml.AttachmentFileVisitor.matches(internalName) || XmlEntityOpenVisitor.matches(internalName) || MyBatisSqlVisitor.matches(internalName)
          || (HttpTransportVisitor.matches(internalName) && !"java/net/URL".equals(internalName))
          || JdbcSqlMethod.isJdbcImplementation(loaded)) {
        retransform(instrumentation, loaded);
      }
    }
    // The bootstrap provider can load while another transformer is running, after
    // the loaded-class snapshot. Revisit the platform owner outside that transform.
    retransformByName(instrumentation, java.io.File.separatorChar == '/'
        ? "sun.nio.fs.UnixFileSystemProvider" : "sun.nio.fs.WindowsFileSystemProvider");
    retransformByName(instrumentation, "com.sun.tools.javac.api.JavacTool");
    // Janino loaded before a dynamic attach: its compiler base class is hooked like javac.
    retransformByName(instrumentation, "org.codehaus.commons.compiler.Cookable");
    retransform(instrumentation, java.util.Base64.Decoder.class);
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
