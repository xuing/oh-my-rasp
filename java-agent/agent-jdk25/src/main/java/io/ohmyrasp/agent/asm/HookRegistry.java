package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import java.util.List;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public final class HookRegistry {
  private static final HookRegistry DEFAULT =
      new HookRegistry(
          List.of(
              new ProcessHookModule(),
              new Base64HookModule(),
              new ElasticLz4HookModule(),
              new FileHookModule(),
              new ArchiveHookModule(),
              new NetworkHookModule(),
              new JndiHookModule(),
              new ClassLoaderHookModule(),
              new SpringConfigHookModule(),
              new JmxHookModule(),
              new ArgumentParserHookModule(),
              new ExpressionHookModule(),
              new JavaCompilationHookModule(),
              new PolymorphicDeserializationHookModule(),
              new RmiRegistryHookModule(),
              new ObjectInputStreamHookModule(),
              new OpenWireHookModule(),
              new HttpInvokerHookModule(),
              new HessianHookModule(),
              new XmlRpcHookModule(),
              new JavaBeansHookModule(),
              new SessionHookModule(),
              new SqlHookModule(),
              new ServletHookModule(),
              new JwtHookModule(),
              new SparkSubmitHookModule(),
              new YarnSubmitHookModule(),
              new MultipartUploadHookModule(),
              new XmlAttachmentHookModule(),
              new XxeHookModule(),
              new RequestBodyHookModule()));

  private final List<HookModule> modules;

  private HookRegistry(List<HookModule> modules) {
    this.modules = List.copyOf(modules);
  }

  public static HookRegistry defaults() {
    return DEFAULT;
  }

  public boolean isDirectTarget(String className) {
    if (className == null || className.isBlank()) {
      return false;
    }
    String internalName = className.replace('.', '/');
    for (HookModule module : modules) {
      if (module.matchesClass(internalName)) {
        return true;
      }
    }
    return false;
  }

  public boolean isRetransformTarget(String className) {
    return isDirectTarget(className);
  }

  MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor, boolean jdbcImplementation) {
    return visitMethod(className, null, true, methodVisitor, access, methodName, descriptor, jdbcImplementation);
  }

  /**
   * {@code superName} is the class's direct superclass; {@code bodyHooks} is false for a class whose loader
   * cannot see the agent (see RequestBodyVisitor.loaderSeesAgent), which the request-body module leaves alone.
   */
  MethodVisitor visitMethod(
      String className,
      String superName,
      boolean bodyHooks,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor, boolean jdbcImplementation) {
    for (HookModule module : modules) {
      if (module instanceof RequestBodyHookModule) {
        if (!bodyHooks || !module.matchesClass(className, superName)) continue;
        MethodVisitor next = module.visitMethod(className, methodVisitor, access, methodName, descriptor);
        if (next != methodVisitor) return next;
        continue;
      }
      boolean jdbcMethod = jdbcImplementation && module instanceof SqlHookModule
          && (access & Opcodes.ACC_STATIC) == 0
          && (JdbcSqlMethod.preparesSql(methodName, descriptor) || JdbcSqlMethod.executesSql(methodName, descriptor));
      boolean multipart = module instanceof MultipartUploadHookModule
          && io.ohmyrasp.agent.http.MultipartFilenameVisitor.specificGetter(methodName, descriptor);
      if (!jdbcMethod && !multipart && !module.matchesClass(className)) {
        continue;
      }
      MethodVisitor next = module.visitMethod(className, methodVisitor, access, methodName, descriptor);
      if (next != methodVisitor) {
        return next;
      }
    }
    return methodVisitor;
  }
}
