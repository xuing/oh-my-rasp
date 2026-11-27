package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
              new XxeHookModule()));

  private final List<HookModule> modules;
  private final Map<String, HookModule> byName = new HashMap<>();

  private HookRegistry(List<HookModule> modules) {
    this.modules = List.copyOf(modules);
    for (HookModule module : this.modules) {
      byName.put(module.getClass().getSimpleName(), module);
    }
  }

  /** The module of this registry with that simple class name, as the recorded hook maps name it, or null. */
  HookModule module(String simpleName) {
    return byName.get(simpleName);
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
    return visitMethod(className, methodVisitor, access, methodName, descriptor, jdbcImplementation, null);
  }

  /**
   * The first module that wraps the method wins. With a hook-miss {@code probe}, the modules are handed a counting
   * visitor instead of {@code methodVisitor}, and the winner's visitor is counted on both sides.
   */
  MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor, boolean jdbcImplementation, HookMissProbe probe) {
    io.ohmyrasp.agent.hookmiss.AgentCalls.Counter output = probe == null ? null : probe.output(methodVisitor);
    MethodVisitor target = output == null ? methodVisitor : output;
    for (HookModule module : modules) {
      boolean jdbcMethod = jdbcImplementation && module instanceof SqlHookModule
          && (access & Opcodes.ACC_STATIC) == 0
          && (JdbcSqlMethod.preparesSql(methodName, descriptor) || JdbcSqlMethod.executesSql(methodName, descriptor));
      boolean multipart = module instanceof MultipartUploadHookModule
          && io.ohmyrasp.agent.http.MultipartFilenameVisitor.specificGetter(methodName, descriptor);
      if (!jdbcMethod && !multipart && !module.matchesClass(className)) {
        continue;
      }
      MethodVisitor next = module.visitMethod(className, target, access, methodName, descriptor);
      if (next != target) {
        return output == null ? next : probe.watch(module, next, output);
      }
    }
    return methodVisitor;
  }
}
