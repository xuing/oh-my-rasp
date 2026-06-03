package io.ohmyrasp.agent.asm;

import java.util.List;
import java.util.Locale;
import org.objectweb.asm.MethodVisitor;

public final class HookRegistry {
  private static final HookRegistry DEFAULT =
      new HookRegistry(
          List.of(
              new ProcessHookModule(),
              new FileHookModule(),
              new ArchiveHookModule(),
              new NetworkHookModule(),
              new JndiHookModule(),
              new JaasHookModule(),
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
              new MultipartUploadHookModule(),
              new XmlAttachmentHookModule(),
              new XxeHookModule()));

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
      String descriptor) {
    for (HookModule module : modules) {
      if (!module.matchesClass(className)) {
        continue;
      }
      MethodVisitor next = module.visitMethod(className, methodVisitor, access, methodName, descriptor);
      if (next != methodVisitor) {
        return next;
      }
    }
    return methodVisitor;
  }

  static boolean methodNameContains(String methodName, String needle) {
    return methodName != null && methodName.toLowerCase(Locale.ROOT).contains(needle);
  }
}
