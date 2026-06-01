package io.ohmyrasp.agent.asm;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

public final class OhMyRaspTransformer implements ClassFileTransformer {
  private final HookRegistry registry;

  public OhMyRaspTransformer() {
    this(HookRegistry.defaults());
  }

  public OhMyRaspTransformer(HookRegistry registry) {
    this.registry = registry;
  }

  @Override
  public byte[] transform(
      Module module,
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || shouldSkip(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      ClassVisitor visitor = new SqlCallsiteClassVisitor(writer);
      visitor = new HookClassVisitor(className, registry, visitor);
      reader.accept(visitor, ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP] transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private boolean shouldSkip(String className) {
    if (className.startsWith("io/ohmyrasp/agent/")
        || className.startsWith("org/objectweb/asm/")
        || className.startsWith("java/lang/instrument/")
        || className.startsWith("jdk/internal/reflect/")
        || className.startsWith("sun/reflect/")) {
      return true;
    }
    return isJdkClass(className) && !registry.isDirectTarget(className);
  }

  private static boolean isJdkClass(String className) {
    return className.startsWith("java/")
        || className.startsWith("javax/")
        || className.startsWith("jdk/")
        || className.startsWith("sun/")
        || className.startsWith("com/sun/");
  }

  static int api() {
    return Opcodes.ASM9;
  }
}
