package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
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
    if (className == null || classfileBuffer == null || className.startsWith("io/ohmyrasp/agent/")) {
      return null;
    }
    try {
      boolean loadedJdbc = JdbcSqlMethod.isJdbcImplementation(classBeingRedefined);
      boolean skip = shouldSkip(className);
      if (skip && !loadedJdbc && loader == null) return null;
      ClassReader reader = new ClassReader(classfileBuffer);
      boolean jdbc = loadedJdbc || JdbcSqlMethod.directJdbcInterface(reader.getInterfaces());
      boolean multipartCaller = loader != null && io.ohmyrasp.agent.http.MultipartFilenameVisitor.multipartCaller(reader);
      if (skip && !jdbc && !multipartCaller && !io.ohmyrasp.agent.http.MultipartFilenameVisitor.mentionsGetter(reader)) return null;
      if (Boolean.getBoolean("ohmyrasp.debug") && registry.isDirectTarget(className)) {
        System.err.println("[OHMYRASP] transforming hook target " + className);
      }
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      ClassVisitor visitor = new HookClassVisitor(className, registry, writer, jdbc);
      if (multipartCaller) visitor = new io.ohmyrasp.agent.http.MultipartCollectionVisitor(visitor,
          org.objectweb.asm.Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks"));
      visitor = new SqlCallsiteClassVisitor(reader, visitor);
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
    if (className.startsWith("org/objectweb/asm/")
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
