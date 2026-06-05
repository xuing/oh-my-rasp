package io.ohmyrasp.agent.java8;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public final class Java8XxeTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_XML_ENTITY =
      Method.getMethod("void beforeXmlEntity(java.lang.String, java.lang.Object)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null
        || classfileBuffer == null
        || !"com/sun/org/apache/xerces/internal/impl/XMLEntityManager".equals(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new XxeClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] XXE transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class XxeClassVisitor extends ClassVisitor {
    XxeClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || !"setupCurrentEntity".equals(name)) {
        return methodVisitor;
      }
      if (descriptor.startsWith("(Ljava/lang/String;")) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            loadArg(1);
            invokeStatic(HOOKS, BEFORE_XML_ENTITY);
          }
        };
      }
      if (descriptor.startsWith("(ZLjava/lang/String;")) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(1);
            loadArg(2);
            invokeStatic(HOOKS, BEFORE_XML_ENTITY);
          }
        };
      }
      return methodVisitor;
    }
  }
}
