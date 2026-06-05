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

public final class Java8JndiTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_JNDI_LOOKUP =
      Method.getMethod("void beforeJndiLookup(java.lang.Object)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null
        || classfileBuffer == null
        || !"javax/naming/InitialContext".equals(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new JndiClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] JNDI transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class JndiClassVisitor extends ClassVisitor {
    JndiClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || !isLookupMethod(name, descriptor)) {
        return methodVisitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeStatic(HOOKS, BEFORE_JNDI_LOOKUP);
        }
      };
    }

    private static boolean isLookupMethod(String name, String descriptor) {
      if (!"lookup".equals(name) && !"lookupLink".equals(name)) {
        return false;
      }
      return descriptor.startsWith("(Ljava/lang/String;")
          || descriptor.startsWith("(Ljavax/naming/Name;");
    }
  }
}
