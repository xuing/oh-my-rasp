package io.ohmyrasp.agent.java17;

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

public final class Java17JmxTransformer implements ClassFileTransformer {
  private static final String JMX_INVOKE_DESCRIPTOR =
      "(Ljavax/management/ObjectName;Ljava/lang/String;[Ljava/lang/Object;[Ljava/lang/String;)Ljava/lang/Object;";
  private static final Type HOOKS = Type.getType(Java17RaspHooks.class);
  private static final Method BEFORE_JMX_MBEAN_INVOKE =
      Method.getMethod(
          "void beforeJmxMBeanInvoke(java.lang.Object, java.lang.String, java.lang.Object)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null
        || classfileBuffer == null
        || !"com/sun/jmx/mbeanserver/JmxMBeanServer".equals(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new JmxClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] JMX transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class JmxClassVisitor extends ClassVisitor {
    JmxClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null
          || !"invoke".equals(name)
          || !JMX_INVOKE_DESCRIPTOR.equals(descriptor)) {
        return methodVisitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(1);
          loadArg(2);
          invokeStatic(HOOKS, BEFORE_JMX_MBEAN_INVOKE);
        }
      };
    }
  }
}
