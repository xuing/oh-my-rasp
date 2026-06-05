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

public final class Java17JaasTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java17RaspHooks.class);
  private static final Method BEFORE_JAAS_CONFIG_ENTRY =
      Method.getMethod("void beforeJaasConfigEntry(java.lang.Object, java.lang.Object)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null
        || classfileBuffer == null
        || !"javax/security/auth/login/AppConfigurationEntry".equals(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new JaasClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] JAAS transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class JaasClassVisitor extends ClassVisitor {
    JaasClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || !isConfigurationEntryConstructor(name, descriptor)) {
        return methodVisitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(2);
          invokeStatic(HOOKS, BEFORE_JAAS_CONFIG_ENTRY);
        }
      };
    }

    private static boolean isConfigurationEntryConstructor(String name, String descriptor) {
      return "<init>".equals(name)
          && descriptor.startsWith(
              "(Ljava/lang/String;Ljavax/security/auth/login/AppConfigurationEntry$LoginModuleControlFlag;Ljava/util/Map;");
    }
  }
}
