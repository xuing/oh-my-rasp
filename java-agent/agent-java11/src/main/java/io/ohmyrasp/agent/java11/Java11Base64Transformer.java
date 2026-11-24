package io.ohmyrasp.agent.java11;

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

public final class Java11Base64Transformer implements ClassFileTransformer {
  private static final String TARGET = "java/util/Base64$Decoder";
  private static final Type HOOKS = Type.getType(Java11RaspHooks.class);
  private static final Method BEFORE_BASE64_DECODE =
      Method.getMethod("void beforeBase64Decode(byte[], int, int, boolean, boolean)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (!TARGET.equals(className) || classfileBuffer == null) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new DecoderClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println(
            "[OHMYRASP-JAVA11] Base64 transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class DecoderClassVisitor extends ClassVisitor {
    DecoderClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor =
          super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null
          || !"decode0".equals(name)
          || !"([BII[B)I".equals(descriptor)) {
        return methodVisitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(1);
          loadArg(2);
          loadThis();
          visitFieldInsn(Opcodes.GETFIELD, TARGET, "isURL", "Z");
          loadThis();
          visitFieldInsn(Opcodes.GETFIELD, TARGET, "isMIME", "Z");
          invokeStatic(HOOKS, BEFORE_BASE64_DECODE);
        }
      };
    }
  }
}
