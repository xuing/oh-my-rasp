package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class Base64HookModule implements HookModule {
  private static final String DECODER_INTERNAL_NAME = "java/util/Base64$Decoder";

  @Override
  public boolean matchesClass(String className) {
    return DECODER_INTERNAL_NAME.equals(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if ("decode0".equals(methodName) && "([BII[B)I".equals(descriptor)) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(1);
          loadArg(2);
          loadThis();
          visitFieldInsn(Opcodes.GETFIELD, DECODER_INTERNAL_NAME, "isURL", "Z");
          loadThis();
          visitFieldInsn(Opcodes.GETFIELD, DECODER_INTERNAL_NAME, "isMIME", "Z");
          invokeHook("beforeBase64Decode", "([BIIZZ)V");
        }
      };
    }
    return methodVisitor;
  }
}
