package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class JwtHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("com/auth0/jwt/JWTVerifier");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if ((access & Opcodes.ACC_ABSTRACT) != 0
        || !methodName.equals("verify")
        || !descriptor.endsWith("Lcom/auth0/jwt/interfaces/DecodedJWT;")) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodExit(int opcode) {
        if (opcode != Opcodes.ATHROW) {
          return;
        }
        dup();
        push("auth0-java-jwt");
        swap();
        invokeHook("beforeJwtVerificationFailure", "(Ljava/lang/String;Ljava/lang/Object;)V");
      }
    };
  }
}
