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

public final class Java11JwtTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java11RaspHooks.class);
  private static final Type THROWABLE = Type.getType(Throwable.class);
  private static final Method BEFORE_JWT_VERIFICATION_FAILURE =
      Method.getMethod("void beforeJwtVerificationFailure(java.lang.Object, java.lang.Throwable)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !isTarget(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer =
          new ClassWriter(reader, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES) {
            @Override
            protected String getCommonSuperClass(String type1, String type2) {
              return commonSuperClass(type1, type2);
            }
          };
      reader.accept(new JwtClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA11] JWT transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "com/auth0/jwt/JWTVerifier".equals(className)
        || className.startsWith("com/auth0/jwt/algorithms/");
  }

  private static String commonSuperClass(String type1, String type2) {
    if (isThrowableLike(type1) || isThrowableLike(type2)) {
      return "java/lang/Throwable";
    }
    return "java/lang/Object";
  }

  private static boolean isThrowableLike(String type) {
    return type != null
        && ("java/lang/Throwable".equals(type)
            || type.endsWith("Exception")
            || type.endsWith("Error")
            || type.endsWith("Throwable"));
  }

  private static final class JwtClassVisitor extends ClassVisitor {
    JwtClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || !isVerifyMethod(name, descriptor)) {
        return methodVisitor;
      }
      final boolean hasTokenArgument = isVerifyString(name, descriptor);
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        private final org.objectweb.asm.Label start = new org.objectweb.asm.Label();
        private final org.objectweb.asm.Label end = new org.objectweb.asm.Label();
        private final org.objectweb.asm.Label handler = new org.objectweb.asm.Label();

        @Override
        public void visitCode() {
          visitTryCatchBlock(
              start,
              end,
              handler,
              "com/auth0/jwt/exceptions/JWTVerificationException");
          super.visitCode();
          visitLabel(start);
        }

        @Override
        public void visitMaxs(int maxStack, int maxLocals) {
          visitLabel(end);
          visitLabel(handler);
          int throwable = newLocal(THROWABLE);
          storeLocal(throwable);
          if (hasTokenArgument) {
            loadArg(0);
          } else {
            visitInsn(ACONST_NULL);
          }
          loadLocal(throwable);
          invokeStatic(HOOKS, BEFORE_JWT_VERIFICATION_FAILURE);
          loadLocal(throwable);
          throwException();
          super.visitMaxs(maxStack, maxLocals);
        }
      };
    }

    private static boolean isVerifyString(String name, String descriptor) {
      return "verify".equals(name)
          && "(Ljava/lang/String;)Lcom/auth0/jwt/interfaces/DecodedJWT;".equals(descriptor);
    }

    private static boolean isVerifyMethod(String name, String descriptor) {
      return isVerifyString(name, descriptor)
          || ("verify".equals(name)
              && "(Lcom/auth0/jwt/interfaces/DecodedJWT;)Lcom/auth0/jwt/interfaces/DecodedJWT;"
                  .equals(descriptor))
          || ("verify".equals(name) && "(Lcom/auth0/jwt/interfaces/DecodedJWT;)V".equals(descriptor));
    }
  }
}
