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

public final class Java8JdbcTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_JDBC_CONNECTION =
      Method.getMethod("void beforeJdbcConnection(java.lang.String)");
  private static final Method BEFORE_H2_JDBC_CONNECTION =
      Method.getMethod("void beforeH2JdbcConnection(java.lang.String)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !isJdbcClass(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new JdbcClassVisitor(writer, className), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] JDBC transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isJdbcClass(String className) {
    return "java/sql/DriverManager".equals(className)
        || "org/h2/jdbc/JdbcConnection".equals(className);
  }

  private static final class JdbcClassVisitor extends ClassVisitor {
    private final String className;

    JdbcClassVisitor(ClassVisitor delegate, String className) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || !isConnectionMethod(className, name, descriptor)) {
        return methodVisitor;
      }
      final boolean h2Constructor = isH2JdbcConnectionConstructor(className, name, descriptor);
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeStatic(HOOKS, h2Constructor ? BEFORE_H2_JDBC_CONNECTION : BEFORE_JDBC_CONNECTION);
        }
      };
    }

    private static boolean isConnectionMethod(String className, String name, String descriptor) {
      if ("java/sql/DriverManager".equals(className)) {
        return isDriverManagerConnectionMethod(name, descriptor);
      }
      return isH2JdbcConnectionConstructor(className, name, descriptor);
    }

    private static boolean isDriverManagerConnectionMethod(String name, String descriptor) {
      return "getConnection".equals(name)
          && ("(Ljava/lang/String;)Ljava/sql/Connection;".equals(descriptor)
              || "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;".equals(descriptor)
              || "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/sql/Connection;".equals(
                  descriptor));
    }

    private static boolean isH2JdbcConnectionConstructor(String className, String name, String descriptor) {
      return "org/h2/jdbc/JdbcConnection".equals(className)
          && "<init>".equals(name)
          && descriptor.startsWith("(Ljava/lang/String;");
    }
  }
}
