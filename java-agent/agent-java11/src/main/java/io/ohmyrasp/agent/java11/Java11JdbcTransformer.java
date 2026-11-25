package io.ohmyrasp.agent.java11;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import io.ohmyrasp.agent.sql.MyBatisSqlVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public final class Java11JdbcTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java11RaspHooks.class);
  private static final Method BEFORE_JDBC_CONNECTION =
      Method.getMethod("void beforeJdbcConnection(java.lang.String)");
  private static final Method BEFORE_H2_JDBC_CONNECTION =
      Method.getMethod("void beforeH2JdbcConnection(java.lang.String)");
  private static final Method BEFORE_SQL_IDENTIFIER =
      Method.getMethod("void beforeSqlIdentifier(java.lang.String)");
  private static final Method BEFORE_SQL_STATEMENT =
      Method.getMethod("void beforeSqlStatement(java.lang.Object, java.lang.String, java.lang.String)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || className.startsWith("io/ohmyrasp/agent/")) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      boolean jdbcImplementation = JdbcSqlMethod.directJdbcInterface(reader.getInterfaces())
          || JdbcSqlMethod.isJdbcImplementation(classBeingRedefined);
      if (!jdbcImplementation && !isJdbcClass(className)) return null;
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new JdbcClassVisitor(writer, className, jdbcImplementation), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA11] JDBC transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isJdbcClass(String className) {
    return "java/sql/DriverManager".equals(className)
        || "org/h2/jdbc/JdbcConnection".equals(className)
        || MyBatisSqlVisitor.matches(className)
        || "org/apache/skywalking/oap/server/storage/plugin/jdbc/h2/dao/H2LogQueryDAO"
            .equals(className)
        || isJdbcStatementClass(className);
  }

  private static boolean isJdbcStatementClass(String className) {
    return JdbcSqlMethod.driverOrPoolPackage(className);
  }

  private static final class JdbcClassVisitor extends ClassVisitor {
    private final String className;
    private boolean isInterface;
    private final boolean jdbcImplementation;

    JdbcClassVisitor(ClassVisitor delegate, String className, boolean jdbcImplementation) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
      this.jdbcImplementation = jdbcImplementation;
    }

    @Override
    public void visit(
        int version,
        int access,
        String name,
        String signature,
        String superName,
        String[] interfaces) {
      this.isInterface = (access & Opcodes.ACC_INTERFACE) != 0;
      super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null) {
        return methodVisitor;
      }
      if (!isInterface
          && (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0
          && (isSqlStatementMethod(className, name, descriptor)
              || (jdbcImplementation && (JdbcSqlMethod.preparesSql(name, descriptor)
                  || JdbcSqlMethod.executesSql(name, descriptor))))) {
        MethodVisitor scope = new io.ohmyrasp.agent.sql.JdbcObservationAdvice(methodVisitor, access, name, descriptor);
        return new AdviceAdapter(Opcodes.ASM9, scope, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            if ((access & Opcodes.ACC_STATIC) == 0) loadThis();
            else visitInsn(Opcodes.ACONST_NULL);
            loadArg(0);
            push(JdbcSqlMethod.preparesSql(name, descriptor) ? "Connection." + name : "Statement.execute");
            invokeStatic(HOOKS, BEFORE_SQL_STATEMENT);
          }
        };
      }
      if (isSqlIdentifierMethod(className, name, descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_SQL_IDENTIFIER);
          }
        };
      }
      if (MyBatisSqlVisitor.matches(className)) {
        return MyBatisSqlVisitor.wrap(className, methodVisitor, access, name, descriptor, HOOKS.getInternalName());
      }
      if (!isConnectionMethod(className, name, descriptor)) {
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

    private static boolean isSqlIdentifierMethod(String className, String name, String descriptor) {
      return "org/apache/skywalking/oap/server/storage/plugin/jdbc/h2/dao/H2LogQueryDAO"
              .equals(className)
          && "queryLogs".equals(name)
          && descriptor.startsWith("(Ljava/lang/String;");
    }

    private static boolean isSqlStatementMethod(
        String className, String name, String descriptor) {
      return isJdbcStatementClass(className)
          && descriptor != null
          && descriptor.startsWith("(Ljava/lang/String;")
          && (JdbcSqlMethod.preparesSql(name, descriptor)
              || "execute".equals(name)
              || "executeQuery".equals(name)
              || "executeUpdate".equals(name)
              || "executeLargeUpdate".equals(name)
              || "addBatch".equals(name));
    }
  }
}
