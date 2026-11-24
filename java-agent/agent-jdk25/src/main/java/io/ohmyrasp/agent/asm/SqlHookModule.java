package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class SqlHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/sql/DriverManager") || isJdbcStatementClass(className);
  }

  private static boolean isJdbcStatementClass(String className) {
    return className.startsWith("org/h2/jdbc/")
        || className.startsWith("com/mysql/cj/jdbc/")
        || className.startsWith("com/mysql/jdbc/")
        || className.startsWith("org/postgresql/jdbc/")
        || className.startsWith("org/mariadb/jdbc/")
        || className.startsWith("org/sqlite/")
        || className.startsWith("org/hsqldb/jdbc/")
        || className.startsWith("org/apache/derby/impl/jdbc/")
        || className.startsWith("oracle/jdbc/driver/")
        || className.startsWith("com/microsoft/sqlserver/jdbc/")
        || className.startsWith("com/zaxxer/hikari/pool/")
        || className.startsWith("org/apache/commons/dbcp")
        || className.startsWith("org/apache/tomcat/jdbc/pool/");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
      return methodVisitor;
    }
    if (className.equals("java/sql/DriverManager")
        && methodName.equals("getConnection")
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeJdbcConnect", "(Ljava/lang/String;)V");
        }
      };
    }
    if ((methodName.equals("execute")
            || methodName.equals("executeQuery")
            || methodName.equals("executeUpdate")
            || methodName.equals("executeLargeUpdate")
            || methodName.equals("addBatch")
            || (className.startsWith("org/h2/jdbc/") && methodName.equals("prepareCommand")))
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeSql", "(Ljava/lang/String;)V");
        }
      };
    }
    return methodVisitor;
  }
}
