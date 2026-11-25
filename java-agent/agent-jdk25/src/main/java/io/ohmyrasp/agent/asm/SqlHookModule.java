package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import io.ohmyrasp.agent.sql.MyBatisSqlVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class SqlHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/sql/DriverManager") || isJdbcStatementClass(className) || MyBatisSqlVisitor.matches(className);
  }

  private static boolean isJdbcStatementClass(String className) {
    return JdbcSqlMethod.driverOrPoolPackage(className);
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
    if (MyBatisSqlVisitor.matches(className)) {
      return MyBatisSqlVisitor.wrap(className, methodVisitor, access, methodName, descriptor,
          "io/ohmyrasp/agent/hook/OhMyRaspHooks");
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
    if ((JdbcSqlMethod.preparesSql(methodName, descriptor)
            || methodName.equals("execute")
            || methodName.equals("executeQuery")
            || methodName.equals("executeUpdate")
            || methodName.equals("executeLargeUpdate")
            || methodName.equals("addBatch")
            || (className.startsWith("org/h2/jdbc/") && methodName.equals("prepareCommand")))
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          if ((access & Opcodes.ACC_STATIC) == 0) {
            loadThis();
            loadArg(0);
            invokeHook("beforeSql", "(Ljava/lang/Object;Ljava/lang/String;)V");
          } else {
            loadArg(0);
            invokeHook("beforeSql", "(Ljava/lang/String;)V");
          }
        }
      };
    }
    return methodVisitor;
  }
}
