package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class SqlHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/sql/DriverManager") || className.startsWith("org/h2/jdbc/");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
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
            || methodName.equals("prepareCommand"))
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
