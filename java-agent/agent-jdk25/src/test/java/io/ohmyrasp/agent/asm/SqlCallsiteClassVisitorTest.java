package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

final class SqlCallsiteClassVisitorTest {
  @Test
  void injectsJavaCompilationHookBeforeCompilerGetTaskCallsite() throws IOException {
    byte[] transformed = transform(classBytes(JavaCompilerCallsiteFixture.class));
    AtomicInteger hookCalls = new AtomicInteger();
    AtomicInteger compilerCalls = new AtomicInteger();

    new ClassReader(transformed)
        .accept(
            new ClassVisitor(OhMyRaspTransformer.api()) {
              @Override
              public MethodVisitor visitMethod(
                  int access, String name, String descriptor, String signature, String[] exceptions) {
                MethodVisitor methodVisitor =
                    super.visitMethod(access, name, descriptor, signature, exceptions);
                return new MethodVisitor(OhMyRaspTransformer.api(), methodVisitor) {
                  @Override
                  public void visitMethodInsn(
                      int opcode,
                      String owner,
                      String methodName,
                      String methodDescriptor,
                      boolean isInterface) {
                    if (opcode == Opcodes.INVOKESTATIC
                        && owner.equals("io/ohmyrasp/agent/hook/OhMyRaspHooks")
                        && methodName.equals("beforeJavaCompilationUnits")
                        && methodDescriptor.equals("(Ljava/lang/Object;)V")) {
                      hookCalls.incrementAndGet();
                    }
                    if (opcode == Opcodes.INVOKEINTERFACE
                        && owner.equals("javax/tools/JavaCompiler")
                        && methodName.equals("getTask")) {
                      compilerCalls.incrementAndGet();
                    }
                    super.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface);
                  }
                };
              }
            },
            0);

    assertEquals(1, hookCalls.get());
    assertEquals(1, compilerCalls.get());
  }

  @Test
  void injectsSqlHookForSingleAndMultipleArgumentStatementCallsites() throws IOException {
    byte[] transformed = transform(classBytes(SqlStatementCallsiteFixture.class));
    AtomicInteger singleArgHookCalls = new AtomicInteger();
    AtomicInteger multiArgHookCalls = new AtomicInteger();

    new ClassReader(transformed)
        .accept(
            new ClassVisitor(OhMyRaspTransformer.api()) {
              @Override
              public MethodVisitor visitMethod(
                  int access, String name, String descriptor, String signature, String[] exceptions) {
                MethodVisitor methodVisitor =
                    super.visitMethod(access, name, descriptor, signature, exceptions);
                return new MethodVisitor(OhMyRaspTransformer.api(), methodVisitor) {
                  @Override
                  public void visitMethodInsn(
                      int opcode,
                      String owner,
                      String methodName,
                      String methodDescriptor,
                      boolean isInterface) {
                    if (opcode == Opcodes.INVOKESTATIC
                        && owner.equals("io/ohmyrasp/agent/hook/OhMyRaspHooks")
                        && methodName.equals("beforeSql")) {
                      if ("singleArg".equals(name)) {
                        singleArgHookCalls.incrementAndGet();
                      } else if ("twoArg".equals(name)) {
                        multiArgHookCalls.incrementAndGet();
                      }
                    }
                    super.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface);
                  }
                };
              }
            },
            0);

    assertEquals(1, singleArgHookCalls.get());
    assertEquals(1, multiArgHookCalls.get());
  }

  @Test
  void recognizesStandardJdbcTemplatesAndLeavesBoundValuesAlone() {
    for (var method : Connection.class.getMethods()) {
      boolean preparation = method.getName().equals("prepareStatement") || method.getName().equals("prepareCall");
      assertEquals(preparation, JdbcSqlMethod.preparesSql(method.getName(), Type.getMethodDescriptor(method)),
          method.toGenericString());
    }
    for (Class<?> type : List.of(Statement.class, PreparedStatement.class, CallableStatement.class)) {
      for (var method : type.getMethods()) {
        String name = method.getName();
        boolean sqlArgument = method.getParameterCount() > 0 && method.getParameterTypes()[0] == String.class
            && List.of("execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch").contains(name);
        assertEquals(sqlArgument, JdbcSqlMethod.executesSql(name, Type.getMethodDescriptor(method)),
            method.toGenericString());
      }
    }
  }

  @Test
  void preservesReceiverOptionsWideLocalsReturnsAndDriverExceptions() throws Exception {
    byte[] bytes = transform(classBytes(OptionsFixture.class));
    Class<?> fixture = new ClassLoader(getClass().getClassLoader()) {
      Class<?> defineFixture() {
        return defineClass(OptionsFixture.class.getName(), bytes, 0, bytes.length);
      }
    }.defineFixture();
    var invoke = fixture.getMethod("invoke", Connection.class, Statement.class, int.class,
        String.class, String[].class, long.class);
    String sql = "select 7";
    String[] columns = {"id", "updated"};
    var expectedFailure = new SQLException("driver failure");
    Statement statement = (Statement) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[]{Statement.class}, (self, method, args) -> {
          assertSame(sql, args[0]);
          assertSame(columns, args[1]);
          if (method.getName().equals("executeUpdate")) throw expectedFailure;
          return 3000000000L;
        });
    Connection connection = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[]{Connection.class}, (self, method, args) -> {
          assertEquals("prepareStatement", method.getName());
          assertArrayEquals(new Object[]{sql, 1003, 1007, 2}, args);
          return null;
        });

    assertEquals(10L, invoke.invoke(null, connection, statement, 0, sql, columns, 10L));
    assertEquals(3000000010L, invoke.invoke(null, connection, statement, 1, sql, columns, 10L));
    assertSame(expectedFailure, assertThrows(InvocationTargetException.class,
        () -> invoke.invoke(null, connection, statement, 2, sql, columns, 10L)).getCause());
  }

  public static class OptionsFixture {
    public static long invoke(Connection conn, Statement stmt, int branch, String sql,
        String[] columns, long total) throws SQLException {
      switch (branch) {
        case 0:
          try (PreparedStatement unused = conn.prepareStatement(sql, 1003, 1007, 2)) {
            return total;
          }
        case 1:
          return total + stmt.executeLargeUpdate(sql, columns);
        default:
          return total + stmt.executeUpdate(sql, columns);
      }
    }
  }

  private static byte[] transform(byte[] original) {
    ClassReader reader = new ClassReader(original);
    ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
    reader.accept(new SqlCallsiteClassVisitor(reader, writer), ClassReader.EXPAND_FRAMES);
    return writer.toByteArray();
  }

  private static byte[] classBytes(Class<?> type) throws IOException {
    String resource = "/" + type.getName().replace('.', '/') + ".class";
    try (InputStream input = type.getResourceAsStream(resource)) {
      if (input == null) {
        throw new IOException("missing class resource " + resource);
      }
      return input.readAllBytes();
    }
  }

  @SuppressWarnings("unused")
  private static final class JavaCompilerCallsiteFixture {
    Boolean compile(JavaCompiler compiler, Iterable<? extends JavaFileObject> units) {
      return compiler.getTask(null, null, null, List.of("-proc:none"), null, units).call();
    }
  }

  @SuppressWarnings("unused")
  private static final class SqlStatementCallsiteFixture {
    void singleArg(Statement statement, String sql) throws SQLException {
      statement.executeQuery(sql);
    }

    void twoArg(Statement statement, String sql) throws SQLException {
      statement.execute(sql, Statement.RETURN_GENERATED_KEYS);
    }
  }
}
