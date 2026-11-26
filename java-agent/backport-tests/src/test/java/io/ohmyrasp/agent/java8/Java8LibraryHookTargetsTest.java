package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** The names the backport lines hook in third-party libraries, kept to the classes real releases have. */
final class Java8LibraryHookTargetsTest {
  @Test
  void hessianLiteHooksTheDeserializersItShipsAndNotAnUnsafeOne() {
    assertTrue(HessianAllocationVisitor.matches("com/alibaba/com/caucho/hessian/io/JavaDeserializer"));
    assertTrue(HessianAllocationVisitor.matches("com/alibaba/com/caucho/hessian/io/BeanDeserializer"));
    assertFalse(HessianAllocationVisitor.matches("com/alibaba/com/caucho/hessian/io/UnsafeDeserializer"));
    assertTrue(HessianAllocationVisitor.matches("com/caucho/hessian/io/UnsafeDeserializer"));
  }

  @Test
  void jexl2HooksItsExpressionClassAndNamesNoScriptImpl() throws Exception {
    // JEXL 2.0.1 to 2.1.1 evaluate scripts and expressions in ExpressionImpl; only JEXL 1.x has a ScriptImpl.
    byte[] expression = classBytes("org/apache/commons/jexl2/ExpressionImpl");
    Java8JexlTransformer transformer = new Java8JexlTransformer();

    byte[] hooked = transformer.transform(null, "org/apache/commons/jexl2/ExpressionImpl", null, null, expression);

    assertNotNull(hooked);
    assertTrue(new String(hooked, StandardCharsets.ISO_8859_1).contains("beforeJexlExpression"));
    assertNull(transformer.transform(null, "org/apache/commons/jexl2/ScriptImpl", null, null, expression));
  }

  @Test
  void janinoCookableInCommonsCompilerPassesTheSourceToTheCompilationDetector() throws Exception {
    // Cookable is org.codehaus.commons.compiler.Cookable (commons-compiler), not org.codehaus.janino.Cookable.
    String name = "org/codehaus/commons/compiler/Cookable";
    byte[] hooked = new Java8JavaCompilationTransformer().transform(null, name, null, null, classBytes(name));

    assertNotNull(hooked);
    String hook = "io/ohmyrasp/agent/java8/Java8RaspHooks";
    assertEquals(
        java.util.Arrays.asList("ldc=janino load=1 beforeJavaCompilationSource"),
        hookCalls(hooked, "cook", "(Ljava/lang/String;)V", hook));
    // cook(fileName, source): the source is the second argument, local 2.
    assertEquals(
        java.util.Arrays.asList("ldc=janino load=2 beforeJavaCompilationSource"),
        hookCalls(hooked, "cook", "(Ljava/lang/String;Ljava/lang/String;)V", hook));
    // The Reader and stream overloads, whose first String is a file name, are not hooked here.
    assertEquals(new ArrayList<String>(), hookCalls(hooked, "cook", "(Ljava/lang/String;Ljava/io/InputStream;)V", hook));
    assertEquals(new ArrayList<String>(), hookCalls(hooked, "cook", "(Ljava/io/Reader;)V", hook));
  }

  @Test
  void skyWalking9LogQueryPassesTheTableNameToTheSqlIdentifierCheck() throws Exception {
    // SkyWalking 9 replaced h2.dao.H2LogQueryDAO.queryLogs(String metricName, ...) with this common DAO,
    // which writes the table name into the statement in buildSQL(..., String table).
    String name = "org/apache/skywalking/oap/server/storage/plugin/jdbc/common/dao/JDBCLogQueryDAO";
    byte[] original = classBytes(name);
    String buildSql = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
        + "Lorg/apache/skywalking/oap/server/core/query/input/TraceScopeCondition;"
        + "Lorg/apache/skywalking/oap/server/core/query/enumeration/Order;IILorg/apache/skywalking/oap/server/core/query/input/Duration;"
        + "Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/lang/String;)"
        + "Lorg/apache/skywalking/oap/server/storage/plugin/jdbc/common/SQLAndParameters;";

    byte[] hooked = new Java8JdbcTransformer().transform(null, name, null, null, original);

    assertNotNull(hooked);
    String hook = "io/ohmyrasp/agent/java8/Java8RaspHooks";
    assertEquals(new ArrayList<String>(), hookCalls(original, "buildSQL", buildSql, hook));
    // The table is the twelfth argument: local 12 of the instance method.
    assertEquals(
        java.util.Arrays.asList("ldc=table load=12 beforeSqlIdentifier"), hookCalls(hooked, "buildSQL", buildSql, hook));
  }

  @Test
  void sqlIdentifierCheckNamesTheSourceAndParameterItWasGiven() throws Exception {
    java.nio.file.Path log = java.nio.file.Files.createTempFile("ohmyrasp-java8-sql-identifier-source", ".jsonl");
    java.nio.file.Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    try {
      Java8RaspHooks.beforeSqlIdentifier("log;drop/**/table/**/x", "SkyWalking.JDBCLogQueryDAO.buildSQL", "table");

      String text = new String(java.nio.file.Files.readAllBytes(log), StandardCharsets.UTF_8);
      assertTrue(text.contains("\"algorithm\":\"java8_sql_identifier_injection\""));
      assertTrue(text.contains("source=SkyWalking.JDBCLogQueryDAO.buildSQL"));
      assertTrue(text.contains("parameter=table"));
    } finally {
      System.clearProperty("ohmyrasp.java8.log");
      java.nio.file.Files.deleteIfExists(log);
    }
  }

  @Test
  void pageHelper42DialectsAreTracedThroughTheirFourArgumentGetPageSql() throws Exception {
    // PageHelper 4.2.x takes (String, Page, RowBounds, CacheKey); 5.x takes (String, Page, CacheKey).
    String name = "com/github/pagehelper/dialect/MySqlDialect";
    String descriptor =
        "(Ljava/lang/String;Lcom/github/pagehelper/Page;Lorg/apache/ibatis/session/RowBounds;Lorg/apache/ibatis/cache/CacheKey;)Ljava/lang/String;";
    byte[] original = classBytes(name);

    byte[] hooked = new Java8JdbcTransformer().transform(null, name, null, null, original);

    assertNotNull(hooked);
    assertEquals(new ArrayList<String>(), calls(original, "getPageSql", descriptor, "io/ohmyrasp/agent/sql/MyBatisSqlTrace"));
    List<String> after = calls(hooked, "getPageSql", descriptor, "io/ohmyrasp/agent/sql/MyBatisSqlTrace");
    assertTrue(after.contains("appendPiece"), after.toString());
    assertTrue(after.contains("built"), after.toString());
  }

  /** Each static call from the method into one agent class, with the constant and local loaded just before it. */
  private static List<String> hookCalls(byte[] classBytes, final String method, final String descriptor, final String owner) {
    final List<String> calls = new ArrayList<String>();
    new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        if (!name.equals(method) || !desc.equals(descriptor)) {
          return null;
        }
        return new MethodVisitor(Opcodes.ASM9) {
          private Object constant;
          private int local = -1;

          @Override public void visitLdcInsn(Object value) {
            constant = value;
          }

          @Override public void visitVarInsn(int opcode, int varIndex) {
            if (opcode == Opcodes.ALOAD) {
              local = varIndex;
            }
          }

          @Override public void visitMethodInsn(int opcode, String target, String callee, String calleeDescriptor, boolean itf) {
            if (opcode == Opcodes.INVOKESTATIC && target.equals(owner)) {
              calls.add("ldc=" + constant + " load=" + local + " " + callee);
            }
          }
        };
      }
    }, 0);
    return calls;
  }

  /** The names of the static methods of one agent class that the method calls, in order. */
  private static List<String> calls(byte[] classBytes, final String method, final String descriptor, final String owner) {
    final List<String> calls = new ArrayList<String>();
    new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        if (!name.equals(method) || !desc.equals(descriptor)) {
          return null;
        }
        return new MethodVisitor(Opcodes.ASM9) {
          @Override public void visitMethodInsn(int opcode, String target, String callee, String calleeDescriptor, boolean itf) {
            if (opcode == Opcodes.INVOKESTATIC && target.equals(owner)) {
              calls.add(callee);
            }
          }
        };
      }
    }, 0);
    return calls;
  }

  private static byte[] classBytes(String internalName) throws IOException {
    try (InputStream input = Java8LibraryHookTargetsTest.class.getClassLoader().getResourceAsStream(internalName + ".class")) {
      if (input == null) {
        throw new IOException("missing class resource " + internalName);
      }
      java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        output.write(buffer, 0, count);
      }
      return output.toByteArray();
    }
  }
}
