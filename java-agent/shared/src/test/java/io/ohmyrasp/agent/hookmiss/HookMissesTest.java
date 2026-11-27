package io.ohmyrasp.agent.hookmiss;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** The parts of the hook-miss report that do not depend on an agent line. */
final class HookMissesTest {
  @AfterEach
  void stop() {
    HookMisses.stop();
  }

  @Test
  void theTableIsReadByClassAndByUnit() {
    HookExpectations table = HookExpectations.parse("# comment\n\n"
        + "SqlHookModule a/B report m(I)V m(J)V n()V\n"
        + "Java{N}JdbcTransformer a/B absent m(I)V\n");

    assertEquals(2, table.size());
    assertEquals(2, table.forClass("a/B").length);
    assertNull(table.forClass("a/C"));
    HookExpectation primary = table.forUnit("SqlHookModule").get("a/B");
    assertArrayEquals(new String[] {"m(I)V", "m(J)V", "n()V"}, primary.methods);
    assertArrayEquals(new String[] {"m", "n"}, primary.names);
    assertFalse(primary.absentIsVersionGap);
    assertTrue(table.forUnit("Java{N}JdbcTransformer").get("a/B").absentIsVersionGap);
    assertNull(table.forUnit("FileHookModule"));
  }

  @Test
  void aMalformedTableIsRejected() {
    for (String line : Arrays.asList("SqlHookModule a/B report", "SqlHookModule a/B maybe m()V", "SqlHookModule a/B report m")) {
      assertThrows(IllegalArgumentException.class, () -> HookExpectations.parse(line + "\n"), line);
    }
  }

  @Test
  void aBackportTransformerIsNamedWithItsTokenInTheTable() {
    assertEquals("Java{N}JdbcTransformer", HookExpectations.unitName("Java8JdbcTransformer"));
    assertEquals("Java{N}JavaBeansTransformer", HookExpectations.unitName("Java17JavaBeansTransformer"));
    assertEquals("JavaBeansHookModule", HookExpectations.unitName("JavaBeansHookModule"));
    assertEquals("SqlHookModule", HookExpectations.unitName("SqlHookModule"));
  }

  @Test
  void theShippedTablesParse() throws Exception {
    assertTrue(HookExpectations.load("primary").size() > 0);
    assertTrue(HookExpectations.load("backport").size() > 0);
  }

  @Test
  void aGainIsACallIntoTheAgentTheInputDidNotHave() {
    byte[] plain = classCalling("x/Plain", null);
    byte[] hooked = classCalling("x/Plain", "io/ohmyrasp/agent/hook/Hooks");
    byte[] twice = classCalling("x/Plain", "io/ohmyrasp/agent/hook/Hooks", "io/ohmyrasp/agent/hook/Hooks");
    byte[] asmOnly = classCalling("x/Plain", "io/ohmyrasp/agent/shaded/asm/Type");

    assertFalse(AgentCalls.mentionsAgent(plain));
    assertTrue(HookMissWatch.gained(plain, hooked), "the byte search");
    assertFalse(HookMissWatch.gained(plain, plain));
    assertTrue(HookMissWatch.gained(hooked, twice), "counted when an earlier transformer already added one");
    assertFalse(HookMissWatch.gained(hooked, hooked), "counted, and equal");
    assertEquals(0, AgentCalls.count(asmOnly), "the relocated ASM is not the agent");
    assertEquals(2, AgentCalls.count(twice));
  }

  @Test
  void aReflectiveHookCountsByTheAgentClassItNames() {
    ClassWriter writer = begin("x/Reflective");
    MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
    mv.visitCode();
    mv.visitLdcInsn("io.ohmyrasp.agent.hook.OhMyRaspHooks");
    mv.visitInsn(Opcodes.POP);
    mv.visitLdcInsn("io.ohmyrasp.agent.shaded.asm.Type");
    mv.visitInsn(Opcodes.POP);
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(0, 0);
    mv.visitEnd();

    assertEquals(1, AgentCalls.count(writer.toByteArray()));
  }

  @Test
  void theCodeSourceIsNamedByItsLastSegment() {
    assertEquals("x.jar", HookMisses.lastSegment("/opt/lib/x.jar"));
    assertEquals("x.jar", HookMisses.lastSegment("jar:file:/app.jar!/BOOT-INF/lib/x.jar!/"));
    assertEquals("classes", HookMisses.lastSegment("/srv/WEB-INF/classes/"));
    assertEquals("x.jar", HookMisses.lastSegment("C:\\lib\\x.jar"));
  }

  @Test
  void textIsEscapedAndCut() {
    assertEquals("\"a\\\"b\\\\c\\n\\u0001\"", HookMisses.quote("a\"b\\c\n\u0001"));
    StringBuilder longText = new StringBuilder();
    for (int i = 0; i < HookMisses.MAX_TEXT + 100; i++) {
      longText.append('x');
    }
    assertEquals(HookMisses.MAX_TEXT + 2, HookMisses.quote(longText.toString()).length());
  }

  @Test
  void aLongListIsCutWithACount() {
    StringBuilder line = new StringBuilder("U a/B report");
    for (int i = 0; i < HookMisses.MAX_LISTED + 3; i++) {
      line.append(" m").append(i).append("()V");
    }
    final List<String> written = new ArrayList<String>();
    HookMisses.start(HookExpectations.parse(line + "\n"), new HookMissSink() {
      @Override public void write(String diagnostic, String fields) {
        written.add(fields);
      }

      @Override public boolean enterOwnIo() {
        return false;
      }

      @Override public void exitOwnIo(boolean entered) {}
    }, true);

    HookMisses.miss(HookMisses.table().forClass("a/B")[0], "U", classCalling("a/B", null), null, HookMisses.NO_AGENT_CALL, null);

    assertEquals(1, written.size());
    assertTrue(written.get(0).contains("\"m15()V\",\"... 3 more\"],\"found\":[]"), written.get(0));
    assertFalse(written.get(0).contains("\"code_source\":"), "a class with no code source has none");
  }

  @Test
  void nothingIsReportedWhileTheReportIsOff() {
    HookExpectations table = HookExpectations.parse("U a/B report m()V\n");
    HookMisses.miss(table.forClass("a/B")[0], "U", classCalling("a/B", null), null, HookMisses.NO_AGENT_CALL, null);
    assertNull(HookMisses.table());
  }

  private static ClassWriter begin(String name) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", null);
    return writer;
  }

  /** A class with one static method that calls {@code owner.hook()} once per owner given. */
  private static byte[] classCalling(String name, String... owners) {
    ClassWriter writer = begin(name);
    MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
    mv.visitCode();
    if (owners != null) {
      for (String owner : owners) {
        if (owner != null) {
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "hook", "()V", false);
        }
      }
    }
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }
}
