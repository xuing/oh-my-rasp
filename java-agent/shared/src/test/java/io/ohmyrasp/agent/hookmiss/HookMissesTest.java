package io.ohmyrasp.agent.hookmiss;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    assertArrayEquals(new String[0], primary.callees[0], "a table written by hand may leave a callee out");
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
  void aMethodIsAppliedWhenItCallsOneOfTheAgentMethodsTheUnitIsRecordedAdding() {
    HookExpectation pair = HookExpectations.parse("U x/Plain report run()V=hook,other\n").forClass("x/Plain")[0];

    assertTrue(AgentCalls.applied(pair, calls(classCalling("x/Plain", "io/ohmyrasp/agent/hook/Hooks"), pair)), "hook is a recorded callee");
    assertFalse(AgentCalls.applied(pair, calls(classCalling("x/Plain", null), pair)), "no call");
    assertFalse(AgentCalls.applied(pair, calls(classCalling("x/Plain", "io/ohmyrasp/agent/shaded/asm/Type"), pair)),
        "the relocated ASM is not the agent");
    assertFalse(AgentCalls.applied(pair, calls(classCalling("x/Plain", "some/other/Owner"), pair)), "not the agent");
  }

  @Test
  void aCallToAnAgentMethodTheUnitIsNotRecordedAddingIsNoEvidence() {
    HookExpectation pair = HookExpectations.parse("U x/Plain report run()V=beforeWanted\n").forClass("x/Plain")[0];
    byte[] calling = classCallingMethod("x/Plain", "run", "()V", "io/ohmyrasp/agent/hook/Hooks", "beforeOther");

    assertFalse(AgentCalls.applied(pair, calls(calling, pair)), "another unit's or a call-site visitor's call");
    assertTrue(AgentCalls.applied(pair,
        calls(classCallingMethod("x/Plain", "run", "()V", "io/ohmyrasp/agent/hook/Hooks", "beforeWanted"), pair)));
  }

  @Test
  void aCallInAnotherMethodOrAnotherOverloadIsNoEvidence() {
    HookExpectation pair = HookExpectations.parse("U x/Plain report run(I)V=hook\n").forClass("x/Plain")[0];

    assertFalse(AgentCalls.applied(pair, calls(classCallingMethod("x/Plain", "run", "()V", "io/ohmyrasp/agent/hook/Hooks", "hook"), pair)),
        "the overload that survived a descriptor change");
    assertFalse(AgentCalls.applied(pair, calls(classCallingMethod("x/Plain", "elsewhere", "(I)V", "io/ohmyrasp/agent/hook/Hooks", "hook"), pair)),
        "a method the unit is not recorded instrumenting");
    assertTrue(AgentCalls.applied(pair, calls(classCallingMethod("x/Plain", "run", "(I)V", "io/ohmyrasp/agent/hook/Hooks", "hook"), pair)));
  }

  @Test
  void aReflectiveHookCountsOnlyAsTheSequenceTheHooksEmit() {
    HookExpectation pair = HookExpectations.parse("U x/Reflective report run()V=evaluate\n").forClass("x/Reflective")[0];

    assertTrue(AgentCalls.applied(pair, calls(reflective("x/Reflective", true, true), pair)), "loadClass, getMethod, invoke");
    assertFalse(AgentCalls.applied(pair, calls(reflective("x/Reflective", false, true), pair)),
        "a constant that names an agent class and is only loaded");
    assertFalse(AgentCalls.applied(pair, calls(reflective("x/Reflective", true, false), pair)), "never invoked");
  }

  @Test
  void aTableClassFileTooLargeOrUnreadableGivesNoVerdict() {
    HookExpectation pair = HookExpectations.parse("U x/Plain report run()V=hook\n").forClass("x/Plain")[0];

    assertNull(AgentCalls.inMethods(new byte[AgentCalls.MAX_CLASS_BYTES + 1], new HookExpectation[] {pair}));
    assertNull(AgentCalls.inMethods(new byte[] {1, 2, 3}, new HookExpectation[] {pair}));
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
  void textIsCutOnACodePointBoundaryAndEveryLoneSurrogateIsReplaced() throws Exception {
    String pair = new String(Character.toChars(0x1F600));
    // The pair straddles the cut: its first half is the 512th character.
    String straddling = repeat('a', HookMisses.MAX_TEXT - 1) + pair + "tail";
    String cut = HookMisses.quote(straddling);
    assertEquals("\"" + repeat('a', HookMisses.MAX_TEXT - 1) + "\"", cut, "the half pair is dropped, not kept");
    assertEncodable(cut);

    String whole = repeat('a', HookMisses.MAX_TEXT - 2) + pair + "tail";
    assertEquals("\"" + repeat('a', HookMisses.MAX_TEXT - 2) + pair + "\"", HookMisses.quote(whole));

    String lone = HookMisses.quote("x\uD83Dy\uDE00z" + pair);
    assertEquals("\"x\uFFFDy\uFFFDz" + pair + "\"", lone);
    assertEncodable(lone);
    assertEncodable(HookMisses.quote("\uD83D")); // a high surrogate that ends the text
  }

  private static String repeat(char ch, int count) {
    StringBuilder out = new StringBuilder(count);
    for (int i = 0; i < count; i++) {
      out.append(ch);
    }
    return out.toString();
  }

  private static void assertEncodable(String text) throws CharacterCodingException {
    StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(text));
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
    assertTrue(written.get(0).contains("\"m15()V\"],\"found\":[],\"looked_for_omitted\":3,"), written.get(0));
    assertFalse(written.get(0).contains("more\""), "the omitted count is a member of its own, not a 17th list element");
    assertFalse(written.get(0).contains("\"code_source\":"), "a class with no code source has none");
  }

  @Test
  void nothingIsReportedWhileTheReportIsOff() {
    HookExpectations table = HookExpectations.parse("U a/B report m()V\n");
    HookMisses.miss(table.forClass("a/B")[0], "U", classCalling("a/B", null), null, HookMisses.NO_AGENT_CALL, null);
    assertNull(HookMisses.table());
  }

  // ---- what a queued miss keeps and how much of it -----------------------------------------------------

  @Test
  void aQueuedMissKeepsNothingThatPinsTheClassLoaderOrHoldsTheClassFile() throws Exception {
    // Held, so nothing drains: the candidate waits as it would for a worker that never gets to run.
    HookMisses.startHeld(HookExpectations.parse("U a/B report m()V\n"), recorder(new ArrayList<String>()));
    ClassLoader loader = new ClassLoader(null) {};
    ProtectionDomain domain = new ProtectionDomain(new CodeSource(new URL("file:/opt/lib/x-1.0.jar"), (Certificate[]) null),
        null, loader, null);
    WeakReference<ClassLoader> weak = new WeakReference<ClassLoader>(loader);

    HookMisses.miss(HookMisses.table().forClass("a/B")[0], "U", classCalling("a/B", null), domain, HookMisses.NO_AGENT_CALL, null);
    assertEquals(1, HookMisses.queued());
    loader = null;
    domain = null;
    long deadline = System.nanoTime() + 10_000_000_000L;
    while (weak.get() != null && System.nanoTime() < deadline) {
      System.gc();
      Thread.sleep(20);
    }

    assertNull(weak.get(), "a candidate that waits must not keep the application's class loader");
    for (Class<?> type : new Class<?>[] {Class.forName(HookMisses.class.getName() + "$Candidate"),
        Class.forName(HookMisses.class.getName() + "$Origin")}) {
      for (Field field : type.getDeclaredFields()) {
        Class<?> held = field.getType();
        assertFalse(held == byte[].class || ProtectionDomain.class.isAssignableFrom(held) || ClassLoader.class.isAssignableFrom(held)
            || Class.class == held || CodeSource.class.isAssignableFrom(held) || URL.class.isAssignableFrom(held),
            type.getSimpleName() + "." + field.getName() + " holds a " + held.getName());
      }
    }
  }

  @Test
  void theQueueHoldsAtMostTheLimitAndOneSuppressedLineAndStopsAcceptingAfterThat() {
    StringBuilder table = new StringBuilder();
    for (int i = 0; i < HookMisses.LIMIT + 50; i++) {
      table.append("U a/B").append(i).append(" report m()V\n");
    }
    HookMisses.startHeld(HookExpectations.parse(table.toString()), recorder(new ArrayList<String>()));

    for (int i = 0; i < HookMisses.LIMIT + 50; i++) {
      HookExpectation pair = HookMisses.table().forClass("a/B" + i)[0];
      boolean wanted = HookMisses.wants(pair);
      HookMisses.miss(pair, "U", classCalling("a/B" + i, null), null, HookMisses.NO_AGENT_CALL, null);
      assertEquals(i <= HookMisses.LIMIT, wanted, "once suppression is final, a candidate is not even read: " + i);
    }

    assertEquals(HookMisses.LIMIT + 1, HookMisses.queued());
  }

  @Test
  void anExemptOlderVersionDoesNotUseThePairUpForABrokenOneLoadedLater() {
    final List<String> written = new ArrayList<String>();
    HookMisses.start(HookExpectations.parse("U a/B absent m(I)V\n"), recorder(written), true);
    HookExpectation pair = HookMisses.table().forClass("a/B")[0];

    HookMisses.miss(pair, "U", classWith("a/B", "other", "()V"), null, HookMisses.NO_AGENT_CALL, null);
    assertEquals(0, written.size(), "an older release, before the hooked method existed");
    assertTrue(HookMisses.wants(pair), "and the pair is still open");

    HookMisses.miss(pair, "U", classWith("a/B", "m", "(J)V"), null, HookMisses.NO_AGENT_CALL, null);
    assertEquals(1, written.size(), "the same method with another descriptor, loaded later, is reported");
  }

  @Test
  void aWriterThatThrowsOnTheWorkerIsCountedNotSwallowed() throws Exception {
    HookMisses.start(HookExpectations.parse("U a/B report m()V\nU a/C report m()V\n"), new HookMissSink() {
      @Override public void write(String diagnostic, String fields) {
        throw new IllegalStateException("sink down");
      }

      @Override public boolean enterOwnIo() {
        return false;
      }

      @Override public void exitOwnIo(boolean entered) {}
    });

    HookMisses.miss(HookMisses.table().forClass("a/B")[0], "U", classCalling("a/B", null), null, HookMisses.NO_AGENT_CALL, null);
    HookMisses.miss(HookMisses.table().forClass("a/C")[0], "U", classCalling("a/C", null), null, HookMisses.NO_AGENT_CALL, null);

    long deadline = System.nanoTime() + 10_000_000_000L;
    while (HookMisses.sinkFailures() < 2 && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    assertEquals(2, HookMisses.sinkFailures());
  }

  @Test
  void theOriginIsPlainTextWithoutQueryCredentialsOrAHandlerCallback() throws Exception {
    assertEquals("/opt/my lib/x-1.0.jar", HookMisses.filePath("/opt/my%20lib/x-1.0.jar"));
    assertEquals("/opt/\u00e9/x.jar", HookMisses.filePath("/opt/%C3%A9/x.jar"));
    assertEquals("/opt/100%/x.jar", HookMisses.filePath("/opt/100%/x.jar"), "a lone percent sign stays");
    assertEquals("http://repo.example/lib/x.jar", HookMisses.withoutCredentials("http://user:secret@repo.example/lib/x.jar"));
    assertEquals("jar:http://repo.example/a.jar!/", HookMisses.withoutCredentials("jar:http://tok@repo.example/a.jar!/"));

    // A handler that would run application code when asked to render the URL is never asked.
    URL handled = new URL(null, "weird://host:9/a/b.jar?token=1#frag", new java.net.URLStreamHandler() {
      @Override protected java.net.URLConnection openConnection(URL u) {
        throw new AssertionError("opened");
      }

      @Override protected String toExternalForm(URL u) {
        throw new AssertionError("a custom handler rendered the location");
      }
    });
    HookMisses.Origin origin = HookMisses.Origin.of(new ProtectionDomain(new CodeSource(handled, (Certificate[]) null), null));
    assertEquals("weird://host:9/a/b.jar", origin.path, "no query, no fragment");
    assertEquals("b.jar", origin.name);
  }

  private static HookMissSink recorder(final List<String> written) {
    return new HookMissSink() {
      @Override public void write(String diagnostic, String fields) {
        written.add(fields);
      }

      @Override public boolean enterOwnIo() {
        return false;
      }

      @Override public void exitOwnIo(boolean entered) {}
    };
  }

  private static Map<String, Set<String>> calls(byte[] classFile, HookExpectation pair) {
    return AgentCalls.inMethods(classFile, new HookExpectation[] {pair});
  }

  /** A class whose {@code run()V} calls {@code owner.hook()} once per owner given, and no other method. */
  private static byte[] classWith(String name, String method, String descriptor) {
    ClassWriter writer = begin(name);
    MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, method, descriptor, null, null);
    mv.visitCode();
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** A class with one static method {@code method} that calls {@code owner.callee()} once. */
  private static byte[] classCallingMethod(String name, String method, String descriptor, String owner, String callee) {
    ClassWriter writer = begin(name);
    MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, method, descriptor, null, null);
    mv.visitCode();
    mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, callee, "()V", false);
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** The reflective hook's sequence for {@code evaluate}, with or without its loadClass and its invoke. */
  private static byte[] reflective(String name, boolean loaded, boolean invoked) {
    ClassWriter writer = begin(name);
    MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
    mv.visitCode();
    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/ClassLoader", "getSystemClassLoader", "()Ljava/lang/ClassLoader;", false);
    mv.visitLdcInsn("io.ohmyrasp.agent.hook.OhMyRaspHooks");
    if (loaded) {
      mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", false);
      mv.visitLdcInsn("evaluate");
      mv.visitInsn(Opcodes.ACONST_NULL);
      mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
          "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
      if (invoked) {
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
            "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
      }
      mv.visitInsn(Opcodes.POP);
    } else {
      mv.visitInsn(Opcodes.POP2);
    }
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
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
