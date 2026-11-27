package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.PrintStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * Every entry the injected code calls asks {@link HookActivation#inactive} first and, while the hooks are off, does
 * what the uninstrumented code would: no detection, no event, no block, no request state. This is what keeps the
 * calls a failed start already injected inert (the start-failure tests show it in a real JVM).
 */
final class HookActivationTest {
  /** Public static methods of OhMyRaspHooks the injected code never calls: the agent's own callers use them. */
  private static final Set<String> AGENT_INTERNAL =
      Set.of("installPolicy", "currentRequest", "blockingEnabled", "isDangerousDeserialization");

  @AfterEach
  void hooksOnAgain() {
    HookActivation.activate();
    OhMyRaspHooks.reportTo(null);
    System.clearProperty("ohmyrasp.block");
  }

  @Test
  void everyPublicEntryChecksTheActivationFirst() throws Exception {
    List<String> unguarded = new ArrayList<>();
    unguarded.addAll(unguardedEntries(OhMyRaspHooks.class, AGENT_INTERNAL));
    unguarded.addAll(unguardedEntries(DeserializationGuard.class, Set.of()));
    assertEquals(List.of(), unguarded,
        "these public entries do not begin with HookActivation.inactive(), so injected calls to them would act "
            + "before a start commits and after a failed one");
  }

  /**
   * The callees of the inventory that need no activation check, as {@code owner.name}, each with its reason. Keep
   * it minimal: a method is here only when it touches no agent state and changes no application value.
   */
  private static final Map<String, String> INERT_WITHOUT_GUARD = Map.of();

  /**
   * Scope exits that take the token their entry returned and do nothing for null, instead of asking the activation:
   * the entry returns a token only when it opened the scope, so the exit undoes exactly that, also when the hooks
   * turned off in between (an exit that asked the activation would leave the scope open on the thread).
   */
  private static final Set<String> TOKEN_EXITS = Set.of(
      "AttachmentFileRead.endRead", "AttachmentFileRead.endReference", "HostDirectory.visited", "HostReadPath.endFacade",
      "HttpTransportObservation.exitAcquisition", "JmxWriteScope.exit", "LookupRoute.exit", "MultipartFilename.exit",
      "MyBatisSqlTrace.exitStatement", "ProcessLaunch.exit", "SpringProcessInit.exitInit", "SpringProcessInit.exitParse",
      "XmlRpcReadScope.exit");

  /**
   * Every agent method that the code the primary transformer injects calls, taken from transformed bytecode (see
   * {@link InjectedCallInventory}), is inert while the hooks are off: it begins with {@code HookActivation.inactive()},
   * or it is a scope exit of {@link #TOKEN_EXITS} that begins by testing its token, or it is in {@link
   * #INERT_WITHOUT_GUARD} with its reason. And wherever the transformed bytecode calls a token exit, it passes a local
   * that the same method stored straight from a token entry's return: an exit never gets a scope its own entry did
   * not open.
   */
  @Test
  void everyAgentMethodTheInjectedCodeCallsIsInertWhileTheHooksAreOff() throws Exception {
    long started = System.nanoTime();
    InjectedCallInventory inventory = new InjectedCallInventory();
    inventory.scanRuntimeImage();
    inventory.scanClassPath();
    String map = System.getProperty("ohmyrasp.hookTargets.primary");
    assertNotNull(map, "the build passes the recorded hook-target map as ohmyrasp.hookTargets.primary");
    inventory.readRecordedMap(Path.of(map));
    System.out.printf("[inventory] %d classes transformed, %d injected agent callees, %d ms%n",
        inventory.classesRead, inventory.callees.size(), (System.nanoTime() - started) / 1_000_000);

    List<String> failures = new ArrayList<>();
    Set<String> seen = new java.util.HashSet<>();
    for (Map.Entry<String, String> callee : inventory.callees.entrySet()) {
      String call = callee.getKey();
      int dot = call.lastIndexOf('.', call.indexOf(' '));
      String owner = call.substring(0, dot);
      String name = call.substring(dot + 1, call.indexOf(' '));
      String descriptor = call.substring(call.indexOf(' ') + 1);
      String method = owner.substring(owner.lastIndexOf('/') + 1) + "." + name;
      System.out.println("[inventory] " + call + "  <- " + callee.getValue());
      if (owner.equals("io/ohmyrasp/agent/hook/HookActivation") || INERT_WITHOUT_GUARD.containsKey(method)) {
        seen.add(method);
        continue;
      }
      Map<String, Opening> openings = openings(owner);
      if (openings == null) {
        failures.add(call + ": no class file for " + owner);
        continue;
      }
      boolean found = false;
      for (Map.Entry<String, Opening> candidate : openings.entrySet()) {
        String candidateName = candidate.getKey().substring(0, candidate.getKey().indexOf('('));
        String candidateDescriptor = candidate.getKey().substring(candidateName.length());
        // A recorded row names no descriptor: every public overload (injected code can call no other).
        boolean matches = candidateName.equals(name) && (descriptor.equals(InjectedCallInventory.ANY_DESCRIPTOR)
            ? (candidate.getValue().access & Opcodes.ACC_PUBLIC) != 0 : descriptor.equals(candidateDescriptor));
        if (!matches || (candidate.getValue().access & Opcodes.ACC_SYNTHETIC) != 0) {
          continue;
        }
        found = true;
        seen.add(method);
        Opening opening = candidate.getValue();
        boolean inert = TOKEN_EXITS.contains(method) ? opening.testsToken() : opening.guarded();
        if (!inert && seen.add(method + candidateDescriptor)) {
          failures.add(method + candidateDescriptor + (TOKEN_EXITS.contains(method)
              ? " does not begin by testing its token" : " does not begin with HookActivation.inactive()")
              + " (called from " + callee.getValue() + ")");
        }
      }
      if (!found) {
        failures.add(call + ": no such method in " + owner + " (called from " + callee.getValue() + ")");
      }
    }
    for (Map.Entry<String, String> exit : inventory.untokenedExits.entrySet()) {
      String call = exit.getKey();
      String owner = call.substring(0, call.lastIndexOf('.', call.indexOf(' ')));
      String method = owner.substring(owner.lastIndexOf('/') + 1) + call.substring(owner.length(), call.indexOf(' '));
      if (TOKEN_EXITS.contains(method)) {
        failures.add(method + " is called with something other than its entry's token (in " + exit.getValue() + ")");
      }
    }
    List<String> stale = new ArrayList<>();
    for (String listed : INERT_WITHOUT_GUARD.keySet()) {
      if (!seen.contains(listed)) stale.add(listed);
    }
    for (String listed : TOKEN_EXITS) {
      if (!seen.contains(listed)) stale.add(listed);
    }
    assertEquals(List.of(), stale, "listed here, but no injected code calls them any more: take them off the list");
    assertEquals(List.of(), failures.stream().distinct().sorted().toList(),
        "the injected code calls these agent methods, and they would act while the hooks are off (before a start "
            + "commits, and after a failed one: removing a transformer does not remove the calls it injected)");
  }

  @Test
  void whileTheHooksAreOffAnEntryThatWouldBlockDoesNothing(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    OhMyRaspHooks.reportTo(JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console));
    System.setProperty("ohmyrasp.block", "true");
    URL metadata = new URL("http://169.254.169.254/latest/meta-data/");
    // The control: with the hooks on, the same calls are detections that are written, and a remote JNDI name blocks
    // outside a request too (an intrinsic finding; a metadata destination alone only logs there).
    assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeJndiLookup("ldap://attacker.example/Exploit"));
    assertTrue(Files.size(log) > 0, "the control detection was not written");
    Files.delete(log);
    OhMyRaspHooks.beforeUrlOpen(metadata);
    assertTrue(Files.exists(log) && Files.size(log) > 0, "the metadata control was not written");
    Files.delete(log);

    HookActivation.deactivate();
    assertTrue(HookActivation.inactive());
    OhMyRaspHooks.beforeUrlOpen(metadata);
    OhMyRaspHooks.beforeRuntimeExecString("sh -c id");
    OhMyRaspHooks.beforeJndiLookup("ldap://attacker.example/Exploit");

    assertFalse(Files.exists(log), "an inactive hook wrote an event");
  }

  @Test
  void whileTheHooksAreOffTheValueReturningEntriesReturnWhatTheApplicationWouldHave() {
    HookActivation.deactivate();
    Object request = new Request();
    assertTrue(OhMyRaspHooks.admitServletRequest(request, null), "an inactive admission admits");
    assertFalse(OhMyRaspHooks.currentRequest().active(), "an inactive admission opened a request");
    assertNull(OhMyRaspHooks.enterBodyRead(new Object()), "an inactive body read records nothing");
    assertNull(OhMyRaspHooks.enterBodyRead(new Object(), java.nio.ByteBuffer.allocate(4)),
        "an inactive buffer read records nothing");
    OhMyRaspHooks.abortBodyRead(); // inert
    assertNull(OhMyRaspHooks.beginGeneratedLines(Path.of("/tmp/x.sh")));
    Object value = new Object();
    assertSame(value, OhMyRaspHooks.jmxAttributeDisplayReceiver(value));
    assertFalse(OhMyRaspHooks.enforceElasticLz4Bounds());
    // The serial filter: no guard is installed, and the application's own filter alone decides.
    assertNull(DeserializationGuard.filterOrGuard(null));
    ObjectInputFilter rejectAll = info -> ObjectInputFilter.Status.REJECTED;
    assertSame(rejectAll, DeserializationGuard.filterOrGuard(rejectAll));
    assertEquals(ObjectInputFilter.Status.REJECTED, DeserializationGuard.checkInput(rejectAll, null, null));
    ObjectInputFilter allowAll = info -> ObjectInputFilter.Status.ALLOWED;
    assertEquals(ObjectInputFilter.Status.ALLOWED, DeserializationGuard.checkInput(allowAll, null));
  }

  /**
   * The XML-RPC parse scope, through the bytecode the primary transformer injects into the parser (a class of that
   * name built here, whose getResult calls {@link Midway}): an entry that runs while the hooks are off opens nothing,
   * and its exit closes nothing even when the hooks came on in between; an entry that opened a scope has it closed
   * by its own exit even when the hooks went off in between, also when the method throws.
   */
  @Test
  void anXmlRpcScopeExitClosesOnlyTheScopeItsOwnEntryOpened() throws Throwable {
    java.lang.reflect.Method getResult = transformedXmlRpcParser().getMethod("getResult");
    Object parser = getResult.getDeclaringClass().getConstructor().newInstance();
    Object[] midway = new Object[1];

    // Off at the entry, on before the exit: the thread's own scope is left as it was.
    Object outer = XmlRpcReadScope.enter();
    try {
      HookActivation.deactivate();
      Midway.next = () -> {
        midway[0] = xmlRpcScope();
        HookActivation.activate();
      };
      assertEquals("result", getResult.invoke(parser));
      assertSame(outer, midway[0], "an entry that ran while the hooks were off opened a scope");
      assertSame(outer, xmlRpcScope(), "the exit closed a scope its entry did not open");
    } finally {
      HookActivation.activate();
      XmlRpcReadScope.exit(outer);
    }
    assertNull(xmlRpcScope());

    // On at the entry, off before the method throws: its exit still closes the scope it opened.
    Midway.next = () -> {
      midway[0] = xmlRpcScope();
      HookActivation.deactivate();
      throw new IllegalStateException("parse failed");
    };
    try {
      var thrown = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> getResult.invoke(parser));
      assertEquals("parse failed", thrown.getCause().getMessage(), "the application's own exception changed");
      assertTrue(midway[0] instanceof XmlRpcReadScope, "the entry opened no scope while the hooks were on");
      assertNull(xmlRpcScope(), "the exit left its scope open because the hooks went off");
    } finally {
      Midway.next = null;
      HookActivation.activate();
    }
  }

  /**
   * Helpers that stand in for an application call, or pass an application value on, do only that while the hooks
   * are off: the value comes back unchanged, and no agent state is read, consumed or changed.
   */
  @Test
  void whileTheHooksAreOffAHelperThatStandsInForAnApplicationValueReturnsItUnchanged() {
    java.io.File original = new java.io.File("/srv/reports");
    java.io.File used = new java.io.File("/srv/reports/../reports");
    String[] entries = {"weekly.txt"};
    io.ohmyrasp.agent.file.HostDirectory.listed(used, entries, original); // hooks on: a substitution is pending
    HookActivation.deactivate();
    assertSame(original, io.ohmyrasp.agent.file.HostDirectory.selectedFile(original, entries),
        "an inactive hand-off replaced the application's File");
    StringBuilder sql = new StringBuilder("select 1");
    assertSame(sql, io.ohmyrasp.agent.sql.MyBatisSqlTrace.appendPiece(sql, " from t"));
    assertSame(sql, io.ohmyrasp.agent.sql.MyBatisSqlTrace.insert(sql, 0, "/* x */ "));
    assertSame(sql, io.ohmyrasp.agent.sql.MyBatisSqlTrace.delete(sql, 0, 8));
    assertEquals("select 1 from t", sql.toString());
    assertNull(io.ohmyrasp.agent.naming.LookupRoute.selecting("ldap://h/x", "ldap", new Object(), "ldap://h/x"));
    HookActivation.activate();
    // The pending substitution was neither used nor consumed while the hooks were off.
    assertSame(used, io.ohmyrasp.agent.file.HostDirectory.selectedFile(original, entries));
  }

  /** What the transformed XML-RPC parser's getResult runs between its scope entry and exit. */
  public static final class Midway {
    static volatile Runnable next;

    public static void run() {
      Runnable step = next;
      if (step != null) step.run();
    }
  }

  /** The thread's current XML-RPC parse scope. */
  private static Object xmlRpcScope() {
    try {
      java.lang.reflect.Field active = XmlRpcReadScope.class.getDeclaredField("ACTIVE");
      active.setAccessible(true);
      return ((ThreadLocal<?>) active.get(null)).get();
    } catch (ReflectiveOperationException unreadable) {
      throw new AssertionError(unreadable);
    }
  }

  /** A class named as the XML-RPC parser, as the primary transformer rewrites it, defined by a loader of its own. */
  private static Class<?> transformedXmlRpcParser() {
    String name = "org/apache/xmlrpc/parser/SerializableParser";
    org.objectweb.asm.ClassWriter writer = new org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", null);
    MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    init.visitCode();
    init.visitVarInsn(Opcodes.ALOAD, 0);
    init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    init.visitInsn(Opcodes.RETURN);
    init.visitMaxs(0, 0);
    init.visitEnd();
    MethodVisitor result = writer.visitMethod(Opcodes.ACC_PUBLIC, "getResult", "()Ljava/lang/Object;", null, null);
    result.visitCode();
    result.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getInternalName(Midway.class), "run", "()V", false);
    result.visitLdcInsn("result");
    result.visitInsn(Opcodes.ARETURN);
    result.visitMaxs(0, 0);
    result.visitEnd();
    writer.visitEnd();
    ClassLoader parent = HookActivationTest.class.getClassLoader();
    byte[] transformed = new io.ohmyrasp.agent.asm.OhMyRaspTransformer()
        .transform(null, parent, name, null, null, writer.toByteArray());
    assertNotNull(transformed, "the primary transformer left the XML-RPC parser alone");
    assertTrue(InjectedCallInventory.agentCalls(transformed, new java.util.HashSet<>())
        .contains("io/ohmyrasp/agent/hook/XmlRpcReadScope.exit (Ljava/lang/Object;)V"));
    return new ClassLoader(parent) {
      Class<?> define() {
        return defineClass(name.replace('/', '.'), transformed, 0, transformed.length);
      }
    }.define();
  }

  @Test
  void theWarmUpThreadAloneSeesTheHooksBeforeTheyAreOn() throws Exception {
    HookActivation.deactivate();
    assertTrue(HookActivation.inactive());
    final boolean[] seen = new boolean[2];
    Thread warming = new Thread(() -> {
      HookActivation.beginWarmUp();
      try {
        seen[0] = HookActivation.inactive();
      } finally {
        HookActivation.endWarmUp();
      }
      seen[1] = HookActivation.inactive();
    });
    warming.start();
    warming.join();
    assertFalse(seen[0], "the warm-up thread did not see the hooks act");
    assertTrue(seen[1], "the hooks stayed on for the thread after its warm-up");
    assertTrue(HookActivation.inactive(), "another thread saw the hooks act during a warm-up");
  }

  /** The servlet request surface an admission reads, with nothing in it. */
  public static final class Request {
    public String getMethod() {
      return "GET";
    }

    public String getRequestURI() {
      return "/";
    }

    public String getQueryString() {
      return null;
    }

    public Map<String, String[]> getParameterMap() {
      return Map.of();
    }

    public java.util.Enumeration<String> getHeaderNames() {
      return java.util.Collections.emptyEnumeration();
    }

    public String getHeader(String name) {
      return null;
    }
  }

  /** The public static methods of {@code type} whose first instruction is not a call to HookActivation.inactive(). */
  static List<String> unguardedEntries(Class<?> type, Set<String> exempt) throws Exception {
    List<String> unguarded = new ArrayList<>();
    for (Map.Entry<String, Opening> method : openings(Type.getInternalName(type)).entrySet()) {
      Opening opening = method.getValue();
      String name = method.getKey().substring(0, method.getKey().indexOf('('));
      boolean entry = (opening.access & Opcodes.ACC_PUBLIC) != 0 && (opening.access & Opcodes.ACC_STATIC) != 0
          && (opening.access & Opcodes.ACC_SYNTHETIC) == 0 && !exempt.contains(name);
      if (entry && !opening.guarded()) {
        unguarded.add(type.getSimpleName() + "." + method.getKey());
      }
    }
    return unguarded;
  }

  /**
   * How each method of a class begins ({@code name descriptor} to its first two instructions), read from the class
   * file the test's loader finds for {@code owner}; null when it finds none.
   */
  static Map<String, Opening> openings(String owner) throws Exception {
    Map<String, Opening> openings = new TreeMap<>();
    try (InputStream in = HookActivationTest.class.getClassLoader().getResourceAsStream(owner + ".class")) {
      if (in == null) {
        return null;
      }
      new ClassReader(in).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
            String[] exceptions) {
          Opening opening = new Opening(access, descriptor);
          openings.put(name + descriptor, opening);
          return new MethodVisitor(Opcodes.ASM9) {
            @Override public void visitMethodInsn(int op, String owner, String called, String desc, boolean itf) {
              opening.add(op, owner + "." + called + desc);
            }

            @Override public void visitInsn(int opcode) {
              opening.add(opcode, null);
            }

            @Override public void visitVarInsn(int opcode, int var) {
              opening.add(opcode, var);
            }

            @Override public void visitFieldInsn(int opcode, String owner, String field, String desc) {
              opening.add(opcode, owner + "." + field);
            }

            @Override public void visitTypeInsn(int opcode, String typeName) {
              opening.add(opcode, typeName);
            }

            @Override public void visitLdcInsn(Object value) {
              opening.add(Opcodes.LDC, value);
            }

            @Override public void visitIntInsn(int opcode, int operand) {
              opening.add(opcode, operand);
            }

            @Override public void visitIincInsn(int var, int increment) {
              opening.add(Opcodes.IINC, var);
            }

            @Override public void visitJumpInsn(int opcode, org.objectweb.asm.Label label) {
              opening.add(opcode, null);
            }

            @Override public void visitTableSwitchInsn(int min, int max, org.objectweb.asm.Label dflt,
                org.objectweb.asm.Label... labels) {
              opening.add(Opcodes.TABLESWITCH, null);
            }

            @Override public void visitLookupSwitchInsn(org.objectweb.asm.Label dflt, int[] keys,
                org.objectweb.asm.Label[] labels) {
              opening.add(Opcodes.LOOKUPSWITCH, null);
            }

            @Override public void visitMultiANewArrayInsn(String desc, int dims) {
              opening.add(Opcodes.MULTIANEWARRAY, desc);
            }

            @Override public void visitInvokeDynamicInsn(String n, String d, org.objectweb.asm.Handle h, Object... a) {
              opening.add(Opcodes.INVOKEDYNAMIC, n);
            }
          };
        }
      }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }
    return openings;
  }

  /** The first two instructions of a method, opcode and operand each. */
  static final class Opening {
    private static final String GUARD = "io/ohmyrasp/agent/hook/HookActivation.inactive()Z";
    final int access;
    final String descriptor;
    final int[] opcodes = {-1, -1};
    final Object[] operands = new Object[2];
    private int seen;

    Opening(int access, String descriptor) {
      this.access = access;
      this.descriptor = descriptor;
    }

    void add(int opcode, Object operand) {
      if (seen < 2) {
        opcodes[seen] = opcode;
        operands[seen] = operand;
      }
      seen++;
    }

    /** It begins with HookActivation.inactive(), or it is a void method that only returns. */
    boolean guarded() {
      return (opcodes[0] == Opcodes.INVOKESTATIC && GUARD.equals(operands[0]))
          || (opcodes[0] == Opcodes.RETURN && descriptor.endsWith(")V"));
    }

    /**
     * It is a static scope exit that begins by testing one of its reference parameters against null: {@code if
     * (token == null) return;}, the token its entry returned when, and only when, it opened the scope.
     */
    boolean testsToken() {
      if ((access & Opcodes.ACC_STATIC) == 0 || opcodes[0] != Opcodes.ALOAD
          || (opcodes[1] != Opcodes.IFNULL && opcodes[1] != Opcodes.IFNONNULL)) {
        return false;
      }
      int slot = 0;
      for (Type argument : Type.getArgumentTypes(descriptor)) {
        if (slot == (Integer) operands[0]) {
          return argument.getSort() == Type.OBJECT || argument.getSort() == Type.ARRAY;
        }
        slot += argument.getSize();
      }
      return false;
    }
  }
}
