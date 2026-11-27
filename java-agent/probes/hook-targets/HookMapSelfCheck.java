import io.ohmyrasp.agent.shaded.asm.ClassWriter;
import io.ohmyrasp.agent.shaded.asm.MethodVisitor;
import io.ohmyrasp.agent.shaded.asm.Opcodes;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * What HookMap counts, on classes made here: the rules the recorded maps rest on, checked before the
 * real run so that a change to them fails by name and not as a silent change of the map.
 *
 * <pre>java -cp &lt;this class&gt;:&lt;HookMap&gt;:&lt;agent jar&gt; HookMapSelfCheck</pre>
 */
public final class HookMapSelfCheck {
  private static final String HOOKS = "io/ohmyrasp/agent/Hooks";

  private interface Body { void emit(MethodVisitor m); }

  /** A class whose static method m()V has the given body. */
  private static byte[] classWith(String name, Body body) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    MethodVisitor m = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m", "()V", null, null);
    m.visitCode();
    body.emit(m);
    m.visitInsn(Opcodes.RETURN);
    m.visitMaxs(0, 0);
    m.visitEnd();
    return writer.toByteArray();
  }

  private static Body calls(final int times, final String method) {
    return new Body() {
      public void emit(MethodVisitor m) {
        for (int i = 0; i < times; i++) m.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, method, "()V", false);
      }
    };
  }

  /** The sequence the EL, JEXL and OSGi servlet hooks emit; `without` names the call to leave out. */
  private static Body reflective(final String without, final int times) {
    return new Body() {
      public void emit(MethodVisitor m) {
        for (int i = 0; i < times; i++) {
          m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/ClassLoader", "getSystemClassLoader", "()Ljava/lang/ClassLoader;", false);
          m.visitLdcInsn("io.ohmyrasp.agent.Hooks");
          if (!"loadClass".equals(without)) {
            m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", false);
          }
          m.visitLdcInsn("beforeHook");
          m.visitInsn(Opcodes.ICONST_0);
          m.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
          if (!"getMethod".equals(without)) {
            m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
          }
          m.visitInsn(Opcodes.ACONST_NULL);
          m.visitInsn(Opcodes.ICONST_0);
          m.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
          if (!"invoke".equals(without)) {
            m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
          }
          m.visitInsn(Opcodes.POP);
        }
      }
    };
  }

  private static void check(boolean condition, String what) {
    if (!condition) throw new AssertionError("HookMap self-check failed: " + what);
  }

  private static int total(Map<String, Map<String, Integer>> gained) {
    int sum = 0;
    for (Map<String, Integer> method : gained.values()) for (int n : method.values()) sum += n;
    return sum;
  }

  private static void counts() {
    byte[] none = classWith("C", calls(0, "x"));
    check(total(HookMap.gains(none, classWith("C", calls(1, "x")))) == 1, "one call is one");
    check(total(HookMap.gains(none, classWith("C", calls(2, "x")))) == 2, "two calls to the same agent method are two");
    check(total(HookMap.gains(classWith("C", calls(2, "x")), classWith("C", calls(1, "x")))) == 0, "losing a call is not a gain");
    check(total(HookMap.gains(classWith("C", calls(1, "x")), classWith("C", calls(2, "x")))) == 1, "a hook added to a method that already called the agent counts");
    check(!HookMap.gains(none, classWith("C", calls(1, "x"))).equals(HookMap.gains(none, classWith("C", calls(2, "x")))),
        "one call and two calls must differ in the map");
  }

  private static void reflection() {
    byte[] none = classWith("C", calls(0, "x"));
    check(total(HookMap.gains(none, classWith("C", reflective("", 1)))) == 1, "the reflective sequence is one call");
    check(total(HookMap.gains(none, classWith("C", reflective("", 2)))) == 2, "two reflective sequences are two calls");
    for (String missing : new String[] {"loadClass", "getMethod", "invoke"}) {
      check(total(HookMap.gains(none, classWith("C", reflective(missing, 1)))) == 0,
          "the class and method constants without " + missing + " are not a hook");
    }
    Map<String, Map<String, Integer>> gained = HookMap.gains(none, classWith("C", reflective("", 1)));
    check(gained.get("m ()V").containsKey("io/ohmyrasp/agent/Hooks.beforeHook (reflective)"), "the reflective hook names its method");
  }

  // ---- registration ------------------------------------------------------------------------------

  private static byte[] transformerClass(String name) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", new String[] {"java/lang/instrument/ClassFileTransformer"});
    MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    init.visitCode();
    init.visitVarInsn(Opcodes.ALOAD, 0);
    init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    init.visitInsn(Opcodes.RETURN);
    init.visitMaxs(0, 0);
    init.visitEnd();
    return writer.toByteArray();
  }

  private static void newObject(MethodVisitor m, String type) {
    m.visitTypeInsn(Opcodes.NEW, type);
    m.visitInsn(Opcodes.DUP);
    m.visitMethodInsn(Opcodes.INVOKESPECIAL, type, "<init>", "()V", false);
  }

  private static final String ADD = "(Ljava/lang/instrument/ClassFileTransformer;Z)V";

  private static void add(MethodVisitor m) {
    m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/instrument/Instrumentation", "addTransformer", ADD, true);
  }

  private interface Entry { void emit(ClassWriter writer); }

  private static List<String> registered(Entry entry) throws Exception {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "p/Entry", null, "java/lang/Object", null);
    entry.emit(writer);
    File file = File.createTempFile("hookmap-selfcheck", ".jar");
    try {
      try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(file))) {
        put(jar, "p/Entry", writer.toByteArray());
        for (String name : new String[] {"p/A", "p/B", "p/C"}) put(jar, name, transformerClass(name));
      }
      try (JarFile jar = new JarFile(file)) {
        return HookMap.registeredTypes(jar, "p/Entry");
      }
    } finally {
      file.delete();
    }
  }

  private static void put(JarOutputStream jar, String name, byte[] bytes) throws Exception {
    jar.putNextEntry(new JarEntry(name + ".class"));
    jar.write(bytes);
    jar.closeEntry();
  }

  private static MethodVisitor install(ClassWriter writer, String name) {
    MethodVisitor m = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, "(Ljava/lang/instrument/Instrumentation;)V", null, null);
    m.visitCode();
    return m;
  }

  private static void finish(MethodVisitor m) {
    m.visitInsn(Opcodes.RETURN);
    m.visitMaxs(0, 0);
    m.visitEnd();
  }

  private static void fails(Entry entry, String what) throws Exception {
    try {
      registered(entry);
    } catch (IllegalStateException expected) {
      return;
    }
    throw new AssertionError("HookMap self-check failed: " + what + " was accepted");
  }

  private static void registration() throws Exception {
    // new A() and new C() passed to addTransformer, in that order; new B() constructed and dropped.
    check(registered(new Entry() {
      public void emit(ClassWriter writer) {
        MethodVisitor m = install(writer, "install");
        m.visitVarInsn(Opcodes.ALOAD, 0);
        newObject(m, "p/A");
        m.visitInsn(Opcodes.ICONST_1);
        add(m);
        newObject(m, "p/B");
        m.visitInsn(Opcodes.POP);
        m.visitVarInsn(Opcodes.ALOAD, 0);
        newObject(m, "p/C");
        m.visitVarInsn(Opcodes.ILOAD, 1);
        add(m);
        finish(m);
      }
    }).equals(Arrays.asList("p/A", "p/C")), "new B() that is never passed to addTransformer must not count, and the order is the call order");
    check(registered(new Entry() {
      public void emit(ClassWriter writer) {
        MethodVisitor m = install(writer, "install");
        newObject(m, "p/C");
        m.visitVarInsn(Opcodes.ASTORE, 2);
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitVarInsn(Opcodes.ALOAD, 2);
        m.visitInsn(Opcodes.ICONST_0);
        add(m);
        finish(m);
      }
    }).equals(Collections.singletonList("p/C")), "a transformer stored once in a local is read");
    fails(new Entry() {
      public void emit(ClassWriter writer) {
        MethodVisitor m = install(writer, "install");
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitVarInsn(Opcodes.ALOAD, 0);   // a transformer that does not come from new X()
        m.visitInsn(Opcodes.ICONST_1);
        add(m);
        finish(m);
      }
    }, "a transformer argument that is not new X()");
    fails(new Entry() {
      public void emit(ClassWriter writer) {
        MethodVisitor m = install(writer, "install");
        newObject(m, "p/A");
        m.visitVarInsn(Opcodes.ASTORE, 2);
        newObject(m, "p/B");
        m.visitVarInsn(Opcodes.ASTORE, 2);
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitVarInsn(Opcodes.ALOAD, 2);
        m.visitInsn(Opcodes.ICONST_1);
        add(m);
        finish(m);
      }
    }, "a local stored twice");
    fails(new Entry() {
      public void emit(ClassWriter writer) {
        MethodVisitor one = install(writer, "one");
        one.visitVarInsn(Opcodes.ALOAD, 0);
        newObject(one, "p/A");
        one.visitInsn(Opcodes.ICONST_1);
        add(one);
        finish(one);
        MethodVisitor two = install(writer, "two");
        two.visitVarInsn(Opcodes.ALOAD, 0);
        newObject(two, "p/B");
        two.visitInsn(Opcodes.ICONST_1);
        add(two);
        finish(two);
      }
    }, "addTransformer calls in two methods");
    fails(new Entry() {
      public void emit(ClassWriter writer) {
        MethodVisitor m = install(writer, "install");
        newObject(m, "p/A");
        m.visitInsn(Opcodes.POP);
        finish(m);
      }
    }, "an entry class that never calls addTransformer");
  }

  // ---- chaining and attribution ------------------------------------------------------------------

  private static final class FakeUnit implements HookMap.Unit {
    private final String name;
    private final byte[] adds;
    private final boolean needsPristine;

    FakeUnit(String name, byte[] adds, boolean needsPristine) {
      this.name = name;
      this.adds = adds;
      this.needsPristine = needsPristine;
    }

    public String name() { return name; }

    /** A hook that rewrites a class only while it has none of the agent's calls yet, as a visitor that does not expect another's. */
    public byte[] apply(String owner, byte[] bytes) {
      if (needsPristine && !HookMap.agentCalls(bytes).isEmpty()) return null;
      return adds;
    }
  }

  private static void chaining() throws Exception {
    byte[] original = classWith("C", calls(0, "x"));
    List<HookMap.Unit> alone = new ArrayList<HookMap.Unit>();
    alone.add(new FakeUnit("A", classWith("C", calls(1, "a")), true));
    alone.add(new FakeUnit("B", classWith("C", calls(1, "b")), false));
    TreeSet<String> rows = new TreeSet<String>(), differs = new TreeSet<String>();
    HookMap.chain(rows, differs, "lib 1 C ", "C", original, alone);
    check(differs.isEmpty(), "transformers that do not disturb one another are not a chain finding");

    List<HookMap.Unit> disturbed = new ArrayList<HookMap.Unit>();
    disturbed.add(new FakeUnit("A", classWith("C", calls(1, "a")), false));
    disturbed.add(new FakeUnit("B", classWith("C", calls(1, "b")), true));   // B stops once A has been through
    rows.clear();
    HookMap.chain(rows, differs, "lib 1 C ", "C", original, disturbed);
    check(differs.size() == 1 && differs.first().contains("lib 1 C B"), "a transformer that fails after its predecessors is a chain finding with the class: " + differs);
    check(rows.size() == 1 && rows.first().endsWith("@ A"), "the rows are the chained ones: " + rows);
  }

  private static Map<String, Map<String, Integer>> gained(String callee, int calls) {
    Map<String, Integer> callees = new java.util.TreeMap<String, Integer>();
    callees.put(callee, calls);
    Map<String, Map<String, Integer>> method = new java.util.TreeMap<String, Map<String, Integer>>();
    method.put("m ()V", callees);
    return method;
  }

  private static void attribution() {
    Map<String, Map<String, Map<String, Integer>>> alone = new java.util.TreeMap<String, Map<String, Map<String, Integer>>>();
    alone.put("(shared visitors)", gained("A.c", 1));
    alone.put("Module", gained("A.c", 2));      // alone it makes one call more than the empty registry does
    alone.put("Other", gained("A.d", 1));
    TreeSet<String> rows = new TreeSet<String>();
    HookMap.attribute(rows, "lib 1 C ", "m ()V", "A.c", 2, alone);
    check(rows.size() == 2 && rows.contains("lib 1 C m ()V -> A.c @ (shared visitors)") && rows.contains("lib 1 C m ()V -> A.c @ Module"),
        "a module call with the callee of a shared call is its own row: " + rows);
  }

  public static void main(String[] args) throws Exception {
    counts();
    reflection();
    java.io.PrintStream err = System.err;
    System.setErr(new java.io.PrintStream(new java.io.ByteArrayOutputStream()));   // the entries here construct classes they do not register, on purpose
    try {
      registration();
    } finally {
      System.setErr(err);
    }
    chaining();
    attribution();
    System.out.println("HookMap self-check ok");
  }
}
