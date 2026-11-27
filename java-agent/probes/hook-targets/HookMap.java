import io.ohmyrasp.agent.shaded.asm.ClassReader;
import io.ohmyrasp.agent.shaded.asm.tree.AbstractInsnNode;
import io.ohmyrasp.agent.shaded.asm.tree.ClassNode;
import io.ohmyrasp.agent.shaded.asm.tree.LdcInsnNode;
import io.ohmyrasp.agent.shaded.asm.tree.MethodInsnNode;
import io.ohmyrasp.agent.shaded.asm.tree.MethodNode;
import io.ohmyrasp.agent.shaded.asm.tree.TypeInsnNode;
import io.ohmyrasp.agent.shaded.asm.tree.VarInsnNode;
import io.ohmyrasp.agent.shaded.asm.Opcodes;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Prints which methods of real library versions the packaged agent rewrites to call back into itself.
 *
 * <pre>java -cp &lt;this class&gt;:&lt;agent jar&gt; HookMap &lt;agent jar&gt; &lt;staged tree&gt; &lt;primary | entry class&gt;</pre>
 *
 * The staged tree holds one folder per group/artifact/version with the library JAR in it. Every class
 * of every JAR goes through the agent's own transformer classes. A method is hooked when its output
 * calls into io/ohmyrasp/agent/ (not the shaded ASM) more often than its input did, and the row
 * records how many more, per callee: losing one of two calls to the same agent method changes the
 * map. A hook that reaches the agent by reflection counts as one call when the output holds the
 * sequence the reflective hooks emit (getSystemClassLoader, the agent class name, loadClass, the
 * method name, getMethod, invoke) and not when only some of those constants are present.
 *
 * Entries under META-INF/versions/N/ of a multi-release JAR (Multi-Release: true) go through the
 * transformers under the class name they have at run time, and their rows carry the versions prefix.
 *
 * Nothing is loaded from the libraries: the transformers read class files with ASM, and the loader
 * handed to them is a fresh one that resolves nothing, so the result does not depend on a classpath.
 * The loader is not null because several hooks apply only to application classes (loader != null).
 * Two paths of production are therefore not in the map: classBeingRedefined is always null, so the
 * JDBC hook that recognises an already-loaded statement implementation inheriting a JDBC interface
 * is absent, and a loader that resolves classes (an OSGi framework loader, say) is not modelled.
 *
 * The primary agent is one transformer over a registry of HookModules: the map comes from the whole
 * registry (first match wins, as in production). Each row is attributed by running the class with
 * no module and with each module alone and comparing call counts: what the empty registry already
 * produces belongs to the shared visitors, the rest to the module. A backport agent is one
 * transformer class per hook family. Only a transformer that its entry class constructs and passes
 * to Instrumentation.addTransformer counts, in the order of those calls. The map is the chained run,
 * as production does it: each transformer sees what the ones before it wrote. A class on which that
 * differs from running every transformer on the original bytes is reported as a "# chain" line.
 */
public final class HookMap {
  private static final String AGENT = "io/ohmyrasp/agent/";
  private static final String SHADED_ASM = "io/ohmyrasp/agent/shaded/asm/";
  private static final String COMMON = "(shared visitors)";

  /** One hook family: a HookModule of the primary agent or a transformer class of a backport. */
  interface Unit {
    String name();
    byte[] apply(String owner, byte[] bytes) throws Exception;
  }

  private static final class Transform implements Unit {
    private final String name;
    private final Object transformer;
    private final Method method;
    private final ClassLoader loader = new ClassLoader(null) {
      @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        throw new ClassNotFoundException(name);
      }
    };

    Transform(String name, Object transformer) {
      this.name = name;
      this.transformer = transformer;
      Method longest = null;
      for (Method candidate : transformer.getClass().getMethods()) {
        if (candidate.getName().equals("transform") && !candidate.isBridge() && candidate.getParameterTypes().length > 4
            && (longest == null || candidate.getParameterTypes().length > longest.getParameterTypes().length)) {
          longest = candidate;
        }
      }
      if (longest == null) throw new IllegalStateException(name + " has no transform method");
      this.method = longest;
    }

    @Override public String name() { return name; }

    @Override public byte[] apply(String owner, byte[] bytes) throws Exception {
      Object[] args = new Object[method.getParameterTypes().length];
      args[args.length - 5] = loader;      // ClassLoader, name, classBeingRedefined, protectionDomain, bytes
      args[args.length - 4] = owner;
      args[args.length - 1] = bytes;       // a leading Module, where the signature has one, stays null
      return (byte[]) method.invoke(transformer, args);
    }
  }

  // ---- finding the agent's transformers ----------------------------------------------------------

  private static List<Unit> primaryModules() throws Exception {
    Class<?> registryType = Class.forName("io.ohmyrasp.agent.asm.HookRegistry");
    Object defaults = registryType.getMethod("defaults").invoke(null);
    java.lang.reflect.Field field = registryType.getDeclaredField("modules");
    field.setAccessible(true);
    List<?> modules = (List<?>) field.get(defaults);
    Constructor<?> registryConstructor = registryType.getDeclaredConstructor(List.class);
    registryConstructor.setAccessible(true);
    Class<?> transformerType = Class.forName("io.ohmyrasp.agent.asm.OhMyRaspTransformer");
    Constructor<?> transformerConstructor = transformerType.getConstructor(registryType);
    List<Unit> units = new ArrayList<Unit>();
    units.add(new Transform(COMMON, transformerConstructor.newInstance(registryConstructor.newInstance(Collections.emptyList()))));
    for (Object module : modules) {
      Object registry = registryConstructor.newInstance(Collections.singletonList(module));
      units.add(new Transform(module.getClass().getSimpleName(), transformerConstructor.newInstance(registry)));
    }
    return units;
  }

  private static final String INSTRUMENTATION = "java/lang/instrument/Instrumentation";

  /**
   * The transformer classes a backport's entry class registers, in the order it registers them: the
   * classes constructed and passed to Instrumentation.addTransformer. A class that is constructed
   * but never reaches addTransformer is not registered and is only reported.
   *
   * The entry method's bytecode is read for these shapes, and anything else stops the run:
   * <ul>
   * <li>{@code addTransformer(new X(), flag)} and {@code addTransformer(new X())}, where flag is one
   *     instruction (a local, a constant or a static field), and</li>
   * <li>the same with the transformer in a local variable that is stored once, from {@code new X()}.</li>
   * </ul>
   * All calls must be in one method, since the class file does not say in which order methods run.
   */
  static List<String> registeredTypes(JarFile agent, String entry) throws Exception {
    ClassNode entryNode = read(agent, entry);
    List<String> registered = new ArrayList<String>();
    // A static helper of the entry class that takes the transformer and the retransform flag last and calls
    // addTransformer (the backport entries' register, which records each transformer to undo a failed start) is
    // where the registrations are: its calls are read instead of the one addTransformer inside it.
    String helper = null;
    for (MethodNode method : entryNode.methods) {
      if (!method.desc.endsWith(TRANSFORMER_AND_FLAG)) continue;
      for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
        if (insn instanceof MethodInsnNode && INSTRUMENTATION.equals(((MethodInsnNode) insn).owner)
            && "addTransformer".equals(((MethodInsnNode) insn).name)) {
          helper = method.name + method.desc;
        }
      }
    }
    MethodNode registering = null;
    for (MethodNode method : entryNode.methods) {
      if ((method.name + method.desc).equals(helper)) continue;
      for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
        if (!(insn instanceof MethodInsnNode)) continue;
        MethodInsnNode call = (MethodInsnNode) insn;
        boolean direct = INSTRUMENTATION.equals(call.owner) && "addTransformer".equals(call.name);
        boolean throughHelper = entry.equals(call.owner) && (call.name + call.desc).equals(helper);
        if (!direct && !throughHelper) continue;
        if (registering != null && registering != method) {
          throw new IllegalStateException(entry + " calls addTransformer in " + registering.name + " and in " + method.name
              + ": the class file does not give their order");
        }
        registering = method;
        registered.add(transformerArgument(entry, method, call));
      }
    }
    if (registered.isEmpty()) throw new IllegalStateException(entry + " never calls Instrumentation.addTransformer");
    Set<String> constructed = new LinkedHashSet<String>();
    for (MethodNode method : entryNode.methods) {
      for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
        if (insn.getOpcode() == Opcodes.NEW && isTransformer(agent, ((TypeInsnNode) insn).desc, new HashMap<String, Boolean>())) {
          constructed.add(((TypeInsnNode) insn).desc);
        }
      }
    }
    constructed.removeAll(registered);
    if (!constructed.isEmpty()) System.err.println("transformers its entry class constructs but never passes to addTransformer: " + constructed);
    String packagePrefix = entry.substring(0, entry.lastIndexOf('/') + 1);
    List<String> unreferenced = new ArrayList<String>();
    for (JarEntry jarEntry : Collections.list(agent.entries())) {
      String name = jarEntry.getName();
      if (name.startsWith(packagePrefix) && name.endsWith("Transformer.class") && name.indexOf('/', packagePrefix.length()) < 0) {
        String type = name.substring(0, name.length() - ".class".length());
        if (!registered.contains(type) && !constructed.contains(type) && isTransformer(agent, type, new HashMap<String, Boolean>())) unreferenced.add(type);
      }
    }
    if (!unreferenced.isEmpty()) System.err.println("transformers in the line's package that its entry class never references: " + unreferenced);
    return registered;
  }

  private static List<Unit> registeredTransformers(JarFile agent, String entry) throws Exception {
    List<Unit> units = new ArrayList<Unit>();
    for (String type : registeredTypes(agent, entry)) {
      units.add(new Transform(type.substring(type.lastIndexOf('/') + 1), Class.forName(type.replace('/', '.')).getConstructor().newInstance()));
    }
    return units;
  }

  private static AbstractInsnNode previous(AbstractInsnNode insn) {
    AbstractInsnNode before = insn.getPrevious();
    while (before != null && before.getOpcode() < 0) before = before.getPrevious();
    return before;
  }

  /** The end of the descriptor of addTransformer(transformer, canRetransform), and of a helper that wraps it. */
  private static final String TRANSFORMER_AND_FLAG = "Ljava/lang/instrument/ClassFileTransformer;Z)V";

  /** The class constructed as the transformer argument of one addTransformer call, or of the helper's. */
  private static String transformerArgument(String entry, MethodNode method, MethodInsnNode call) {
    String where = entry + "." + method.name + " at instruction " + method.instructions.indexOf(call);
    AbstractInsnNode producer = previous(call);
    if (call.desc.endsWith(TRANSFORMER_AND_FLAG)) {
      int op = producer == null ? -1 : producer.getOpcode();
      boolean oneInstruction = op == Opcodes.ILOAD || (op >= Opcodes.ICONST_0 && op <= Opcodes.ICONST_1)
          || op == Opcodes.BIPUSH || op == Opcodes.GETSTATIC;
      if (!oneInstruction) throw new IllegalStateException(where + ": the retransform flag is not one load or constant; HookMap does not read this shape");
      producer = previous(producer);
    } else if (!call.desc.equals("(Ljava/lang/instrument/ClassFileTransformer;)V")) {
      throw new IllegalStateException(where + ": addTransformer " + call.desc + " is not a shape HookMap reads");
    }
    if (producer != null && producer.getOpcode() == Opcodes.ALOAD) {
      int local = ((VarInsnNode) producer).var;
      AbstractInsnNode store = null;
      for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
        if (insn.getOpcode() == Opcodes.ASTORE && ((VarInsnNode) insn).var == local) {
          if (store != null) throw new IllegalStateException(where + ": local " + local + " is stored more than once; HookMap does not read this shape");
          store = insn;
        }
      }
      if (store == null) throw new IllegalStateException(where + ": local " + local + " is never stored in this method");
      producer = previous(store);
    }
    // After new X(): NEW X, DUP, INVOKESPECIAL X.<init>()V, with the new object left on the stack.
    if (producer instanceof MethodInsnNode && producer.getOpcode() == Opcodes.INVOKESPECIAL
        && "<init>".equals(((MethodInsnNode) producer).name) && "()V".equals(((MethodInsnNode) producer).desc)) {
      AbstractInsnNode dup = previous(producer);
      AbstractInsnNode created = dup == null ? null : previous(dup);
      if (dup != null && dup.getOpcode() == Opcodes.DUP && created != null && created.getOpcode() == Opcodes.NEW
          && ((TypeInsnNode) created).desc.equals(((MethodInsnNode) producer).owner)) {
        return ((TypeInsnNode) created).desc;
      }
    }
    throw new IllegalStateException(where + ": the transformer argument is not `new X()` or a local stored from it; HookMap does not read this shape");
  }

  static boolean isTransformer(JarFile agent, String type, Map<String, Boolean> seen) throws Exception {
    if ("java/lang/instrument/ClassFileTransformer".equals(type)) return true;
    if (seen.containsKey(type)) return seen.get(type);
    seen.put(type, false);
    JarEntry entry = agent.getJarEntry(type + ".class");
    if (entry == null) return false;
    ClassReader reader = new ClassReader(bytes(agent.getInputStream(entry)));
    boolean result = reader.getSuperName() != null && isTransformer(agent, reader.getSuperName(), seen);
    for (String iface : reader.getInterfaces()) result |= isTransformer(agent, iface, seen);
    seen.put(type, result);
    return result;
  }

  private static ClassNode read(JarFile jar, String type) throws Exception {
    ClassNode node = new ClassNode();
    new ClassReader(bytes(jar.getInputStream(jar.getJarEntry(type + ".class")))).accept(node, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    return node;
  }

  // ---- comparing a class with what the agent made of it -----------------------------------------

  /** Method (name and descriptor) to the agent callees it calls more often in the output than in the input, with by how many. */
  static Map<String, Map<String, Integer>> gains(byte[] before, byte[] after) {
    Map<String, Map<String, Integer>> gained = new TreeMap<String, Map<String, Integer>>();
    if (after == null || !(contains(after, AGENT.getBytes(StandardCharsets.ISO_8859_1))
        || contains(after, AGENT.replace('/', '.').getBytes(StandardCharsets.ISO_8859_1)))) return gained;
    Map<String, Map<String, Integer>> was = agentCalls(before);
    for (Map.Entry<String, Map<String, Integer>> method : agentCalls(after).entrySet()) {
      Map<String, Integer> had = was.get(method.getKey());
      Map<String, Integer> added = new TreeMap<String, Integer>();
      for (Map.Entry<String, Integer> callee : method.getValue().entrySet()) {
        int more = callee.getValue() - (had == null || !had.containsKey(callee.getKey()) ? 0 : had.get(callee.getKey()));
        if (more > 0) added.put(callee.getKey(), more);
      }
      if (!added.isEmpty()) gained.put(method.getKey(), added);
    }
    return gained;
  }

  private static void count(Map<String, Integer> calls, String callee) {
    Integer seen = calls.get(callee);
    calls.put(callee, seen == null ? 1 : seen + 1);
  }

  static Map<String, Map<String, Integer>> agentCalls(byte[] bytes) {
    ClassNode node = new ClassNode();
    new ClassReader(bytes).accept(node, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    Map<String, Map<String, Integer>> calls = new HashMap<String, Map<String, Integer>>();
    for (MethodNode method : node.methods) {
      Map<String, Integer> found = new TreeMap<String, Integer>();
      for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
        if (insn instanceof MethodInsnNode) {
          MethodInsnNode call = (MethodInsnNode) insn;
          if (call.owner.startsWith(AGENT) && !call.owner.startsWith(SHADED_ASM)) count(found, call.owner + "." + call.name);
        } else if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String) {
          String constant = (String) ((LdcInsnNode) insn).cst;
          if (constant.startsWith(AGENT.replace('/', '.')) && !constant.startsWith(SHADED_ASM.replace('/', '.'))) {
            String hook = reflectiveHook(insn);
            if (hook != null) count(found, constant.replace('.', '/') + "." + hook + " (reflective)");
          }
        }
      }
      if (!found.isEmpty()) calls.put(method.name + " " + method.desc, found);
    }
    return calls;
  }

  private static boolean isCall(AbstractInsnNode insn, int opcode, String owner, String name, String desc) {
    if (!(insn instanceof MethodInsnNode) || insn.getOpcode() != opcode) return false;
    MethodInsnNode call = (MethodInsnNode) insn;
    return owner.equals(call.owner) && name.equals(call.name) && (desc == null || desc.equals(call.desc));
  }

  /**
   * The method a reflective hook calls, when the agent class name constant starts the sequence the
   * EL, JEXL and OSGi servlet hooks emit, or null when it does not:
   *
   * <pre>
   * ClassLoader.getSystemClassLoader(); ldc "agent.Class"; ClassLoader.loadClass(String);
   * ldc "method"; ... Class.getMethod(String, Class[]); ... Method.invoke(Object, Object[])
   * </pre>
   */
  private static String reflectiveHook(AbstractInsnNode className) {
    if (!isCall(previous(className), Opcodes.INVOKESTATIC, "java/lang/ClassLoader", "getSystemClassLoader", "()Ljava/lang/ClassLoader;")) return null;
    AbstractInsnNode load = className.getNext();
    while (load != null && load.getOpcode() < 0) load = load.getNext();
    if (load == null || !isCall(load, Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;")) return null;
    AbstractInsnNode name = load.getNext();
    while (name != null && name.getOpcode() < 0) name = name.getNext();
    if (!(name instanceof LdcInsnNode) || !(((LdcInsnNode) name).cst instanceof String)
        || !((String) ((LdcInsnNode) name).cst).matches("[A-Za-z_$][A-Za-z0-9_$]*")) return null;
    boolean getMethod = false;
    int looked = 0;
    for (AbstractInsnNode insn = name.getNext(); insn != null && looked < 24; insn = insn.getNext(), looked++) {
      if (!getMethod) {
        getMethod = isCall(insn, Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
      } else if (isCall(insn, Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;")) {
        return (String) ((LdcInsnNode) name).cst;
      }
    }
    return null;
  }

  private static boolean contains(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i + needle.length <= haystack.length; i++) {
      for (int j = 0; j < needle.length; j++) if (haystack[i + j] != needle[j]) continue outer;
      return true;
    }
    return false;
  }

  private static byte[] bytes(InputStream input) throws Exception {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[16384];
      for (int n; (n = input.read(buffer)) > 0; ) out.write(buffer, 0, n);
      return out.toByteArray();
    } finally {
      input.close();
    }
  }

  // ---- the staged tree --------------------------------------------------------------------------

  /** group:artifact version jar, sorted. */
  private static List<String[]> libraries(File root) {
    List<String[]> found = new ArrayList<String[]>();
    File[] groups = root.listFiles();
    if (groups == null) throw new IllegalArgumentException("no staged tree at " + root);
    for (File group : groups) {
      for (File artifact : listing(group)) {
        for (File version : listing(artifact)) {
          File[] jars = version.listFiles();
          if (jars == null || jars.length != 1 || !jars[0].getName().endsWith(".jar")) {
            throw new IllegalStateException(version + " should hold exactly one JAR, has " + Arrays.toString(jars));
          }
          found.add(new String[] {group.getName() + ":" + artifact.getName(), version.getName(), jars[0].getPath()});
        }
      }
    }
    Collections.sort(found, (a, b) -> (a[0] + " " + a[1]).compareTo(b[0] + " " + b[1]));
    return found;
  }

  private static File[] listing(File directory) {
    File[] files = directory.listFiles();
    if (files == null) return new File[0];
    Arrays.sort(files);
    return files;
  }

  private static int shadowed;
  private static final String VERSIONS = "META-INF/versions/";

  /** The entries a run of the JVM would load as classes: base entries, and versioned ones of a multi-release JAR. */
  private static boolean multiRelease(JarFile jar) throws Exception {
    return jar.getManifest() != null && "true".equalsIgnoreCase(jar.getManifest().getMainAttributes().getValue("Multi-Release"));
  }

  /** The class name the JVM gives an entry: a versioned entry loses its META-INF/versions/N/ prefix. */
  private static String runtimeName(String path) {
    if (!path.startsWith(VERSIONS)) return path;
    int slash = path.indexOf('/', VERSIONS.length());
    return slash < 0 ? path : path.substring(slash + 1);
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      throw new IllegalArgumentException("usage: HookMap <agent jar> <staged tree> <primary | line entry class>");
    }
    List<Unit> units;
    Unit whole = null;
    try (JarFile agent = new JarFile(args[0])) {
      // The JAR's manifest names the launcher, and a universal JAR holds every line: the caller says which.
      if ("primary".equals(args[2])) {
        units = primaryModules();
        Class<?> transformerType = Class.forName("io.ohmyrasp.agent.asm.OhMyRaspTransformer");
        whole = new Transform("OhMyRaspTransformer", transformerType.getConstructor().newInstance());
      } else {
        units = registeredTransformers(agent, args[2]);
      }
    }
    List<String> names = new ArrayList<String>();
    for (Unit unit : units) if (!COMMON.equals(unit.name())) names.add(unit.name());
    Collections.sort(names);

    TreeSet<String> rows = new TreeSet<String>();
    TreeSet<String> chainDiffers = new TreeSet<String>();
    int libraries = 0, classes = 0, versioned = 0, unreadable = 0;
    for (String[] library : libraries(new File(args[1]))) {
      libraries++;
      try (JarFile jar = new JarFile(library[2])) {
        boolean multi = multiRelease(jar);
        for (JarEntry entry : Collections.list(jar.entries())) {
          String file = entry.getName();
          if (entry.isDirectory() || !file.endsWith(".class")) continue;
          if (file.startsWith(VERSIONS)) {
            if (!multi) continue;           // a JVM does not read these from a JAR that is not multi-release
            versioned++;
          } else if (file.startsWith("META-INF/")) {
            continue;
          }
          String path = file.substring(0, file.length() - ".class".length());
          String owner = runtimeName(path);
          byte[] before = bytes(jar.getInputStream(entry));
          classes++;
          try {
            new ClassReader(before);
          } catch (IllegalArgumentException unsupported) {
            unreadable++;
            continue;
          }
          String prefix = library[0] + " " + library[1] + " " + path + " ";
          if (whole != null) {
            Map<String, Map<String, Integer>> hooked = gains(before, whole.apply(owner, before));
            if (hooked.isEmpty()) continue;
            Map<String, Map<String, Map<String, Integer>>> alone = new TreeMap<String, Map<String, Map<String, Integer>>>();
            for (Unit unit : units) alone.put(unit.name(), gains(before, unit.apply(owner, before)));
            for (Map.Entry<String, Map<String, Integer>> method : hooked.entrySet()) {
              for (Map.Entry<String, Integer> callee : method.getValue().entrySet()) {
                attribute(rows, prefix, method.getKey(), callee.getKey(), callee.getValue(), alone);
              }
            }
          } else {
            chain(rows, chainDiffers, prefix, owner, before, units);
          }
        }
      }
    }
    System.out.println("# units (" + names.size() + "): " + String.join(" ", names));
    System.out.println("# libraries: " + libraries + ", classes: " + classes + " (multi-release entries: " + versioned
        + "), unreadable by the agent's ASM: " + unreadable);
    if (shadowed > 0) System.err.println("rows where modules shadow one another and the count is the registry's: " + shadowed);
    for (String differs : chainDiffers) System.out.println(differs);
    for (String row : rows) System.out.println(row);
  }

  static String row(String prefix, String method, String callee, int calls, String by) {
    return prefix + method + " -> " + callee + (calls > 1 ? " x" + calls : "") + " @ " + by;
  }

  /**
   * One backport class through every transformer in registration order. The rows are what each
   * transformer adds to what it was given. The same transformers on the original bytes make the
   * comparison: a transformer whose rows differ there is reported with the class.
   */
  static void chain(TreeSet<String> rows, TreeSet<String> differs, String prefix, String owner, byte[] original, List<Unit> units)
      throws Exception {
    byte[] current = original;
    for (Unit unit : units) {
      byte[] produced = unit.apply(owner, current);
      Map<String, Map<String, Integer>> chained = gains(current, produced);
      Map<String, Map<String, Integer>> pristine = gains(original, unit.apply(owner, original));
      for (Map.Entry<String, Map<String, Integer>> method : chained.entrySet()) {
        for (Map.Entry<String, Integer> callee : method.getValue().entrySet()) {
          rows.add(row(prefix, method.getKey(), callee.getKey(), callee.getValue(), unit.name()));
        }
      }
      if (!chained.equals(pristine)) {
        differs.add("# chain: " + prefix + unit.name() + " adds " + describe(chained) + " after its predecessors, " + describe(pristine) + " on the original class");
      }
      if (produced != null) current = produced;
    }
  }

  private static String describe(Map<String, Map<String, Integer>> gained) {
    int calls = 0;
    for (Map<String, Integer> method : gained.values()) for (int n : method.values()) calls += n;
    return gained.size() + " methods and " + calls + " calls";
  }

  /**
   * Rows of one method and callee in the primary agent. The registry's own count is the truth; the
   * empty registry's count is what the shared visitors make, and each module's own part is its
   * count when it runs alone minus that. A module-specific call with the callee of a shared one
   * therefore stays visible under its module.
   */
  static void attribute(TreeSet<String> rows, String prefix, String method, String callee, int total,
      Map<String, Map<String, Map<String, Integer>>> alone) {
    int shared = calls(alone.get(COMMON), method, callee);
    if (shared > 0) rows.add(row(prefix, method, callee, Math.min(shared, total), COMMON));
    int remaining = total - shared;
    if (remaining <= 0) return;
    Map<Integer, TreeSet<String>> byCount = new TreeMap<Integer, TreeSet<String>>();
    int sum = 0;
    for (Map.Entry<String, Map<String, Map<String, Integer>>> unit : alone.entrySet()) {
      if (COMMON.equals(unit.getKey())) continue;
      int own = calls(unit.getValue(), method, callee) - shared;
      if (own <= 0) continue;
      sum += own;
      TreeSet<String> same = byCount.get(own);
      if (same == null) byCount.put(own, same = new TreeSet<String>());
      same.add(unit.getKey());
    }
    if (byCount.isEmpty()) {
      rows.add(row(prefix, method, callee, remaining, "?"));
    } else if (sum != remaining) {
      // Modules shadow one another (the first that wraps a method wins): say what production does, and which could.
      shadowed++;
      TreeSet<String> any = new TreeSet<String>();
      for (TreeSet<String> same : byCount.values()) any.addAll(same);
      rows.add(row(prefix, method, callee, remaining, String.join(",", any)));
    } else {
      for (Map.Entry<Integer, TreeSet<String>> same : byCount.entrySet()) {
        rows.add(row(prefix, method, callee, same.getKey(), String.join(",", same.getValue())));
      }
    }
  }

  private static int calls(Map<String, Map<String, Integer>> gained, String method, String callee) {
    Map<String, Integer> callees = gained == null ? null : gained.get(method);
    Integer n = callees == null ? null : callees.get(callee);
    return n == null ? 0 : n;
  }
}
