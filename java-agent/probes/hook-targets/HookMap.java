import io.ohmyrasp.agent.shaded.asm.ClassReader;
import io.ohmyrasp.agent.shaded.asm.tree.AbstractInsnNode;
import io.ohmyrasp.agent.shaded.asm.tree.ClassNode;
import io.ohmyrasp.agent.shaded.asm.tree.LdcInsnNode;
import io.ohmyrasp.agent.shaded.asm.tree.MethodInsnNode;
import io.ohmyrasp.agent.shaded.asm.tree.MethodNode;
import io.ohmyrasp.agent.shaded.asm.tree.TypeInsnNode;
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
import java.util.LinkedHashMap;
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
 * <pre>java -cp &lt;this class&gt;:&lt;agent jar&gt; HookMap &lt;agent jar&gt; &lt;staged tree&gt;</pre>
 *
 * The staged tree holds one folder per group/artifact/version with the library JAR in it. Every class
 * of every JAR goes through the agent's own transformer classes and a method counts as hooked when
 * its output has a call into io/ohmyrasp/agent/ (not the shaded ASM) that its input did not. A hook
 * that reaches the agent by reflection counts too: its class name is a string constant of the
 * output, and the next string constant names the method.
 *
 * Nothing is loaded from the libraries: the transformers read class files with ASM, and the loader
 * handed to them is a fresh one that resolves nothing, so the result does not depend on a classpath.
 * The loader is not null because several hooks apply only to application classes (loader != null).
 *
 * The primary agent is one transformer over a registry of HookModules: the map comes from the whole
 * registry (first match wins, as in production) and each row is attributed to the modules that
 * produce it alone. A backport agent is one transformer class per hook family, registered by its
 * entry class: each runs on the original class bytes.
 */
public final class HookMap {
  private static final String AGENT = "io/ohmyrasp/agent/";
  private static final String SHADED_ASM = "io/ohmyrasp/agent/shaded/asm/";
  private static final String COMMON = "(shared visitors)";

  /** One hook family: a HookModule of the primary agent or a transformer class of a backport. */
  private interface Unit {
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

  /**
   * The transformer classes a backport's entry class registers: every class it instantiates that,
   * through the agent JAR's own classes, implements ClassFileTransformer. This follows the entry
   * class, so a transformer added there is picked up and one that is never registered is not counted.
   */
  private static List<Unit> registeredTransformers(JarFile agent) throws Exception {
    String entry = agent.getManifest().getMainAttributes().getValue("Premain-Class").replace('.', '/');
    ClassNode entryNode = read(agent, entry);
    Set<String> registered = new LinkedHashSet<String>();
    for (MethodNode method : entryNode.methods) {
      for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
        if (insn.getOpcode() == Opcodes.NEW && isTransformer(agent, ((TypeInsnNode) insn).desc, new HashMap<String, Boolean>())) {
          registered.add(((TypeInsnNode) insn).desc);
        }
      }
    }
    String packagePrefix = entry.substring(0, entry.lastIndexOf('/') + 1);
    List<String> unregistered = new ArrayList<String>();
    for (JarEntry jarEntry : Collections.list(agent.entries())) {
      String name = jarEntry.getName();
      if (name.startsWith(packagePrefix) && name.endsWith("Transformer.class") && name.indexOf('/', packagePrefix.length()) < 0) {
        String type = name.substring(0, name.length() - ".class".length());
        if (!registered.contains(type) && isTransformer(agent, type, new HashMap<String, Boolean>())) unregistered.add(type);
      }
    }
    if (!unregistered.isEmpty()) System.err.println("transformers in the line's package that its entry class never registers: " + unregistered);
    List<Unit> units = new ArrayList<Unit>();
    for (String type : registered) {
      units.add(new Transform(type.substring(type.lastIndexOf('/') + 1), Class.forName(type.replace('/', '.')).getConstructor().newInstance()));
    }
    return units;
  }

  private static boolean isTransformer(JarFile agent, String type, Map<String, Boolean> seen) throws Exception {
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

  /** Method (name and descriptor) to the agent methods it newly calls, as owner.name. */
  private static Map<String, Set<String>> gains(byte[] before, byte[] after) {
    Map<String, Set<String>> gained = new TreeMap<String, Set<String>>();
    if (after == null || !(contains(after, AGENT.getBytes(StandardCharsets.ISO_8859_1))
        || contains(after, AGENT.replace('/', '.').getBytes(StandardCharsets.ISO_8859_1)))) return gained;
    Map<String, Set<String>> was = agentCalls(before);
    for (Map.Entry<String, Set<String>> method : agentCalls(after).entrySet()) {
      Set<String> added = new TreeSet<String>(method.getValue());
      Set<String> had = was.get(method.getKey());
      if (had != null) added.removeAll(had);
      if (!added.isEmpty()) gained.put(method.getKey(), added);
    }
    return gained;
  }

  private static Map<String, Set<String>> agentCalls(byte[] bytes) {
    ClassNode node = new ClassNode();
    new ClassReader(bytes).accept(node, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    Map<String, Set<String>> calls = new HashMap<String, Set<String>>();
    for (MethodNode method : node.methods) {
      Set<String> found = new TreeSet<String>();
      for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
        if (insn instanceof MethodInsnNode) {
          MethodInsnNode call = (MethodInsnNode) insn;
          if (call.owner.startsWith(AGENT) && !call.owner.startsWith(SHADED_ASM)) found.add(call.owner + "." + call.name);
        } else if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String) {
          String constant = (String) ((LdcInsnNode) insn).cst;
          if (constant.startsWith(AGENT.replace('/', '.')) && !constant.startsWith(SHADED_ASM.replace('/', '.'))) {
            found.add(constant.replace('.', '/') + "." + reflectiveMethod(insn) + " (reflective)");
          }
        }
      }
      if (!found.isEmpty()) calls.put(method.name + " " + method.desc, found);
    }
    return calls;
  }

  /** A hook reached by reflection names its class in one string constant and the method in the next one. */
  private static String reflectiveMethod(AbstractInsnNode classNameConstant) {
    int looked = 0;
    for (AbstractInsnNode insn = classNameConstant.getNext(); insn != null && looked < 12; insn = insn.getNext(), looked++) {
      if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String
          && ((String) ((LdcInsnNode) insn).cst).matches("[A-Za-z_$][A-Za-z0-9_$]*")) {
        return (String) ((LdcInsnNode) insn).cst;
      }
    }
    return "?";
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

  public static void main(String[] args) throws Exception {
    if (args.length != 2) throw new IllegalArgumentException("usage: HookMap <agent jar> <staged tree>");
    List<Unit> units;
    Unit whole = null;
    try (JarFile agent = new JarFile(args[0])) {
      if (agent.getJarEntry("io/ohmyrasp/agent/asm/OhMyRaspTransformer.class") != null) {
        units = primaryModules();
        Class<?> transformerType = Class.forName("io.ohmyrasp.agent.asm.OhMyRaspTransformer");
        whole = new Transform("OhMyRaspTransformer", transformerType.getConstructor().newInstance());
      } else {
        units = registeredTransformers(agent);
      }
    }
    List<String> names = new ArrayList<String>();
    for (Unit unit : units) if (!COMMON.equals(unit.name())) names.add(unit.name());
    Collections.sort(names);

    TreeSet<String> rows = new TreeSet<String>();
    int libraries = 0, classes = 0, unreadable = 0;
    for (String[] library : libraries(new File(args[1]))) {
      libraries++;
      try (JarFile jar = new JarFile(library[2])) {
        for (JarEntry entry : Collections.list(jar.entries())) {
          String file = entry.getName();
          if (entry.isDirectory() || !file.endsWith(".class") || file.startsWith("META-INF/")) continue;
          String owner = file.substring(0, file.length() - ".class".length());
          byte[] before = bytes(jar.getInputStream(entry));
          classes++;
          try {
            new ClassReader(before);
          } catch (IllegalArgumentException unsupported) {
            unreadable++;
            continue;
          }
          String prefix = library[0] + " " + library[1] + " " + owner + " ";
          if (whole != null) {
            Map<String, Set<String>> hooked = gains(before, whole.apply(owner, before));
            if (hooked.isEmpty()) continue;
            Map<String, Map<String, Set<String>>> alone = new TreeMap<String, Map<String, Set<String>>>();
            for (Unit unit : units) alone.put(unit.name(), gains(before, unit.apply(owner, before)));
            for (Map.Entry<String, Set<String>> method : hooked.entrySet()) {
              for (String callee : method.getValue()) {
                rows.add(prefix + method.getKey() + " -> " + callee + " @ " + attribute(alone, method.getKey(), callee));
              }
            }
          } else {
            for (Unit unit : units) {
              for (Map.Entry<String, Set<String>> method : gains(before, unit.apply(owner, before)).entrySet()) {
                for (String callee : method.getValue()) rows.add(prefix + method.getKey() + " -> " + callee + " @ " + unit.name());
              }
            }
          }
        }
      }
    }
    System.out.println("# units (" + names.size() + "): " + String.join(" ", names));
    System.out.println("# libraries: " + libraries + ", classes: " + classes + ", unreadable by the agent's ASM: " + unreadable);
    for (String row : rows) System.out.println(row);
  }

  /** The modules that hook this method alone; a row the shared visitors also make belongs to them. */
  private static String attribute(Map<String, Map<String, Set<String>>> alone, String method, String callee) {
    if (has(alone.get(COMMON), method, callee)) return COMMON;
    Set<String> by = new TreeSet<String>();
    for (Map.Entry<String, Map<String, Set<String>>> unit : alone.entrySet()) {
      if (has(unit.getValue(), method, callee)) by.add(unit.getKey());
    }
    return by.isEmpty() ? "?" : String.join(",", by);
  }

  private static boolean has(Map<String, Set<String>> gained, String method, String callee) {
    Set<String> callees = gained.get(method);
    return callees != null && callees.contains(callee);
  }
}
