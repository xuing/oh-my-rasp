package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.asm.OhMyRaspTransformer;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReader;
import java.lang.module.ModuleReference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * The agent methods that the primary transformer's injected code calls, taken from transformed bytecode: every class
 * of the JDK runtime image and of the test class path goes through {@link OhMyRaspTransformer} (the production
 * module chain of {@code HookRegistry.defaults()}), and each call into {@code io/ohmyrasp/agent/} present in the
 * output and absent from the input is one. Library classes that are not on the test class path come from the
 * recorded hook-target map ({@code probes/hook-targets/recorded/primary.txt}), which the hook-targets probe writes
 * from the same transformer run over real library versions; its rows name a callee without its descriptor.
 */
final class InjectedCallInventory {
  /** Internal name of the agent's package; the relocated ASM under it is not the agent. */
  private static final String AGENT = "io/ohmyrasp/agent/";
  private static final String SHADED = "io/ohmyrasp/agent/shaded/";
  /** A descriptor of a recorded callee, whose map row names the method only: every overload of that name. */
  static final String ANY_DESCRIPTOR = "*";

  /** Callee ({@code owner.name descriptor}) to one class that calls it, for the failure message. */
  final Map<String, String> callees = new TreeMap<>();
  /**
   * Injected calls of an agent method that takes one Object and returns nothing (a token exit's shape) whose
   * argument is not a local the same method stored straight from an agent call returning an Object (a token entry):
   * callee to one class that calls it so.
   */
  final Map<String, String> untokenedExits = new TreeMap<>();
  int classesRead;

  private final OhMyRaspTransformer transformer = new OhMyRaspTransformer();

  /** Every class of every module of the runtime image, each with the loader its module has in the boot layer. */
  void scanRuntimeImage() throws IOException {
    for (ModuleReference module : ModuleFinder.ofSystem().findAll()) {
      String name = module.descriptor().name();
      List<ClassLoader> loaders = new ArrayList<>();
      try {
        loaders.add(ModuleLayer.boot().findLoader(name));
      } catch (IllegalArgumentException notResolved) {
        // A module the boot layer did not resolve (an incubator, a tool) loads with --add-modules, on either loader.
        loaders.add(null);
        loaders.add(ClassLoader.getPlatformClassLoader());
      }
      try (ModuleReader reader = module.open(); Stream<String> entries = reader.list()) {
        for (String entry : (Iterable<String>) entries::iterator) {
          if (!entry.endsWith(".class") || entry.equals("module-info.class")) continue;
          byte[] bytes;
          try (InputStream in = reader.open(entry).orElseThrow()) {
            bytes = in.readAllBytes();
          }
          for (ClassLoader loader : loaders) {
            transform(entry.substring(0, entry.length() - ".class".length()), loader, bytes);
          }
        }
      }
    }
  }

  /** Every class of every JAR and directory on the test class path, as if the test's own loader defined it. */
  void scanClassPath() throws IOException {
    ClassLoader loader = InjectedCallInventory.class.getClassLoader();
    for (String element : System.getProperty("java.class.path").split(File.pathSeparator)) {
      Path path = Path.of(element);
      if (element.endsWith(".jar") && Files.isRegularFile(path)) {
        try (JarFile jar = new JarFile(path.toFile())) {
          Enumeration<JarEntry> entries = jar.entries();
          while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String name = classNameOf(entry.getName());
            if (name == null) continue;
            try (InputStream in = jar.getInputStream(entry)) {
              transform(name, loader, in.readAllBytes());
            }
          }
        }
      } else if (Files.isDirectory(path)) {
        try (Stream<Path> files = Files.walk(path)) {
          for (Path file : (Iterable<Path>) files::iterator) {
            String name = classNameOf(path.relativize(file).toString().replace(File.separatorChar, '/'));
            if (name != null && Files.isRegularFile(file)) transform(name, loader, Files.readAllBytes(file));
          }
        }
      }
    }
  }

  /** The callees of the recorded map's rows, each as {@code owner.name *}. */
  void readRecordedMap(Path map) throws IOException {
    for (String line : Files.readAllLines(map)) {
      int arrow = line.indexOf(" -> ");
      if (line.startsWith("#") || arrow < 0) continue;
      String targets = line.substring(arrow + 4);
      int at = targets.indexOf(" @ ");
      String where = line.substring(0, arrow) + " (recorded)";
      if (at >= 0) targets = targets.substring(0, at);
      for (String target : targets.split(",")) {
        String callee = target.trim().replaceAll(" x[0-9]+$", "");
        callees.putIfAbsent(callee + " " + ANY_DESCRIPTOR, where);
      }
    }
  }

  private static String classNameOf(String entry) {
    if (!entry.endsWith(".class") || entry.endsWith("module-info.class") || entry.startsWith(AGENT)) return null;
    if (entry.startsWith("META-INF/versions/")) {
      int slash = entry.indexOf('/', "META-INF/versions/".length());
      if (slash < 0) return null;
      entry = entry.substring(slash + 1);
    } else if (entry.startsWith("META-INF/")) {
      return null;
    }
    return entry.substring(0, entry.length() - ".class".length());
  }

  private void transform(String className, ClassLoader loader, byte[] bytes) {
    classesRead++;
    byte[] out = transformer.transform(null, loader, className, null, null, bytes);
    if (out == null) return;
    Set<String> before = agentCalls(bytes, new HashSet<>());
    Set<String> untokened = new HashSet<>();
    for (String call : agentCalls(out, untokened)) {
      if (!before.contains(call)) callees.putIfAbsent(call, className);
    }
    for (String call : untokened) untokenedExits.putIfAbsent(call, className);
  }

  /**
   * The agent methods a class file calls, as {@code owner.name descriptor}: a method instruction whose owner is an
   * agent class, and a string constant naming an agent class followed by one naming a method (a reflective call,
   * whose descriptor is not in the code: {@link #ANY_DESCRIPTOR}). Adds to {@code untokened} each call shaped like
   * a token exit whose argument is not a token (see {@link #untokenedExits}).
   */
  static Set<String> agentCalls(byte[] classFile, Set<String> untokened) {
    Set<String> calls = new HashSet<>();
    new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
          String[] exceptions) {
        return new MethodVisitor(Opcodes.ASM9) {
          private String reflectiveOwner;
          private int reach;
          /** Locals stored straight from an agent call returning an Object. */
          private final Set<Integer> tokens = new HashSet<>();
          private boolean afterTokenEntry;
          private int loaded = -1;

          @Override public void visitMethodInsn(int op, String owner, String called, String desc, boolean itf) {
            boolean agent = owner.startsWith(AGENT) && !owner.startsWith(SHADED);
            if (agent) {
              calls.add(owner + "." + called + " " + desc);
              if (op == Opcodes.INVOKESTATIC && desc.equals("(Ljava/lang/Object;)V") && !tokens.contains(loaded)) {
                untokened.add(owner + "." + called + " " + desc);
              }
            }
            step();
            afterTokenEntry = agent && op == Opcodes.INVOKESTATIC && desc.endsWith(")Ljava/lang/Object;");
          }

          @Override public void visitLdcInsn(Object value) {
            if (value instanceof String text) {
              String internal = text.replace('.', '/');
              if (internal.startsWith(AGENT) && !internal.startsWith(SHADED)) {
                reflectiveOwner = internal;
                reach = 0;
                return;
              }
              if (reflectiveOwner != null && text.matches("[A-Za-z_$][A-Za-z0-9_$]*")) {
                calls.add(reflectiveOwner + "." + text + " " + ANY_DESCRIPTOR);
                reflectiveOwner = null;
                return;
              }
            }
            step();
          }

          private void step() {
            if (reflectiveOwner != null && ++reach > 24) reflectiveOwner = null;
            afterTokenEntry = false;
            loaded = -1;
          }

          @Override public void visitInsn(int opcode) {
            step();
          }

          @Override public void visitVarInsn(int opcode, int var) {
            boolean stored = opcode == Opcodes.ASTORE && afterTokenEntry;
            step();
            if (stored) tokens.add(var);
            if (opcode == Opcodes.ALOAD) loaded = var;
          }

          @Override public void visitTypeInsn(int opcode, String type) {
            step();
          }

          @Override public void visitIntInsn(int opcode, int operand) {
            step();
          }

          @Override public void visitIincInsn(int var, int increment) {
            step();
          }

          @Override public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
            step();
          }

          @Override public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
            step();
          }

          @Override public void visitMultiANewArrayInsn(String desc, int dims) {
            step();
          }

          @Override public void visitFieldInsn(int opcode, String owner, String field, String desc) {
            step();
          }

          @Override public void visitJumpInsn(int opcode, Label label) {
            step();
          }

          @Override public void visitInvokeDynamicInsn(String n, String d, Handle h, Object... args) {
            step();
          }
        };
      }
    }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    return calls;
  }
}
