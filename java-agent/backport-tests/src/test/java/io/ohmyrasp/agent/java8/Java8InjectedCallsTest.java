package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * The agent methods this line's transformers make application and JDK classes call, other than the line's own
 * {@code Java8RaspHooks} (whose methods are one-line calls into {@code BackportHooks}), are inert while the hooks are
 * off: removing a transformer does not remove what it injected. The inventory is taken from transformed bytecode:
 * every class of the build JDK's runtime image and of the test class path goes through every transformer of the line,
 * and the callees of {@code probes/hook-targets/recorded/backport.txt} are added. Each callee begins with {@code
 * HookActivation.inactive()}, or is a token exit that begins by testing its token, or is exempt with its reason.
 */
final class Java8InjectedCallsTest {
  private static final String AGENT = "io/ohmyrasp/agent/";
  private static final String SHADED = "io/ohmyrasp/agent/shaded/";
  private static final String LINE_HOOKS = Type.getInternalName(Java8RaspHooks.class);
  private static final String GUARD = "io/ohmyrasp/agent/hook/HookActivation.inactive()Z";

  /**
   * Callees, as {@code Owner.method}, that need no guard, each with its reason. None today. (The DataEase visitor's
   * FilterVerification is not in the inventory: its target is an application class, on neither the class path nor
   * the recorded map. It is one object per filter call, held in that frame's own local, and only a guarded hook
   * entry acts on what it records.)
   */
  private static final Map<String, String> INERT_WITHOUT_GUARD = new HashMap<String, String>();

  /** Scope exits that take their entry's token and do nothing for null (see ScopedMethodAdvice). */
  private static final Set<String> TOKEN_EXITS = new HashSet<String>(Arrays.asList(
      "AttachmentFileRead.endRead", "AttachmentFileRead.endReference", "HostDirectory.visited", "HostReadPath.endFacade",
      "HttpTransportObservation.exitAcquisition", "JdbcObservation.exit", "JmxWriteScope.exit", "LookupRoute.exit",
      "MultipartFilename.exit", "MyBatisSqlTrace.exitStatement", "PlotWrite.finished", "ProcessLaunch.exit",
      "SpringProcessInit.exitInit", "SpringProcessInit.exitParse"));

  private final Map<String, String> callees = new TreeMap<String, String>();
  private final List<ClassFileTransformer> transformers = new ArrayList<ClassFileTransformer>();

  @Test
  void everyAgentHelperTheInjectedCodeCallsIsInertWhileTheHooksAreOff() throws Exception {
    long started = System.nanoTime();
    loadTransformers();
    assertTrue(transformers.size() > 1, "found no transformers of the line");
    scanRuntimeImage();
    scanClassPath();
    String map = System.getProperty("ohmyrasp.hookTargets.backport");
    assertNotNull(map, "the build passes the recorded hook-target map as ohmyrasp.hookTargets.backport");
    readRecordedMap(Paths.get(map));
    System.out.println("[inventory] " + transformers.size() + " transformers, " + callees.size() + " callees, "
        + (System.nanoTime() - started) / 1000000 + " ms");

    List<String> failures = new ArrayList<String>();
    Set<String> seen = new HashSet<String>();
    for (Map.Entry<String, String> callee : callees.entrySet()) {
      String call = callee.getKey();
      int space = call.indexOf(' ');
      int dot = call.lastIndexOf('.', space);
      String owner = call.substring(0, dot);
      String name = call.substring(dot + 1, space);
      String descriptor = call.substring(space + 1);
      String method = owner.substring(owner.lastIndexOf('/') + 1) + "." + name;
      System.out.println("[inventory] " + call + "  <- " + callee.getValue());
      if (owner.equals(LINE_HOOKS) || owner.equals("io/ohmyrasp/agent/hook/HookActivation")) continue;
      if (INERT_WITHOUT_GUARD.containsKey(method)) {
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
        Opening opening = candidate.getValue();
        boolean matches = candidateName.equals(name) && ("*".equals(descriptor)
            ? (opening.access & Opcodes.ACC_PUBLIC) != 0 : descriptor.equals(candidateDescriptor));
        if (!matches || (opening.access & Opcodes.ACC_SYNTHETIC) != 0) continue;
        found = true;
        seen.add(method);
        boolean inert = TOKEN_EXITS.contains(method) ? opening.testsToken() : opening.guarded();
        if (!inert) {
          failures.add(method + candidateDescriptor + (TOKEN_EXITS.contains(method)
              ? " does not begin by testing its token" : " does not begin with HookActivation.inactive()")
              + " (called from " + callee.getValue() + ")");
        }
      }
      if (!found) failures.add(call + ": no such method in " + owner + " (called from " + callee.getValue() + ")");
    }
    List<String> sorted = new ArrayList<String>(new java.util.TreeSet<String>(failures));
    assertEquals(new ArrayList<String>(), sorted,
        "the injected code calls these agent methods, and they would act while the hooks are off");
    List<String> stale = new ArrayList<String>();
    for (String listed : INERT_WITHOUT_GUARD.keySet()) if (!seen.contains(listed)) stale.add(listed);
    for (String listed : TOKEN_EXITS) if (!seen.contains(listed)) stale.add(listed);
    Collections.sort(stale);
    assertEquals(new ArrayList<String>(), stale, "listed here, but no injected code calls them any more");
  }

  /** Every concrete transformer class of the line, from the directory or JAR that holds Java8RaspHooks. */
  private void loadTransformers() throws Exception {
    String prefix = LINE_HOOKS.substring(0, LINE_HOOKS.lastIndexOf('/') + 1);
    File source = new File(Java8RaspHooks.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    List<String> names = new ArrayList<String>();
    if (source.isDirectory()) {
      File[] files = new File(source, prefix).listFiles();
      if (files != null) for (File file : files) names.add(prefix + file.getName());
    } else {
      JarFile jar = new JarFile(source);
      try {
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) names.add(entries.nextElement().getName());
      } finally {
        jar.close();
      }
    }
    Collections.sort(names);
    for (String name : names) {
      if (!name.startsWith(prefix) || !name.endsWith("Transformer.class") || name.indexOf('$') >= 0) continue;
      Class<?> type = Class.forName(name.substring(0, name.length() - ".class".length()).replace('/', '.'));
      if (!ClassFileTransformer.class.isAssignableFrom(type) || Modifier.isAbstract(type.getModifiers())) continue;
      java.lang.reflect.Constructor<?> constructor = type.getDeclaredConstructor();
      constructor.setAccessible(true);
      transformers.add((ClassFileTransformer) constructor.newInstance());
    }
  }

  private void scanRuntimeImage() throws Exception {
    FileSystem jrt = FileSystems.getFileSystem(URI.create("jrt:/"));
    final ClassLoader platform = (ClassLoader) ClassLoader.class.getMethod("getPlatformClassLoader").invoke(null);
    DirectoryStream<Path> modules = Files.newDirectoryStream(jrt.getPath("/modules"));
    try {
      for (final Path module : modules) {
        Files.walkFileTree(module, new SimpleFileVisitor<Path>() {
          @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
            String entry = module.relativize(file).toString();
            if (entry.endsWith(".class") && !entry.equals("module-info.class")) {
              byte[] bytes = Files.readAllBytes(file);
              String name = entry.substring(0, entry.length() - ".class".length());
              // Either loader can define a JDK class; the transformers may choose by it.
              transform(name, null, bytes);
              transform(name, platform, bytes);
            }
            return FileVisitResult.CONTINUE;
          }
        });
      }
    } finally {
      modules.close();
    }
  }

  private void scanClassPath() throws IOException {
    ClassLoader loader = Java8InjectedCallsTest.class.getClassLoader();
    for (String element : System.getProperty("java.class.path").split(File.pathSeparator)) {
      File file = new File(element);
      if (element.endsWith(".jar") && file.isFile()) {
        JarFile jar = new JarFile(file);
        try {
          Enumeration<JarEntry> entries = jar.entries();
          while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String name = classNameOf(entry.getName());
            if (name == null) continue;
            InputStream in = jar.getInputStream(entry);
            try {
              transform(name, loader, readAll(in));
            } finally {
              in.close();
            }
          }
        } finally {
          jar.close();
        }
      } else if (file.isDirectory()) {
        final Path root = file.toPath();
        final ClassLoader classes = loader;
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
          @Override public FileVisitResult visitFile(Path path, BasicFileAttributes attributes) throws IOException {
            String name = classNameOf(root.relativize(path).toString().replace(File.separatorChar, '/'));
            if (name != null) transform(name, classes, Files.readAllBytes(path));
            return FileVisitResult.CONTINUE;
          }
        });
      }
    }
  }

  private void readRecordedMap(Path map) throws IOException {
    for (String line : Files.readAllLines(map, java.nio.charset.StandardCharsets.UTF_8)) {
      int arrow = line.indexOf(" -> ");
      if (line.startsWith("#") || arrow < 0) continue;
      String targets = line.substring(arrow + 4);
      int at = targets.indexOf(" @ ");
      if (at >= 0) targets = targets.substring(0, at);
      for (String target : targets.split(",")) {
        // The map names the line's own classes with a {N} placeholder for the release.
        String callee = target.trim().replaceAll(" x[0-9]+$", "").replace("{N}", release());
        if (!callees.containsKey(callee + " *")) callees.put(callee + " *", line.substring(0, arrow) + " (recorded)");
      }
    }
  }

  /** This line's release, as the package of its hooks class names it. */
  private static String release() {
    String name = LINE_HOOKS.substring(LINE_HOOKS.lastIndexOf('/') + 1);
    return name.substring("Java".length(), name.indexOf("RaspHooks"));
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

  private static byte[] readAll(InputStream in) throws IOException {
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    for (int read; (read = in.read(buffer)) > 0;) out.write(buffer, 0, read);
    return out.toByteArray();
  }

  private void transform(String className, ClassLoader loader, byte[] bytes) {
    Set<String> before = null;
    for (ClassFileTransformer transformer : transformers) {
      byte[] out;
      try {
        out = transformer.transform(loader, className, null, null, bytes);
      } catch (Throwable failure) {
        continue; // a transformer that cannot rewrite the class leaves it as it was
      }
      if (out == null) continue;
      if (before == null) before = agentCalls(bytes);
      for (String call : agentCalls(out)) {
        if (!before.contains(call) && !callees.containsKey(call)) callees.put(call, className);
      }
    }
  }

  /** The agent methods a class file calls, as {@code owner.name descriptor}. */
  private static Set<String> agentCalls(byte[] classFile) {
    final Set<String> calls = new HashSet<String>();
    new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
          String[] exceptions) {
        return new MethodVisitor(Opcodes.ASM9) {
          @Override public void visitMethodInsn(int op, String owner, String called, String desc, boolean itf) {
            if (owner.startsWith(AGENT) && !owner.startsWith(SHADED)) calls.add(owner + "." + called + " " + desc);
          }
        };
      }
    }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    return calls;
  }

  /** How each method of {@code owner} begins, or null when the test's loader has no class file for it. */
  private static Map<String, Opening> openings(String owner) throws IOException {
    InputStream in = Java8InjectedCallsTest.class.getClassLoader().getResourceAsStream(owner + ".class");
    if (in == null) return null;
    final Map<String, Opening> openings = new TreeMap<String, Opening>();
    try {
      new ClassReader(in).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
            String[] exceptions) {
          final Opening opening = new Opening(access, descriptor);
          openings.put(name + descriptor, opening);
          return new MethodVisitor(Opcodes.ASM9) {
            @Override public void visitMethodInsn(int op, String owner, String called, String desc, boolean itf) {
              opening.add(op, owner + "." + called + desc);
            }
            @Override public void visitInsn(int opcode) { opening.add(opcode, null); }
            @Override public void visitVarInsn(int opcode, int var) { opening.add(opcode, var); }
            @Override public void visitFieldInsn(int opcode, String owner, String field, String desc) { opening.add(opcode, field); }
            @Override public void visitTypeInsn(int opcode, String type) { opening.add(opcode, type); }
            @Override public void visitLdcInsn(Object value) { opening.add(Opcodes.LDC, value); }
            @Override public void visitIntInsn(int opcode, int operand) { opening.add(opcode, operand); }
            @Override public void visitIincInsn(int var, int increment) { opening.add(Opcodes.IINC, var); }
            @Override public void visitJumpInsn(int opcode, Label label) { opening.add(opcode, null); }
            @Override public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
              opening.add(Opcodes.TABLESWITCH, null);
            }
            @Override public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
              opening.add(Opcodes.LOOKUPSWITCH, null);
            }
            @Override public void visitMultiANewArrayInsn(String desc, int dims) { opening.add(Opcodes.MULTIANEWARRAY, desc); }
          };
        }
      }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    } finally {
      in.close();
    }
    return openings;
  }

  /** The first two instructions of a method (see the primary's HookActivationTest.Opening). */
  private static final class Opening {
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

    boolean guarded() {
      return (opcodes[0] == Opcodes.INVOKESTATIC && GUARD.equals(operands[0]))
          || (opcodes[0] == Opcodes.RETURN && descriptor.endsWith(")V"));
    }

    boolean testsToken() {
      if ((access & Opcodes.ACC_STATIC) == 0 || opcodes[0] != Opcodes.ALOAD
          || (opcodes[1] != Opcodes.IFNULL && opcodes[1] != Opcodes.IFNONNULL)) {
        return false;
      }
      int slot = 0;
      for (Type argument : Type.getArgumentTypes(descriptor)) {
        if (slot == ((Integer) operands[0]).intValue()) {
          return argument.getSort() == Type.OBJECT || argument.getSort() == Type.ARRAY;
        }
        slot += argument.getSize();
      }
      return false;
    }
  }
}
