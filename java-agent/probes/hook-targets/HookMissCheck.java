import io.ohmyrasp.agent.hookmiss.HookExpectation;
import io.ohmyrasp.agent.hookmiss.HookExpectations;
import io.ohmyrasp.agent.hookmiss.HookMissSink;
import io.ohmyrasp.agent.hookmiss.HookMissWatch;
import io.ohmyrasp.agent.hookmiss.HookMisses;
import io.ohmyrasp.agent.hookmiss.NamedTargets;
import io.ohmyrasp.agent.shaded.asm.ClassReader;
import io.ohmyrasp.agent.shaded.asm.ClassVisitor;
import io.ohmyrasp.agent.shaded.asm.MethodVisitor;
import io.ohmyrasp.agent.shaded.asm.Opcodes;
import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs the packaged agent's own transformers, with its run-time hook-miss report on, over the classes of the
 * staged library JARs that the agent's expectation table names, and prints what the report sees.
 *
 * <pre>java -cp &lt;this class&gt;:&lt;agent jar&gt; HookMissCheck &lt;agent jar&gt; &lt;staged tree&gt; &lt;primary | entry class&gt;</pre>
 *
 * The table is the one in the agent JAR ({@code META-INF/ohmyrasp/hook-expectations/<family>.txt}), the report
 * writes inline to a recorder, and it forgets what it reported before each class, so every library version counts
 * on its own. The primary agent is its transformer over the default registry; a backport agent is the chain of the
 * transformers its entry class registers ({@link HookMap#registeredTypes}), each wrapped as the entry wraps it. Two
 * kinds of line:
 *
 * <pre>
 * claimed &lt;unit&gt; &lt;class&gt; &lt;library&gt; &lt;version&gt; &lt;methods of the class with a name the unit looks for&gt;
 * report &lt;unit&gt; &lt;class&gt; &lt;library&gt; &lt;version&gt; &lt;reason&gt;
 * </pre>
 *
 * A pair is claimed when the table names it and its unit selects the class by name (a primary module's
 * {@code matchesClass}; a backport transformer's {@code NamedTargets.selectsByName}, or any class for one that
 * selects by name only). check.py derives from the recorded map which claimed pairs the report must report.
 */
public final class HookMissCheck {
  private static final Pattern REPORT = Pattern.compile("^\"unit\":\"([^\"]+)\",\"class\":\"([^\"]+)\",\"reason\":\"([^\"]+)\"");
  private static final ClassLoader APPLICATION = new ClassLoader(null) {
    @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      throw new ClassNotFoundException(name);
    }
  };

  /** One unit: how to ask whether it selects a class by name. */
  interface Claim {
    boolean claims(String className) throws Exception;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      throw new IllegalArgumentException("usage: HookMissCheck <agent jar> <staged tree> <primary | line entry class>");
    }
    boolean primary = "primary".equals(args[2]);
    HookExpectations table = HookExpectations.load(primary ? "primary" : "backport");
    final List<String> written = new ArrayList<String>();
    HookMisses.start(table, new HookMissSink() {
      @Override public void write(String diagnostic, String fields) {
        if (!"hook_miss".equals(diagnostic)) throw new IllegalStateException("the limit was reached within one class: " + fields);
        written.add(fields);
      }

      @Override public boolean enterOwnIo() {
        return false;
      }

      @Override public void exitOwnIo(boolean entered) {}
    }, true);

    Map<String, Claim> claims = new HashMap<String, Claim>();
    List<ClassFileTransformer> chain = new ArrayList<ClassFileTransformer>();
    Object primaryTransformer = null;
    Method primaryTransform = null;
    if (primary) {
      Class<?> registryType = Class.forName("io.ohmyrasp.agent.asm.HookRegistry");
      Object registry = registryType.getMethod("defaults").invoke(null);
      Field modulesField = registryType.getDeclaredField("modules");
      modulesField.setAccessible(true);
      Method matchesClass = Class.forName("io.ohmyrasp.agent.asm.HookModule").getDeclaredMethod("matchesClass", String.class);
      matchesClass.setAccessible(true);
      for (Object module : (List<?>) modulesField.get(registry)) {
        claims.put(module.getClass().getSimpleName(), (className) -> (Boolean) matchesClass.invoke(module, className));
      }
      Class<?> transformerType = Class.forName("io.ohmyrasp.agent.asm.OhMyRaspTransformer");
      primaryTransformer = transformerType.getConstructor(registryType).newInstance(registry);
      for (Method method : transformerType.getMethods()) {
        if (method.getName().equals("transform") && method.getParameterTypes().length == 6) primaryTransform = method;
      }
    } else {
      try (JarFile agent = new JarFile(args[0])) {
        for (String type : HookMap.registeredTypes(agent, args[2])) {
          Constructor<?> constructor = Class.forName(type.replace('/', '.')).getConstructor();
          ClassFileTransformer transformer = (ClassFileTransformer) constructor.newInstance();
          String unit = HookExpectations.unitName(transformer.getClass().getSimpleName());
          claims.put(unit, transformer instanceof NamedTargets
              ? (className) -> ((NamedTargets) transformer).selectsByName(className)
              : (className) -> true);
          chain.add(HookMissWatch.wrap(transformer));
        }
      }
    }

    int checked = 0;
    for (String[] library : HookMap.libraries(new File(args[1]))) {
      try (JarFile jar = new JarFile(library[2])) {
        boolean multi = HookMap.multiRelease(jar);
        for (JarEntry entry : Collections.list(jar.entries())) {
          String file = entry.getName();
          if (entry.isDirectory() || !file.endsWith(".class")) continue;
          if (file.startsWith(HookMap.VERSIONS) ? !multi : file.startsWith("META-INF/")) continue;
          String owner = HookMap.runtimeName(file.substring(0, file.length() - ".class".length()));
          HookExpectation[] expected = table.forClass(owner);
          if (expected == null) continue;
          byte[] bytes = HookMap.bytes(jar.getInputStream(entry));
          String where = library[0] + " " + library[1];
          for (HookExpectation expectation : expected) {
            Claim claim = claims.get(expectation.unit);
            if (claim != null && claim.claims(owner)) {
              System.out.println("claimed " + expectation.unit + " " + owner + " " + where + " " + named(bytes, expectation));
            }
          }
          HookMisses.forget();
          written.clear();
          if (primary) {
            primaryTransform.invoke(primaryTransformer, null, APPLICATION, owner, null, null, bytes);
          } else {
            byte[] current = bytes;
            for (ClassFileTransformer transformer : chain) {
              byte[] produced = transformer.transform(APPLICATION, owner, null, null, current);
              if (produced != null) current = produced;
            }
          }
          for (String fields : written) {
            Matcher matcher = REPORT.matcher(fields);
            if (!matcher.find()) throw new IllegalStateException("not a hook-miss line: " + fields);
            System.out.println("report " + matcher.group(1) + " " + matcher.group(2).replace('.', '/') + " " + where + " " + matcher.group(3));
          }
          checked++;
        }
      }
    }
    System.err.println("hook-miss check: " + checked + " library classes the table names, " + table.size() + " table pairs");
  }

  /** How many methods of the class have a name the unit looks for. */
  static int named(byte[] bytes, final HookExpectation expectation) {
    final int[] count = new int[1];
    new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        if (expectation.looksFor(name)) count[0]++;
        return null;
      }
    }, ClassReader.SKIP_CODE);
    return count[0];
  }
}
