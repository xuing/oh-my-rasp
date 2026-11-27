import java.io.File;
import java.lang.ref.SoftReference;
import java.lang.reflect.Constructor;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Defines every library class the agent's transformers rewrite in a fresh class loader and has this JVM verify it,
 * so that a transformer that writes bytecode the JVM rejects fails the probe instead of the application.
 *
 * <pre>java -cp &lt;this class&gt;:&lt;HookMap&gt;:&lt;agent jar&gt; HookVerify &lt;agent jar&gt; &lt;staged tree&gt; &lt;primary | entry class&gt; [dependency jar...]</pre>
 *
 * <p>The units are HookMap's: on the primary agent the whole registry (what production runs) and each unit alone
 * (the shared visitors, and each HookModule), on a classes the whole registry changes; on a backport the transformers
 * its entry class registers, chained in that order as production chains them. A class is rewritten by a unit when the
 * bytes the unit returns differ from the bytes it was given. In a chain the bytes after each unit are verified, and a
 * class that fails is pinned on the first unit after which it fails.
 *
 * <p>How a class is verified without running library code: it is defined from its bytes in a fresh loader and
 * {@code getDeclaredConstructors()} (an interface: {@code getDeclaredFields()}) is called on it. In HotSpot, on
 * JDK 8 through 25, both link the class first (jvm.cpp), which verifies it and its superclasses, and neither
 * initialises it. Verification of classes of a loader other than the boot loader is on by default
 * (BytecodeVerificationRemote); before anything else the run defines a class that does not verify, and stops when
 * the JVM accepts it.
 *
 * <p>The loader of one check holds one staged JAR: the class under test with the bytes under test, every other class
 * of that JAR with its original bytes, as the JAR ships. A name resolves, in order, to: the JDK for {@code java.*};
 * the agent JAR for {@code io.ohmyrasp.agent.*}, so the calls the hooks inject resolve to the agent's classes; the
 * JAR itself (for a multi-release JAR, the entry this JVM would read); the JDK's platform (on 8, extension) loader;
 * and last the nearest other staged JAR that has the class: most leading group segments in common, then the same
 * version, then the nearest major version, then the highest version, then the order of the staged tree, skipping a
 * class file newer than this JVM reads. A container's stream class thus finds its servlet API and the rest of its
 * own release (tomcat-catalina 9.0.124 finds Coyote in tomcat-embed-core 9.0.124).
 *
 * <p>The rule that tells a defect from a dependency the staged tree lacks: the original class is linked in one fresh
 * loader and the rewritten one in another with the same classpath.
 * <ul>
 * <li>The original links and the rewritten does too: verified.</li>
 * <li>The original links and the rewritten throws anything (VerifyError, ClassFormatError, a NoClassDefFoundError
 *     for a class only the rewritten code needs, any other LinkageError): a failure.</li>
 * <li>The original does not link here (a class it needs is not staged, its class file is newer than this JVM, or
 *     the fallback JAR's class does not fit it): the class is skipped and counted under that reason, unless the
 *     rewritten class throws a VerifyError or ClassFormatError where the original threw neither. A missing class
 *     makes the verifier throw NoClassDefFoundError, never VerifyError, so that VerifyError is the rewrite's.</li>
 * </ul>
 * Output, one line each: {@code unit} (the counts of one unit), {@code skip} (the commonest reasons a unit's classes
 * were skipped), {@code synthetic} (one class of {@link BodyReadShapes} through the line's transformers), and
 * {@code fail} (tab-separated: unit, library, version, class, the JVM's message).
 */
public final class HookVerify {
  private static final ClassLoader AGENT = HookVerify.class.getClassLoader();
  private static final ClassLoader JDK = ClassLoader.getSystemClassLoader().getParent();
  private static final int FEATURE = feature();
  /** The newest class file major version this JVM reads. */
  private static final int MAX_MAJOR = 44 + FEATURE;
  static final String WHOLE = "OhMyRaspTransformer";

  // ---- the staged tree as class paths -----------------------------------------------------------

  /** One staged JAR: the class names it provides to a loader, and where to find the ones it lacks. */
  static final class Library {
    final int index;
    final String name;
    final String group;
    final String version;
    final File file;
    /** Internal class name to the entry this JVM would read for it. */
    final Map<String, String> entries = new HashMap<String, String>();
    final Map<String, Library> fallback = new ConcurrentHashMap<String, Library>();
    final Map<String, List<Library>> providers;
    /** A JAR given only to resolve classes the staged tree lacks: never transformed, and the last fallback. */
    final boolean dependency;
    JarFile jar;

    Library(int index, String name, String version, File file, Map<String, List<Library>> providers, boolean dependency) {
      this.index = index;
      this.name = name;
      this.group = name.substring(0, name.indexOf(':'));
      this.version = version;
      this.file = file;
      this.providers = providers;
      this.dependency = dependency;
    }

    synchronized JarFile jar() throws Exception {
      if (jar == null) jar = new JarFile(file);
      return jar;
    }

    byte[] own(String internal) {
      String entry = entries.get(internal);
      return entry == null ? null : read(this, entry);
    }

    /** The bytes of a class this JAR lacks, from the nearest staged JAR that has a version this JVM reads. */
    byte[] fallback(String internal) {
      Library chosen = fallback.get(internal);
      if (chosen == null) {
        List<Library> candidates = providers.get(internal);
        if (candidates == null) return null;
        for (Library candidate : candidates) {
          if (candidate == this || major(read(candidate, candidate.entries.get(internal))) > MAX_MAJOR) continue;
          if (chosen == null || nearer(candidate, chosen)) chosen = candidate;
        }
        if (chosen == null) return null;
        fallback.put(internal, chosen);
      }
      return read(chosen, chosen.entries.get(internal));
    }

    private boolean nearer(Library a, Library b) {
      int c = Boolean.compare(a.dependency, b.dependency);
      if (c == 0) c = Integer.compare(commonSegments(b.group), commonSegments(a.group));
      if (c == 0) c = Boolean.compare(!a.version.equals(version), !b.version.equals(version));
      if (c == 0) c = Integer.compare(Math.abs(majorOf(a.version) - majorOf(version)), Math.abs(majorOf(b.version) - majorOf(version)));
      if (c == 0) c = -compareVersions(a.version, b.version);
      if (c == 0) c = Integer.compare(a.index, b.index);
      return c < 0;
    }

    private int commonSegments(String other) {
      String[] mine = group.split("\\."), theirs = other.split("\\.");
      int n = 0;
      while (n < mine.length && n < theirs.length && mine[n].equals(theirs[n])) n++;
      return n;
    }

    @Override public String toString() {
      return name + " " + version;
    }
  }

  private static final Map<String, SoftReference<byte[]>> CACHE = new ConcurrentHashMap<String, SoftReference<byte[]>>();

  static byte[] read(Library library, String entry) {
    String key = library.index + "!" + entry;
    SoftReference<byte[]> cached = CACHE.get(key);
    byte[] bytes = cached == null ? null : cached.get();
    if (bytes == null) {
      try {
        JarFile jar = library.jar();
        JarEntry jarEntry;
        synchronized (library) {
          jarEntry = jar.getJarEntry(entry);
        }
        bytes = HookMap.bytes(jar.getInputStream(jarEntry));
      } catch (Exception failure) {
        throw new IllegalStateException("cannot read " + entry + " of " + library, failure);
      }
      CACHE.put(key, new SoftReference<byte[]>(bytes));
    }
    return bytes;
  }

  /** The staged libraries, then the dependency JARs, each indexed by the class names it provides. */
  static List<Library> stage(File root, List<File> dependencies) throws Exception {
    List<Library> all = new ArrayList<Library>();
    Map<String, List<Library>> providers = new HashMap<String, List<Library>>();
    List<String[]> jars = new ArrayList<String[]>(HookMap.libraries(root));
    for (File dependency : dependencies) jars.add(new String[] {"dependency:" + dependency.getName(), "", dependency.getPath()});
    for (String[] staged : jars) {
      Library library = new Library(all.size(), staged[0], staged[1], new File(staged[2]), providers, staged[0].startsWith("dependency:"));
      all.add(library);
      try (JarFile jar = new JarFile(library.file)) {
        boolean multi = HookMap.multiRelease(jar);
        Map<String, Integer> release = new HashMap<String, Integer>();
        for (JarEntry entry : Collections.list(jar.entries())) {
          String file = entry.getName();
          if (entry.isDirectory() || !file.endsWith(".class")) continue;
          int version = 0;
          if (file.startsWith(HookMap.VERSIONS)) {
            if (!multi) continue;
            String number = file.substring(HookMap.VERSIONS.length(), file.indexOf('/', HookMap.VERSIONS.length()));
            try {
              version = Integer.parseInt(number);
            } catch (NumberFormatException notARelease) {
              continue;
            }
            if (version > FEATURE) continue;
          } else if (file.startsWith("META-INF/")) {
            continue;
          }
          String internal = HookMap.runtimeName(file.substring(0, file.length() - ".class".length()));
          Integer had = release.get(internal);
          if (had != null && had > version) continue;
          release.put(internal, version);
          library.entries.put(internal, file);
        }
      }
      for (String internal : library.entries.keySet()) {
        List<Library> list = providers.get(internal);
        if (list == null) providers.put(internal, list = new ArrayList<Library>(1));
        list.add(library);
      }
    }
    return all;
  }

  // ---- defining and linking one class -----------------------------------------------------------

  /** A fresh loader over one staged JAR in which `target` has the bytes under test. */
  static final class ProbeLoader extends ClassLoader {
    private final Library library;
    private final String target;
    private final byte[] targetBytes;

    ProbeLoader(Library library, String target, byte[] targetBytes) {
      super(JDK);
      this.library = library;
      this.target = target;
      this.targetBytes = targetBytes;
    }

    @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      synchronized (getClassLoadingLock(name)) {
        Class<?> found = findLoadedClass(name);
        if (found != null) return found;
        if (name.startsWith("java.")) return JDK.loadClass(name);
        if (name.startsWith("io.ohmyrasp.agent.")) return AGENT.loadClass(name);
        String internal = name.replace('.', '/');
        byte[] bytes = internal.equals(target) ? targetBytes : library.own(internal);
        if (bytes == null) {
          try {
            return JDK.loadClass(name);
          } catch (ClassNotFoundException notInTheJdk) {
            bytes = library.fallback(internal);
          }
        }
        if (bytes == null) throw new ClassNotFoundException(name);
        return defineClass(name, bytes, 0, bytes.length);
      }
    }
  }

  /** Null when the class links in a fresh loader, or what the JVM threw. Library code does not run. */
  static Throwable link(Library library, String internal, byte[] bytes) {
    try {
      Class<?> type = Class.forName(internal.replace('/', '.'), false, new ProbeLoader(library, internal, bytes));
      if (type.isInterface()) type.getDeclaredFields(); // getDeclaredConstructors does not reach the JVM for an interface
      else type.getDeclaredConstructors();
      return null;
    } catch (Throwable failure) {
      return failure;
    }
  }

  /** Why an original class does not link here, as a reason to count. */
  static String reason(Throwable failure) {
    if (failure instanceof NoClassDefFoundError || failure instanceof ClassNotFoundException) {
      return "missing " + String.valueOf(failure.getMessage()).replace('.', '/');
    }
    if (failure instanceof UnsupportedClassVersionError) return "class file newer than Java " + FEATURE;
    return "original does not link here: " + failure.getClass().getName();
  }

  static String message(Throwable failure) {
    String text = failure.getClass().getName() + ": " + failure.getMessage();
    return text.replace("\t", " ").replaceAll("\\s*\n\\s*", " | ");
  }

  // ---- tallies ----------------------------------------------------------------------------------

  /** A unit with at most this many skipped classes has each listed; one with more, its commonest reasons. */
  static final int SKIPS_LISTED = 25;

  static final class Tally {
    int rewritten, verified, failed, skipped, afterFailure;
    final Map<String, Integer> reasons = new TreeMap<String, Integer>();
    final Map<String, String> example = new HashMap<String, String>();
    final List<String> each = new ArrayList<String>();

    synchronized void count(Verdict verdict, String where) {
      rewritten++;
      if (verdict.failure != null) failed++;
      else if (verdict.skipped == null) verified++;
      else {
        skipped++;
        Integer n = reasons.get(verdict.skipped);
        reasons.put(verdict.skipped, n == null ? 1 : n + 1);
        if (!example.containsKey(verdict.skipped)) example.put(verdict.skipped, where);
        if (each.size() <= SKIPS_LISTED) each.add(where + ": " + verdict.skipped);
      }
    }

    synchronized void notVerified() {
      rewritten++;
      afterFailure++;
    }
  }

  /** The result of one rewritten class: a failure (the JVM's message), a skip (why), or neither (verified). */
  static final class Verdict {
    final String failure;
    final String skipped;

    Verdict(String failure, String skipped) {
      this.failure = failure;
      this.skipped = skipped;
    }
  }

  private final Map<String, Throwable> originals = new ConcurrentHashMap<String, Throwable>();
  private final Map<String, Verdict> verdicts = new ConcurrentHashMap<String, Verdict>();
  private final Map<String, Tally> tallies = Collections.synchronizedMap(new LinkedHashMap<String, Tally>());
  private final List<String> failures = Collections.synchronizedList(new ArrayList<String>());

  private static final Throwable LINKS = new Throwable("links");

  Verdict verify(Library library, String internal, byte[] original, byte[] rewritten) throws Exception {
    String key = library.index + "!" + internal + "!" + digest(rewritten);
    Verdict verdict = verdicts.get(key);
    if (verdict != null) return verdict;
    String originalKey = library.index + "!" + internal + "!" + digest(original);
    Throwable before = originals.get(originalKey);
    if (before == null) {
      before = link(library, internal, original);
      originals.put(originalKey, before == null ? LINKS : before);
    }
    if (before == LINKS) before = null;
    Throwable after = link(library, internal, rewritten);
    if (before == null) {
      verdict = new Verdict(after == null ? null : message(after), null);
    } else if (after != null && rejectsBytes(after) && !rejectsBytes(before)) {
      verdict = new Verdict(message(after) + " (the original class does not link here either: " + message(before) + ")", null);
    } else {
      verdict = new Verdict(null, reason(before));
    }
    verdicts.put(key, verdict);
    return verdict;
  }

  private static boolean rejectsBytes(Throwable failure) {
    return failure instanceof VerifyError || (failure instanceof ClassFormatError && !(failure instanceof UnsupportedClassVersionError));
  }

  Tally tally(String unit) {
    synchronized (tallies) {
      Tally tally = tallies.get(unit);
      if (tally == null) tallies.put(unit, tally = new Tally());
      return tally;
    }
  }

  /** Counts the verdict under the unit; returns whether the class failed. */
  boolean record(String unit, Library library, String internal, byte[] original, byte[] rewritten) throws Exception {
    Verdict verdict = verify(library, internal, original, rewritten);
    tally(unit).count(verdict, internal + " (" + library + ")");
    if (verdict.failure != null) {
      failures.add("fail\t" + unit + "\t" + library.name + "\t" + library.version + "\t" + internal + "\t" + verdict.failure);
    }
    return verdict.failure != null;
  }

  static boolean changed(byte[] before, byte[] after) {
    return after != null && !Arrays.equals(before, after);
  }

  // ---- one library through the units ------------------------------------------------------------

  void library(Library library, HookMap.Unit whole, List<HookMap.Unit> units) throws Exception {
    for (Map.Entry<String, String> entry : new TreeMap<String, String>(library.entries).entrySet()) {
      String internal = entry.getKey();
      byte[] original = read(library, entry.getValue());
      try {
        new io.ohmyrasp.agent.shaded.asm.ClassReader(original);
      } catch (IllegalArgumentException unsupported) {
        continue; // the agent's ASM cannot read it, so no transformer changes it (HookMap counts these)
      }
      if (whole != null) {
        byte[] production = whole.apply(internal, original);
        if (!changed(original, production)) continue;
        record(WHOLE, library, internal, original, production);
        // The shared visitors rewrite against the original; a module, against what the shared visitors alone write,
        // since the transformer writes every class it reads again and a module's own change is the rest.
        byte[] shared = original;
        for (HookMap.Unit unit : units) {
          boolean common = HookMap.COMMON.equals(unit.name());
          byte[] alone = unit.apply(internal, original);
          if (changed(common ? original : shared, alone)) record(unit.name(), library, internal, original, alone);
          if (common && alone != null) shared = alone;
        }
      } else {
        byte[] current = original;
        boolean failed = false;
        for (HookMap.Unit unit : units) {
          byte[] produced = unit.apply(internal, current);
          if (!changed(current, produced)) continue;
          if (failed) tally(unit.name()).notVerified();
          else failed = record(unit.name(), library, internal, original, produced);
          current = produced;
        }
      }
    }
  }

  // ---- synthetic request-body classes -----------------------------------------------------------

  /** Each class of BodyReadShapes through the line's transformers as production runs them, then verified. */
  void synthetic(List<Library> all, HookMap.Unit whole, List<HookMap.Unit> units) throws Exception {
    Library servlet = new Library(-1, "javax.servlet:synthetic", "", null, all.get(0).providers, false);
    for (BodyReadShapes.Shape shape : BodyReadShapes.all()) {
      Throwable original = link(servlet, shape.className, shape.bytes);
      if (original != null) {
        throw new IllegalStateException("synthetic " + shape.name + " is not valid bytecode before any rewrite: " + message(original));
      }
      byte[] current = shape.bytes;
      List<String> by = new ArrayList<String>();
      if (whole != null) {
        byte[] produced = whole.apply(shape.className, current);
        if (changed(current, produced)) {
          by.add(WHOLE);
          current = produced;
        }
      } else {
        for (HookMap.Unit unit : units) {
          byte[] produced = unit.apply(shape.className, current);
          if (changed(current, produced)) {
            by.add(unit.name());
            current = produced;
          }
        }
      }
      String unit = by.isEmpty() ? "-" : String.join("+", by);
      if (by.isEmpty()) {
        if (!shape.mayStayUntouched) {
          failures.add("fail\t-\tsynthetic\t" + shape.name + "\t" + shape.className + "\tno transformer of this line rewrote it; "
              + "the shape no longer reaches the request-body hook");
        }
        System.out.println("synthetic " + shape.name + ": left untouched");
        continue;
      }
      Throwable rewritten = link(servlet, shape.className, current);
      if (rewritten != null) {
        failures.add("fail\t" + unit + "\tsynthetic\t" + shape.name + "\t" + shape.className + "\t" + message(rewritten));
      }
      System.out.println("synthetic " + shape.name + ": rewritten by " + unit + ", " + (rewritten == null ? "verified" : "REJECTED"));
    }
  }

  // ---- checks on the JVM itself -----------------------------------------------------------------

  /** Stops the run when this JVM accepts a class that does not verify, or initialises a class it only links. */
  static void canary(List<Library> all) {
    Library none = new Library(-1, "canary:canary", "", null, new HashMap<String, List<Library>>(), false);
    for (boolean iface : new boolean[] {false, true}) {
      String name = iface ? "ohmyrasp/canary/Interface" : "ohmyrasp/canary/Class";
      Throwable valid = link(none, name, BodyReadShapes.canary(name, iface, false));
      if (valid != null) throw new IllegalStateException("the canary " + name + " does not link: " + message(valid));
      Throwable invalid = link(none, name, BodyReadShapes.canary(name, iface, true));
      if (!(invalid instanceof VerifyError)) {
        throw new IllegalStateException("this JVM linked " + name + ", whose method does not verify, without a VerifyError ("
            + (invalid == null ? "no error" : message(invalid)) + "): run it with bytecode verification on");
      }
    }
  }

  // ---- the run ----------------------------------------------------------------------------------

  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      throw new IllegalArgumentException("usage: HookVerify <agent jar> <staged tree> <primary | line entry class> [dependency jar...]");
    }
    long start = System.nanoTime();
    HookMap.Unit whole = null;
    List<HookMap.Unit> units;
    if ("primary".equals(args[2])) {
      units = HookMap.primaryModules();
      Constructor<?> constructor = Class.forName("io.ohmyrasp.agent.asm.OhMyRaspTransformer").getConstructor();
      whole = new HookMap.Transform(WHOLE, constructor.newInstance());
    } else {
      try (JarFile agent = new JarFile(args[0])) {
        units = HookMap.registeredTransformers(agent, args[2]);
      }
    }
    List<File> dependencies = new ArrayList<File>();
    for (int i = 3; i < args.length; i++) dependencies.add(new File(args[i]));
    List<Library> all = stage(new File(args[1]), dependencies);
    canary(all);
    HookVerify run = new HookVerify();
    run.synthetic(all, whole, units);

    int threads = Math.max(1, Math.min(8, Runtime.getRuntime().availableProcessors()));
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    List<Future<?>> done = new ArrayList<Future<?>>();
    final HookMap.Unit production = whole;
    final List<HookMap.Unit> chain = units;
    // The largest JARs first, so that one of them does not start last.
    List<Library> order = new ArrayList<Library>();
    for (Library library : all) if (!library.dependency) order.add(library);
    Collections.sort(order, (a, b) -> Long.compare(b.file.length(), a.file.length()));
    for (final Library library : order) {
      done.add(pool.submit(() -> {
        run.library(library, production, chain);
        return null;
      }));
    }
    for (Future<?> future : done) future.get();
    pool.shutdown();

    List<String> names = new ArrayList<String>();
    if (whole != null) names.add(WHOLE);
    for (HookMap.Unit unit : units) names.add(unit.name());
    for (String name : names) {
      Tally tally = run.tallies.get(name);
      if (tally == null) {
        System.out.println("unit " + name + ": rewrites no staged class");
        continue;
      }
      System.out.println("unit " + name + ": rewritten " + tally.rewritten + ", verified " + tally.verified + ", failed "
          + tally.failed + ", skipped " + tally.skipped + (tally.afterFailure > 0 ? ", not verified after an earlier unit's failure "
          + tally.afterFailure : ""));
      if (tally.skipped <= SKIPS_LISTED) {
        Collections.sort(tally.each);
        for (String skipped : tally.each) System.out.println("skip " + name + ": " + skipped);
        continue;
      }
      List<Map.Entry<String, Integer>> reasons = new ArrayList<Map.Entry<String, Integer>>(tally.reasons.entrySet());
      Collections.sort(reasons, (a, b) -> b.getValue() != a.getValue().intValue() ? b.getValue() - a.getValue() : a.getKey().compareTo(b.getKey()));
      for (Map.Entry<String, Integer> reason : reasons.subList(0, Math.min(5, reasons.size()))) {
        System.out.println("skip " + name + ": " + reason.getValue() + " x " + reason.getKey() + ", e.g. " + tally.example.get(reason.getKey()));
      }
    }
    List<String> failures = new ArrayList<String>(run.failures);
    Collections.sort(failures);
    for (String failure : failures) System.out.println(failure);
    System.err.println("hook verify: " + order.size() + " libraries and " + dependencies.size() + " dependency JARs on Java " + FEATURE + " with " + threads + " threads in "
        + (System.nanoTime() - start) / 1000000 + " ms");
  }

  // ---- small helpers ----------------------------------------------------------------------------

  private static int feature() {
    String version = System.getProperty("java.specification.version");
    return Integer.parseInt(version.startsWith("1.") ? version.substring(2) : version);
  }

  static int major(byte[] bytes) {
    return bytes.length < 8 ? 0 : ((bytes[6] & 0xff) << 8) | (bytes[7] & 0xff);
  }

  static int majorOf(String version) {
    int i = 0;
    while (i < version.length() && Character.isDigit(version.charAt(i))) i++;
    return i == 0 ? -1000 : Integer.parseInt(version.substring(0, Math.min(i, 9)));
  }

  /** Compares versions by their runs of digits as numbers and the rest as text. */
  static int compareVersions(String a, String b) {
    String[] x = a.split("(?<=\\d)(?=\\D)|(?<=\\D)(?=\\d)"), y = b.split("(?<=\\d)(?=\\D)|(?<=\\D)(?=\\d)");
    for (int i = 0; i < Math.min(x.length, y.length); i++) {
      boolean digits = !x[i].isEmpty() && Character.isDigit(x[i].charAt(0)) && !y[i].isEmpty() && Character.isDigit(y[i].charAt(0));
      int c = digits ? Long.compare(Long.parseLong(x[i].substring(0, Math.min(18, x[i].length()))),
          Long.parseLong(y[i].substring(0, Math.min(18, y[i].length())))) : x[i].compareTo(y[i]);
      if (c != 0) return c;
    }
    return Integer.compare(x.length, y.length);
  }

  private static String digest(byte[] bytes) throws Exception {
    byte[] hash = MessageDigest.getInstance("SHA-1").digest(bytes);
    StringBuilder text = new StringBuilder();
    for (byte b : hash) text.append(Integer.toHexString((b & 0xff) | 0x100).substring(1));
    return text.toString();
  }
}
