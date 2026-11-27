package io.ohmyrasp.agent.hookmiss;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

/**
 * The expectation table of the run-time hook-miss report: per hook unit, the library classes it is meant to
 * instrument and the methods it instruments there.
 *
 * <p>The table is generated, never written by hand: {@code java-agent/scripts/gen-hook-targets.py} derives it from
 * the recorded hook maps ({@code probes/hook-targets/recorded/<family>.txt}) and the reviewed exceptions in
 * {@code probes/hook-targets/hook-miss.toml}, into {@code META-INF/ohmyrasp/hook-expectations/<family>.txt} of the
 * {@code :shared} module, so every agent JAR carries both families. Lines that start with {@code #} are comments,
 * apart from two that start with {@code #!}: {@code #! family <family>} before the first row, and
 * {@code #! end rows=<n> sha256=<hex>} as the last line, where the digest is the SHA-256 of every byte before that
 * line. Between them, one line per pair, fields separated by one space:
 *
 * <pre>unit class check method=callee[,callee] [method=callee ...]</pre>
 *
 * where {@code class} is an internal name, {@code check} is {@code report} or {@code absent} (see
 * {@link HookExpectation#absentIsVersionGap}), each {@code method} is a name followed by its complete descriptor
 * and each {@code callee} the name of an agent method the unit's hook calls from that method.
 *
 * <p>{@link #load} reads the table from the agent JAR that holds this class and publishes it only when it is the
 * table of the family asked for, no larger than {@link #MAX_BYTES}, complete (the digest and the row count match)
 * and well formed: complete descriptors, a unit of the family, no pair twice. Anything else is an
 * {@link IOException} or {@link IllegalArgumentException}, and the line starts with the report off.
 */
public final class HookExpectations {
  /** The resource directory; the table of a family is {@code <family>.txt} in it. */
  public static final String RESOURCE_DIRECTORY = "META-INF/ohmyrasp/hook-expectations/";
  /** The largest table {@link #load} reads, in bytes; the shipped ones are about a tenth of it. */
  public static final int MAX_BYTES = 1 << 20;

  private static final String FAMILY_PREFIX = "#! family ";
  private static final String END_PREFIX = "#! end ";

  private final Map<String, HookExpectation[]> byClass;
  private final Map<String, Map<String, HookExpectation>> byUnit;
  private final int size;

  private HookExpectations(List<HookExpectation> entries) {
    Map<String, List<HookExpectation>> classes = new HashMap<String, List<HookExpectation>>();
    Map<String, Map<String, HookExpectation>> units = new HashMap<String, Map<String, HookExpectation>>();
    for (HookExpectation entry : entries) {
      List<HookExpectation> same = classes.get(entry.className);
      if (same == null) {
        same = new ArrayList<HookExpectation>(1);
        classes.put(entry.className, same);
      }
      same.add(entry);
      Map<String, HookExpectation> unit = units.get(entry.unit);
      if (unit == null) {
        unit = new HashMap<String, HookExpectation>();
        units.put(entry.unit, unit);
      }
      unit.put(entry.className, entry);
    }
    Map<String, HookExpectation[]> arrays = new HashMap<String, HookExpectation[]>(classes.size() * 2);
    for (Map.Entry<String, List<HookExpectation>> entry : classes.entrySet()) {
      arrays.put(entry.getKey(), entry.getValue().toArray(new HookExpectation[0]));
    }
    this.byClass = arrays;
    this.byUnit = units;
    this.size = entries.size();
  }

  /**
   * Parses rows of the shape above, without the {@code #!} lines {@link #parseVerified} requires, for a table
   * written by hand in a test; a {@code method} may then have no callee, which accepts any call into the agent. A
   * line that does not have the shape, a descriptor that is not complete or a pair listed twice stops the parse.
   */
  public static HookExpectations parse(String text) {
    return parse(text, null);
  }

  /**
   * Parses a generated table of {@code family} ({@code primary} or {@code backport}): as {@link #parse}, and the
   * table must also name that family, end with a line whose row count and SHA-256 match what precedes it, give
   * every method a callee and hold only units of the family.
   */
  public static HookExpectations parseVerified(String text, String family) {
    return parse(text, family);
  }

  private static HookExpectations parse(String text, String family) {
    String body = text;
    if (family != null) {
      int end = text.lastIndexOf("\n" + END_PREFIX);
      if (end < 0) {
        throw new IllegalArgumentException("the table has no '#! end' line: it is truncated or not generated");
      }
      body = text.substring(0, end + 1);
      String trailer = text.substring(end + 1).trim();
      String[] fields = trailer.split(" ");
      if (fields.length != 4 || !fields[2].startsWith("rows=") || !fields[3].startsWith("sha256=")) {
        throw new IllegalArgumentException("not a table trailer: " + trailer);
      }
      String digest = sha256(body.getBytes(StandardCharsets.UTF_8));
      if (!digest.equals(fields[3].substring("sha256=".length()))) {
        throw new IllegalArgumentException("the table does not match its digest: it was changed after it was generated");
      }
      int declared;
      try {
        declared = Integer.parseInt(fields[2].substring("rows=".length()));
      } catch (NumberFormatException notANumber) {
        throw new IllegalArgumentException("not a table trailer: " + trailer);
      }
      HookExpectations table = rows(body, family);
      if (table.size != declared) {
        throw new IllegalArgumentException("the table has " + table.size + " rows, its trailer says " + declared);
      }
      return table;
    }
    return rows(body, null);
  }

  private static HookExpectations rows(String body, String family) {
    List<HookExpectation> entries = new ArrayList<HookExpectation>();
    Set<String> seen = new HashSet<String>();
    boolean named = false;
    for (String line : body.split("\n", -1)) {
      String trimmed = line.trim();
      if (trimmed.isEmpty()) {
        continue;
      }
      if (trimmed.startsWith("#")) {
        if (trimmed.startsWith(FAMILY_PREFIX)) {
          if (family != null && !trimmed.substring(FAMILY_PREFIX.length()).trim().equals(family)) {
            throw new IllegalArgumentException("the table is for another family than " + family + ": " + trimmed);
          }
          named = true;
        }
        continue;
      }
      if (family != null && !named) {
        throw new IllegalArgumentException("the table has a row before its '#! family' line: " + trimmed);
      }
      String[] fields = trimmed.split(" ");
      if (fields.length < 4 || !("report".equals(fields[2]) || "absent".equals(fields[2]))) {
        throw new IllegalArgumentException("not a hook expectation line: " + trimmed);
      }
      if (family != null && fields[0].startsWith("Java{N}") != "backport".equals(family)) {
        throw new IllegalArgumentException("a unit of another family than " + family + ": " + fields[0]);
      }
      if (fields[1].isEmpty() || fields[1].indexOf('.') >= 0 || fields[1].indexOf(';') >= 0) {
        throw new IllegalArgumentException("not an internal class name: " + fields[1] + " in " + trimmed);
      }
      if (!seen.add(fields[0] + " " + fields[1])) {
        throw new IllegalArgumentException("a unit and class listed twice: " + fields[0] + " " + fields[1]);
      }
      String[] methods = new String[fields.length - 3];
      String[][] callees = new String[fields.length - 3][];
      LinkedHashSet<String> names = new LinkedHashSet<String>();
      Set<String> methodsSeen = new HashSet<String>();
      for (int i = 3; i < fields.length; i++) {
        int equals = fields[i].indexOf('=');
        String method = equals < 0 ? fields[i] : fields[i].substring(0, equals);
        int open = method.indexOf('(');
        if (!validMethod(method, open)) {
          throw new IllegalArgumentException("not a method and complete descriptor: " + fields[i] + " in " + trimmed);
        }
        if (!methodsSeen.add(method)) {
          throw new IllegalArgumentException("a method listed twice: " + method + " in " + trimmed);
        }
        if (equals < 0 && family != null) {
          throw new IllegalArgumentException("a method with no callee: " + method + " in " + trimmed);
        }
        methods[i - 3] = method;
        callees[i - 3] = equals < 0 ? new String[0] : calleeNames(fields[i].substring(equals + 1), trimmed);
        names.add(method.substring(0, open));
      }
      entries.add(new HookExpectation(fields[0], fields[1], methods, callees, names.toArray(new String[0]),
          "absent".equals(fields[2])));
    }
    return new HookExpectations(entries);
  }

  private static String[] calleeNames(String list, String line) {
    String[] names = list.split(",", -1);
    for (String name : names) {
      if (!validIdentifier(name)) {
        throw new IllegalArgumentException("not an agent method name: '" + name + "' in " + line);
      }
    }
    return names;
  }

  private static boolean validIdentifier(String name) {
    if (name.isEmpty() || !Character.isJavaIdentifierStart(name.charAt(0))) {
      return false;
    }
    for (int i = 1; i < name.length(); i++) {
      if (!Character.isJavaIdentifierPart(name.charAt(i))) {
        return false;
      }
    }
    return true;
  }

  /** A method name followed by a complete method descriptor, {@code open} the index of its parenthesis. */
  private static boolean validMethod(String method, int open) {
    if (open <= 0) {
      return false;
    }
    for (int i = 0; i < open; i++) {
      char ch = method.charAt(i);
      if (ch == '.' || ch == ';' || ch == '[' || ch == '/' || ch == '=') {
        return false;
      }
    }
    int at = open + 1;
    while (at < method.length() && method.charAt(at) != ')') {
      at = fieldType(method, at);
      if (at < 0) {
        return false;
      }
    }
    if (at >= method.length()) {
      return false;
    }
    at++;
    if (at < method.length() && method.charAt(at) == 'V') {
      return at + 1 == method.length();
    }
    at = fieldType(method, at);
    return at == method.length();
  }

  /** The index after the field type that starts at {@code at}, or -1 when there is none. */
  private static int fieldType(String text, int at) {
    while (at < text.length() && text.charAt(at) == '[') {
      at++;
    }
    if (at >= text.length()) {
      return -1;
    }
    char ch = text.charAt(at);
    if ("BCDFIJSZ".indexOf(ch) >= 0) {
      return at + 1;
    }
    if (ch != 'L') {
      return -1;
    }
    int end = text.indexOf(';', at);
    if (end <= at + 1) {
      return -1;
    }
    for (int i = at + 1; i < end; i++) {
      char part = text.charAt(i);
      if (part == '.' || part == '[' || part == '(' || part == ')' || part == '=') {
        return -1;
      }
    }
    return end + 1;
  }

  /** The SHA-256 of {@code data}, as lower-case hexadecimal. */
  static String sha256(byte[] data) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
      StringBuilder out = new StringBuilder(64);
      for (byte b : digest) {
        out.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
      }
      return out.toString();
    } catch (NoSuchAlgorithmException missing) {
      throw new IllegalStateException(missing);
    }
  }

  /**
   * The table of {@code family} ({@code primary} or {@code backport}), read from the agent JAR that holds this
   * class, so a table of the same name on the application's class path cannot stand in for it; when this class does
   * not come from a JAR file (a class directory, the bootstrap class path), through the class loader that defined
   * it or the system class loader. It is published only when {@link #parseVerified} accepts it.
   *
   * @throws IOException when the table is missing, too large or cannot be read
   * @throws IllegalArgumentException when it is not the complete, well formed table of the family
   */
  public static HookExpectations load(String family) throws IOException {
    return load(family, ownJar());
  }

  /** As {@link #load(String)}, from {@code agentJar} when it is not null. */
  static HookExpectations load(String family, File agentJar) throws IOException {
    String name = RESOURCE_DIRECTORY + family + ".txt";
    byte[] data;
    if (agentJar != null) {
      JarFile jar = new JarFile(agentJar);
      try {
        ZipEntry entry = jar.getEntry(name);
        if (entry == null) {
          throw new IOException("no " + name + " in " + agentJar);
        }
        if (entry.getSize() > MAX_BYTES) {
          throw new IOException(name + " in " + agentJar + " is larger than " + MAX_BYTES + " bytes");
        }
        data = read(jar.getInputStream(entry), name);
      } finally {
        jar.close();
      }
    } else {
      ClassLoader loader = HookExpectations.class.getClassLoader();
      InputStream in = loader == null ? ClassLoader.getSystemResourceAsStream(name) : loader.getResourceAsStream(name);
      if (in == null) {
        throw new IOException("no " + name + " on the agent's class path");
      }
      data = read(in, name);
    }
    return parseVerified(new String(data, StandardCharsets.UTF_8), family);
  }

  private static byte[] read(InputStream in, String name) throws IOException {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      for (int n = in.read(buffer); n > 0; n = in.read(buffer)) {
        out.write(buffer, 0, n);
        if (out.size() > MAX_BYTES) {
          throw new IOException(name + " is larger than " + MAX_BYTES + " bytes");
        }
      }
      return out.toByteArray();
    } finally {
      in.close();
    }
  }

  /** The JAR file that holds this class, or null when it does not come from one. */
  private static File ownJar() {
    try {
      CodeSource source = HookExpectations.class.getProtectionDomain().getCodeSource();
      URL location = source == null ? null : source.getLocation();
      if (location == null || !"file".equals(location.getProtocol())) {
        return null;
      }
      File file = new File(location.toURI());
      return file.isFile() ? file : null;
    } catch (Throwable unknown) {
      return null;
    }
  }

  /** The pairs of every unit for a class, by internal name, or null when no unit expects to hook it. */
  public HookExpectation[] forClass(String className) {
    return byClass.get(className);
  }

  /** The pairs of one unit, by class internal name, or null when the unit expects to hook no library class. */
  public Map<String, HookExpectation> forUnit(String unit) {
    Map<String, HookExpectation> found = byUnit.get(unit);
    return found == null ? null : Collections.unmodifiableMap(found);
  }

  /** The number of pairs. */
  public int size() {
    return size;
  }

  /**
   * The name a unit has in the table: a backport transformer's simple name with its line's number written
   * {@code {N}} ({@code Java8JdbcTransformer} is {@code Java{N}JdbcTransformer}); any other name as it is.
   */
  public static String unitName(String simpleName) {
    int digits = 4;
    while (simpleName.startsWith("Java") && digits < simpleName.length() && Character.isDigit(simpleName.charAt(digits))) {
      digits++;
    }
    return digits == 4 ? simpleName : "Java{N}" + simpleName.substring(digits);
  }
}
