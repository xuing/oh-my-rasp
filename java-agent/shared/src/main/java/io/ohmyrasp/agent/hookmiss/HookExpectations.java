package io.ohmyrasp.agent.hookmiss;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * The expectation table of the run-time hook-miss report: per hook unit, the library classes it is meant to
 * instrument and the methods it instruments there.
 *
 * <p>The table is generated, never written by hand: {@code java-agent/scripts/gen-hook-targets.py} derives it from
 * the recorded hook maps ({@code probes/hook-targets/recorded/<family>.txt}) and the reviewed exceptions in
 * {@code probes/hook-targets/hook-miss.toml}, into {@code META-INF/ohmyrasp/hook-expectations/<family>.txt} of the
 * {@code :shared} module, so every agent JAR carries both families. One line per pair, fields separated by one
 * space:
 *
 * <pre>unit class check method [method ...]</pre>
 *
 * where {@code class} is an internal name, {@code check} is {@code report} or {@code absent} (see
 * {@link HookExpectation#absentIsVersionGap}) and each {@code method} is a name followed by its descriptor. Lines
 * that start with {@code #} are comments.
 */
public final class HookExpectations {
  /** The resource directory; the table of a family is {@code <family>.txt} in it. */
  public static final String RESOURCE_DIRECTORY = "META-INF/ohmyrasp/hook-expectations/";

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
   * Parses a table. A line that does not have the shape above stops the parse: the table is generated and
   * checked, so a malformed one is a build defect, not input to tolerate.
   */
  public static HookExpectations parse(String text) {
    List<HookExpectation> entries = new ArrayList<HookExpectation>();
    for (String line : text.split("\n", -1)) {
      String trimmed = line.trim();
      if (trimmed.isEmpty() || trimmed.startsWith("#")) {
        continue;
      }
      String[] fields = trimmed.split(" ");
      if (fields.length < 4 || !("report".equals(fields[2]) || "absent".equals(fields[2]))) {
        throw new IllegalArgumentException("not a hook expectation line: " + trimmed);
      }
      String[] methods = new String[fields.length - 3];
      LinkedHashSet<String> names = new LinkedHashSet<String>();
      for (int i = 3; i < fields.length; i++) {
        int open = fields[i].indexOf('(');
        if (open <= 0) {
          throw new IllegalArgumentException("not a method and descriptor: " + fields[i] + " in " + trimmed);
        }
        methods[i - 3] = fields[i];
        names.add(fields[i].substring(0, open));
      }
      entries.add(new HookExpectation(fields[0], fields[1], methods, names.toArray(new String[0]),
          "absent".equals(fields[2])));
    }
    return new HookExpectations(entries);
  }

  /**
   * The table of {@code family} ({@code primary} or {@code backport}), read through the loader that defined this
   * class, or the system class loader when that is the bootstrap loader: the agent JAR is on both searches.
   *
   * @throws IOException when the table is missing or cannot be read
   */
  public static HookExpectations load(String family) throws IOException {
    String name = RESOURCE_DIRECTORY + family + ".txt";
    ClassLoader loader = HookExpectations.class.getClassLoader();
    InputStream in = loader == null ? ClassLoader.getSystemResourceAsStream(name) : loader.getResourceAsStream(name);
    if (in == null) {
      throw new IOException("no " + name + " on the agent's class path");
    }
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      for (int n = in.read(buffer); n > 0; n = in.read(buffer)) {
        out.write(buffer, 0, n);
      }
      return parse(new String(out.toByteArray(), StandardCharsets.UTF_8));
    } finally {
      in.close();
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
