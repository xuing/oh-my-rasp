package io.ohmyrasp.agent.hookmiss;

/**
 * One (hook unit, library class) pair of the expectation table: the methods the recorded hook maps show the unit
 * instrumenting in that class, on the library versions of {@code probes/hook-targets/libraries.toml}, and for each
 * the agent methods it calls from there. A unit is a primary {@code HookModule} or a backport transformer, named
 * as in the recorded maps.
 */
public final class HookExpectation {
  /** The unit, as the recorded maps name it: {@code SqlHookModule}, {@code Java{N}JdbcTransformer}. */
  public final String unit;
  /** The class, by internal name. */
  public final String className;
  /** The methods instrumented on some recorded version, each its name followed by its descriptor. */
  final String[] methods;
  /**
   * For each of {@link #methods}, the names of the agent methods the recorded maps show the unit adding a call to
   * there (the owner is the line's hook class or a helper of the agent and differs between lines, so only the name
   * is compared). An empty list, which a table written by hand for a test can have, accepts any call into the agent.
   */
  final String[][] callees;
  /** The distinct names of {@link #methods}. */
  final String[] names;
  /**
   * True when a class that declares no method of these names is not a miss: the instrumented code came with a
   * later release, and an older one has nothing to hook. A method of one of these names with another descriptor
   * still is one.
   */
  final boolean absentIsVersionGap;

  HookExpectation(String unit, String className, String[] methods, String[][] callees, String[] names,
      boolean absentIsVersionGap) {
    this.unit = unit;
    this.className = className;
    this.methods = methods;
    this.callees = callees;
    this.names = names;
    this.absentIsVersionGap = absentIsVersionGap;
  }

  /** Whether {@code name} is the name of a method this pair looks for. */
  public boolean looksFor(String name) {
    for (String candidate : names) {
      if (candidate.equals(name)) {
        return true;
      }
    }
    return false;
  }
}
