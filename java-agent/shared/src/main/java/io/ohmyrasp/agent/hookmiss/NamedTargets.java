package io.ohmyrasp.agent.hookmiss;

/**
 * Implemented by a backport transformer that chooses some classes by what they contain rather than by name (a
 * JDBC interface they implement, a multipart getter they declare or call). Such a class can drop that content in a
 * release without anything being wrong, so the hook-miss report checks only the classes this transformer selects
 * by name. The primary agent's counterpart is {@code HookModule.matchesClass}, which the content selection
 * bypasses.
 */
public interface NamedTargets {
  /** Whether the transformer selects the class, by internal name, by its name alone. */
  boolean selectsByName(String className);
}
