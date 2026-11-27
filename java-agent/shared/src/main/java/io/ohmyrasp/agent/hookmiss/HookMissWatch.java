package io.ohmyrasp.agent.hookmiss;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.Map;
import java.util.Set;

/**
 * A backport transformer as a backport line registers it: the transformer itself, and after it the hook-miss check
 * for the classes the {@link HookExpectations} table expects it to instrument.
 *
 * <p>For any other class the check adds one hash lookup on the class name, which the JVM hands every transformer
 * as the same string, so its hash is computed once per class. For an expected class it reads what the transformer
 * returned (the class file it was given when it returned nothing) once, after the transformer is done, and asks
 * whether one of the methods the unit is recorded instrumenting there now calls an agent method the unit is
 * recorded adding ({@link AgentCalls#applied}). That reading is a separate pass over a finished class file, so
 * whatever it does, the transformer's result is returned as it is; a failure in the check is dropped. What the
 * transformer throws is reported as a failed transform and thrown again unchanged.
 *
 * <p>What this observes is what this transformer returned: a transformer that runs later can still remove the
 * hook, and the JVM can still reject the class it defines.
 */
public final class HookMissWatch implements ClassFileTransformer {
  private final ClassFileTransformer delegate;
  private final String unit;
  private final Map<String, HookExpectation> expected;
  private final NamedTargets named;
  private final HookMissScope scope;

  private HookMissWatch(ClassFileTransformer delegate, String unit, Map<String, HookExpectation> expected,
      NamedTargets named, HookMissScope scope) {
    this.delegate = delegate;
    this.unit = unit;
    this.expected = expected;
    this.named = named;
    this.scope = scope;
  }

  /**
   * The transformer to register in place of {@code transformer}: itself when the report is off or the table
   * expects it to instrument no library class (a transformer of JDK classes), else a watch around it.
   */
  public static ClassFileTransformer wrap(ClassFileTransformer transformer) {
    HookExpectations table = HookMisses.table();
    String simpleName = transformer.getClass().getSimpleName();
    Map<String, HookExpectation> mine = table == null ? null : table.forUnit(HookExpectations.unitName(simpleName));
    if (mine == null || mine.isEmpty()) {
      return transformer;
    }
    return new HookMissWatch(transformer, simpleName, mine,
        transformer instanceof NamedTargets ? (NamedTargets) transformer : null,
        transformer instanceof HookMissScope ? (HookMissScope) transformer : null);
  }

  /** The transformer this watch wraps. */
  public ClassFileTransformer delegate() {
    return delegate;
  }

  @Override
  public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
    byte[] result;
    try {
      result = delegate.transform(loader, className, classBeingRedefined, protectionDomain, classfileBuffer);
    } catch (IllegalClassFormatException failure) {
      failed(loader, className, protectionDomain, classfileBuffer, failure);
      throw failure;
    } catch (RuntimeException failure) {
      failed(loader, className, protectionDomain, classfileBuffer, failure);
      throw failure;
    } catch (Error failure) {
      failed(loader, className, protectionDomain, classfileBuffer, failure);
      throw failure;
    }
    if (className == null || classfileBuffer == null) {
      return result;
    }
    HookExpectation expectation = expected.get(className);
    if (expectation == null) {
      return result;
    }
    try {
      if (!claimed(loader, className) || !HookMisses.wants(expectation)) {
        return result;
      }
      // A transformer that returned nothing left the class as it was: a hook it finds already there is no miss.
      Map<String, Set<String>> calls = AgentCalls.inMethods(result == null ? classfileBuffer : result,
          new HookExpectation[] {expectation});
      if (calls == null || AgentCalls.applied(expectation, calls)) {
        return result;
      }
      HookMisses.miss(expectation, unit, classfileBuffer, protectionDomain,
          result == null ? HookMisses.NOT_TRANSFORMED : HookMisses.NO_AGENT_CALL, null);
    } catch (Throwable dropped) {
      // The diagnostic never fails a transform: the class is returned as the transformer made it.
    }
    return result;
  }

  /** The transformer threw: its class loads unchanged, so the unit missed it. Never throws. */
  private void failed(ClassLoader loader, String className, ProtectionDomain protectionDomain, byte[] classfileBuffer,
      Throwable failure) {
    try {
      if (className == null || classfileBuffer == null) {
        return;
      }
      HookExpectation expectation = expected.get(className);
      if (expectation != null && claimed(loader, className)) {
        HookMisses.miss(expectation, unit, classfileBuffer, protectionDomain, HookMisses.TRANSFORM_FAILED, failure);
      }
    } catch (Throwable dropped) {
      // The failure the transformer threw is the one that goes on.
    }
  }

  /** Whether the transformer means to instrument this class: it takes it by name and has not skipped it on purpose. */
  private boolean claimed(ClassLoader loader, String className) {
    return (named == null || named.selectsByName(className)) && (scope == null || scope.inScope(loader, className));
  }
}
