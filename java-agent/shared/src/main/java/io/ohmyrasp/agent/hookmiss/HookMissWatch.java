package io.ohmyrasp.agent.hookmiss;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.Map;

/**
 * A backport transformer as a backport line registers it: the transformer itself, and after it the hook-miss check
 * for the classes the {@link HookExpectations} table expects it to instrument.
 *
 * <p>For any other class the check adds one hash lookup on the class name, which the JVM hands every transformer
 * as the same string, so its hash is computed once per class. For an expected class it compares what the
 * transformer returned with what it was given: when the input names no agent class (the usual case, a library
 * class no earlier transformer touched) a gain is any mention of the agent in the output, found by a byte search;
 * otherwise the calls into the agent are counted in both. A failure in the check is dropped, and the
 * transformer's result is returned as it is.
 */
public final class HookMissWatch implements ClassFileTransformer {
  private final ClassFileTransformer delegate;
  private final String unit;
  private final Map<String, HookExpectation> expected;
  private final NamedTargets named;

  private HookMissWatch(ClassFileTransformer delegate, String unit, Map<String, HookExpectation> expected,
      NamedTargets named) {
    this.delegate = delegate;
    this.unit = unit;
    this.expected = expected;
    this.named = named;
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
        transformer instanceof NamedTargets ? (NamedTargets) transformer : null);
  }

  /** The transformer this watch wraps. */
  public ClassFileTransformer delegate() {
    return delegate;
  }

  @Override
  public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
    byte[] result = delegate.transform(loader, className, classBeingRedefined, protectionDomain, classfileBuffer);
    if (className == null || classfileBuffer == null) {
      return result;
    }
    HookExpectation expectation = expected.get(className);
    if (expectation == null) {
      return result;
    }
    try {
      if (named != null && !named.selectsByName(className)) {
        return result;
      }
      if (result == null) {
        HookMisses.miss(expectation, unit, classfileBuffer, protectionDomain, HookMisses.NOT_TRANSFORMED, null);
      } else if (!gained(classfileBuffer, result)) {
        HookMisses.miss(expectation, unit, classfileBuffer, protectionDomain, HookMisses.NO_AGENT_CALL, null);
      }
    } catch (Throwable dropped) {
      // The diagnostic never fails a transform: the class is returned as the transformer made it.
    }
    return result;
  }

  /** Whether {@code after} calls into the agent more than {@code before}. */
  static boolean gained(byte[] before, byte[] after) {
    if (!AgentCalls.mentionsAgent(before)) {
      return AgentCalls.mentionsAgent(after);
    }
    return AgentCalls.count(after) > AgentCalls.count(before);
  }
}
