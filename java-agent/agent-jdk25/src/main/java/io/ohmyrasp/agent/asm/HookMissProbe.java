package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.hookmiss.AgentCalls;
import io.ohmyrasp.agent.hookmiss.HookExpectation;
import io.ohmyrasp.agent.hookmiss.HookExpectations;
import io.ohmyrasp.agent.hookmiss.HookMisses;
import java.security.ProtectionDomain;
import org.objectweb.asm.MethodVisitor;

/**
 * The hook-miss check of one class in {@link OhMyRaspTransformer}. It exists only for a class of the
 * {@link HookExpectations} table that one of the expected modules claims by {@link HookModule#matchesClass}; for any
 * other class the transformer pays one hash lookup on its name.
 *
 * <p>For each method a module wraps, one counter sits behind the module's visitor and one in front of it: the
 * calls into the agent that leave the module minus those that enter it (from the class itself, or from the
 * call-site visitors that run before the modules) are the calls the module added. A module whose count stays at
 * zero over the whole class missed it. The counts are the hook-targets probe's ({@code HookMap.java}), taken
 * while the class is written instead of from a second reading of it.
 */
final class HookMissProbe {
  private final HookExpectation[] expected;
  private final HookModule[] modules;
  private final int[] entering;
  private final int[] leaving;

  private HookMissProbe(HookExpectation[] expected, HookModule[] modules) {
    this.expected = expected;
    this.modules = modules;
    this.entering = new int[expected.length];
    this.leaving = new int[expected.length];
  }

  /** The check for this class, or null when no module is expected to instrument it. Never throws. */
  static HookMissProbe of(String className, HookRegistry registry) {
    try {
      HookExpectations table = HookMisses.table();
      HookExpectation[] candidates = table == null ? null : table.forClass(className);
      if (candidates == null) {
        return null;
      }
      int watched = 0;
      HookModule[] found = new HookModule[candidates.length];
      for (int i = 0; i < candidates.length; i++) {
        HookModule module = registry.module(candidates[i].unit);
        if (module != null && module.matchesClass(className)) {
          found[i] = module;
          watched++;
        }
      }
      if (watched == 0) {
        return null;
      }
      HookExpectation[] expected = new HookExpectation[watched];
      HookModule[] modules = new HookModule[watched];
      for (int i = 0, j = 0; i < candidates.length; i++) {
        if (found[i] != null) {
          expected[j] = candidates[i];
          modules[j++] = found[i];
        }
      }
      return new HookMissProbe(expected, modules);
    } catch (Throwable failure) {
      return null;
    }
  }

  /** The visitor handed to the modules for one method: counts what leaves whichever module wraps it. */
  AgentCalls.Counter output(MethodVisitor downstream) {
    return new AgentCalls.Counter(downstream, leaving, -1);
  }

  /** {@code module} wrapped a method in {@code wrapped}, around {@code output}: count both sides for that module. */
  MethodVisitor watch(HookModule module, MethodVisitor wrapped, AgentCalls.Counter output) {
    for (int slot = 0; slot < modules.length; slot++) {
      if (modules[slot] == module) {
        output.countInto(leaving, slot);
        return new AgentCalls.Counter(wrapped, entering, slot);
      }
    }
    return wrapped;
  }

  /** After the class was written: reports each expected module that added no call. Never throws. */
  void finish(byte[] classFile, ProtectionDomain domain) {
    for (int slot = 0; slot < expected.length; slot++) {
      try {
        if (leaving[slot] <= entering[slot]) {
          HookMisses.miss(expected[slot], expected[slot].unit, classFile, domain, HookMisses.NO_AGENT_CALL, null);
        }
      } catch (Throwable dropped) {
        // The diagnostic never fails a transform.
      }
    }
  }

  /** The transform threw: every expected module missed the class, which the JVM loads unchanged. Never throws. */
  void failed(byte[] classFile, ProtectionDomain domain, Throwable failure) {
    for (HookExpectation expectation : expected) {
      try {
        HookMisses.miss(expectation, expectation.unit, classFile, domain, HookMisses.TRANSFORM_FAILED, failure);
      } catch (Throwable dropped) {
        // The diagnostic never fails a transform.
      }
    }
  }
}
