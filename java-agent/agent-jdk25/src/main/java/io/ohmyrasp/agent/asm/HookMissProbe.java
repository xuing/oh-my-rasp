package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.hookmiss.AgentCalls;
import io.ohmyrasp.agent.hookmiss.HookExpectation;
import io.ohmyrasp.agent.hookmiss.HookExpectations;
import io.ohmyrasp.agent.hookmiss.HookMisses;
import io.ohmyrasp.agent.http.RequestBodyVisitor;
import java.security.ProtectionDomain;
import java.util.Map;
import java.util.Set;

/**
 * The hook-miss check of one class in {@link OhMyRaspTransformer}. It exists only for a class of the
 * {@link HookExpectations} table that one of the expected modules claims ({@link HookModule#expectedFor}); for any
 * other class the transformer pays one hash lookup on its name.
 *
 * <p>It is not part of the transform. The production visitor chain ({@link HookClassVisitor}, the modules, the
 * writer) knows nothing of it, so nothing here can turn a transform that succeeded into one that is discarded. After
 * the class is written, {@link #finish} reads the finished class file once, for the methods the expected modules are
 * recorded instrumenting, and asks for each module whether one of them calls an agent method that module is recorded
 * adding ({@link AgentCalls#applied}); a module for which none does missed the class. Every method here catches
 * {@link Throwable}, and the transformer calls {@link #finish} after the transform's own {@code try}, so a failure
 * of the check leaves the transform's result exactly as it is with the report off.
 *
 * <p>What this observes is what this transformer wrote: a transformer that runs later can still remove the hook,
 * and the JVM can still reject the class it defines.
 */
final class HookMissProbe {
  private final HookExpectation[] expected;

  private HookMissProbe(HookExpectation[] expected) {
    this.expected = expected;
  }

  /**
   * The check for this class, or null when no module is expected to instrument it. Never throws.
   *
   * @param loader the loader that defines the class; the request-body module leaves a class whose loader cannot see
   *     the agent alone on purpose, which is no miss
   */
  static HookMissProbe of(String className, HookRegistry registry, ClassLoader loader) {
    try {
      HookExpectations table = HookMisses.table();
      HookExpectation[] candidates = table == null ? null : table.forClass(className);
      if (candidates == null) {
        return null;
      }
      boolean bodyHooks = RequestBodyVisitor.loaderSeesAgent(loader);
      HookExpectation[] found = new HookExpectation[candidates.length];
      int watched = 0;
      for (HookExpectation candidate : candidates) {
        HookModule module = registry.module(candidate.unit);
        if (module != null && module.expectedFor(className)
            && (bodyHooks || !(module instanceof RequestBodyHookModule))) {
          found[watched++] = candidate;
        }
      }
      if (watched == 0) {
        return null;
      }
      HookExpectation[] expected = new HookExpectation[watched];
      System.arraycopy(found, 0, expected, 0, watched);
      return new HookMissProbe(expected);
    } catch (Throwable failure) {
      return null;
    }
  }

  /**
   * After the class was written: reports each expected module none of whose recorded methods calls one of its
   * recorded agent methods in {@code transformed}. {@code classFile} is the class as it was given. Never throws.
   */
  void finish(byte[] classFile, byte[] transformed, ProtectionDomain domain) {
    Map<String, Set<String>> calls = null;
    for (HookExpectation pair : expected) {
      try {
        if (!HookMisses.wants(pair)) {
          continue;
        }
        if (calls == null) {
          calls = AgentCalls.inMethods(transformed, expected);
          if (calls == null) {
            return; // unreadable or too large: no verdict
          }
        }
        if (!AgentCalls.applied(pair, calls)) {
          HookMisses.miss(pair, pair.unit, classFile, domain, HookMisses.NO_AGENT_CALL, null);
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
