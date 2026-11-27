package io.ohmyrasp.agent.hookmiss;

/**
 * Implemented by a backport transformer that leaves some classes alone on purpose, for a reason that is no
 * failure of its hooks: {@code Java{N}RequestBodyTransformer} skips a class whose loader cannot see the agent (the
 * bootstrap loader, an OSGi framework's), because a hook inserted there would not link. The hook-miss report asks
 * before it counts the missing hook as a miss. The primary agent's counterpart is the {@code bodyHooks} flag of its
 * transformer.
 */
public interface HookMissScope {
  /** Whether a class of this name, defined by this loader, is one the transformer means to instrument. */
  boolean inScope(ClassLoader loader, String className);
}
