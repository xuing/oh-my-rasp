package io.ohmyrasp.agent.sql;

import io.ohmyrasp.agent.hook.HookActivation;

/** Scope monitor receipts to a JDBC call and its nested delegations of the same SQL. */
public final class JdbcObservation {
  private static final ThreadLocal<JdbcObservation> CURRENT = new ThreadLocal<JdbcObservation>();
  private final JdbcObservation parent;
  private final Object receiver;
  private final String sql;
  private int depth = 1;
  private boolean reported;

  private JdbcObservation(JdbcObservation parent, Object receiver, String sql) {
    this.parent = parent;
    this.receiver = receiver;
    this.sql = sql;
  }

  /**
   * Enters one JDBC call: a nested delegation of the same SQL on the same receiver deepens the current observation.
   * Returns the observation entered, as the token {@link #exit} takes, or null while the hooks are off.
   */
  public static Object enter(Object receiver, String sql) {
    if (HookActivation.inactive()) return null;
    JdbcObservation current = CURRENT.get();
    if (current != null && current.receiver == receiver && java.util.Objects.equals(sql, current.sql)) {
      current.depth++;
      return current;
    }
    JdbcObservation observation = new JdbcObservation(current, receiver, sql);
    CURRENT.set(observation);
    return observation;
  }

  public static boolean repeated(Object receiver, String sql) {
    JdbcObservation current = CURRENT.get();
    if (current == null || current.receiver != receiver || !java.util.Objects.equals(sql, current.sql)) return false;
    boolean seen = current.reported;
    current.reported = true;
    return seen;
  }

  /** Leaves the call {@code token} entered; the last one out makes its parent current again. Null entered none. */
  public static void exit(Object token) {
    if (token == null) return;
    JdbcObservation observation = (JdbcObservation) token;
    if (--observation.depth != 0) return;
    if (observation.parent == null) CURRENT.remove();
    else CURRENT.set(observation.parent);
  }
}
