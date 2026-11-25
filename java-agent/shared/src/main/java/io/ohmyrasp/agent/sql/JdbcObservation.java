package io.ohmyrasp.agent.sql;

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

  public static void enter(Object receiver, String sql) {
    JdbcObservation current = CURRENT.get();
    if (current != null && current.receiver == receiver && java.util.Objects.equals(sql, current.sql)) current.depth++;
    else CURRENT.set(new JdbcObservation(current, receiver, sql));
  }

  public static boolean repeated(Object receiver, String sql) {
    JdbcObservation current = CURRENT.get();
    if (current == null || current.receiver != receiver || !java.util.Objects.equals(sql, current.sql)) return false;
    boolean seen = current.reported;
    current.reported = true;
    return seen;
  }

  public static void exit() {
    JdbcObservation current = CURRENT.get();
    if (--current.depth != 0) return;
    if (current.parent == null) CURRENT.remove();
    else CURRENT.set(current.parent);
  }
}
