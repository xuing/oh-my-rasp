import java.sql.*;
import org.sqlite.Function;

/** All queries operate on an in-memory SQLite database. The test function only returns its integer argument. */
public final class SqliteIdentifierCheck {
  private static int calls;

  private static void check(Connection db, String track, String mode, String name, String query,
      String label, boolean policy, boolean prepared) throws Exception {
    int before = calls;
    boolean denied = false;
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(track, label);
         Statement stmt = prepared ? db.prepareStatement(query) : db.createStatement();
         ResultSet result = prepared ? ((PreparedStatement)stmt).executeQuery() : stmt.executeQuery(query)) {
      if (!result.next() || result.getInt(1) != 7 || !label.equals(result.getMetaData().getColumnLabel(1)))
        throw new AssertionError("incorrect report result for " + name);
    } catch (Exception failure) {
      if (!HttpTransportCheck.blocked(failure)) throw failure;
      denied = true;
    }
    if (calls - before != (policy && !denied ? 1 : 0)) throw new AssertionError("incorrect function receipt for " + name);
    if (!mode.equals("observe") && denied != (policy && mode.equals("block"))) throw new AssertionError(name);
    System.out.println("receipt," + name + "," + policy + "," + denied + "," + (calls - before) + ","
        + java.util.Base64.getEncoder().encodeToString(query.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }

  private static Connection pooled(Connection delegate) {
    return (Connection) java.lang.reflect.Proxy.newProxyInstance(SqliteIdentifierCheck.class.getClassLoader(),
        new Class<?>[]{Connection.class}, (proxy, method, args) -> {
          try { return method.invoke(delegate, args); }
          catch (java.lang.reflect.InvocationTargetException wrapped) { throw wrapped.getCause(); }
        });
  }

  public static void main(String[] args) throws Exception {
    Class.forName("org.sqlite.JDBC");
    try (Connection db = DriverManager.getConnection("jdbc:sqlite::memory:")) {
      Function.create(db, "benchmark", new Function() {
        protected void xFunc() throws SQLException { calls++; result(value_int(0)); }
      });
      String track = args[0], mode = args[1];
      check(db, track, mode, "alias", "SELECT 7 AS [benchmark(7) samples]", "benchmark(7) samples", false, false);
      check(db, track, mode, "sort", "SELECT 7 AS [weekly -- total] ORDER BY [weekly -- total]", "weekly -- total", false, true);
      check(db, track, mode, "cr-comment", "SELECT 7 AS weekly -- report\r benchmark(7)", "weekly", false, false);
      check(db, track, mode, "lf-expression", "SELECT -- report\r\n benchmark(7) AS weekly", "weekly", true, true);
      Connection pool = pooled(db);
      check(pool, track, mode, "pooled-cr-comment", "SELECT 7 AS weekly --report\r benchmark(7)", "weekly", false, true);
      check(pool, track, mode, "pooled-title", "SELECT 7 AS [benchmark(7) samples]", "benchmark(7) samples", false, true);
      check(pool, track, mode, "pooled-expression", "SELECT 7 AS [reviewer's total], benchmark(7)", "reviewer's total", true, true);
      check(db, track, mode, "actual", "SELECT benchmark(7) AS [weekly]", "weekly", true, true);
      check(db, track, mode, "after-label", "SELECT 7 AS [reviewer's note], benchmark(7)", "reviewer's note", true, false);
    }
  }
}
