import java.sql.*;
import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationTargetException;
import java.util.Base64;
import java.util.Properties;
import java.nio.charset.StandardCharsets;

/** Read-only reports. BENCHMARK uses zero iterations and serves only as a JDBC policy control. */
public final class MysqlCommentCheck {
  interface Open { Statement get() throws SQLException; }

  private static Statement wrapped(Statement delegate) {
    return (Statement) Proxy.newProxyInstance(MysqlCommentCheck.class.getClassLoader(), new Class<?>[]{Statement.class},
        (proxy, method, args) -> {
          try { return method.invoke(delegate, args); }
          catch (InvocationTargetException wrapped) { throw wrapped.getCause(); }
        });
  }

  private static void check(Open open, String track, String mode, String name, String sql,
      String requestValue, boolean selected, int value, int columns) throws Exception {
    boolean denied = false;
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(track, requestValue);
         Statement statement = open.get();
         ResultSet rows = statement.executeQuery(sql)) {
      if (!rows.next() || rows.getInt(1) != value || rows.getMetaData().getColumnCount() != columns
          || (columns == 2 && rows.getInt(2) != 0) || rows.next()) throw new AssertionError(name + " returned unexpected data");
    } catch (Exception failure) {
      if (!HttpTransportCheck.blocked(failure)) throw failure;
      denied = true;
    }
    System.out.println("receipt," + name + "," + selected + "," + denied + "," + columns + "," +
        Base64.getEncoder().encodeToString(sql.getBytes(StandardCharsets.UTF_8)));
    if (!"observe".equals(mode) && denied != (selected && "block".equals(mode))) throw new AssertionError(name);
  }

  public static void main(String[] args) throws Exception {
    Class.forName("org.mariadb.jdbc.Driver");
    Properties properties = new Properties();
    properties.setProperty("user", "reports");
    properties.setProperty("localSocket", args[2]);
    try (Connection db = DriverManager.getConnection("jdbc:mariadb://localhost/", properties)) {
      Open direct = db::createStatement;
      Open pool = () -> wrapped(db.createStatement());
      String track = args[0], mode = args[1];
      check(direct, track, mode, "hash-notes", "SELECT 7 # report benchmark(0,1)", "weekly", false, 7, 1);
      check(direct, track, mode, "cr-in-note", "SELECT 7 -- report\r, BENCHMARK(0,1)", "weekly", false, 7, 1);
      check(direct, track, mode, "arithmetic", "SELECT 9--2", "--2", false, 11, 1);
      check(direct, track, mode, "quoted-label", "SELECT 7 AS `# weekly`", "# weekly", false, 7, 1);
      check(direct, track, mode, "request-tag", "SELECT '7' # 'report -- notes'", "# 'report -- notes'", false, 7, 1);
      check(pool, track, mode, "pool-notes", "SELECT 7 # pool benchmark(0,1)", "weekly", false, 7, 1);
      check(pool, track, mode, "pool-call", "SELECT 7 # pool's note\n, BENCHMARK(0,1)", "weekly", true, 7, 2);
      check(direct, track, mode, "actual", "SELECT 7, BENCHMARK(0,1)", "weekly", true, 7, 2);
      check(direct, track, mode, "after-hash", "SELECT 7 # reviewer's note\n, BENCHMARK(0,1)", "weekly", true, 7, 2);
    }
  }
}
