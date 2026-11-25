package io.ohmyrasp.agent.sql;

/** JDBC entry points whose first argument is SQL source. Bind values and translations are excluded. */
public final class JdbcSqlMethod {
  private JdbcSqlMethod() {}

  // The hooks can be bootstrap-loaded while java.sql belongs to the platform loader.
  private static final class Types {
    static final Class<?> CONNECTION = lookup("java.sql.Connection");
    static final Class<?> STATEMENT = lookup("java.sql.Statement");

    private static Class<?> lookup(String name) {
      try {
        return Class.forName(name, false, ClassLoader.getSystemClassLoader());
      } catch (ClassNotFoundException | SecurityException unavailable) {
        return null;
      }
    }
  }

  public static boolean isJdbcImplementation(Class<?> type) {
    return type != null && !type.isInterface()
        && ((Types.CONNECTION != null && Types.CONNECTION.isAssignableFrom(type))
            || (Types.STATEMENT != null && Types.STATEMENT.isAssignableFrom(type)));
  }

  public static boolean directJdbcInterface(String[] interfaces) {
    for (String name : interfaces) {
      if (name.equals("java/sql/Connection") || name.equals("java/sql/Statement")
          || name.equals("java/sql/PreparedStatement") || name.equals("java/sql/CallableStatement")) return true;
    }
    return false;
  }

  public static boolean driverPackage(String name) {
    return name.startsWith("org/h2/jdbc/") || name.startsWith("com/mysql/cj/jdbc/")
        || name.startsWith("com/mysql/jdbc/") || name.startsWith("org/postgresql/jdbc/")
        || name.startsWith("org/mariadb/jdbc/") || name.startsWith("org/sqlite/")
        || name.startsWith("org/hsqldb/jdbc/") || name.startsWith("org/apache/derby/impl/jdbc/")
        || name.startsWith("oracle/jdbc/driver/") || name.startsWith("com/microsoft/sqlserver/jdbc/");
  }

  public static boolean driverOrPoolPackage(String name) {
    return driverPackage(name) || name.startsWith("com/zaxxer/hikari/pool/")
        || name.startsWith("org/apache/commons/dbcp") || name.startsWith("org/apache/tomcat/jdbc/pool/");
  }

  public static boolean preparesSql(String name, String descriptor) {
    if (name.equals("prepareCall")) {
      return signatureMatches(descriptor, "Ljava/sql/CallableStatement;", true, false);
    }
    return name.equals("prepareStatement")
        && signatureMatches(descriptor, "Ljava/sql/PreparedStatement;", true, true);
  }

  public static boolean executesSql(String name, String descriptor) {
    switch (name) {
      case "executeQuery":
        return descriptor.equals("(Ljava/lang/String;)Ljava/sql/ResultSet;");
      case "addBatch":
        return descriptor.equals("(Ljava/lang/String;)V");
      case "execute":
        return signatureMatches(descriptor, "Z", false, true);
      case "executeUpdate":
        return signatureMatches(descriptor, "I", false, true);
      case "executeLargeUpdate":
        return signatureMatches(descriptor, "J", false, true);
      default:
        return false;
    }
  }

  private static boolean signatureMatches(String descriptor, String result, boolean cursorOptions, boolean keyOptions) {
    String prefix = "(Ljava/lang/String;";
    if (!descriptor.startsWith(prefix)) return false;
    int end = descriptor.indexOf(')', prefix.length());
    if (end < 0 || !descriptor.substring(end + 1).equals(result)) return false;
    String options = descriptor.substring(prefix.length(), end);
    return options.isEmpty() || (cursorOptions && (options.equals("II") || options.equals("III")))
        || (keyOptions && (options.equals("I") || options.equals("[I") || options.equals("[Ljava/lang/String;")));
  }
}
