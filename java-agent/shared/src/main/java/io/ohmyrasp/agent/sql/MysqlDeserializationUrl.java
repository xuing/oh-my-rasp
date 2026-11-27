package io.ohmyrasp.agent.sql;

import java.util.Locale;

/**
 * A MySQL-family JDBC URL that makes the driver deserialize what the server sends, the same rule on every agent line.
 *
 * <p>Connector/J deserializes a {@code BLOB} result only with {@code autoDeserialize} on, and the server's bytes
 * reach that code at connect time only through one of two chains: {@code ServerStatusDiffInterceptor} named as a
 * statement or query interceptor (it runs {@code SHOW SESSION STATUS} and reads the result), or
 * {@code detectCustomCollations} on (5.1 reads the collation table). A pool that sets {@code autoDeserialize} with an
 * interceptor of its own, or none, does not match.
 *
 * <p>The URL is read as the backports always read it: lower-cased, with the percent escapes and {@code +} a URL can
 * carry its options in decoded, and blanks ignored. The event carries {@link #evidence}, never the URL: it can hold
 * the database credentials. Java 8 source with no lambdas: the backport lines call it from their hooks.
 */
public final class MysqlDeserializationUrl {
  private static final String INTERCEPTOR = "serverstatusdiffinterceptor";

  private MysqlDeserializationUrl() {}

  /**
   * What makes {@code url} deserialize at connect time, as option names ({@code autoDeserialize+
   * ServerStatusDiffInterceptor} or {@code autoDeserialize+detectCustomCollations}), or null when it does not.
   */
  public static String trigger(String url) {
    String relaxed = relaxed(url);
    if (relaxed == null || driver(relaxed) == null || !enabled(relaxed, "autodeserialize")) {
      return null;
    }
    if (relaxed.indexOf(INTERCEPTOR) >= 0
        && (relaxed.indexOf("statementinterceptors=") >= 0 || relaxed.indexOf("queryinterceptors=") >= 0)) {
      return "autoDeserialize+ServerStatusDiffInterceptor";
    }
    if (enabled(relaxed, "detectcustomcollations")) {
      return "autoDeserialize+detectCustomCollations";
    }
    return null;
  }

  /** {@code mysql} or {@code mariadb} for a URL of that family, else null. */
  public static String driver(String url) {
    String relaxed = url == null ? null : url.trim().toLowerCase(Locale.ROOT);
    if (relaxed == null) {
      return null;
    }
    if (relaxed.startsWith("jdbc:mysql:")) {
      return "mysql";
    }
    return relaxed.startsWith("jdbc:mariadb:") ? "mariadb" : null;
  }

  /**
   * The first host (and port) of {@code url}, without user information: {@code db.internal:3306}. Empty when the URL
   * names none.
   */
  public static String host(String url) {
    if (url == null) {
      return "";
    }
    int slashes = url.indexOf("//");
    if (slashes < 0) {
      return "";
    }
    int start = slashes + 2;
    int end = start;
    while (end < url.length() && "/?#;,".indexOf(url.charAt(end)) < 0 && url.charAt(end) > ' ') {
      end++;
    }
    int at = url.lastIndexOf('@', end - 1);
    if (at >= start) {
      start = at + 1;
    }
    return url.substring(start, end);
  }

  /** What an event says about {@code url} instead of the URL: the driver, the first host and the trigger. */
  public static String evidence(String url) {
    return "driver=" + driver(url) + " host=" + host(url) + " options=" + trigger(url);
  }

  private static boolean enabled(String relaxed, String option) {
    return relaxed.indexOf(option + "=true") >= 0
        || relaxed.indexOf(option + "=1") >= 0
        || relaxed.indexOf(option + "=yes") >= 0;
  }

  private static String relaxed(String url) {
    if (url == null) {
      return null;
    }
    String lower = url.trim().toLowerCase(Locale.ROOT)
        .replace('+', ' ')
        .replace("%20", " ")
        .replace("%09", " ")
        .replace("%0a", " ")
        .replace("%0d", " ")
        .replace("%26", "&")
        .replace("%2b", "+")
        .replace("%2c", ",")
        .replace("%3b", ";")
        .replace("%3d", "=");
    StringBuilder out = new StringBuilder(lower.length());
    for (int i = 0; i < lower.length(); i++) {
      char ch = lower.charAt(i);
      if (ch > ' ') {
        out.append(ch);
      }
    }
    return out.toString();
  }
}
