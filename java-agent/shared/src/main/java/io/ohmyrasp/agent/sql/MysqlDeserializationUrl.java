package io.ohmyrasp.agent.sql;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A MySQL-family JDBC URL that makes the driver deserialize what the server sends, the same rule on every agent line.
 *
 * <p>Connector/J deserializes a {@code BLOB} result only with {@code autoDeserialize} on, and the server's bytes
 * reach that code at connect time only through one of two chains: {@code ServerStatusDiffInterceptor} named as a
 * statement or query interceptor (it runs {@code SHOW SESSION STATUS} and reads the result), or
 * {@code detectCustomCollations} on (5.1 reads the collation table). A pool that sets {@code autoDeserialize} with an
 * interceptor of its own, or none, does not match.
 *
 * <p>The URL is read with the drivers' own grammar, checked against Connector/J 8.0.33 and 5.1.49 and MariaDB
 * Connector/J 3.5 and 4.0 ({@code MysqlDeserializationUrlDriverTest} uses their parsers as the oracle):
 * {@code scheme//authority[/database][?properties][#fragment]}. The authority ends at the first {@code /}, {@code ?}
 * or {@code #} and is a comma list of hosts outside parentheses and brackets; a host is
 * {@code [user[:password]@]host[:port]}, {@code address=(key=value)...}, {@code (key=value,...)} or a bracketed
 * sub-list. Properties are {@code &}-separated {@code key=value} pairs, percent-decoded, and the last of a repeated key
 * wins; a host's own {@code key=value} pairs override them for that host (Connector/J 8). An option is a property whose
 * key is the option's name; an interceptor is an entry of the comma list, trimmed, equal to the class name. Where the
 * drivers differ the rule takes either reading: the query cut at {@code #} (8.0) and not (5.1), each host's overrides
 * and the properties alone, keys compared ignoring case.
 *
 * <p>The event carries {@link #evidence}, never the URL: the driver, the first host as the driver names it (only when
 * it reads as a host name or address, so never user information or a key's value) and the options. Java 8 source with
 * no lambdas: the backport lines call it from their hooks.
 */
public final class MysqlDeserializationUrl {
  private static final Charset UTF_8 = Charset.forName("UTF-8");
  private static final String[] INTERCEPTORS = {
    "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor", // Connector/J 8
    "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor", // Connector/J 5.1
  };
  // queryInterceptors (8.0) and statementInterceptors (5.1).
  private static final String[] INTERCEPTOR_KEYS = {"queryinterceptors", "statementinterceptors"};
  private static final String AUTO_DESERIALIZE = "autodeserialize";
  private static final String CUSTOM_COLLATIONS = "detectcustomcollations";
  private static final String[] KEYS = {
    AUTO_DESERIALIZE, CUSTOM_COLLATIONS, INTERCEPTOR_KEYS[0], INTERCEPTOR_KEYS[1],
  };

  private MysqlDeserializationUrl() {}

  /**
   * What makes {@code url} deserialize at connect time, as option names ({@code autoDeserialize+
   * ServerStatusDiffInterceptor} or {@code autoDeserialize+detectCustomCollations}), or null when it does not.
   */
  public static String trigger(String url) {
    if (driver(url) == null) {
      return null;
    }
    String text = url.trim();
    int authorityStart = authorityStart(text);
    int authorityEnd = authorityEnd(text, authorityStart);
    int query = text.indexOf('?', authorityEnd);
    List<Map<String, String>> readings = new ArrayList<Map<String, String>>(2);
    if (query >= 0) {
      int fragment = text.indexOf('#', query);
      readings.add(properties(text.substring(query + 1, fragment < 0 ? text.length() : fragment)));
      if (fragment >= 0) {
        readings.add(properties(text.substring(query + 1)));
      }
    } else {
      readings.add(new HashMap<String, String>());
    }
    List<Host> hosts = hosts(authorityStart < 0 ? "" : text.substring(authorityStart, authorityEnd));
    String found = null;
    for (int r = 0; r < readings.size(); r++) {
      Map<String, String> global = readings.get(r);
      found = stronger(found, triggerOf(global));
      for (int h = 0; h < hosts.size(); h++) {
        Map<String, String> own = hosts.get(h).properties;
        if (own.isEmpty()) {
          continue;
        }
        Map<String, String> merged = new HashMap<String, String>(global);
        merged.putAll(own);
        found = stronger(found, triggerOf(merged));
      }
    }
    return found;
  }

  /** {@code mysql} or {@code mariadb} for a URL of that family, else null. */
  public static String driver(String url) {
    String relaxed = url == null ? null : url.trim().toLowerCase(Locale.ROOT);
    if (relaxed == null) {
      return null;
    }
    if (relaxed.startsWith("jdbc:mysql:") || relaxed.startsWith("jdbc:mysql+srv:")) {
      return "mysql";
    }
    return relaxed.startsWith("jdbc:mariadb:") ? "mariadb" : null;
  }

  /**
   * The first host (and port) of {@code url} as the driver names it: {@code db.internal:3306}. Empty when the URL
   * names none, or when what stands there does not read as a host name or address: user information, a password and
   * the other keys of {@code address=(...)} are never part of it.
   */
  public static String host(String url) {
    if (url == null) {
      return "";
    }
    String text = url.trim();
    int authorityStart = authorityStart(text);
    if (authorityStart < 0) {
      return "";
    }
    List<Host> hosts = hosts(text.substring(authorityStart, authorityEnd(text, authorityStart)));
    for (int i = 0; i < hosts.size(); i++) {
      if (hosts.get(i).name.length() > 0) {
        return hosts.get(i).name;
      }
    }
    return "";
  }

  /** What an event says about {@code url} instead of the URL: the driver, the first host and the trigger. */
  public static String evidence(String url) {
    return "driver=" + driver(url) + " host=" + host(url) + " options=" + trigger(url);
  }

  private static String triggerOf(Map<String, String> options) {
    if (!enabled(options.get(AUTO_DESERIALIZE))) {
      return null;
    }
    for (int k = 0; k < INTERCEPTOR_KEYS.length; k++) {
      String list = options.get(INTERCEPTOR_KEYS[k]);
      if (list == null) {
        continue;
      }
      int start = 0;
      for (int i = 0; i <= list.length(); i++) {
        if (i < list.length() && list.charAt(i) != ',') {
          continue;
        }
        String entry = list.substring(start, i).trim();
        for (int j = 0; j < INTERCEPTORS.length; j++) {
          if (INTERCEPTORS[j].equalsIgnoreCase(entry)) {
            return "autoDeserialize+ServerStatusDiffInterceptor";
          }
        }
        start = i + 1;
      }
    }
    return enabled(options.get(CUSTOM_COLLATIONS)) ? "autoDeserialize+detectCustomCollations" : null;
  }

  private static String stronger(String found, String candidate) {
    if (found == null) {
      return candidate;
    }
    return candidate != null && candidate.endsWith("ServerStatusDiffInterceptor") ? candidate : found;
  }

  /** A boolean option the drivers read as on: {@code true} or {@code yes} in any case, trimmed (and {@code 1}). */
  private static boolean enabled(String value) {
    if (value == null) {
      return false;
    }
    String trimmed = value.trim();
    return trimmed.equalsIgnoreCase("true") || trimmed.equalsIgnoreCase("yes") || trimmed.equals("1");
  }

  /** The index after {@code //}, or -1 when the URL has no authority. */
  private static int authorityStart(String text) {
    int slashes = text.indexOf("//");
    return slashes < 0 ? -1 : slashes + 2;
  }

  /** Where the authority ends: the first {@code /}, {@code ?} or {@code #} after it starts, as Connector/J reads it. */
  private static int authorityEnd(String text, int start) {
    if (start < 0) {
      return 0;
    }
    int end = start;
    while (end < text.length() && "/?#".indexOf(text.charAt(end)) < 0) {
      end++;
    }
    return end;
  }

  /** The options this rule reads, from {@code key=value&...}, keys lower-cased and decoded, the last one winning. */
  private static Map<String, String> properties(String query) {
    Map<String, String> options = new HashMap<String, String>();
    int start = 0;
    for (int i = 0; i <= query.length(); i++) {
      if (i < query.length() && query.charAt(i) != '&') {
        continue;
      }
      option(query.substring(start, i), options);
      start = i + 1;
    }
    return options;
  }

  private static void option(String pair, Map<String, String> options) {
    int equals = pair.indexOf('=');
    String key = decode(equals < 0 ? pair : pair.substring(0, equals)).trim().toLowerCase(Locale.ROOT);
    for (int i = 0; i < KEYS.length; i++) {
      if (KEYS[i].equals(key)) {
        options.put(key, equals < 0 ? "" : decode(pair.substring(equals + 1)));
        return;
      }
    }
  }

  /** One host of the authority: its name as an event may show it (or empty), and its own options. */
  private static final class Host {
    final String name;
    final Map<String, String> properties;

    Host(String name, Map<String, String> properties) {
      this.name = name;
      this.properties = properties;
    }
  }

  /** The hosts of {@code authority}: split on commas outside parentheses and brackets. */
  private static List<Host> hosts(String authority) {
    List<Host> hosts = new ArrayList<Host>();
    int depth = 0;
    int start = 0;
    for (int i = 0; i <= authority.length(); i++) {
      char ch = i < authority.length() ? authority.charAt(i) : ',';
      if (ch == '(' || ch == '[') {
        depth++;
      } else if ((ch == ')' || ch == ']') && depth > 0) {
        depth--;
      } else if (ch == ',' && (depth == 0 || i == authority.length())) {
        host(authority.substring(start, i).trim(), hosts);
        start = i + 1;
      }
    }
    return hosts;
  }

  private static void host(String segment, List<Host> hosts) {
    if (segment.length() == 0) {
      return;
    }
    String lower = segment.toLowerCase(Locale.ROOT);
    if (segment.charAt(0) == '[' && segment.charAt(segment.length() - 1) == ']'
        && (segment.indexOf(',') >= 0 || segment.indexOf('(') >= 0 || segment.indexOf('=') >= 0)) {
      hosts.addAll(hosts(segment.substring(1, segment.length() - 1)));
      return;
    }
    if (lower.startsWith("address=")) {
      keyValues(segment.substring("address=".length()), true, hosts);
      return;
    }
    if (segment.charAt(0) == '(') {
      keyValues(segment, false, hosts);
      return;
    }
    // [user[:password]@]host[:port]: only what follows the last @ can be the host. A segment with key-value syntax
    // that did not parse as such (a / inside a value ends the authority early) names no host: Connector/J then reads
    // a piece of the value after an @ as the host, and that piece can be part of a password.
    boolean mangled = segment.indexOf('(') >= 0 || segment.indexOf(')') >= 0 || segment.indexOf('=') >= 0;
    String hostPort = segment.substring(segment.lastIndexOf('@') + 1);
    hosts.add(new Host(mangled ? "" : hostName(hostPort, null), new HashMap<String, String>()));
  }

  /**
   * {@code (key=value)(key=value)...} ({@code grouped}) or {@code (key=value,key=value)}: the host and port name the
   * host, the options this rule reads are its own; user, password and the other keys are left.
   */
  private static void keyValues(String text, boolean grouped, List<Host> hosts) {
    Map<String, String> options = new HashMap<String, String>();
    List<String> pairs = new ArrayList<String>();
    if (grouped) {
      int at = 0;
      while (at < text.length() && text.charAt(at) == '(') {
        int close = text.indexOf(')', at);
        if (close < 0) {
          break;
        }
        pairs.add(text.substring(at + 1, close));
        at = close + 1;
      }
    } else {
      String inner = text.substring(1, text.endsWith(")") ? text.length() - 1 : text.length());
      int start = 0;
      for (int i = 0; i <= inner.length(); i++) {
        if (i == inner.length() || inner.charAt(i) == ',') {
          pairs.add(inner.substring(start, i));
          start = i + 1;
        }
      }
    }
    String name = null;
    String port = null;
    for (int i = 0; i < pairs.size(); i++) {
      String pair = pairs.get(i);
      int equals = pair.indexOf('=');
      String key = equals < 0 ? "" : pair.substring(0, equals).trim().toLowerCase(Locale.ROOT);
      if (key.equals("host") && name == null) {
        name = pair.substring(equals + 1).trim();
      } else if (key.equals("port") && port == null) {
        port = pair.substring(equals + 1).trim();
      } else {
        option(pair, options);
      }
    }
    hosts.add(new Host(name == null ? "" : hostName(name, port), options));
  }

  /**
   * {@code hostPort} ({@code host[:port]}, or a bracketed IPv6 address with a port) when it reads as a host name or
   * address, with {@code port} appended when given; else empty.
   */
  private static String hostName(String hostPort, String port) {
    String host = hostPort;
    String suffix = "";
    if (host.startsWith("[")) {
      int close = host.indexOf(']');
      if (close < 0) {
        return "";
      }
      suffix = host.substring(close + 1);
      host = host.substring(0, close + 1);
      for (int i = 1; i < host.length() - 1; i++) {
        char ch = host.charAt(i);
        if (!(isHex(ch) || ch == ':' || ch == '.' || ch == '%')) {
          return "";
        }
      }
    } else {
      int colon = host.indexOf(':');
      if (colon >= 0) {
        suffix = host.substring(colon);
        host = host.substring(0, colon);
      }
      if (host.length() == 0) {
        return "";
      }
      for (int i = 0; i < host.length(); i++) {
        char ch = host.charAt(i);
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
            || ch == '.' || ch == '-' || ch == '_')) {
          return "";
        }
      }
    }
    if (suffix.length() > 0 && !(suffix.charAt(0) == ':' && digits(suffix.substring(1)))) {
      return "";
    }
    if (port != null && port.length() > 0) {
      if (!digits(port) || suffix.length() > 0) {
        return "";
      }
      suffix = ":" + port;
    }
    return host + suffix;
  }

  private static boolean digits(String text) {
    if (text.length() == 0 || text.length() > 5) {
      return false;
    }
    for (int i = 0; i < text.length(); i++) {
      if (text.charAt(i) < '0' || text.charAt(i) > '9') {
        return false;
      }
    }
    return true;
  }

  private static boolean isHex(char ch) {
    return hexValue(ch) >= 0;
  }

  private static int hexValue(char ch) {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    return ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
  }

  /** Percent-decodes {@code text} as UTF-8, with {@code +} as a space, as the drivers decode a property. */
  private static String decode(String text) {
    if (text.indexOf('%') < 0 && text.indexOf('+') < 0) {
      return text;
    }
    StringBuilder out = new StringBuilder(text.length());
    ByteArrayOutputStream run = new ByteArrayOutputStream();
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      int high = ch == '%' && i + 2 < text.length() ? hexValue(text.charAt(i + 1)) : -1;
      int low = high < 0 ? -1 : hexValue(text.charAt(i + 2));
      if (low >= 0) {
        run.write(high * 16 + low);
        i += 2;
        continue;
      }
      if (run.size() > 0) {
        out.append(new String(run.toByteArray(), UTF_8));
        run.reset();
      }
      out.append(ch == '+' ? ' ' : ch);
    }
    if (run.size() > 0) {
      out.append(new String(run.toByteArray(), UTF_8));
    }
    return out.toString();
  }
}
