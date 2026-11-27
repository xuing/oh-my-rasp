package io.ohmyrasp.agent.util;

import java.nio.charset.Charset;
import java.util.Locale;

/**
 * Removes secrets from what an agent writes to its event spool, on every agent line.
 *
 * <ul>
 *   <li>{@link #redactedQuery}: the values of sensitive parameters inside a request's query string (the primary agent's
 *       {@code request.query}).
 *   <li>{@link #redactedUrls}: the credentials inside a URL in a detection's details, a JDBC URL included: the user
 *       information before {@code @}, Oracle's {@code user/password@}, and the value of each parameter whose name is
 *       a credential ({@code password}, {@code pwd}, {@code token}, {@code secret}...), in the query, in the fragment
 *       and in {@code ;}-separated driver properties. The rest of the URL stays: it is the evidence.
 * </ul>
 *
 * <p>Runs on the event-writing path: plain loops over ASCII comparisons, no regular expression, no lambda, no Unicode
 * tables. Java 8 source: the backport lines call it from their hooks.
 */
public final class Redaction {
  /** What a redacted value is replaced with. */
  public static final String MARKER = "[redacted]";
  // A query longer than this is not scanned: it is replaced by the marker as a whole.
  static final int MAX_REDACTED_QUERY_LENGTH = 8192;
  static final int MAX_DECODE_ROUNDS = 8;
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  /** Names of credentials, compared after removing {@code _} and {@code -} and lower-casing. */
  private static final String[] CREDENTIAL_NAMES = {
    "authorization", "password", "passwd", "pwd", "pass", "token", "accesstoken", "refreshtoken", "idtoken", "secret",
    "apikey", "xapikey", "auth", "credential", "credentials",
  };

  /** Names of request parameters that carry executable source; a request query hides them too. */
  private static final String[] EXECUTABLE_SOURCE_NAMES = {
    "gluesource", "executorparams", "script", "source", "command", "commandline", "cmd", "shell", "code", "payload",
    "dataconfig", "routeconfig", "routedefinition", "gatewayroute", "filterconfig", "scriptfields", "scriptfield",
    "scriptconfig", "template", "expression",
  };

  private Redaction() {}

  /** The one name rule for a request's {@code parameters} and for the parameters inside its query. */
  public static boolean isRedactedParameterName(String name) {
    String normalized = normalizeName(name);
    return contains(CREDENTIAL_NAMES, normalized) || contains(EXECUTABLE_SOURCE_NAMES, normalized);
  }

  /** Whether {@code name} names a credential. */
  public static boolean isCredentialName(String name) {
    return contains(CREDENTIAL_NAMES, normalizeName(name));
  }

  /**
   * Whether {@code name}, or what it decodes to, holds a credential's name as a token: {@code password},
   * {@code user[password]}, {@code login.api-key} and {@code %70assword} do, {@code passwordless} does not. The rule
   * a URL's parameters are read with ({@link #redactedUrls}), for a field name that is not in a URL.
   */
  public static boolean namesCredential(String name) {
    if (name == null) {
      return false;
    }
    String current = name;
    for (int round = 0; ; round++) {
      String lower = asciiLowerCase(current);
      if (holdsToken(lower, false, true) || holdsToken(lower, true, true)) {
        return true;
      }
      String next = percentDecode(current);
      if (next.equals(current) || round == MAX_DECODE_ROUNDS) {
        return false;
      }
      current = next;
    }
  }

  /**
   * The query string with every piece that names a sensitive parameter carrying the marker in place of its value.
   * The query is split once, left to right, on {@code &} only, and the separators stay: a {@code ;} is part of its
   * piece, as Tomcat reads it, so {@code password=alpha;omega} is one value. A piece is sensitive when it, or what it
   * decodes to (percent escapes and {@code +}, repeated until the text stops changing, at most
   * {@value #MAX_DECODE_ROUNDS} rounds; a piece still changing after that is sensitive), holds a name
   * {@link #isRedactedParameterName} names as a token: a run of ASCII letters, digits and underscores, or of those and
   * hyphens, so {@code amp;password}, {@code user[password]}, {@code {"password":"x"}} and
   * {@code next=/cb?token=abc} match and {@code passwordless} does not. A sensitive piece keeps its text up to and
   * including the first {@code =} and gets the marker as its value, as long as that text is a plain parameter name; a
   * piece with no {@code =}, or whose text before it holds punctuation that could carry the secret
   * ({@code {"password":"a=b"}}), is replaced as a whole. A parameter with an empty value has nothing to hide and
   * stays. A query longer than {@value #MAX_REDACTED_QUERY_LENGTH} characters is not scanned and becomes the marker.
   */
  public static String redactedQuery(String query) {
    if (query == null || query.length() == 0) {
      return query;
    }
    int length = query.length();
    if (length > MAX_REDACTED_QUERY_LENGTH) {
      return MARKER;
    }
    StringBuilder out = new StringBuilder(length + 16);
    boolean changed = false;
    int start = 0;
    for (int i = 0; i <= length; i++) {
      if (i < length && query.charAt(i) != '&') {
        continue;
      }
      String piece = query.substring(start, i);
      String written = redactedPiece(piece);
      changed |= written != piece;
      out.append(written);
      if (i < length) {
        out.append(query.charAt(i));
      }
      start = i + 1;
    }
    return changed ? out.toString() : query;
  }

  /**
   * {@code text} with the credentials of every URL in it removed: a detail value that is a URL ({@code http://...},
   * {@code ldap://...}), a JDBC URL ({@code jdbc:...}, whose driver properties may follow {@code ;}), or text that holds
   * URLs (a command line). The same string comes back when there is nothing to remove.
   */
  public static String redactedUrls(String text) {
    if (text == null || text.length() == 0) {
      return text;
    }
    String trimmed = text.trim();
    if (trimmed.regionMatches(true, 0, "jdbc:", 0, 5)) {
      return redactedJdbcUrl(text);
    }
    if (text.indexOf("://") < 0) {
      return text;
    }
    StringBuilder out = null;
    int copied = 0;
    int from = 0;
    while (true) {
      int separator = text.indexOf("://", from);
      if (separator < 0) {
        break;
      }
      int start = separator;
      while (start > 0 && isSchemeChar(text.charAt(start - 1))) {
        start--;
      }
      int end = separator + 3;
      while (end < text.length() && !endsUrl(text.charAt(end))) {
        end++;
      }
      String url = text.substring(start, end);
      String written = redactedUrl(url, '?');
      if (written != url) {
        if (out == null) {
          out = new StringBuilder(text.length());
        }
        out.append(text, copied, start).append(written);
        copied = end;
      }
      from = end;
    }
    if (out == null) {
      return text;
    }
    return out.append(text, copied, text.length()).toString();
  }

  /** A JDBC URL: Oracle's {@code user/password@}, user information of each authority, and driver properties. */
  private static String redactedJdbcUrl(String url) {
    String current = url;
    String lower = current.toLowerCase(Locale.ROOT);
    // jdbc:oracle:thin:scott/tiger@host:1521:orcl, and the oci form.
    if (lower.startsWith("jdbc:oracle:")) {
      int driverEnd = current.indexOf(':', "jdbc:oracle:".length());
      int at = driverEnd < 0 ? -1 : current.indexOf('@', driverEnd + 1);
      if (at > driverEnd + 1 && current.substring(driverEnd + 1, at).indexOf('/') >= 0
          && current.substring(driverEnd + 1, at).indexOf("//") < 0) {
        current = current.substring(0, driverEnd + 1) + MARKER + current.substring(at);
      }
    }
    return redactedUrl(current, ';');
  }

  /**
   * One URL: the user information of each authority (after {@code //}, before the last {@code @} preceding the path),
   * and the credential parameters of what follows the first {@code ?}, {@code #} or {@code ;}, split on {@code &}
   * and {@code ;}. {@code properties} is {@code ;} for a JDBC URL, whose driver properties may start right after the
   * host or the database name and so end its authority, and {@code ?} for any other URL, where a {@code ;} is a
   * character user information may hold ({@code http://user:pass;word@host/}).
   */
  private static String redactedUrl(String url, char properties) {
    String current = url;
    int slashes = current.indexOf("//");
    if (slashes >= 0) {
      int authorityStart = slashes + 2;
      int authorityEnd = authorityStart;
      while (authorityEnd < current.length() && "/?#".indexOf(current.charAt(authorityEnd)) < 0
          && !(properties == ';' && current.charAt(authorityEnd) == ';')
          && !endsUrl(current.charAt(authorityEnd))) {
        authorityEnd++;
      }
      int at = current.lastIndexOf('@', authorityEnd - 1);
      if (at >= authorityStart) {
        current = current.substring(0, authorityStart) + MARKER + current.substring(at);
      }
    }
    int params = -1;
    for (int i = 0; i < current.length(); i++) {
      char ch = current.charAt(i);
      if (ch == '?' || ch == '#' || (ch == properties && i > 5)) {
        params = i + 1;
        break;
      }
    }
    if (params < 0 || params >= current.length()) {
      return current.equals(url) ? url : current;
    }
    StringBuilder out = new StringBuilder(current.length() + 16).append(current, 0, params);
    boolean changed = !current.equals(url);
    int start = params;
    for (int i = params; i <= current.length(); i++) {
      char ch = i < current.length() ? current.charAt(i) : 0;
      if (i < current.length() && ch != '&' && ch != ';' && ch != '#' && ch != '?') {
        continue;
      }
      String piece = current.substring(start, i);
      String written = redactedCredentialParameter(piece);
      changed |= written != piece;
      out.append(written);
      if (i < current.length()) {
        out.append(ch);
      }
      start = i + 1;
    }
    return changed ? out.toString() : url;
  }

  /** {@code name=value} with the value replaced when the name, or what it decodes to, names a credential. */
  private static String redactedCredentialParameter(String piece) {
    int equals = piece.indexOf('=');
    if (equals <= 0 || equals + 1 == piece.length()) {
      return piece;
    }
    return namesCredential(piece.substring(0, equals)) ? piece.substring(0, equals + 1) + MARKER : piece;
  }

  /** The piece itself when nothing in it is sensitive, so the caller can tell by identity. */
  private static String redactedPiece(String piece) {
    if (piece.length() == 0 || !holdsRedactedName(piece)) {
      return piece;
    }
    int equals = piece.indexOf('=');
    if (equals < 0 || !isPlainParameterName(piece.substring(0, equals))) {
      return MARKER;
    }
    if (equals + 1 == piece.length()) {
      return piece;
    }
    return piece.substring(0, equals + 1) + MARKER;
  }

  /**
   * Whether the text, or any of its decodings, holds a redacted parameter name as a token. Text that is still changing
   * after {@link #MAX_DECODE_ROUNDS} rounds counts as holding one: a name could be behind the next layer.
   */
  private static boolean holdsRedactedName(String text) {
    String current = text;
    for (int round = 0; ; round++) {
      String lower = asciiLowerCase(current);
      if (holdsToken(lower, false, false) || holdsToken(lower, true, false)) {
        return true;
      }
      String next = percentDecode(current);
      if (next.equals(current)) {
        return false;
      }
      if (round == MAX_DECODE_ROUNDS) {
        return true;
      }
      current = next;
    }
  }

  /**
   * Whether a token of {@code lower} is a redacted name (a credential name only, with {@code credentialsOnly}). A token
   * is a maximal run of ASCII letters, digits and underscores, or, with {@code hyphenJoins}, of those and hyphens,
   * which keeps {@code api-key} and {@code access-token} one name.
   */
  private static boolean holdsToken(String lower, boolean hyphenJoins, boolean credentialsOnly) {
    int length = lower.length();
    int from = 0;
    while (from < length) {
      while (from < length && !isTokenChar(lower.charAt(from), hyphenJoins)) {
        from++;
      }
      int to = from;
      while (to < length && isTokenChar(lower.charAt(to), hyphenJoins)) {
        to++;
      }
      if (to > from) {
        String token = lower.substring(from, to);
        if (credentialsOnly ? isCredentialName(token) : isRedactedParameterName(token)) {
          return true;
        }
      }
      from = to;
    }
    return false;
  }

  private static boolean isTokenChar(char ch, boolean hyphenJoins) {
    return (ch >= 'a' && ch <= 'z')
        || (ch >= 'A' && ch <= 'Z')
        || (ch >= '0' && ch <= '9')
        || ch == '_'
        || (hyphenJoins && ch == '-');
  }

  /**
   * Whether the text before the first {@code =} is only a parameter name once decoded: letters, digits,
   * {@code _ - . [ ]}, spaces and non-ASCII characters. Quotes, braces, colons, slashes and a {@code %} left over after
   * the decoding rounds could carry a secret.
   */
  private static boolean isPlainParameterName(String rawKey) {
    String current = rawKey;
    for (int round = 0; round < MAX_DECODE_ROUNDS; round++) {
      String next = percentDecode(current);
      if (next.equals(current)) {
        break;
      }
      current = next;
    }
    for (int i = 0; i < current.length(); i++) {
      char ch = current.charAt(i);
      boolean plain =
          isTokenChar(ch, true) || ch == '.' || ch == '[' || ch == ']' || ch == ' ' || ch > 0x7f;
      if (!plain) {
        return false;
      }
    }
    return true;
  }

  private static boolean isSchemeChar(char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
        || ch == '+' || ch == '-' || ch == '.';
  }

  /** A character that ends a URL inside free text. */
  private static boolean endsUrl(char ch) {
    return ch <= ' ' || ch == '"' || ch == '\'' || ch == '<' || ch == '>' || ch == '`';
  }

  /**
   * ASCII lower-casing, with the two characters whose Unicode lower case is ASCII ({@code U+212A} Kelvin sign,
   * {@code U+0130} dotted capital I) mapped by hand, so a server that folds case with Unicode rules still reads
   * {@code toKen} as {@code token}. The same string comes back when nothing changes.
   */
  private static String asciiLowerCase(String text) {
    char[] chars = null;
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      char lower = ch;
      if (ch >= 'A' && ch <= 'Z') {
        lower = (char) (ch + ('a' - 'A'));
      } else if (ch == 'K') {
        lower = 'k';
      } else if (ch == 'İ') {
        lower = 'i';
      }
      if (lower != ch) {
        if (chars == null) {
          chars = text.toCharArray();
        }
        chars[i] = lower;
      }
    }
    return chars == null ? text : new String(chars);
  }

  /** URL-decodes a query component: {@code %XX} as UTF-8 bytes, {@code +} as a space. */
  private static String percentDecode(String value) {
    if (value.indexOf('%') < 0 && value.indexOf('+') < 0) {
      return value;
    }
    int length = value.length();
    StringBuilder out = new StringBuilder(length);
    byte[] run = new byte[length];
    int runLength = 0;
    for (int i = 0; i < length; i++) {
      char ch = value.charAt(i);
      int high = ch == '%' && i + 2 < length ? hexValue(value.charAt(i + 1)) : -1;
      int low = high < 0 ? -1 : hexValue(value.charAt(i + 2));
      if (low >= 0) {
        run[runLength++] = (byte) (high * 16 + low);
        i += 2;
        continue;
      }
      if (runLength > 0) {
        out.append(new String(run, 0, runLength, UTF_8));
        runLength = 0;
      }
      out.append(ch == '+' ? ' ' : ch);
    }
    if (runLength > 0) {
      out.append(new String(run, 0, runLength, UTF_8));
    }
    return out.toString();
  }

  private static int hexValue(char ch) {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
      return ch - 'A' + 10;
    }
    return -1;
  }

  private static String normalizeName(String name) {
    return name == null ? "" : name.replace("_", "").replace("-", "").toLowerCase(Locale.ROOT);
  }

  private static boolean contains(String[] values, String value) {
    for (int i = 0; i < values.length; i++) {
      if (values[i].equals(value)) {
        return true;
      }
    }
    return false;
  }
}
