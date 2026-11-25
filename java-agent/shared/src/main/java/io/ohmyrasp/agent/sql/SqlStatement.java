package io.ohmyrasp.agent.sql;

import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Lexical context for signatures applied to a complete JDBC statement. */
public final class SqlStatement {
  private static final String BOOLEAN_OPERANDS = "(?:\\d+\\s*=\\s*\\d+|'[^']{0,32}'\\s*=\\s*'[^']{0,32}')";
  private static final Pattern REQUEST_STRUCTURE = Pattern.compile(
      "(?i)\\b(?:union\\s+(?:all\\s+)?select\\b|information_schema\\s*\\.|(and|or)\\s+" + BOOLEAN_OPERANDS + ")|;\\s*(?:select|insert|update|delete|drop|alter)\\b");
  private static final Pattern STRUCTURE_KEYWORD =
      Pattern.compile("(?i)\\b(?:union|information_schema)\\b|\\b(?:and|or)\\s+(?:\\d+\\s*=|')");
  // A fixed AND predicate cannot widen the result set. For an untainted OR,
  // require identical operands and the end of the comparison, not a numeric prefix.
  private static final Pattern CONSTANT_DISJUNCTION = Pattern.compile(
      "(?i:\\bor)\\s+(?:(\\d+)\\s*=\\s*\\1|(['\"])([^'\"]{1,32})\\2\\s*=\\s*\\2\\3\\2)"
          + "(?=\\s*(?:$|[);'\"]|(?i:and|or|order|group|limit|offset|fetch|having|union)\\b))");
  private static final Pattern QUERY_START = Pattern.compile("(?i)^\\s*(select|with)\\b");
  private static final Pattern SELECT_TOKEN = Pattern.compile("(?i)\\bselect\\b");
  private static final Pattern MUTATION_TOKEN = Pattern.compile("(?i)\\b(?:insert|delete|update|merge|call)\\b");
  private static final Pattern SINK_POLICY = Pattern.compile(
      "(?i)(?:\\binto\\s+(?:out|dump)file\\b|/\\*!|\\b(?:load_file|sleep|benchmark)\\s*\\()");

  private enum Dialect { UNSPECIFIED, WRAPPER, H2_1, H2_CURRENT, POSTGRESQL, DERBY, MYSQL, OTHER }

  private static final Pattern SOURCE_CLAUSE = Pattern.compile("(?i)\\b(?:as|for|call)\\b");
  private final String original;
  private final CharSequence text;
  private final BitSet comments = new BitSet();
  private final SqlStatement mysqlView;
  private boolean truncatedLiteral;
  private final BitSet quoted = new BitSet();

  public SqlStatement(String sql) {
    this(sql, null);
  }

  public SqlStatement(String sql, String jdbcClass) {
    this(sql, false, dialectOf(sql, jdbcClass, null));
  }

  public static SqlStatement fromJdbc(String sql, Object receiver) {
    if (receiver == null) return new SqlStatement(sql);
    Class<?> type = receiver.getClass();
    String name = type.getName();
    String version = null;
    if (name.startsWith("org.h2.jdbc.") && sql.contains("/*") && type.getPackage() != null) {
      version = type.getPackage().getImplementationVersion();
    }
    return new SqlStatement(sql, false, dialectOf(sql, name, version));
  }

  public String source() { return original; }

  private SqlStatement(String sql, boolean mysql, Dialect dialect) {
    original = sql;
    boolean ambiguous = false;
    boolean namedDollarQuotes = dialect == Dialect.POSTGRESQL || dialect == Dialect.WRAPPER;
    StringBuilder commentsRemoved = null;
    int i = 0;
    while (i < sql.length()) {
      char ch = sql.charAt(i);
      if (ch == '\'' || ch == '"' || ch == '`') {
        boolean escapeString = ch == '\'' && (dialect == Dialect.POSTGRESQL || dialect == Dialect.WRAPPER) && i >= 1
            && (sql.charAt(i - 1) == 'E' || sql.charAt(i - 1) == 'e')
            && (i == 1 || !Character.isJavaIdentifierPart(sql.charAt(i - 2)));
        int start = i++;
        // Leave the closing delimiter visible to signatures anchored at the end of a literal.
        int end = sql.length();
        while (i < sql.length()) {
          char current = sql.charAt(i++);
          if (current == '\\' && i < sql.length()) {
            ambiguous = true;
            if (mysql || escapeString) {
              i++;
              continue;
            }
          }
          if (current == ch) {
            if (i == sql.length() || sql.charAt(i) != ch) {
              end = i - 1;
              break;
            }
            i++;
          }
        }
        quoted.set(start, end);
      } else if (ch == '$' && (dialect == Dialect.H2_1 || dialect == Dialect.H2_CURRENT
          || dialect == Dialect.POSTGRESQL || dialect == Dialect.WRAPPER)
          && (i == 0 || !Character.isJavaIdentifierPart(sql.charAt(i - 1)))) {
        int delimiterEnd = dollarDelimiterEnd(sql, i, namedDollarQuotes);
        if (delimiterEnd < 0) {
          i++;
          continue;
        }
        String delimiter = sql.substring(i, delimiterEnd);
        int end = sql.indexOf(delimiter, delimiterEnd);
        if (end < 0) {
          if (dialect != Dialect.WRAPPER) {
            quoted.set(i, sql.length());
            break;
          }
          // This cannot be a valid PostgreSQL statement under the tagged interpretation.
          // Fall back once instead of searching the entire tail for each unmatched tag.
          namedDollarQuotes = false;
          i = delimiterEnd;
        } else {
          quoted.set(i, end + delimiter.length());
          i = end + delimiter.length();
        }
      } else if (sql.startsWith("--", i) || sql.startsWith("/*", i)
          || ((dialect == Dialect.H2_1 || dialect == Dialect.H2_CURRENT || dialect == Dialect.WRAPPER)
              && sql.startsWith("//", i))) {
        boolean line = !sql.startsWith("/*", i);
        if (ch == '-' && i + 2 < sql.length() && sql.charAt(i + 2) > ' ') {
          ambiguous = true;
          if (mysql) {
            i += 2;
            continue;
          }
        }
        comments.set(i);
        boolean executableComments = dialect == Dialect.UNSPECIFIED || dialect == Dialect.MYSQL;
        if (!line && executableComments && (sql.startsWith("/*!", i) || sql.startsWith("/*M!", i))) {
          // Versioned MySQL/MariaDB comments can execute SQL.
          i += 2;
          continue;
        }
        int start = i;
        i += 2;
        if (line) {
          while (i < sql.length() && sql.charAt(i) != '\r' && sql.charAt(i) != '\n') {
            i++;
          }
        } else {
          i = blockCommentEnd(sql, i, dialect == Dialect.POSTGRESQL
              || dialect == Dialect.H2_CURRENT || dialect == Dialect.DERBY || dialect == Dialect.WRAPPER);
        }
        if (commentsRemoved == null) {
          commentsRemoved = new StringBuilder(sql);
        }
        if (line && !truncatedLiteral) {
          int before = start - 1;
          while (before >= 0 && Character.isWhitespace(sql.charAt(before))) {
            before--;
          }
          int after = start + 2;
          while (after < i && Character.isWhitespace(sql.charAt(after))) {
            after++;
          }
          truncatedLiteral = before >= 0 && after < i && sql.charAt(before) == sql.charAt(after)
              && (sql.charAt(before) == '\'' || sql.charAt(before) == '"');
        }
        for (int k = start; k < i; k++) {
          commentsRemoved.setCharAt(k, ' ');
        }
      } else {
        i++;
      }
    }
    boolean tryMysql = dialect == Dialect.UNSPECIFIED || dialect == Dialect.MYSQL || dialect == Dialect.WRAPPER;
    SqlStatement alternate = ambiguous && !mysql && tryMysql ? new SqlStatement(sql, true, dialect) : null;
    if (dialect == Dialect.WRAPPER && alternate != null) {
      // A proxy can delegate to either dialect. Only use code that is outside
      // quotes and comments under both interpretations at this boundary.
      quoted.or(alternate.quoted);
      comments.and(alternate.comments);
      truncatedLiteral &= alternate.truncatedLiteral;
      for (int k = 0; k < sql.length(); k++) {
        if (alternate.text.charAt(k) == ' ' && sql.charAt(k) != ' ') {
          if (commentsRemoved == null) commentsRemoved = new StringBuilder(sql);
          commentsRemoved.setCharAt(k, ' ');
        }
      }
      alternate = null;
    }
    text = commentsRemoved == null ? sql : commentsRemoved;
    mysqlView = alternate;
  }

  private static int blockCommentEnd(String sql, int i, boolean nested) {
    if (!nested) {
      int end = sql.indexOf("*/", i);
      return end < 0 ? sql.length() : end + 2;
    }
    int depth = 1;
    while (i < sql.length()) {
      if (sql.startsWith("*/", i)) {
        i += 2;
        if (--depth == 0) break;
      } else if (sql.startsWith("/*", i)) {
        depth++;
        i += 2;
      } else {
        i++;
      }
    }
    return i;
  }

  private static Dialect dialectOf(String sql, String jdbcClass, String version) {
    if (jdbcClass == null) {
      if (sql.indexOf('$') < 0 && !sql.contains("/*") && !sql.contains("//")
          && !sql.contains("--") && sql.indexOf('\\') < 0) return Dialect.UNSPECIFIED;
      jdbcClass = driverAtJdbcEntry();
    }
    if (jdbcClass.startsWith("org.postgresql.jdbc.")) return Dialect.POSTGRESQL;
    if (jdbcClass.startsWith("org.h2.jdbc.")) {
      return version != null && version.startsWith("1.") ? Dialect.H2_1 : Dialect.H2_CURRENT;
    }
    if (jdbcClass.startsWith("org.apache.derby.impl.jdbc.")) return Dialect.DERBY;
    if (jdbcClass.startsWith("com.mysql.") || jdbcClass.startsWith("org.mariadb.jdbc.")) return Dialect.MYSQL;
    if (jdbcClass.isEmpty()) return Dialect.UNSPECIFIED;
    // A wrapper has no SQL grammar of its own. Defer ambiguous text inside
    // matched dollar quotes or nested comments to the concrete driver.
    return JdbcSqlMethod.driverPackage(jdbcClass.replace('.', '/')) ? Dialect.OTHER : Dialect.WRAPPER;
  }

  private static int dollarDelimiterEnd(String sql, int start, boolean namedDollarQuotes) {
    int i = start + 1;
    if (i < sql.length() && sql.charAt(i) == '$') return i + 1;
    if (!namedDollarQuotes || i == sql.length()) return -1;
    int cp = sql.codePointAt(i);
    if (cp != '_' && !Character.isLetter(cp)) return -1;
    do {
      i += Character.charCount(cp);
      if (i == sql.length()) return -1;
      cp = sql.codePointAt(i);
    } while (cp == '_' || Character.isLetterOrDigit(cp));
    return cp == '$' ? i + 1 : -1;
  }

  private static String driverAtJdbcEntry() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i + 1 < stack.length; i++) {
      if (isSqlHook(stack[i])) {
        String caller = stack[i + 1].getClassName();
        if (JdbcSqlMethod.driverPackage(caller.replace('.', '/'))) return caller;
      }
    }
    return "";
  }

  public boolean hasConstantDisjunction() {
    return matches(CONSTANT_DISJUNCTION);
  }

  public static boolean mayControlStructure(String input) {
    return input != null && (input.indexOf(';') >= 0 || STRUCTURE_KEYWORD.matcher(input).find());
  }

  public boolean matchesSinkPolicy() {
    return matches(SINK_POLICY);
  }

  public boolean matchesStructureFrom(String input) {
    if (!mayControlStructure(input)) {
      return false;
    }
    input = input.trim();
    int offset = original.indexOf(input);
    while (offset >= 0) {
      int end = offset + input.length();
      // The query builder may supply the closing quote of the right operand.
      int limit = end < original.length() && original.charAt(end) == '\'' ? end + 1 : end;
      Matcher match = REQUEST_STRUCTURE.matcher(text).region(offset, limit)
          .useTransparentBounds(true);
      while (match.find()) {
        // A bare SQL keyword phrase can coincide with a search term. Require the
        // copied fragment to supply more of the clause than its operator alone.
        boolean bareOperator = match.group(1) == null && match.start() == offset && match.end() == end;
        boolean supportedContext = match.group(1) == null || followsClosingQuote(match.start());
        if (supportedContext && !bareOperator && !quoted.get(match.start())) {
          return !isSubmittedConsoleSelect(input);
        }
      }
      offset = original.indexOf(input, offset + 1);
    }
    return mysqlView != null && mysqlView.matchesStructureFrom(input);
  }

  private boolean followsClosingQuote(int offset) {
    int i = offset - 1;
    while (i >= 0 && Character.isWhitespace(text.charAt(i))) {
      i--;
    }
    return i >= 0 && (text.charAt(i) == '\'' || text.charAt(i) == '"') && !quoted.get(i);
  }

  // H2 Console is a SQL editor. Copying the entire submitted SELECT into Statement.execute
  // is expected there. Only discount this one source signal; sink signatures still run.
  public boolean isSubmittedConsoleSelect(String input) {
    if (input == null) {
      return false;
    }
    String sql = original.trim();
    Matcher start = QUERY_START.matcher(text);
    if (!start.find() || ("with".equalsIgnoreCase(start.group(1))
        && (!matches(SELECT_TOKEN) || matches(MUTATION_TOKEN)))) {
      return false;
    }
    String submitted = input.trim();
    if (!sql.equals(submitted)
        && !(submitted.endsWith(";") && sql.equals(submitted.substring(0, submitted.length() - 1).trim()))) {
      return false;
    }
    return directH2ConsoleCaller(Thread.currentThread().getStackTrace());
  }

  private static boolean isSqlHook(StackTraceElement frame) {
    return frame.getClassName().startsWith("io.ohmyrasp.agent.")
        && frame.getClassName().endsWith("RaspHooks")
        && ("beforeSql".equals(frame.getMethodName()) || "beforeSqlStatement".equals(frame.getMethodName()));
  }

  static boolean directH2ConsoleCaller(StackTraceElement[] stack) {
    for (int i = 0; i + 1 < stack.length; i++) {
      if (!isSqlHook(stack[i])) {
        continue;
      }
      // Inspect the innermost SQL hook only. A routine called by the editor
      // can issue another statement whose real caller is application code.
      int caller = i + 1;
      if (frameAt(stack, caller, "org.h2.jdbc.JdbcConnection", "prepareCommand")) {
        if (!frameAt(stack, caller + 1, "org.h2.jdbc.JdbcStatement", "executeInternal")
            || !frameAt(stack, caller + 2, "org.h2.jdbc.JdbcStatement", "execute")) {
          return false;
        }
        caller += 3;
      } else if (frameAt(stack, caller, "org.h2.jdbc.JdbcStatement", "execute")) {
        caller++;
      }
      return frameAt(stack, caller, "org.h2.server.web.WebApp", "getResult");
    }
    return false;
  }

  private static boolean frameAt(StackTraceElement[] stack, int index, String owner, String method) {
    return index < stack.length && owner.equals(stack[index].getClassName())
        && method.equals(stack[index].getMethodName());
  }

  public boolean hasTruncatedLiteral() {
    return truncatedLiteral || (mysqlView != null && mysqlView.truncatedLiteral);
  }

  public boolean hasCommentFrom(String input) {
    if (input == null || (input.indexOf("--") < 0 && input.indexOf("/*") < 0)) {
      return false;
    }
    if (mysqlView != null && mysqlView.hasCommentFrom(input)) {
      return true;
    }
    int offset = original.indexOf(input);
    while (offset >= 0) {
      int marker = comments.nextSetBit(offset);
      if (marker < 0) {
        return false;
      }
      if (marker + 2 <= offset + input.length()) {
        return !isSubmittedConsoleSelect(input);
      }
      offset = original.indexOf(input, offset + 1);
    }
    return false;
  }


  private static final Pattern MAPPER_TOKENS = Pattern.compile(
      "(?i)(\\border\\s+by\\b)|(\\b(?:limit|offset|fetch|for|union|except|intersect)\\b)"
          + "|(;\\s*(?:select|insert|update|delete|alter|drop)\\b)"
          + "|(\\b(?:sleep|benchmark|load_file)\\s*\\()|(\\b(?:select|and|or)\\b)|[();]");

  /** Check syntax contributed by an observed raw substitution, at its actual JDBC offsets. */
  String mapperControl(BitSet supplied) {
    if (mysqlView == null) return scanMapperControl(supplied, null);
    Map<Integer, String> alternate = new HashMap<Integer, String>();
    mysqlView.scanMapperControl(supplied, (offset, reason) -> {
      alternate.put(offset, reason);
      return false;
    });
    return scanMapperControl(supplied, (offset, reason) -> reason.equals(alternate.get(offset)));
  }

  private String scanMapperControl(BitSet supplied, BiPredicate<Integer, String> confirmed) {
    for (int marker = comments.nextSetBit(0); marker >= 0; marker = comments.nextSetBit(marker + 1)) {
      if (supplied.get(marker) && supplied.get(marker + 1) && escapesMapperQuote(supplied, marker)
          && text.charAt(supplied.nextClearBit(marker)) == ' '
          && confirmedAt(confirmed, marker, "quoted-slot-comment")) {
        return "quoted-slot-comment";
      }
    }
    int fixedPrefix = firstFixedToken(supplied);
    Matcher token = MAPPER_TOKENS.matcher(text);
    BitSet sortLevels = new BitSet();
    int depth = 0;
    while (token.find()) {
      int start = token.start();
      if (quoted.get(start)) continue;
      boolean fromMapperInput = supplied.get(start) && supplied.nextClearBit(start) >= token.end();
      if (token.group(1) != null) {
        int suppliedAt = supplied.nextSetBit(start);
        if (suppliedAt < 0 || suppliedAt >= token.end()) sortLevels.set(depth);
      } else if (token.group(3) != null) {
        if (fromMapperInput && fixedPrefix < start && confirmedAt(confirmed, start, "additional-statement")) {
          return "additional-statement";
        }
        sortLevels.clear();
        depth = 0;
      } else if (token.group(4) != null) {
        if (fromMapperInput && !sortLevels.isEmpty() && confirmedAt(confirmed, start, "sort-policy-operation")) {
          return "sort-policy-operation";
        }
        depth++; // the token includes its opening parenthesis
      } else if (token.group(2) != null || token.group(5) != null) {
        if (fromMapperInput && escapesMapperQuote(supplied, start) && confirmedAt(confirmed, start, "quoted-slot-control")) {
          return "quoted-slot-control";
        }
        if (token.group(2) != null) sortLevels.clear(depth);
      } else if (text.charAt(start) == '(') {
        depth++;
      } else if (text.charAt(start) == ')') {
        sortLevels.clear(depth);
        if (depth > 0) depth--;
      } else {
        sortLevels.clear();
        depth = 0;
      }
    }
    return null;
  }

  private int firstFixedToken(BitSet supplied) {
    for (int i = supplied.nextClearBit(0); i < text.length(); i = supplied.nextClearBit(i + 1)) {
      if (!Character.isWhitespace(text.charAt(i)) && text.charAt(i) != ';') return i;
    }
    return text.length();
  }

  private boolean escapesMapperQuote(BitSet supplied, int token) {
    int opening = supplied.previousClearBit(token);
    int closing = supplied.nextClearBit(token);
    if (opening < 0 || closing >= original.length() || !quoted.get(opening)
        || (opening > 0 && quoted.get(opening - 1))) return false;
    char quote = original.charAt(opening);
    return (quote == '\'' || quote == '"' || quote == '`') && original.charAt(closing) == quote;
  }

  private static boolean confirmedAt(BiPredicate<Integer, String> confirmed, int offset, String reason) {
    return confirmed == null || confirmed.test(offset, reason);
  }

  /** A definition's source operand, in the same SQL command as its declaration. */
  public boolean definesSourceMatching(Pattern declaration, Pattern primitive) {
    Matcher ddl = declaration.matcher(text);
    while (ddl.find()) {
      if (!atCommandStart(ddl.start())) continue;
      Matcher clause = SOURCE_CLAUSE.matcher(text).region(ddl.end(), commandEnd(ddl.end()));
      while (clause.find()) {
        if (quoted.get(clause.start())) continue;
        int start = clause.end();
        while (start < text.length() && Character.isWhitespace(text.charAt(start))) start++;
        int end = sourceLiteralEnd(start);
        if (end > start && primitive.matcher(original).region(start, end).find()) return true;
      }
    }
    return false;
  }

  private int sourceLiteralEnd(int start) {
    if (original.startsWith("$$", start)) {
      int closing = original.indexOf("$$", start + 2);
      return closing < 0 ? -1 : closing;
    }
    if (start == original.length()) return -1;
    char delimiter = original.charAt(start);
    if ((delimiter != '\'' && delimiter != '"') || !quoted.get(start)) return -1;
    int end = quoted.nextClearBit(start);
    return end < original.length() && original.charAt(end) == delimiter ? end : -1;
  }

  public boolean hasCommand(Pattern operation) {
    Matcher match = operation.matcher(text);
    while (match.find()) {
      if (atCommandStart(match.start())) return true;
    }
    return false;
  }

  public boolean hasClausesInOneCommand(Pattern first, Pattern second) {
    Matcher firstMatch = first.matcher(text);
    while (firstMatch.find()) {
      if (quoted.get(firstMatch.start())) continue;
      int end = commandEnd(firstMatch.end());
      Matcher secondMatch = second.matcher(text).region(firstMatch.end(), end);
      while (secondMatch.find()) {
        if (!quoted.get(secondMatch.start())) return true;
      }
      if (end == text.length()) break;
      firstMatch.region(end + 1, text.length());
    }
    return false;
  }

  private boolean atCommandStart(int start) {
    if (quoted.get(start)) return false;
    int i = start - 1;
    while (i >= 0 && Character.isWhitespace(text.charAt(i))) i--;
    return i < 0 || (text.charAt(i) == ';' && !quoted.get(i));
  }

  private int commandEnd(int start) {
    for (int i = start; i < text.length(); i++) {
      if (text.charAt(i) == ';' && !quoted.get(i)) return i;
    }
    return text.length();
  }

  public boolean matches(Pattern signature) {
    Matcher matcher = signature.matcher(text);
    while (matcher.find()) {
      if (!quoted.get(matcher.start())) {
        return true;
      }
    }
    return mysqlView != null && mysqlView.matches(signature);
  }
}
