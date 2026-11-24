package io.ohmyrasp.agent.sql;

import java.util.BitSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Lexical context for signatures applied to a complete JDBC statement. */
public final class SqlStatement {
  private static final String BOOLEAN_OPERANDS = "(?:\\d+\\s*=\\s*\\d+|'[^']{0,32}'\\s*=\\s*'[^']{0,32}')";
  private static final Pattern REQUEST_STRUCTURE = Pattern.compile(
      "(?i)\\b(?:union\\s+(?:all\\s+)?select\\b|information_schema\\s*\\.|(and|or)\\s+" + BOOLEAN_OPERANDS + ")");
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
    this(sql, false, sql.contains("$$") && (jdbcClass == null
        ? dollarQuotedAtJdbcEntry() : supportsDollarQuotes(jdbcClass)));
  }

  private SqlStatement(String sql, boolean mysql, boolean dollarQuotes) {
    original = sql;
    boolean ambiguous = false;
    StringBuilder commentsRemoved = null;
    int i = 0;
    while (i < sql.length()) {
      char ch = sql.charAt(i);
      if (ch == '\'' || ch == '"' || ch == '`') {
        int start = i++;
        // Leave the closing delimiter visible to signatures anchored at the end of a literal.
        int end = sql.length();
        while (i < sql.length()) {
          char current = sql.charAt(i++);
          if (current == '\\' && i < sql.length()) {
            ambiguous = true;
            if (mysql) {
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
      } else if (dollarQuotes && sql.startsWith("$$", i)
          && (i == 0 || !Character.isJavaIdentifierPart(sql.charAt(i - 1)))) {
        int end = sql.indexOf("$$", i + 2);
        if (end < 0) {
          i += 2;
        } else {
          quoted.set(i, end + 2);
          i = end + 2;
        }
      } else if (sql.startsWith("--", i) || sql.startsWith("/*", i)) {
        boolean line = ch == '-';
        if (line && i + 2 < sql.length() && sql.charAt(i + 2) > ' ') {
          ambiguous = true;
          if (mysql) {
            i += 2;
            continue;
          }
        }
        comments.set(i);
        if (!line && (sql.startsWith("/*!", i) || sql.startsWith("/*M!", i))) {
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
          int close = sql.indexOf("*/", i);
          i = close < 0 ? sql.length() : close + 2;
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
    text = commentsRemoved == null ? sql : commentsRemoved;
    // The JDBC hook does not always know the server dialect. Preserve evidence
    // under either interpretation of backslash quoting and adjacent minus signs.
    mysqlView = ambiguous && !mysql ? new SqlStatement(sql, true, dollarQuotes) : null;
  }

  private static boolean supportsDollarQuotes(String jdbcClass) {
    return jdbcClass.startsWith("org.h2.jdbc.") || jdbcClass.startsWith("org.postgresql.jdbc.");
  }

  private static boolean dollarQuotedAtJdbcEntry() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i + 1 < stack.length; i++) {
      if (isSqlHook(stack[i])) {
        return supportsDollarQuotes(stack[i + 1].getClassName());
      }
    }
    return false;
  }

  public boolean hasConstantDisjunction() {
    return matches(CONSTANT_DISJUNCTION);
  }

  public static boolean mayControlStructure(String input) {
    return input != null && STRUCTURE_KEYWORD.matcher(input).find();
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
