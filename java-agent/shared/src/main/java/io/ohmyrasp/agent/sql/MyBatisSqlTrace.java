package io.ohmyrasp.agent.sql;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.BitSet;
import java.util.HashSet;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.ConcurrentHashMap;

/** Tracks character offsets across observed MyBatis string operations with weak identity keys. */
public final class MyBatisSqlTrace {
  private static final ReferenceQueue<Object> COLLECTED = new ReferenceQueue<Object>();
  private static final ConcurrentHashMap<Key, Marks> MARKS = new ConcurrentHashMap<Key, Marks>();

  private static final ThreadLocal<Use> ACTIVE = new ThreadLocal<Use>();

  private static final class Use {
    final Use parent;
    final Object owner;
    final WeakReference<String> original;
    String returned;
    String reported;
    Set<String> reportedAlgorithms;

    Use(Use parent, Object owner, WeakReference<String> original) {
      this.parent = parent;
      this.owner = owner;
      this.original = original;
    }
  }

  private MyBatisSqlTrace() {}

  private static final class Key extends WeakReference<Object> {
    final int hash;
    Key(Object value, ReferenceQueue<Object> queue) {
      super(value, queue);
      hash = System.identityHashCode(value);
    }
    @Override public int hashCode() { return hash; }
    @Override public boolean equals(Object other) {
      if (this == other) return true;
      Object value = get();
      return value != null && other instanceof Key && ((Key) other).get() == value;
    }
  }

  private static final class Marks {
    // Builders are confined by MyBatis. Each immutable string receives its own copy.
    final BitSet offsets = new BitSet();
    boolean candidate;
    volatile boolean compiled;
    WeakReference<String> original;
  }

  private static Marks get(Object owner) {
    if (owner == null || MARKS.isEmpty()) return null;
    Key dead;
    while ((dead = (Key) COLLECTED.poll()) != null) MARKS.remove(dead);
    return MARKS.get(new Key(owner, null));
  }

  private static Marks writable(Object owner) {
    Marks marks = get(owner);
    if (marks != null) return marks;
    Marks fresh = new Marks();
    Marks previous = MARKS.putIfAbsent(new Key(owner, COLLECTED), fresh);
    return previous == null ? fresh : previous;
  }

  public static void substitution(StringBuilder builder, String value, Object handler, String expression) {
    if (value == null || value.isEmpty()
        || handler == null || !handler.getClass().getName().equals(
            "org.apache.ibatis.scripting.xmltags.TextSqlNode$BindingTokenParser")
        || !propertyPath(expression)) return;
    Marks marks = writable(builder);
    marks.offsets.set(builder.length() - value.length(), builder.length());
    marks.candidate |= value.indexOf(';') >= 0 || value.indexOf('(') >= 0 || value.indexOf('\'') >= 0
        || value.indexOf('"') >= 0 || value.indexOf('`') >= 0;
  }

  // Only direct property substitutions establish this source. Evaluating an expression
  // ourselves could run application code a second time or mistake mapper constants for inputs.
  private static boolean propertyPath(String expression) {
    if (expression == null) return false;
    String path = expression.trim();
    int i = 0;
    while (i < path.length()) {
      if (!Character.isJavaIdentifierStart(path.charAt(i++))) return false;
      while (i < path.length() && Character.isJavaIdentifierPart(path.charAt(i))) i++;
      while (i < path.length() && path.charAt(i) == '[') {
        int end = path.indexOf(']', i + 1);
        if (end < 0 || !constantIndex(path.substring(i + 1, end).trim())) return false;
        i = end + 1;
      }
      if (i == path.length()) return true;
      if (path.charAt(i++) != '.') return false;
    }
    return false;
  }

  private static boolean constantIndex(String key) {
    if (key.isEmpty()) return false;
    char first = key.charAt(0);
    if (first == '\'' || first == '"') {
      return key.length() >= 2 && key.indexOf(first, 1) == key.length() - 1;
    }
    for (int i = 0; i < key.length(); i++) if (!Character.isDigit(key.charAt(i))) return false;
    return true;
  }

  private static void copy(Object source, int start, int length, Object dest, int destStart) {
    if (source == dest || length <= 0) return;
    Marks from = get(source);
    if (from == null) return;
    int limit = start + length;
    int at = from.offsets.nextSetBit(start);
    if (at < 0 || at >= limit) return;
    Marks to = writable(dest);
    to.candidate |= from.candidate;
    while (at >= 0 && at < limit) {
      int end = Math.min(from.offsets.nextClearBit(at), limit);
      to.offsets.set(destStart + (at - start), destStart + (end - start));
      at = from.offsets.nextSetBit(end);
    }
  }

  public static void characters(String source, char[] chars) {
    copy(source, 0, chars.length, chars, 0);
  }

  /** GenericTokenParser copies precisely this slice around a token it expands or binds. */
  public static StringBuilder appendSlice(StringBuilder dest, char[] chars, int start, int length) {
    dest.append(chars, start, length);
    copy(chars, start, length, dest, dest.length() - length);
    return dest;
  }

  public static StringBuilder appendPiece(StringBuilder dest, String piece) {
    dest.append(piece);
    if (piece != null) copy(piece, 0, piece.length(), dest, dest.length() - piece.length());
    return dest;
  }

  public static StringJoiner joinPiece(StringJoiner dest, CharSequence piece) {
    dest.add(piece);
    if (piece instanceof String) copy(piece, 0, piece.length(), dest, dest.length() - piece.length());
    return dest;
  }

  public static void built(Object builder, String result) {
    copy(builder, 0, result.length(), result, 0);
  }

  public static void trimmed(String source, String result) {
    if (source == result || get(source) == null) return;
    int start = 0;
    while (start < source.length() && source.charAt(start) <= ' ') start++;
    copy(source, start, result.length(), result, 0);
  }

  public static void initialized(StringBuilder builder, String text) {
    copy(text, 0, text.length(), builder, 0);
  }

  public static StringBuilder delete(StringBuilder builder, int start, int end) {
    int oldLength = builder.length();
    builder.delete(start, end);
    relocateTail(builder, Math.min(end, oldLength), start, oldLength);
    return builder;
  }

  public static StringBuilder insert(StringBuilder builder, int start, String text) {
    int oldLength = builder.length();
    builder.insert(start, text);
    int added = builder.length() - oldLength;
    relocateTail(builder, start, start + added, oldLength);
    if (text != null) copy(text, 0, text.length(), builder, start);
    return builder;
  }

  private static void relocateTail(StringBuilder builder, int oldStart, int newStart, int oldLength) {
    Marks marks = get(builder);
    if (marks == null || oldStart == newStart) return;
    BitSet tail = marks.offsets.get(oldStart, oldLength);
    marks.offsets.clear(Math.min(oldStart, newStart), oldLength);
    for (int at = tail.nextSetBit(0); at >= 0;) {
      int end = tail.nextClearBit(at);
      marks.offsets.set(newStart + at, newStart + end);
      at = tail.nextSetBit(end);
    }
  }

  public static void compiled(Object boundSql, String sql) {
    Marks marks = get(sql);
    if (marks == null || !marks.candidate) return;
    marks.compiled = true;
    if (boundSql != null) writable(boundSql).original = new WeakReference<String>(sql);
  }

  public static void enterStatement(Object boundSql) {
    Use parent = ACTIVE.get();
    Marks owner = get(boundSql);
    if (parent != null || (owner != null && owner.original != null)) {
      ACTIVE.set(new Use(parent, boundSql, owner == null ? null : owner.original));
    }
  }

  public static void exitStatement() {
    Use current = ACTIVE.get();
    if (current == null) return;
    if (current.parent == null) ACTIVE.remove();
    else ACTIVE.set(current.parent);
  }

  public static void returnedSql(Object boundSql, String result) {
    Use current = ACTIVE.get();
    if (current != null && current.owner == boundSql) current.returned = result;
  }

  private static Marks jdbcMarks(String sql) {
    if (MARKS.isEmpty()) return null;
    Marks marks = get(sql);
    if (marks == null || !marks.compiled) {
      Use current = ACTIVE.get();
      if (current == null || current.original == null || current.returned != sql) return null;
      String original = current.original.get();
      if (original == null || !original.equals(sql)) return null;
      marks = get(original);
    }
    return marks != null && marks.compiled ? marks : null;
  }

  public static String controlAtJdbc(SqlStatement statement) {
    Marks marks = jdbcMarks(statement.source());
    return marks == null ? null : statement.mapperControl(marks.offsets);
  }

  public static String controlAtJdbc(String sql, Object receiver) {
    Marks marks = jdbcMarks(sql);
    return marks == null ? null : SqlStatement.fromJdbc(sql, receiver).mapperControl(marks.offsets);
  }

  public static boolean repeatedObservation(String sql, String algorithm) {
    Use use = ACTIVE.get();
    if (use == null || use.original == null || use.returned != sql) return false;
    if (use.reported != sql) {
      use.reported = sql;
      use.reportedAlgorithms = new HashSet<String>();
    }
    return !use.reportedAlgorithms.add(algorithm);
  }

  /** Preserve offsets only when the whole observed output matches the tokenized input. */
  public static void compacted(String input, String result) {
    Marks source = get(input);
    if (source == null || input == result || result.isEmpty()) return;
    BitSet offsets = new BitSet();
    int dst = 0;
    int i = 0;
    while (i < input.length()) {
      int gap = i;
      while (i < input.length() && tokenSeparator(input.charAt(i))) i++;
      if (i == input.length()) break;
      if (dst > 0) {
        if (dst >= result.length() || result.charAt(dst) != ' ') return;
        if (i > gap && source.offsets.nextClearBit(gap) >= i) offsets.set(dst);
        dst++;
      }
      int start = i;
      while (i < input.length() && !tokenSeparator(input.charAt(i))) i++;
      if (!input.regionMatches(start, result, dst, i - start)) return;
      for (int at = source.offsets.nextSetBit(start); at >= 0 && at < i;) {
        int end = Math.min(source.offsets.nextClearBit(at), i);
        offsets.set(dst + at - start, dst + end - start);
        at = source.offsets.nextSetBit(end);
      }
      dst += i - start;
    }
    if (dst == result.length() && !offsets.isEmpty()) {
      Marks target = writable(result);
      target.offsets.or(offsets);
      target.candidate |= source.candidate;
    }
  }

  private static boolean tokenSeparator(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
  }
}
