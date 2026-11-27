package io.ohmyrasp.agent.http;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The values a recorded request body offers for matching against a sink argument, by content type:
 * a JSON document gives every key (as a name) and every string leaf, unescaped; a form body
 * ({@code application/x-www-form-urlencoded}) gives its decoded names and values; any other text gives
 * itself, trimmed, as one value. {@link #parameters()} pairs each value with the name it was found under
 * (a JSON leaf with the nearest member key, "" at the top level), so a body can stand where request
 * parameters are consulted. Bounded: at most {@link #MAX_ITEMS} names and values together, each cut to
 * {@link #MAX_VALUE_CHARS} characters, and JSON containers nested at most {@link #MAX_DEPTH} deep (the
 * scan stops at a deeper one and keeps what it found before).
 */
public final class BodyValues {
  public static final int MAX_ITEMS = 512;
  public static final int MAX_VALUE_CHARS = 4096;
  public static final int MAX_DEPTH = 64;

  public static final BodyValues EMPTY = new BodyValues(Collections.<String>emptyList(), Collections.<String>emptyList(),
      Collections.<String, List<String>>emptyMap(), false);

  private final List<String> names;
  private final List<String> values;
  private final Map<String, List<String>> parameters;
  private final boolean cut;

  private BodyValues(List<String> names, List<String> values, Map<String, List<String>> parameters, boolean cut) {
    this.names = names;
    this.values = values;
    this.parameters = parameters;
    this.cut = cut;
  }

  /** Keys of a JSON body, names of a form body. */
  public List<String> names() { return names; }

  /** String leaves of a JSON body, values of a form body, or the text of any other text body. */
  public List<String> values() { return values; }

  /** Each name with the values found under it, in the order found; a name with no string value has an empty list. */
  public Map<String, List<String>> parameters() { return parameters; }

  /** Whether a bound stopped the extraction or cut a value. */
  public boolean cut() { return cut; }

  public boolean isEmpty() { return names.isEmpty() && values.isEmpty(); }

  /** The text itself, trimmed, as one value. */
  public static BodyValues text(String text) {
    String value = text == null ? "" : text.trim();
    if (value.isEmpty()) return EMPTY;
    Builder out = new Builder();
    out.value("", value);
    return out.build();
  }

  /** Decoded names and values of a form body; a field that does not decode is left out. */
  public static BodyValues form(String text) {
    if (text == null || text.isEmpty()) return EMPTY;
    Builder out = new Builder();
    for (Map.Entry<String, List<String>> field : ServletQueryParameters.parse(text.trim()).entrySet()) {
      if (!out.name(field.getKey())) break;
      for (String value : field.getValue()) {
        if (!out.value(field.getKey(), value)) break;
      }
      if (out.full()) break;
    }
    return out.build();
  }

  /**
   * Keys and string leaves of a JSON document. Lenient: it reads what it can of malformed or truncated JSON and
   * stops at the first string it cannot read. Iterative, with a fixed nesting limit.
   */
  public static BodyValues json(String text) {
    if (text == null || text.isEmpty()) return EMPTY;
    Builder out = new Builder();
    boolean[] object = new boolean[MAX_DEPTH];      // container kind per level: true for an object
    boolean[] expectKey = new boolean[MAX_DEPTH];   // an object level waiting for a key
    String[] member = new String[MAX_DEPTH];        // the last key read at an object level
    int depth = 0;
    int length = text.length();
    StringBuilder scratch = new StringBuilder();
    int i = 0;
    scan:
    while (i < length && !out.full()) {
      char ch = text.charAt(i);
      switch (ch) {
        case '{':
        case '[':
          if (depth == MAX_DEPTH) {
            out.cut = true;
            break scan;
          }
          object[depth] = ch == '{';
          expectKey[depth] = ch == '{';
          member[depth] = null;
          depth++;
          i++;
          break;
        case '}':
        case ']':
          if (depth > 0) depth--;
          i++;
          break;
        case ',':
          if (depth > 0 && object[depth - 1]) expectKey[depth - 1] = true;
          i++;
          break;
        case ':':
          if (depth > 0 && object[depth - 1]) expectKey[depth - 1] = false;
          i++;
          break;
        case '"': {
          int end = readString(text, i, scratch);
          if (end < 0) break scan;
          String value = scratch.toString();
          if (scratch.length() > MAX_VALUE_CHARS) {
            value = value.substring(0, MAX_VALUE_CHARS);
            out.cut = true;
          }
          if (depth > 0 && object[depth - 1] && expectKey[depth - 1]) {
            member[depth - 1] = value;
            expectKey[depth - 1] = false;
            out.name(value);
          } else {
            out.value(nearestMember(object, member, depth), value);
          }
          i = end;
          break;
        }
        default:
          i++;
      }
    }
    if (out.full() && i < length) out.cut = true;
    return out.build();
  }

  private static final int MALFORMED = -1;

  /**
   * Reads the JSON string whose opening quote is at {@code quote} into {@code out} (cleared first), unescaped,
   * and returns the index after its closing quote; {@link #MALFORMED} for a bad escape or an unterminated string.
   * Characters past {@link #MAX_VALUE_CHARS} + 1 are read but not kept.
   */
  private static int readString(String text, int quote, StringBuilder out) {
    out.setLength(0);
    int length = text.length();
    for (int i = quote + 1; i < length; i++) {
      char ch = text.charAt(i);
      if (ch == '"') return i + 1;
      if (ch != '\\') {
        if (out.length() <= MAX_VALUE_CHARS) out.append(ch);
        continue;
      }
      if (++i >= length) return MALFORMED;
      char escaped = text.charAt(i);
      char decoded;
      switch (escaped) {
        case 'b': decoded = '\b'; break;
        case 'f': decoded = '\f'; break;
        case 'n': decoded = '\n'; break;
        case 'r': decoded = '\r'; break;
        case 't': decoded = '\t'; break;
        case 'u': {
          if (i + 4 >= length) return MALFORMED;
          int point = 0;
          for (int j = 1; j <= 4; j++) {
            int digit = Character.digit(text.charAt(i + j), 16);
            if (digit < 0) return MALFORMED;
            point = (point << 4) | digit;
          }
          i += 4;
          decoded = (char) point; // a surrogate pair arrives as two escapes, appended in turn
          break;
        }
        default: decoded = escaped; // \" \\ \/ and, leniently, any other character
      }
      if (out.length() <= MAX_VALUE_CHARS) out.append(decoded);
    }
    return MALFORMED;
  }

  private static String nearestMember(boolean[] object, String[] member, int depth) {
    for (int level = depth - 1; level >= 0; level--) {
      if (object[level]) return member[level] == null ? "" : member[level];
    }
    return "";
  }

  /** Collects names and values up to the bounds. */
  private static final class Builder {
    final List<String> names = new ArrayList<String>();
    final List<String> values = new ArrayList<String>();
    final Map<String, List<String>> parameters = new LinkedHashMap<String, List<String>>();
    boolean cut;

    boolean full() {
      return names.size() + values.size() >= MAX_ITEMS;
    }

    boolean name(String name) {
      if (full()) {
        cut = true;
        return false;
      }
      names.add(name);
      if (!parameters.containsKey(name)) parameters.put(name, new ArrayList<String>(1));
      return true;
    }

    boolean value(String name, String value) {
      if (full()) {
        cut = true;
        return false;
      }
      if (value.length() > MAX_VALUE_CHARS) {
        value = value.substring(0, MAX_VALUE_CHARS);
        cut = true;
      }
      values.add(value);
      List<String> under = parameters.get(name);
      if (under == null) {
        under = new ArrayList<String>(1);
        parameters.put(name, under);
      }
      under.add(value);
      return true;
    }

    BodyValues build() {
      if (names.isEmpty() && values.isEmpty()) return cut ? new BodyValues(Collections.<String>emptyList(),
          Collections.<String>emptyList(), Collections.<String, List<String>>emptyMap(), true) : EMPTY;
      Map<String, List<String>> frozen = new LinkedHashMap<String, List<String>>();
      for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
        frozen.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
      }
      return new BodyValues(Collections.unmodifiableList(names), Collections.unmodifiableList(values),
          Collections.unmodifiableMap(frozen), cut);
    }
  }
}
