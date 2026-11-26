package io.ohmyrasp.agent.util;

/**
 * Reads one top-level string field of a control file, and only when the whole text is exactly one
 * well-formed JSON object (RFC 8259 grammar, surrounding whitespace allowed).
 *
 * <p>A truncated document, trailing text, a key inside a nested object or array, or a key inside a
 * string value does not count. Containers deeper than {@link #MAX_DEPTH} are rejected, which bounds
 * the recursion; control files are a few levels deep. When a key occurs more than once, the last
 * occurrence wins. Java 8 source with no lambdas: the backport agents call it from their poller.
 */
public final class ControlDocument {
  /** The deepest container nesting accepted, counting the top-level object. */
  public static final int MAX_DEPTH = 64;

  private final String text;
  private int offset;

  private ControlDocument(String text) {
    this.text = text;
  }

  /**
   * The string value of {@code key} in the top-level object of {@code text}, or null when the key
   * is absent or its value is not a string.
   *
   * @throws IllegalArgumentException when {@code text} is not exactly one well-formed JSON object
   */
  public static String topLevelString(String text, String key) {
    if (text == null) {
      throw new IllegalArgumentException("no control document");
    }
    ControlDocument document = new ControlDocument(text);
    document.skipWhitespace();
    String value = document.topLevelObject(key);
    document.skipWhitespace();
    if (document.offset != text.length()) {
      throw new IllegalArgumentException("text after the control object");
    }
    return value;
  }

  private String topLevelObject(String key) {
    expect('{');
    skipWhitespace();
    if (take('}')) {
      return null;
    }
    String found = null;
    while (true) {
      skipWhitespace();
      String name = string();
      skipWhitespace();
      expect(':');
      skipWhitespace();
      if (peek() == '"') {
        String value = string();
        if (name.equals(key)) {
          found = value;
        }
      } else {
        value(1);
        if (name.equals(key)) {
          found = null;
        }
      }
      skipWhitespace();
      if (take(',')) {
        continue;
      }
      expect('}');
      return found;
    }
  }

  /** Skips one value; {@code depth} counts the containers already open around it. */
  private void value(int depth) {
    char next = peek();
    if (next == '{' || next == '[') {
      if (depth >= MAX_DEPTH) {
        throw new IllegalArgumentException("control document nested too deeply");
      }
      container(depth + 1);
    } else if (next == '"') {
      string();
    } else if (next == 't') {
      literal("true");
    } else if (next == 'f') {
      literal("false");
    } else if (next == 'n') {
      literal("null");
    } else {
      number();
    }
  }

  private void container(int depth) {
    boolean object = text.charAt(offset++) == '{';
    char close = object ? '}' : ']';
    skipWhitespace();
    if (take(close)) {
      return;
    }
    while (true) {
      skipWhitespace();
      if (object) {
        string();
        skipWhitespace();
        expect(':');
        skipWhitespace();
      }
      value(depth);
      skipWhitespace();
      if (take(',')) {
        continue;
      }
      expect(close);
      return;
    }
  }

  private String string() {
    expect('"');
    StringBuilder builder = new StringBuilder();
    while (offset < text.length()) {
      char ch = text.charAt(offset++);
      if (ch == '"') {
        return builder.toString();
      }
      if (ch < 0x20) {
        throw new IllegalArgumentException("control character in a control document string");
      }
      if (ch != '\\') {
        builder.append(ch);
        continue;
      }
      if (offset >= text.length()) {
        break;
      }
      char escaped = text.charAt(offset++);
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          builder.append(escaped);
          break;
        case 'b':
          builder.append('\b');
          break;
        case 'f':
          builder.append('\f');
          break;
        case 'n':
          builder.append('\n');
          break;
        case 'r':
          builder.append('\r');
          break;
        case 't':
          builder.append('\t');
          break;
        case 'u':
          builder.append(unicodeEscape());
          break;
        default:
          throw new IllegalArgumentException("unknown escape in a control document string");
      }
    }
    throw new IllegalArgumentException("unterminated control document string");
  }

  private char unicodeEscape() {
    if (offset + 4 > text.length()) {
      throw new IllegalArgumentException("short unicode escape in a control document");
    }
    int value = 0;
    for (int i = 0; i < 4; i++) {
      int digit = Character.digit(text.charAt(offset++), 16);
      if (digit < 0) {
        throw new IllegalArgumentException("bad unicode escape in a control document");
      }
      value = value * 16 + digit;
    }
    return (char) value;
  }

  private void number() {
    take('-');
    if (take('0')) {
      // A leading zero stands alone.
    } else if (!digits()) {
      throw new IllegalArgumentException("unexpected character in a control document");
    }
    if (take('.') && !digits()) {
      throw new IllegalArgumentException("bad fraction in a control document number");
    }
    if (take('e') || take('E')) {
      if (!take('+')) {
        take('-');
      }
      if (!digits()) {
        throw new IllegalArgumentException("bad exponent in a control document number");
      }
    }
  }

  /** Consumes one or more ASCII digits; false when there is none. */
  private boolean digits() {
    int start = offset;
    while (offset < text.length() && text.charAt(offset) >= '0' && text.charAt(offset) <= '9') {
      offset++;
    }
    return offset > start;
  }

  private void literal(String word) {
    if (!text.startsWith(word, offset)) {
      throw new IllegalArgumentException("bad literal in a control document");
    }
    offset += word.length();
  }

  private void skipWhitespace() {
    while (offset < text.length()) {
      char ch = text.charAt(offset);
      if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') {
        return;
      }
      offset++;
    }
  }

  private char peek() {
    if (offset >= text.length()) {
      throw new IllegalArgumentException("control document ends early");
    }
    return text.charAt(offset);
  }

  private boolean take(char expected) {
    if (offset < text.length() && text.charAt(offset) == expected) {
      offset++;
      return true;
    }
    return false;
  }

  private void expect(char expected) {
    if (!take(expected)) {
      throw new IllegalArgumentException("malformed control document");
    }
  }
}
