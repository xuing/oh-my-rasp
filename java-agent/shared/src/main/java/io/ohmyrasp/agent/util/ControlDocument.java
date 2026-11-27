package io.ohmyrasp.agent.util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/**
 * Checks that a control file is exactly one well-formed JSON object (RFC 8259 grammar: JSON
 * whitespace only around tokens, no control characters in strings, backslash-u escapes of four
 * ASCII hex digits, no leading zeros or bare fractions in numbers), and reads one top-level string
 * field of it.
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
    Object value = topLevelValues(text, new String[] {key})[0];
    return value instanceof String ? (String) value : null;
  }

  /** What {@link #topLevelValues} returns for a member whose value is not a string and not null. */
  public static final Object NOT_A_STRING = new Object();

  /**
   * The values of {@code keys} in the top-level object of {@code text}, in the same order: the string for a string
   * value, null for a key that is absent or whose value is JSON null, and {@link #NOT_A_STRING} for any other value.
   *
   * @throws IllegalArgumentException when {@code text} is not exactly one well-formed JSON object
   */
  public static Object[] topLevelValues(String text, String[] keys) {
    if (text == null) {
      throw new IllegalArgumentException("no control document");
    }
    ControlDocument document = new ControlDocument(text);
    document.skipWhitespace();
    Object[] values = document.topLevelObject(keys);
    document.skipWhitespace();
    if (document.offset != text.length()) {
      throw new IllegalArgumentException("text after the control object");
    }
    return values;
  }

  /**
   * Checks that {@code text} is exactly one well-formed JSON object.
   *
   * @throws IllegalArgumentException when it is not
   */
  public static void requireObject(String text) {
    topLevelString(text, "");
  }

  /**
   * The text of the control file at {@code path}, read as strict UTF-8. At most {@code maxBytes}
   * + 1 bytes are read: a longer file is not read to its end.
   *
   * <p>The file is opened with {@link FileChannel#open}, which the agents do not wrap as a file
   * read facade, so the only hooks it reaches are the native channel-open ones.
   *
   * @throws IllegalArgumentException when the file holds more than {@code maxBytes} bytes or is
   *     not UTF-8
   * @throws IOException when it cannot be opened or read
   */
  public static String read(Path path, int maxBytes) throws IOException {
    FileChannel channel = FileChannel.open(path, StandardOpenOption.READ);
    try {
      byte[] data = new byte[Math.min(8192, maxBytes + 1)];
      int length = 0;
      while (true) {
        if (length == data.length) {
          if (length > maxBytes) {
            throw new IllegalArgumentException("control document larger than its bound");
          }
          data = Arrays.copyOf(data, (int) Math.min(2L * data.length, maxBytes + 1L));
        }
        int read = channel.read(ByteBuffer.wrap(data, length, data.length - length));
        if (read < 0) {
          return decodeUtf8(data, length);
        }
        length += read;
      }
    } finally {
      channel.close();
    }
  }

  /**
   * The text of {@code length} bytes of strict UTF-8. Malformed or unmappable bytes are not
   * replaced: the content is unparseable.
   *
   * @throws IllegalArgumentException when the bytes are not UTF-8
   */
  public static String decodeUtf8(byte[] bytes, int length) {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes, 0, length))
          .toString();
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("control document is not UTF-8");
    }
  }

  private Object[] topLevelObject(String[] keys) {
    Object[] found = new Object[keys.length];
    expect('{');
    skipWhitespace();
    if (take('}')) {
      return found;
    }
    while (true) {
      skipWhitespace();
      String name = string();
      skipWhitespace();
      expect(':');
      skipWhitespace();
      Object value;
      if (peek() == '"') {
        value = string();
      } else {
        value = text.startsWith("null", offset) ? null : NOT_A_STRING;
        value(1);
      }
      for (int i = 0; i < keys.length; i++) {
        if (name.equals(keys[i])) {
          found[i] = value;
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
      value = value * 16 + hexDigit(text.charAt(offset++));
    }
    return (char) value;
  }

  /** The value of one ASCII hex digit; JSON allows no other digits in a backslash-u escape. */
  private static int hexDigit(char ch) {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
      return ch - 'A' + 10;
    }
    throw new IllegalArgumentException("bad unicode escape in a control document");
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
