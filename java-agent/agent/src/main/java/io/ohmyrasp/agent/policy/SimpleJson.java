package io.ohmyrasp.agent.policy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class SimpleJson {
  private SimpleJson() {}

  static Object parse(String json) {
    Parser parser = new Parser(json);
    Object value = parser.readValue();
    parser.skipWhitespace();
    if (!parser.done()) {
      throw new IllegalArgumentException("unexpected JSON trailing content");
    }
    return value;
  }

  private static final class Parser {
    private final String input;
    private int offset;

    Parser(String input) {
      this.input = input == null ? "" : input;
    }

    boolean done() {
      return offset >= input.length();
    }

    Object readValue() {
      skipWhitespace();
      if (done()) {
        throw new IllegalArgumentException("unexpected end of JSON");
      }
      return switch (input.charAt(offset)) {
        case '{' -> readObject();
        case '[' -> readArray();
        case '"' -> readString();
        case 't' -> readLiteral("true", Boolean.TRUE);
        case 'f' -> readLiteral("false", Boolean.FALSE);
        case 'n' -> readLiteral("null", null);
        default -> readNumber();
      };
    }

    void skipWhitespace() {
      while (!done() && Character.isWhitespace(input.charAt(offset))) {
        offset++;
      }
    }

    private Map<String, Object> readObject() {
      expect('{');
      Map<String, Object> object = new LinkedHashMap<>();
      skipWhitespace();
      if (peek('}')) {
        offset++;
        return object;
      }
      while (true) {
        skipWhitespace();
        String key = readString();
        skipWhitespace();
        expect(':');
        object.put(key, readValue());
        skipWhitespace();
        if (peek('}')) {
          offset++;
          return object;
        }
        expect(',');
      }
    }

    private List<Object> readArray() {
      expect('[');
      List<Object> items = new ArrayList<>();
      skipWhitespace();
      if (peek(']')) {
        offset++;
        return items;
      }
      while (true) {
        items.add(readValue());
        skipWhitespace();
        if (peek(']')) {
          offset++;
          return items;
        }
        expect(',');
      }
    }

    private String readString() {
      expect('"');
      StringBuilder builder = new StringBuilder();
      while (!done()) {
        char ch = input.charAt(offset++);
        if (ch == '"') {
          return builder.toString();
        }
        if (ch != '\\') {
          builder.append(ch);
          continue;
        }
        if (done()) {
          throw new IllegalArgumentException("unterminated JSON escape");
        }
        char escaped = input.charAt(offset++);
        switch (escaped) {
          case '"' -> builder.append('"');
          case '\\' -> builder.append('\\');
          case '/' -> builder.append('/');
          case 'b' -> builder.append('\b');
          case 'f' -> builder.append('\f');
          case 'n' -> builder.append('\n');
          case 'r' -> builder.append('\r');
          case 't' -> builder.append('\t');
          case 'u' -> builder.append(readUnicode());
          default -> throw new IllegalArgumentException("unsupported JSON escape: " + escaped);
        }
      }
      throw new IllegalArgumentException("unterminated JSON string");
    }

    private char readUnicode() {
      if (offset + 4 > input.length()) {
        throw new IllegalArgumentException("short JSON unicode escape");
      }
      String hex = input.substring(offset, offset + 4);
      offset += 4;
      return (char) Integer.parseInt(hex, 16);
    }

    private Object readNumber() {
      int start = offset;
      if (peek('-')) {
        offset++;
      }
      while (!done() && Character.isDigit(input.charAt(offset))) {
        offset++;
      }
      boolean decimal = false;
      if (!done() && input.charAt(offset) == '.') {
        decimal = true;
        offset++;
        while (!done() && Character.isDigit(input.charAt(offset))) {
          offset++;
        }
      }
      if (!done() && (input.charAt(offset) == 'e' || input.charAt(offset) == 'E')) {
        decimal = true;
        offset++;
        if (!done() && (input.charAt(offset) == '+' || input.charAt(offset) == '-')) {
          offset++;
        }
        while (!done() && Character.isDigit(input.charAt(offset))) {
          offset++;
        }
      }
      if (offset == start || (offset == start + 1 && input.charAt(start) == '-')) {
        throw new IllegalArgumentException("invalid JSON number");
      }
      String number = input.substring(start, offset);
      return decimal ? Double.parseDouble(number) : Long.parseLong(number);
    }

    private Object readLiteral(String literal, Object value) {
      if (!input.startsWith(literal, offset)) {
        throw new IllegalArgumentException("invalid JSON literal");
      }
      offset += literal.length();
      return value;
    }

    private void expect(char expected) {
      if (done() || input.charAt(offset) != expected) {
        throw new IllegalArgumentException("expected JSON character " + expected);
      }
      offset++;
    }

    private boolean peek(char expected) {
      return !done() && input.charAt(offset) == expected;
    }
  }
}
