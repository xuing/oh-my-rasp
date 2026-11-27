package io.ohmyrasp.agent.http;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Turns the recorded bytes of a request body into text: with the request's character encoding when it names
 * one the JVM knows, else UTF-8, and with ISO-8859-1 when the bytes are malformed in that encoding. The bytes
 * are always decoded from the first one, so a character whose bytes arrived in two reads decodes whole. An
 * incomplete sequence at the very end is left out while more can come (or the cap cut the body inside a
 * character); in a body known to be complete it is malformed input.
 */
public final class BodyText {
  private BodyText() {}

  public static String decode(byte[] bytes, int length, String encoding, boolean complete) {
    if (bytes == null || length <= 0) return "";
    Charset charset = charset(encoding);
    CharsetDecoder decoder = charset.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT);
    ByteBuffer in = ByteBuffer.wrap(bytes, 0, length);
    CharBuffer out = CharBuffer.allocate(Math.max(16, (int) Math.ceil(length * (double) decoder.maxCharsPerByte())));
    CoderResult result = decoder.decode(in, out, false);
    if (result.isError() || result.isOverflow()) {
      return new String(bytes, 0, length, StandardCharsets.ISO_8859_1);
    }
    if (in.hasRemaining() && complete) {
      return new String(bytes, 0, length, StandardCharsets.ISO_8859_1);
    }
    // UNDERFLOW with bytes left: the last character is not complete yet. Leave it out.
    out.flip();
    return out.toString();
  }

  /** The charset named by {@code encoding}, or UTF-8 when it names none or one this JVM does not have. */
  static Charset charset(String encoding) {
    if (encoding == null) return StandardCharsets.UTF_8;
    String name = encoding.trim();
    if (name.isEmpty()) return StandardCharsets.UTF_8;
    try {
      return Charset.forName(name);
    } catch (RuntimeException unknown) {
      return StandardCharsets.UTF_8;
    }
  }

  /**
   * How many bytes {@code count} chars of text took in {@code encoding}, as far as can be told cheaply: exact for
   * UTF-8 and the single-byte charsets below, and -1 for any other, which has no estimate.
   */
  static int bytesPerCharKind(String encoding) {
    if (encoding == null) return 1; // the servlet default, ISO-8859-1
    String name = encoding.trim().toLowerCase(java.util.Locale.ROOT);
    if (name.equals("utf-8") || name.equals("utf8")) return 0;
    if (name.equals("iso-8859-1") || name.equals("iso8859_1") || name.equals("latin1") || name.equals("us-ascii")
        || name.equals("ascii") || name.equals("windows-1252") || name.equals("cp1252")) return 1;
    return -1;
  }
}
