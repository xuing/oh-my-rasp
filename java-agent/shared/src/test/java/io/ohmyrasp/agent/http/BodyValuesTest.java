package io.ohmyrasp.agent.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class BodyValuesTest {
  @Test
  void jsonGivesEveryKeyAndStringLeafUnderItsMember() {
    BodyValues values = BodyValues.json(
        "{\"user\":{\"name\":\"a\",\"tags\":[\"x\",\"y\"]},\"n\":1,\"ok\":true,\"list\":[[\"deep\"]],\"empty\":null}");
    assertEquals(Arrays.asList("user", "name", "tags", "n", "ok", "list", "empty"), values.names());
    assertEquals(Arrays.asList("a", "x", "y", "deep"), values.values());
    assertEquals(Arrays.asList("x", "y"), values.parameters().get("tags"));
    assertEquals(Collections.singletonList("deep"), values.parameters().get("list"));
    assertEquals(Collections.emptyList(), values.parameters().get("user"));
    assertFalse(values.cut());
  }

  @Test
  void jsonTopLevelStringsHaveNoName() {
    BodyValues values = BodyValues.json("[\"a\", \"b\"]");
    assertEquals(Arrays.asList("a", "b"), values.parameters().get(""));
  }

  @Test
  void jsonEscapesAreDecoded() {
    BodyValues values = BodyValues.json("{\"k\\u0065y\":\"a\\\"b\\\\c\\/d\\n\\t\\u00e9\"}");
    assertEquals(Collections.singletonList("key"), values.names());
    assertEquals(Collections.singletonList("a\"b\\c/d\n\t\u00e9"), values.values());
  }

  @Test
  void jsonSurrogatePairEscapesMakeOneCharacter() {
    String value = BodyValues.json("{\"e\":\"\\ud83d\\ude00!\"}").values().get(0);
    assertEquals("\ud83d\ude00!", value);
    assertEquals(0x1F600, value.codePointAt(0));
    assertEquals("\ud83d\ude00", BodyValues.json("{\"e\":\"\ud83d\ude00\"}").values().get(0));
  }

  @Test
  void malformedJsonKeepsWhatCameBeforeTheFault() {
    assertEquals(Collections.singletonList("a"), BodyValues.json("{\"k\":\"a\",\"j\":\"unterminated").values());
    assertEquals(Collections.singletonList("a"), BodyValues.json("{\"k\":\"a\",\"j\":\"bad \\u12G4 escape\"}").values());
    assertEquals(Collections.singletonList("a"), BodyValues.json("{\"k\":\"a\",\"j\":\"ends in \\").values());
    // Truncated by the cap in the middle of the document: the strings before the cut still count.
    assertEquals(Arrays.asList("x", "y"), BodyValues.json("{\"k\":[\"x\",\"y\",{\"z\":").values());
    assertEquals(Arrays.asList("k", "z"), BodyValues.json("{\"k\":[\"x\",\"y\",{\"z\":").names());
  }

  @Test
  void nestingDeeperThanTheLimitStopsTheScanWithoutRecursion() {
    StringBuilder deep = new StringBuilder("{\"before\":\"kept\",\"d\":");
    for (int i = 0; i < 10000; i++) deep.append('[');
    deep.append("\"lost\"");
    BodyValues values = BodyValues.json(deep.toString());
    assertEquals(Collections.singletonList("kept"), values.values());
    assertTrue(values.cut());
    StringBuilder atLimit = new StringBuilder();
    for (int i = 0; i < BodyValues.MAX_DEPTH; i++) atLimit.append('[');
    atLimit.append("\"inside\"");
    assertEquals(Collections.singletonList("inside"), BodyValues.json(atLimit.toString()).values());
  }

  @Test
  void hugeStringsAreCutAndTheScanGoesOn() {
    char[] filler = new char[BodyValues.MAX_VALUE_CHARS * 3];
    Arrays.fill(filler, 'a');
    BodyValues values = BodyValues.json("{\"big\":\"" + new String(filler) + "\",\"next\":\"after\"}");
    assertEquals(BodyValues.MAX_VALUE_CHARS, values.values().get(0).length());
    assertEquals("after", values.values().get(1));
    assertTrue(values.cut());
  }

  @Test
  void theNumberOfItemsIsBounded() {
    StringBuilder many = new StringBuilder("[");
    for (int i = 0; i < 2000; i++) many.append(i == 0 ? "" : ",").append("\"v").append(i).append('"');
    BodyValues values = BodyValues.json(many.append(']').toString());
    assertEquals(BodyValues.MAX_ITEMS, values.values().size());
    assertTrue(values.cut());
  }

  @Test
  void formBodiesGiveDecodedPairs() {
    BodyValues values = BodyValues.form("host=127.0.0.1%3B+id&lang=caf%C3%A9&flag&host=second");
    assertEquals(Arrays.asList("host", "lang", "flag"), values.names());
    assertEquals(Arrays.asList("127.0.0.1; id", "second"), values.parameters().get("host"));
    assertEquals(Collections.singletonList("caf\u00e9"), values.parameters().get("lang"));
    assertEquals(Collections.singletonList(""), values.parameters().get("flag"));
  }

  @Test
  void otherTextIsOneTrimmedValue() {
    assertEquals(Collections.singletonList("<a>1</a>"), BodyValues.text("  <a>1</a>\n").values());
    assertTrue(BodyValues.text("   ").isEmpty());
  }

  @Test
  void decodingUsesTheNamedCharsetElseUtf8AndFallsBackOnMalformedBytes() {
    byte[] utf8 = "caf\u00e9 \u4e2d".getBytes(StandardCharsets.UTF_8);
    assertEquals("caf\u00e9 \u4e2d", BodyText.decode(utf8, utf8.length, null, true));
    assertEquals("caf\u00e9 \u4e2d", BodyText.decode(utf8, utf8.length, "no-such-charset", true));
    byte[] latin = "caf\u00e9".getBytes(StandardCharsets.ISO_8859_1);
    assertEquals("caf\u00e9", BodyText.decode(latin, latin.length, "ISO-8859-1", true));
    // 0xE9 at the end of a complete body is not UTF-8: the whole body is read as ISO-8859-1. While more can
    // come, it is the start of a character that has not arrived yet.
    assertEquals("caf\u00e9", BodyText.decode(latin, latin.length, "UTF-8", true));
    assertEquals("caf", BodyText.decode(latin, latin.length, "UTF-8", false));
    byte[] bad = {'a', (byte) 0xff, 'b'};
    assertEquals("a\u00ffb", BodyText.decode(bad, bad.length, "UTF-8", false));
    byte[] utf16 = "ab".getBytes(StandardCharsets.UTF_16BE);
    assertEquals("ab", BodyText.decode(utf16, utf16.length, "UTF-16BE", true));
  }

  @Test
  void anIncompleteCharacterAtTheEndIsLeftOut() {
    byte[] bytes = "a\u4e2d".getBytes(StandardCharsets.UTF_8); // 'a' then three bytes
    assertEquals("a", BodyText.decode(bytes, 2, "UTF-8", false));
    assertEquals("a", BodyText.decode(bytes, 3, "UTF-8", false));
    assertEquals("a\u4e2d", BodyText.decode(bytes, 4, "UTF-8", false));
  }
}
