package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

import io.ohmyrasp.agent.util.ControlDocument;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Control-file polling of the backport RaspRuntime, one poll step at a time and without the poller
 * thread. docs/agent.md "Operating modes" describes the contract these tests pin.
 */
final class Java8RuntimeControlTest {
  /** Documents that are not one complete JSON object with a recognised top-level mode. */
  static final String[] NOT_A_MODE_CHANGE =
      new String[] {
        "{\"mode\":\"off\"",
        "{\"mode\":\"of",
        "{\"mode\":\"off\",",
        "{\"policy\":{\"mode\":\"off\"}}",
        "{\"algorithms\":[{\"mode\":\"off\"}]}",
        "{\"note\":\"\\\"mode\\\":\\\"off\\\"\"}",
        "{\"mode\":\"sleep\"}",
        "{\"mode\":\"off\"} trailing",
        "{\"mode\":\"off\"}{}",
        "[{\"mode\":\"off\"}]",
        "{\"mode\":\"off\",}",
        "{\"mode\":off}",
        "{'mode':'off'}",
        "",
      };

  @TempDir Path dir;
  private long nextMtime = 1_000_000_000_000L;

  @Test
  void onlyACompleteControlObjectWithATopLevelModeChangesTheMode() throws Exception {
    Path file = dir.resolve("control.json");
    RaspRuntime.ControlState state = new RaspRuntime.ControlState(RaspRuntime.Mode.BLOCK);
    for (String text : NOT_A_MODE_CHANGE) {
      write(file, text);
      state.poll(file);
      assertEquals(RaspRuntime.Mode.BLOCK, state.mode(), text);
    }

    // A policy string that mentions a mode is data; the top-level mode decides.
    write(
        file,
        "{\n  \"revision\": 3,\n  \"policy\": \"{\\\"mode\\\":\\\"block\\\"}\",\n"
            + "  \"algorithms\": {\"sql_userinput\": false},\n  \"mode\": \"monitor\"\n}\n");
    state.poll(file);
    assertEquals(RaspRuntime.Mode.MONITOR, state.mode());
  }

  @Test
  void aControlFileReadHalfWrittenIsPickedUpOnceCompleteWithTheSameModificationTime()
      throws Exception {
    Path file = dir.resolve("control.json");
    FileTime sameTime = FileTime.fromMillis(1_500_000_000_000L);
    RaspRuntime.ControlState state = new RaspRuntime.ControlState(RaspRuntime.Mode.BLOCK);

    writeAt(file, "{\"mode\":\"off\"", sameTime);
    state.poll(file);
    assertEquals(RaspRuntime.Mode.BLOCK, state.mode(), "a half-written document changes nothing");
    writeAt(file, "{\"mode\":\"off\"}", sameTime);
    state.poll(file);
    assertEquals(RaspRuntime.Mode.OFF, state.mode(), "the completed document applies");

    // Content decides, not the modification time: a new document with the same time applies.
    writeAt(file, "{\"mode\":\"monitor\"}", sameTime);
    state.poll(file);
    assertEquals(RaspRuntime.Mode.MONITOR, state.mode());
    state.poll(file);
    assertEquals(RaspRuntime.Mode.MONITOR, state.mode(), "unchanged content");
  }

  @Test
  void aMissingControlFileRestoresTheStartUpModeAndAnUnreadableOneKeepsTheLastGoodMode()
      throws Exception {
    Path file = dir.resolve("control.json");
    RaspRuntime.ControlState state = new RaspRuntime.ControlState(RaspRuntime.Mode.BLOCK);
    state.poll(file);
    assertEquals(RaspRuntime.Mode.BLOCK, state.mode(), "no file yet");

    write(file, "{\"mode\":\"off\"}");
    state.poll(file);
    assertEquals(RaspRuntime.Mode.OFF, state.mode());

    // Present but not readable as a document: the daemon replaces the file atomically, so this is
    // transient and the last good mode stays.
    write(file, "{\"mode\":\"block\"");
    state.poll(file);
    assertEquals(RaspRuntime.Mode.OFF, state.mode(), "truncated content");
    Files.delete(file);
    Files.createDirectory(file);
    state.poll(file);
    assertEquals(RaspRuntime.Mode.OFF, state.mode(), "a directory in the file's place");

    Files.delete(file);
    state.poll(file);
    assertEquals(RaspRuntime.Mode.BLOCK, state.mode(), "a missing control file restores the start-up mode");

    // The same document written again applies again.
    write(file, "{\"mode\":\"off\"}");
    state.poll(file);
    assertEquals(RaspRuntime.Mode.OFF, state.mode(), "the same document after a removal");

    // With no mode resolved at start-up, removal returns to the unset (legacy) mode.
    RaspRuntime.ControlState unset = new RaspRuntime.ControlState(null);
    unset.poll(file);
    assertEquals(RaspRuntime.Mode.OFF, unset.mode());
    Files.delete(file);
    unset.poll(file);
    assertNull(unset.mode());
  }

  @Test
  void controlDocumentReadsOnlyTheTopLevelOfOneWellFormedObject() {
    assertEquals("off", ControlDocument.topLevelString(" \r\n\t{ \"mode\" : \"off\" }\n", "mode"));
    assertEquals(
        "off",
        ControlDocument.topLevelString(
            "{\"a\":[1,-2.5e+3,0,0.5E-1,true,false,null,{\"b\":\"c\"},[]],\"mode\":\"\\u006fff\"}", "mode"));
    assertEquals("block", ControlDocument.topLevelString("{\"mode\":\"off\",\"mode\":\"block\"}", "mode"));
    assertNull(ControlDocument.topLevelString("{\"mode\":\"off\",\"mode\":3}", "mode"));
    assertNull(ControlDocument.topLevelString("{}", "mode"));
    assertNull(ControlDocument.topLevelString("{\"policy\":{\"mode\":\"off\"}}", "mode"));
    assertNull(ControlDocument.topLevelString("{\"x\":\"\\\"mode\\\":\\\"off\\\"\"}", "mode"));
    assertEquals("a\"\\/\b\f\n\r\t", ControlDocument.topLevelString("{\"k\":\"a\\\"\\\\\\/\\b\\f\\n\\r\\t\"}", "k"));

    String[] malformed =
        new String[] {
          "{\"mode\":\"off\"",
          "{\"mode\":\"of",
          "{\"mode\":\"off\",",
          "{\"mode\":\"off\"} trailing",
          "{\"mode\":\"off\"}{}",
          "[{\"mode\":\"off\"}]",
          "\"off\"",
          "{\"mode\":\"off\",}",
          "{\"mode\":off}",
          "{'mode':'off'}",
          "",
          "   ",
          "{\"a\":01}",
          "{\"a\":1.}",
          "{\"a\":-}",
          "{\"a\":1e}",
          "{\"a\":tru}",
          "{\"a\":[1,]}",
          "{\"a\":{\"b\"}}",
          "{\"a\":\"\\u00zz\"}",
          "{\"a\":\"\\x\"}",
          "{\"a\":\"line\nbreak\"}",
          "{\"a\":\"\\",
          "\uFEFF{\"mode\":\"off\"}",
        };
    for (String text : malformed) {
      try {
        ControlDocument.topLevelString(text, "mode");
        fail("accepted malformed control document: " + text);
      } catch (IllegalArgumentException expected) {
        // rejected as it should be
      }
    }
  }

  @Test
  void controlDocumentBoundsItsNestingDepth() {
    assertNull(ControlDocument.topLevelString(nested(ControlDocument.MAX_DEPTH - 1), "mode"));
    try {
      ControlDocument.topLevelString(nested(ControlDocument.MAX_DEPTH), "mode");
      fail("accepted a control document nested deeper than the bound");
    } catch (IllegalArgumentException expected) {
      // rejected as it should be
    }
  }

  /** A top-level object whose one value is {@code arrays} nested arrays. */
  private static String nested(int arrays) {
    StringBuilder builder = new StringBuilder("{\"a\":");
    for (int i = 0; i < arrays; i++) {
      builder.append('[');
    }
    for (int i = 0; i < arrays; i++) {
      builder.append(']');
    }
    return builder.append('}').toString();
  }

  /** Writes {@code text} with a modification time no earlier write in this test used. */
  private void write(Path file, String text) throws Exception {
    nextMtime += 1000L;
    writeAt(file, text, FileTime.fromMillis(nextMtime));
  }

  private static void writeAt(Path file, String text, FileTime time) throws Exception {
    Files.write(file, text.getBytes(StandardCharsets.UTF_8));
    Files.setLastModifiedTime(file, time);
  }
}
