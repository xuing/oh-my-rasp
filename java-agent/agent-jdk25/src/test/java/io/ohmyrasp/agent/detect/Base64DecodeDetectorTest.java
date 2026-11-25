package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Base64DecodeDetector: JDK Base64 decoder tail-underflow guard. */
final class Base64DecodeDetectorTest {
  @Test
  void detectsBase64Avx512TailUnderflowCandidatesAndRedactsPayload() {
    byte[] stdLen66 = ("A".repeat(64) + "A=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] stdLen67 = ("A".repeat(64) + "AA=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] stdLen130 = ("A".repeat(128) + "A=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] urlLen66 = ("A".repeat(64) + "-=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] sliceWithOffset = ("!!" + "B".repeat(64) + "B=" + "!!").getBytes(StandardCharsets.ISO_8859_1);

    var stdResult = Base64DecodeDetector.detectBase64Decode(stdLen66, 0, stdLen66.length, false, false, request());
    assertAlgorithm(stdResult, "base64_avx512_tail_underflow");
    assertEquals("base64", stdResult.orElseThrow().hook());
    assertEquals("66", stdResult.orElseThrow().details().get("length"));
    assertEquals("1", stdResult.orElseThrow().details().get("padding"));
    assertEquals("2", stdResult.orElseThrow().details().get("remainder"));
    assertEquals("standard", stdResult.orElseThrow().details().get("alphabet"));
    assertEquals("CVE-2026-114938", stdResult.orElseThrow().details().get("cve"));
    assertFalse(stdResult.orElseThrow().details().toString().contains("AAAA"));

    assertAlgorithm(
        Base64DecodeDetector.detectBase64Decode(stdLen67, 0, stdLen67.length, false, false, RequestContext.empty()),
        "base64_avx512_tail_underflow");
    assertAlgorithm(
        Base64DecodeDetector.detectBase64Decode(stdLen130, 0, stdLen130.length, false, false, RequestContext.empty()),
        "base64_avx512_tail_underflow");
    var urlResult =
        Base64DecodeDetector.detectBase64Decode(urlLen66, 0, urlLen66.length, true, false, RequestContext.empty());
    assertAlgorithm(urlResult, "base64_avx512_tail_underflow");
    assertEquals("URL-safe", urlResult.orElseThrow().details().get("alphabet"));

    assertAlgorithm(
        Base64DecodeDetector.detectBase64Decode(
            sliceWithOffset, 2, sliceWithOffset.length - 2, false, false, RequestContext.empty()),
        "base64_avx512_tail_underflow");
  }

  @Test
  void ignoresNonCandidateBase64Inputs() {
    byte[] validAligned = ("A".repeat(64) + "AA==").getBytes(StandardCharsets.ISO_8859_1);
    byte[] shortPadded = "YQ==".getBytes(StandardCharsets.ISO_8859_1);
    byte[] unpadded65 = "A".repeat(65).getBytes(StandardCharsets.ISO_8859_1);
    byte[] triplePad67 = ("A".repeat(64) + "===").getBytes(StandardCharsets.ISO_8859_1);
    byte[] excessPad65 = ("A".repeat(63) + "==").getBytes(StandardCharsets.ISO_8859_1);
    byte[] urlCharInStandard = ("A".repeat(64) + "-=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] nonAlpha = ("A".repeat(63) + "!A=").getBytes(StandardCharsets.ISO_8859_1);
    byte[] cand = ("A".repeat(64) + "A=").getBytes(StandardCharsets.ISO_8859_1);

    assertTrue(Base64DecodeDetector.detectBase64Decode(validAligned, 0, validAligned.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(shortPadded, 0, shortPadded.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(unpadded65, 0, unpadded65.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(triplePad67, 0, triplePad67.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(excessPad65, 0, excessPad65.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(urlCharInStandard, 0, urlCharInStandard.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(nonAlpha, 0, nonAlpha.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(cand, 0, cand.length, false, true, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(null, 0, 66, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(cand, -1, cand.length, false, false, request()).isEmpty());
    assertTrue(Base64DecodeDetector.detectBase64Decode(cand, 0, cand.length + 1, false, false, request()).isEmpty());
  }
}
