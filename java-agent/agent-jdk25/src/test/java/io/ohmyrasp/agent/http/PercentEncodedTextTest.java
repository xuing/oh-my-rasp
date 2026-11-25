package io.ohmyrasp.agent.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class PercentEncodedTextTest {
  @Test
  void decodesTextOneLayerAtATimeAndPreservesRealControls() {
    for (boolean lenient : new boolean[]{false, true}) {
      assertEquals("/資料/📊+x", PercentEncodedText.decode("/%E8%B3%87%E6%96%99/%F0%9F%93%8A+x", lenient));
      assertEquals("%E6%9D%B1", PercentEncodedText.decode("%25E6%259D%25B1", lenient));
      assertEquals("x\u0085y", PercentEncodedText.decode("x%C2%85y", lenient));
      assertEquals("\u00e2x東", PercentEncodedText.decode("%E2x%E6%9D%B1", lenient));
      assertEquals("x%", PercentEncodedText.decode("x%", lenient));
    }
  }
}
