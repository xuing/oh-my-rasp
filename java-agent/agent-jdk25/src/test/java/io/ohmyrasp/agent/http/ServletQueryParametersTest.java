package io.ohmyrasp.agent.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ServletQueryParametersTest {
  @Test void malformedFieldsDoNotSupplyPartialNamesOrReplacementValues() {
    String query = "label=one&label=%+1&label=%ＦＦ&bad%X=word&%FF=report&label=%C3x&label=%F0%9F"
        + "&label=%ED%A0%80&label=%C0%AF&label=%&label=%EF%BF%BD&label=two";
    assertEquals(Map.of("label", List.of("one", "\uFFFD", "two")), ServletQueryParameters.parse(query));
  }

  @Test void decodesFieldBoundariesOnceAndPreservesValidValues() {
    assertEquals(Map.of("a&b", List.of("東京 =+/%26", "☎"), "flag", List.of(""), "blank", List.of("")),
        ServletQueryParameters.parse("a%26b=東京+%3d%2B/%2526&flag&a%26b=%E2%98%8E&blank="));
  }
}
