package io.ohmyrasp.playground;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

final class LabCatalog {
  private static final String RESOURCE = "/ohmyrasp/labs/archived-java-ranges.json";

  private LabCatalog() {}

  static String json() {
    try (InputStream stream = LabCatalog.class.getResourceAsStream(RESOURCE)) {
      if (stream == null) {
        return "{\"groups\":[]}";
      }
      return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      return "{\"groups\":[]}";
    }
  }
}
