package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.parser.ParserConfig;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Pins the vulnerable resource-name conversion in the real Fastjson 1.2.83 artifact. */
final class Fastjson1283RootCauseTest {
  @Test
  void attackerTypeNamesCrossFromClassNamesIntoUrlResources() {
    assertEquals(
        "http://2130706433:19090/a.class", resourceFor("http:..2130706433:19090.a"));
    assertEquals(
        "jar:http://2130706433:19090/probe!/foo/Exception.class",
        resourceFor("jar:http:..2130706433:19090.probe!.foo.Exception"));
    assertEquals(
        "jar:file:/proc/self/fd/3!/fd3/Exception.class",
        resourceFor("jar:file:.proc.self.fd.3!.fd3.Exception"));
  }

  @Test
  void normalTypeNameRemainsAClasspathRelativeResource() {
    assertEquals("com/acme/orders/Order.class", resourceFor("com.acme.orders.Order"));
  }

  @Test
  void safeModeStopsBeforeTheResourceLookupBoundary() {
    CapturingClassLoader loader = new CapturingClassLoader();
    ParserConfig config = new ParserConfig();
    config.setDefaultClassLoader(loader);
    config.setSafeMode(true);

    assertThrows(
        JSONException.class,
        () -> config.checkAutoType("http:..2130706433:19090.a", null, 0));
    assertTrue(loader.resources.isEmpty());
  }

  private static String resourceFor(String typeName) {
    CapturingClassLoader loader = new CapturingClassLoader();
    ParserConfig config = new ParserConfig();
    config.setDefaultClassLoader(loader);
    try {
      config.checkAutoType(typeName, null, 0);
    } catch (JSONException expected) {
      // The lookup happens before Fastjson rejects an unknown auto type.
    }
    assertEquals(1, loader.resources.size(), "expected exactly one class-resource probe");
    return loader.resources.get(0);
  }

  private static final class CapturingClassLoader extends ClassLoader {
    private final List<String> resources = new ArrayList<>();

    private CapturingClassLoader() {
      super(null);
    }

    @Override
    public InputStream getResourceAsStream(String name) {
      resources.add(name);
      return null;
    }
  }
}
