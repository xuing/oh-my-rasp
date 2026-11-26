import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.io.UrlResource;

/** XML contains only a fixed report bean. Origin checks never give the test builder a command. */
public final class SpringProcessCheck {
  public static final class LocalReport implements InitializingBean {
    public void afterPropertiesSet() throws Exception {
      Process child = new ProcessBuilder("/usr/bin/printf", "%s", "weekly").start();
      try (InputStream stream = child.getInputStream()) {
        byte[] bytes = new byte[6];
        new java.io.DataInputStream(stream).readFully(bytes);
        if (!"weekly".equals(new String(bytes, StandardCharsets.US_ASCII)) || child.waitFor() != 0)
          throw new AssertionError("ordinary initializer failed");
      } finally { child.destroy(); }
    }
  }
  public static final class Weekly {
    boolean ready;
    public void start() { ready = true; }
  }

  private static final String XML = "<beans xmlns=\"http://www.springframework.org/schema/beans\">"
      + "<bean id=\"weekly\" class=\"SpringProcessCheck$Weekly\" init-method=\"start\"/></beans>";

  private static final class TestFactory extends DefaultListableBeanFactory {
    void localDispatch(ProcessBuilder target, RootBeanDefinition definition) throws Throwable {
      invokeInitMethods("local-fixture", target, definition);
    }
  }

  // Exercise the real Spring dispatcher with a locally supplied builder. No executable exists
  // at the selected path and the XML fixture cannot supply a command.
  private static void checkBinding(TestFactory factory, RootBeanDefinition definition, boolean expected,
                                   String mode) throws Throwable {
    Path directory = Files.createTempDirectory("spring-process-check");
    try {
      boolean blocked = false;
      try {
        factory.localDispatch(new ProcessBuilder(directory.resolve("absent").toString()), definition);
        throw new AssertionError("missing executable started");
      } catch (IOException missing) {
        if (HttpTransportCheck.blocked(missing)) blocked = true;
      } catch (RuntimeException e) {
        if (!HttpTransportCheck.blocked(e)) throw e;
        blocked = true;
      }
      if (blocked != (expected && "block".equals(mode))) throw new AssertionError("incorrect dispatch decision");
    } finally { Files.delete(directory); }
  }

  public static void main(String[] args) throws Throwable {
    TestFactory factory = new TestFactory();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/weekly.xml", exchange -> {
      byte[] bytes = XML.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    server.start();
    try (GenericApplicationContext context = new GenericApplicationContext(factory)) {
      UrlResource url = new UrlResource(new URL("http://127.0.0.1:" + server.getAddress().getPort() + "/weekly.xml"));
      XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(context);
      reader.setValidationMode(XmlBeanDefinitionReader.VALIDATION_NONE);
      reader.setNamespaceAware(true);
      reader.loadBeanDefinitions(url);
      RootBeanDefinition local = new RootBeanDefinition(LocalReport.class);
      local.setResource(url); // The same displayed location, assigned outside the parser.
      context.registerBeanDefinition("applicationReport", local);
      context.refresh();
      if (!context.getBean("weekly", Weekly.class).ready) throw new AssertionError("report did not initialize");
      RootBeanDefinition merged = (RootBeanDefinition) factory.getMergedBeanDefinition("weekly");
      checkBinding(factory, merged, true, args[1]);
      RootBeanDefinition inherited = new RootBeanDefinition(merged);
      inherited.overrideFrom(new org.springframework.beans.factory.support.GenericBeanDefinition());
      checkBinding(factory, inherited, true, args[1]);
      RootBeanDefinition localMethod = new RootBeanDefinition();
      localMethod.setInitMethodName("start");
      localMethod.setResource(url);
      checkBinding(factory, localMethod, false, args[1]);
      RootBeanDefinition changed = new RootBeanDefinition(merged);
      changed.setInitMethodName(null);
      changed.setInitMethodName("start");
      checkBinding(factory, changed, false, args[1]);
      RootBeanDefinition overridden = new RootBeanDefinition(merged);
      overridden.overrideFrom(localMethod);
      checkBinding(factory, overridden, false, args[1]);
    } finally { server.stop(0); }
  }
}
