import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/** Real JAXP parsing with a process-local in-memory transport, including relative resolution. */
public final class XmlResolutionCheck {
  private static final String DTD = "<!ELEMENT order EMPTY><!ATTLIST order unit CDATA 'boxes'>";
  private static final String DOC = "http://catalog.example.invalid/forms/order.xml";
  private static int transportOpens;

  public static void main(String[] args) throws Exception {
    URL.setURLStreamHandlerFactory(protocol -> !"http".equals(protocol) ? null : new URLStreamHandler() {
      @Override
      protected URLConnection openConnection(URL url) {
        if (!"catalog.example.invalid".equals(url.getHost())) {
          throw new AssertionError("Unexpected transport destination");
        }
        transportOpens++;
        return new URLConnection(url) {
          public void connect() {}
          public InputStream getInputStream() {
            String text = url.getPath().endsWith(".dtd") ? DTD : "<order unit='boxes'/>";
            return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
          }
        };
      }
    });
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    if (Boolean.getBoolean("fixture.systemCatalog")) {
      DocumentBuilder stock = factory.newDocumentBuilder();
      URL packaged = XmlResolutionCheck.class.getResource("/catalog/stock.dtd");
      if (packaged == null) throw new AssertionError("packaged catalogue missing");
      stock.setEntityResolver((pub, sys) -> new InputSource(packaged.toExternalForm()));
      expectBoxes(stock.parse(document(DOC + ".dtd")));
    }
    expectBoxes(factory.newDocumentBuilder().parse(DOC));
    if (transportOpens != 1) throw new AssertionError("Expected one document open");

    for (boolean bytes : new boolean[]{true, false}) {
      DocumentBuilder parser = factory.newDocumentBuilder();
      parser.setEntityResolver((publicId, systemId) -> source(DTD, systemId, bytes));
      expectBoxes(parser.parse(document("order.dtd")));
    }
    if (transportOpens != 1) throw new AssertionError("A supplied stream was reopened");

    Path jar = Files.createTempFile("application-catalog-", ".jar");
    try {
      try (JarOutputStream contents = new JarOutputStream(Files.newOutputStream(jar))) {
        contents.putNextEntry(new JarEntry("catalog/order.dtd"));
        contents.write(DTD.getBytes(StandardCharsets.UTF_8));
        contents.closeEntry();
        contents.putNextEntry(new JarEntry("catalog/order.xml"));
        contents.write("<!DOCTYPE order SYSTEM './order.dtd'><order/>".getBytes(StandardCharsets.UTF_8));
        contents.closeEntry();
      }
      Thread thread = Thread.currentThread();
      ClassLoader previous = thread.getContextClassLoader();
      try (URLClassLoader application = new URLClassLoader(new URL[]{jar.toUri().toURL()}, previous)) {
        thread.setContextClassLoader(application);
        DocumentBuilder parser = factory.newDocumentBuilder();
        parser.setEntityResolver((publicId, systemId) ->
            new InputSource(application.getResource("catalog/order.dtd").toExternalForm()));
        expectBoxes(parser.parse(document("http://catalog.example.invalid/forms/order.dtd")));
        parser.setEntityResolver(new org.xml.sax.ext.DefaultHandler2() {
          @Override
          public InputSource resolveEntity(String name, String publicId, String base, String systemId) {
            return new InputSource(application.getResource("catalog/order.dtd").toExternalForm());
          }
        });
        expectBoxes(parser.parse(document("order.dtd")));
        URL root = application.getResource("catalog/order.xml");
        DocumentBuilder directParser = factory.newDocumentBuilder();
        expectBoxes(directParser.parse(root.toExternalForm()));
        if (args.length == 1 && "observe".equals(args[0])) {
          // A reader can supply an identical base name. Only a parser-opened root
          // archive establishes the sibling resource relationship.
          expectBoxes(directParser.parse(source(
              "<!DOCTYPE order SYSTEM 'order.dtd'><order/>", root.toExternalForm(), true)));
          Path other = Files.createTempFile("outside-catalog-", ".jar");
          String startupPath = System.getProperty("java.class.path");
          try {
            System.setProperty("java.class.path", startupPath + java.io.File.pathSeparator + other);
            Files.copy(jar, other, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            parser.setEntityResolver((pub, sys) -> new InputSource("jar:" + other.toUri() + "!/catalog/order.dtd"));
            expectBoxes(parser.parse(document(DOC + ".dtd")));
          } finally {
            System.setProperty("java.class.path", startupPath);
            Files.deleteIfExists(other);
          }
        }
      } finally {
        thread.setContextClassLoader(previous);
      }
    } finally {
      Files.deleteIfExists(jar);
    }
    if (transportOpens != 1) throw new AssertionError("Catalogue mapping opened a remote URL");
    if (args.length == 1 && "observe".equals(args[0])) {
      // Monitor mode must report the resolved destination and preserve the parser result.
      expectBoxes(factory.newDocumentBuilder().parse(document("order.dtd?catalogTicket=sample")));
      if (transportOpens != 2) throw new AssertionError("Expected one additional schema open");
    }
  }

  private static InputSource source(String text, String id, boolean bytes) {
    InputSource input = bytes ? new InputSource(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)))
        : new InputSource(new StringReader(text));
    input.setSystemId(id);
    return input;
  }

  private static InputSource document(String identifier) {
    return source("<!DOCTYPE order SYSTEM '" + identifier + "'><order/>", DOC, false);
  }

  private static void expectBoxes(Document doc) {
    if (!"boxes".equals(doc.getDocumentElement().getAttribute("unit"))) {
      throw new AssertionError("Schema was not applied");
    }
  }
}
