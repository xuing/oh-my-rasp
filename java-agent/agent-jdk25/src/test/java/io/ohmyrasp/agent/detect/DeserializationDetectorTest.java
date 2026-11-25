package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** DeserializationDetector: Deserialized types, transports, polymorphic binding, RPC payloads and XMLDecoder object graphs. */
final class DeserializationDetectorTest {
  @Test
  void detectsDeserializationBlacklist() {
    var result = DeserializationDetector.detectDeserialization("io.ohmyrasp.playground.EvilSerialized", request());

    assertTrue(result.isPresent());
    assertEquals("deserialization_blacklist", result.orElseThrow().algorithm());
  }

  @Test
  void detectsExpandedDeserializationGadgetClass() {
    var result = DeserializationDetector.detectDeserialization("com.sun.rowset.JdbcRowSetImpl", request());

    assertAlgorithm(result, "deserialization_blacklist");
  }

  @Test
  void detectsBeanShellDeserializationGadgetFamily() {
    var result = DeserializationDetector.detectDeserialization("bsh.XThis", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsRomeDeserializationGadgetFamily() {
    var result =
        DeserializationDetector.detectDeserialization("com.sun.syndication.feed.impl.ToStringBean", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsC3p0DeserializationGadgetFamily() {
    var result =
        DeserializationDetector.detectDeserialization(
            "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsCommonsBeanutilsDeserializationGadgetFamily() {
    var result =
        DeserializationDetector.detectDeserialization("org.apache.commons.beanutils.BeanComparator", request());

    assertAlgorithm(result, "deserialization_gadget");
  }

  @Test
  void detectsTomcatTribesClusterMessageDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.commons.collections.functors.InvokerTransformer",
            RequestContext.empty(),
            tomcatTribesStack());

	    assertAlgorithm(result, "deserialization_cluster_message");
	    assertEquals("tomcat-tribes", result.orElseThrow().details().get("transport"));
	    assertEquals(
	        "tomcat-tribes-encrypt", result.orElseThrow().details().get("securityInterceptor"));
	  }

  @Test
  void ignoresBenignTomcatTribesClusterMessageClass() {
    var result =
        DeserializationDetector.detectDeserialization("java.util.HashMap", RequestContext.empty(), tomcatTribesStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsLog4jSocketServerDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.commons.collections.functors.InvokerTransformer",
            RequestContext.empty(),
            log4jSocketServerStack());

    assertAlgorithm(result, "deserialization_logging_message");
    assertEquals("log4j-socket", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignLog4jSocketServerMessageClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.logging.log4j.core.impl.MutableLogEvent",
            RequestContext.empty(),
            log4jSocketServerStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsCasWebflowClientStateDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.commons.collections4.functors.InvokerTransformer",
            RequestContext.empty(),
            casWebflowStateStack());

    assertAlgorithm(result, "deserialization_webflow_state");
    assertEquals("cas-webflow-state", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignWebflowClientStateClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.springframework.webflow.execution.impl.FlowExecutionImpl",
            RequestContext.empty(),
            casWebflowStateStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void fallsBackToGenericBlacklistForWebflowControllerStackWithoutClientStateDeserialization() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.commons.collections4.functors.InvokerTransformer",
            RequestContext.empty(),
            List.of(
                "org.apereo.cas.web.flow.CasWebflowConfigurer",
                "org.springframework.webflow.mvc.servlet.FlowHandlerAdapter",
                "org.springframework.web.servlet.DispatcherServlet"));

    assertAlgorithm(result, "deserialization_blacklist");
  }

  @Test
  void detectsRmiTransportDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization("bsh.XThis", RequestContext.empty(), rmiTransportStack());

    assertAlgorithm(result, "deserialization_rmi_transport");
    assertEquals("rmi-transport", result.orElseThrow().details().get("transport"));
  }

  @Test
  void detectsNeo4jShellRmiTransportRhinoGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.mozilla.javascript.NativeJavaObject",
            RequestContext.empty(),
            neo4jShellRmiStack());

    assertAlgorithm(result, "deserialization_rmi_transport");
    assertEquals("rmi-transport", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignRmiTransportDeserializationClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "org.apache.jmeter.engine.RemoteJMeterEngineImpl",
            RequestContext.empty(),
            rmiTransportStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsWeblogicT3RemotingTransportDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "sun.rmi.server.UnicastRef", RequestContext.empty(), weblogicT3Stack());

    assertAlgorithm(result, "deserialization_remoting_transport");
    assertEquals("weblogic-t3", result.orElseThrow().details().get("transport"));
  }

  @Test
  void detectsWeblogicIiopRemotingTransportDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "com.sun.rowset.JdbcRowSetImpl", RequestContext.empty(), weblogicIiopStack());

    assertAlgorithm(result, "deserialization_remoting_transport");
    assertEquals("weblogic-iiop", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignWeblogicRemotingTransportDeserializationClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "weblogic.rjvm.PeerInfo", RequestContext.empty(), weblogicT3Stack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsActiveMqJmsObjectMessageDeserializationGadget() {
    var result =
        DeserializationDetector.detectDeserialization(
            "com.rometools.rome.feed.impl.ToStringBean",
            RequestContext.empty(),
            activeMqJmsObjectMessageStack());

    assertAlgorithm(result, "deserialization_jms_object_message");
    assertEquals("activemq-object-message", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresBenignJmsObjectMessageDeserializationClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "com.example.messaging.OrderEvent",
            RequestContext.empty(),
            activeMqJmsObjectMessageStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsJenkinsCliSignedObjectDeserializationWrapper() {
    var result =
        DeserializationDetector.detectDeserialization(
            "java.security.SignedObject",
            RequestContext.empty(),
            jenkinsCliSignedObjectStack());

    assertAlgorithm(result, "deserialization_signed_object");
    assertEquals("jenkins-cli-remoting", result.orElseThrow().details().get("transport"));
  }

  @Test
  void ignoresSignedObjectDeserializationOutsideRemoteCli() {
    var result =
        DeserializationDetector.detectDeserialization(
            "java.security.SignedObject",
            RequestContext.empty(),
            List.of("com.example.security.SignedEnvelopeVerifier", "java.io.ObjectInputStream"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignJenkinsCliDeserializationClass() {
    var result =
        DeserializationDetector.detectDeserialization(
            "hudson.cli.CLICommand", RequestContext.empty(), jenkinsCliSignedObjectStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRmiRegistryProxyBindFromTransport() {
    var result =
        DeserializationDetector.detectRmiRegistryBind(
            "bind",
            "pwn",
            "jdk.proxy1.$Proxy0",
            RequestContext.empty(),
            rmiRegistryStack());

    assertAlgorithm(result, "deserialization_rmi_registry_bind");
    assertEquals("rmi-transport", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsRmiRegistryUnicastRefBindBypassShape() {
    var result =
        DeserializationDetector.detectRmiRegistryBind(
            "rebind",
            "pwn",
            "sun.rmi.server.UnicastRef",
            RequestContext.empty(),
            rmiRegistryStack());

    assertAlgorithm(result, "deserialization_rmi_registry_bind");
  }

  @Test
  void ignoresRmiRegistryProxyBindOutsideTransportDispatch() {
    var result =
        DeserializationDetector.detectRmiRegistryBind(
            "bind", "local", "jdk.proxy1.$Proxy0", RequestContext.empty(), List.of("app.Main"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresOrdinaryRmiRegistryImplementationBind() {
    var result =
        DeserializationDetector.detectRmiRegistryBind(
            "bind",
            "service",
            "com.example.ExportedService",
            RequestContext.empty(),
            rmiRegistryStack());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSuspiciousFileBackedSessionDeserialization() {
    var result = DeserializationDetector.detectSessionDeserialization(".deserialize", "TomcatFileStore", request());

    assertAlgorithm(result, "deserialization_session_file");
  }

  @Test
  void detectsTraversalFileBackedSessionDeserialization() {
    var result =
        DeserializationDetector.detectSessionDeserialization("../work/.payload", "TomcatFileStore", request());

    assertAlgorithm(result, "deserialization_session_file");
  }

  @Test
  void ignoresNormalRoutedTomcatSessionId() {
    var result =
        DeserializationDetector.detectSessionDeserialization(
            "A1B2C3D4E5F60718293A4B5C6D7E8F90.node1", "TomcatFileStore", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignDeserializationClass() {
    var result = DeserializationDetector.detectDeserialization("java.util.HashMap", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void apacheNativeFunctorRestrictionsRequireAnObjectStream() {
    for (String pkg : List.of("org.apache.commons.collections.functors.", "org.apache.commons.collections4.functors.")) {
      for (String type : List.of("CloneTransformer", "ForClosure", "InstantiateFactory", "WhileClosure",
          "PrototypeFactory$PrototypeCloneFactory", "PrototypeFactory$PrototypeSerializationFactory")) {
        String name = pkg + type;
        assertAlgorithm(DeserializationDetector.detectDeserialization(name, request()), "deserialization_blacklist");
        assertTrue(DeserializationDetector.detectPolymorphicType("jackson", name, request()).isEmpty(), name);
      }
    }
  }

  @Test
  void detectsFastjsonPolymorphicJndiGadget() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "fastjson",
            "com.sun.rowset.JdbcRowSetImpl",
            request(Map.of("@type", List.of("com.sun.rowset.JdbcRowSetImpl"))));

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void ignoresFastjsonClassLiteralUntilConcreteDangerousTypeIsResolved() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "fastjson", "java.lang.Class", request(Map.of("@type", List.of("java.lang.Class"))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsJacksonPolymorphicTemplatesGadgetWithArraySyntax() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "jackson",
            "[Lcom.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;",
            request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsJacksonPolymorphicSpringXmlContextGadget() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "jackson",
            "org.springframework.context.support.FileSystemXmlApplicationContext",
            request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsXstreamPolymorphicJndiPrefixGadget() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "xstream", "com.sun.jndi.rmi.registry.BindingEnumeration", request());

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void detectsSnakeyamlPolymorphicH2JdbcConnection() {
    var result =
        DeserializationDetector.detectPolymorphicType(
            "snakeyaml",
            "org.h2.jdbc.JdbcConnection",
            request(Map.of("type", List.of("org.h2.jdbc.JdbcConnection"))));

    assertAlgorithm(result, "deserialization_polymorphic_type");
  }

  @Test
  void ignoresBenignPolymorphicType() {
    var result = DeserializationDetector.detectPolymorphicType("jackson", "java.util.HashMap", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsFastjson1283DirectHttpClassResource() {
    var result =
        DeserializationDetector.detectFastjsonClassResource(
            "http://192.168.65.254:19090/a.class", request());

    assertAlgorithm(result, "deserialization_fastjson_resource_url");
    assertEquals("block", result.orElseThrow().action());
    assertEquals("http", result.orElseThrow().details().get("mechanism"));
    assertEquals("ParserConfig.checkAutoType", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsFastjson1283RemoteJarAndProcFdClassResources() {
    var remote =
        DeserializationDetector.detectFastjsonClassResource(
            "jar:http://192.168.65.254:19090/probe!/foo/Exception.class", request());
    var procFd =
        DeserializationDetector.detectFastjsonClassResource(
            "jar:file:/proc/self/fd/3!/fd3/Exception.class", request());

    assertAlgorithm(remote, "deserialization_fastjson_resource_url");
    assertEquals("jar:http", remote.orElseThrow().details().get("mechanism"));
    assertAlgorithm(procFd, "deserialization_fastjson_resource_url");
    assertEquals("jar:file:proc-fd", procFd.orElseThrow().details().get("mechanism"));
  }

  @Test
  void ignoresNormalFastjsonClasspathResourcesAndUnrelatedFileUrls() {
    assertTrue(
        DeserializationDetector
            .detectFastjsonClassResource("com/example/orders/Order.class", request())
            .isEmpty());
    assertTrue(
        DeserializationDetector
            .detectFastjsonClassResource("jar:file:/opt/app/lib/models.jar!/Order.class", request())
            .isEmpty());
    assertTrue(DeserializationDetector.detectFastjsonClassResource(null, request()).isEmpty());
  }

  @Test
  void checksTheConstructorTypeSelectedForTheOpenWireException() {
    var invalid = DeserializationDetector.detectOpenWireThrowable(StringBuilder.class, RequestContext.empty());
    assertAlgorithm(invalid, "deserialization_protocol_class");
    assertEquals("non_throwable_constructor", invalid.orElseThrow().details().get("decision_basis"));
    assertTrue(DeserializationDetector.detectOpenWireThrowable(IllegalArgumentException.class, request()).isEmpty());
    assertTrue(DeserializationDetector.detectOpenWireThrowable(Error.class, request()).isEmpty());
    assertTrue(DeserializationDetector.detectOpenWireThrowable(null, request()).isEmpty());
    assertTrue(DeserializationDetector.detectProtocolClassInstantiation("OpenWire", "bsh.Report", List.of("weekly"), request()).isEmpty());
  }

  @Test
  void detectsHttpInvokerDeserializationDuringRequest() {
    var context =
        new RequestContext(
            "POST",
            "/dubbo/hello",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "content-type",
                "application/x-java-serialized-object"));

    var result = DeserializationDetector.detectHttpInvokerDeserialization("SpringHttpInvoker", context);

    assertAlgorithm(result, "deserialization_http_invoker");
    assertEquals("SpringHttpInvoker", result.orElseThrow().details().get("mechanism"));
    assertTrue(result.orElseThrow().requiresExplicitRule());
    assertEquals("invocation_stream_read", result.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void ignoresHttpInvokerDeserializationOutsideRequest() {
    var result =
        DeserializationDetector.detectHttpInvokerDeserialization("SpringHttpInvoker", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void checksObservedServletObjectReadForExplicitPolicy() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "report.RequestBody", request());

    assertAlgorithm(result, "deserialization_http_object_stream");
    assertTrue(result.orElseThrow().requiresExplicitRule());
    assertEquals("servlet_stream_read", result.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void serializedContentTypeAloneDoesNotIdentifyTheStream() {
    var context =
        new RequestContext(
            "POST",
            "/invoker/readonly",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/x-java-serialized-object"));

    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream", context, List.of());

    assertTrue(result.isEmpty());
  }

  @Test
  void readOnlyAccessFilterStackAloneDoesNotIdentifyTheStream() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.invocation.http.servlet.ReadOnlyAccessFilter"));

    assertTrue(result.isEmpty());
  }

  @Test
  void invokerServletStackAloneDoesNotIdentifyTheStream() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.invocation.http.servlet.InvokerServlet"));

    assertTrue(result.isEmpty());
  }

  @Test
  void httpilStackAloneDoesNotIdentifyTheStream() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.BufferedInputStream",
            request(),
            List.of("org.jboss.mq.il.http.HTTPServerILServlet"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresFileObjectStreamDuringHttpRequest() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "java.io.FileInputStream", request(), List.of("com.example.ReportController"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresRequestObjectStreamOutsideHttpRequest() {
    var result =
        DeserializationDetector.detectHttpObjectStreamDeserialization(
            "org.apache.catalina.connector.CoyoteInputStream", RequestContext.empty(), List.of());

    assertTrue(result.isEmpty());
  }

  @Test
  void checksTheSelectedHessianAllocation() {
    assertTrue(DeserializationDetector.detectHessianType("java.lang.ProcessBuilder", request()).isEmpty());
    assertTrue(DeserializationDetector.detectHessianAllocation(java.util.HashMap.class, "hessian_constructor", request()).isEmpty());
    assertTrue(DeserializationDetector.detectHessianAllocation(ProcessBuilder[].class, "hessian_constructor", request()).isEmpty());
    var result = DeserializationDetector.detectHessianAllocation(ProcessBuilder.class, "hessian_constructor", RequestContext.empty());
    assertAlgorithm(result, "deserialization_hessian_type");
    assertEquals("hessian_constructor", result.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void detectsXmlRpcSerializableValueDuringRequest() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/xmlrpc",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/xml"));

    var result = DeserializationDetector.detectXmlRpcSerializableValue("ApacheXmlRpc", context);

    assertAlgorithm(result, "deserialization_xmlrpc_serialized");
    assertEquals("ApacheXmlRpc", result.orElseThrow().details().get("mechanism"));
    assertEquals("xmlrpc_extension_read", result.orElseThrow().details().get("decision_basis"));
    assertTrue(result.orElseThrow().requiresExplicitRule());
    assertTrue(DeserializationDetector.detectXmlRpcSerializableValue("declaration", context).isEmpty());
  }

  @Test
  void xmlRpcWorkerReadRequiresExplicitTransportPolicy() {
    var result =
        DeserializationDetector.detectXmlRpcSerializableValue("ApacheXmlRpc", RequestContext.empty());

    assertTrue(result.orElseThrow().requiresExplicitRule());
  }

  @Test
  void detectsXmlDecoderProcessBuilderStart() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder",
            "start",
            List.of("sh", "-c", "id"),
            request(),
            xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_runtime");
  }

  @Test
  void detectsWebLogicWorkContextXmlDecoderProcessBuilderStart() {
    String body =
        """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
              <java version="1.4.0" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                  <array class="java.lang.String" length="3">
                    <void index="0"><string>sh</string></void>
                    <void index="1"><string>-c</string></void>
                    <void index="2"><string>id</string></void>
                  </array>
                  <void method="start"/>
                </void>
              </java>
            </work:WorkContext>
          </soapenv:Header>
          <soapenv:Body/>
        </soapenv:Envelope>
        """;
    RequestContext context =
        new RequestContext(
            "POST",
            "/wls-wsat/CoordinatorPortType",
            "",
            Map.of(),
            Map.of("content-type", "text/xml"),
            body);

    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder",
            "start",
            List.of("sh", "-c", "id"),
            context,
            xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_runtime");
    assertEquals("/wls-wsat/CoordinatorPortType", result.orElseThrow().request().uri());
    assertEquals("java.lang.ProcessBuilder", result.orElseThrow().details().get("target"));
  }

  @Test
  void detectsXmlDecoderRuntimeExec() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.lang.Runtime", "exec", List.of("id"), request(), xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_runtime");
  }

  @Test
  void detectsXmlDecoderServerSideScriptWriter() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.io.PrintWriter", "new", List.of("/tmp/shell.jsp"), request(), xmlDecoderStack());

    assertAlgorithm(result, "xml_decoder_webshell");
  }

  @Test
  void ignoresJavaBeansRuntimeOutsideXmlDecoderStack() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder", "start", List.of("id"), request(), List.of("app.BeanUtil"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundXmlDecoderRuntime() {
    var result =
        DeserializationDetector.detectXmlDecoderExpression(
            "java.lang.ProcessBuilder",
            "start",
            List.of("id"),
            RequestContext.empty(),
            xmlDecoderStack());

    assertTrue(result.isEmpty());
  }

  private static List<String> rmiRegistryStack() {
    return List.of(
        "sun.rmi.registry.RegistryImpl",
        "sun.rmi.server.UnicastServerRef",
        "sun.rmi.transport.Transport",
        "sun.rmi.transport.tcp.TCPTransport");
  }

  private static List<String> tomcatTribesStack() {
    return List.of(
        "org.apache.catalina.tribes.group.interceptors.EncryptInterceptor",
        "org.apache.catalina.tribes.io.XByteBuffer",
        "org.apache.catalina.tribes.transport.nio.NioReplicationTask");
  }

  private static List<String> log4jSocketServerStack() {
    return List.of(
        "org.apache.logging.log4j.core.net.server.ObjectInputStreamLogEventBridge",
        "org.apache.logging.log4j.core.net.server.TcpSocketServer",
        "org.apache.logging.log4j.core.net.server.AbstractSocketServer");
  }

  private static List<String> casWebflowStateStack() {
    return List.of(
        "org.jasig.cas.util.EncryptedTranscoder",
        "org.springframework.webflow.execution.repository.support.ClientFlowExecutionRepository",
        "org.springframework.webflow.execution.repository.snapshot.SerializedFlowExecutionSnapshot",
        "java.io.ObjectInputStream");
  }

  private static List<String> rmiTransportStack() {
    return List.of(
        "sun.rmi.server.UnicastServerRef",
        "sun.rmi.transport.Transport",
        "sun.rmi.transport.tcp.TCPTransport",
        "org.apache.jmeter.engine.RemoteJMeterEngineImpl");
  }

  private static List<String> neo4jShellRmiStack() {
    return List.of(
        "org.neo4j.shell.impl.ShellServerImpl",
        "org.neo4j.shell.ShellServer",
        "sun.rmi.server.UnicastServerRef",
        "sun.rmi.transport.Transport",
        "sun.rmi.transport.tcp.TCPTransport",
        "java.io.ObjectInputStream");
  }

  private static List<String> weblogicT3Stack() {
    return List.of(
        "weblogic.rjvm.InboundMsgAbbrev",
        "weblogic.rjvm.MsgAbbrevInputStream",
        "weblogic.protocol.ServerChannelInputStream",
        "weblogic.socket.SocketMuxer");
  }

  private static List<String> weblogicIiopStack() {
    return List.of(
        "weblogic.iiop.IIOPInputStream",
        "weblogic.iiop.ServerIIOPConnection",
        "weblogic.rmi.internal.BasicServerRef");
  }

  private static List<String> activeMqJmsObjectMessageStack() {
    return List.of(
        "org.apache.activemq.command.ActiveMQObjectMessage",
        "org.apache.activemq.util.ClassLoadingAwareObjectInputStream",
        "java.io.ObjectInputStream",
        "org.apache.activemq.web.MessageServletSupport");
  }

  private static List<String> jenkinsCliSignedObjectStack() {
    return List.of(
        "hudson.cli.CLICommand",
        "hudson.cli.CliManagerImpl",
        "hudson.remoting.ObjectInputStreamEx",
        "java.io.ObjectInputStream");
  }

  private static List<String> xmlDecoderStack() {
    return List.of(
        "io.ohmyrasp.agent.hook.OhMyRaspHooks",
        "java.beans.Expression",
        "com.sun.beans.decoder.ObjectElementHandler",
        "java.beans.XMLDecoder");
  }
}
