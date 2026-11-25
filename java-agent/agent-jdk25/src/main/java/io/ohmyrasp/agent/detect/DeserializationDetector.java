package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DeserializationTypes.dangerousDeserializationType;
import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationTypes;
import static io.ohmyrasp.agent.detect.DeserializationTypes.dangerousPolymorphicType;
import static io.ohmyrasp.agent.detect.DeserializationTypes.deserializationGadgetType;
import static io.ohmyrasp.agent.detect.DeserializationTypes.normalizeJavaTypeName;
import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/** Correlate deserialized types with the transport, session or unmarshaller that supplied them. */
final class DeserializationDetector {
  private DeserializationDetector() {}

  static Optional<Detection> detectDeserialization(String className, RequestContext request) {
    return detectDeserialization(className, request, List.of());
  }

  static boolean isDangerousDeserializationType(String className) {
    if (className == null || className.isBlank()) {
      return false;
    }
    return dangerousDeserializationType(normalizeJavaTypeName(className));
  }

  static Optional<Detection> detectDeserialization(
      String className, RequestContext request, List<String> stackClassNames) {
    if (className == null || className.isBlank()) {
      return Optional.empty();
    }
    String normalized = normalizeJavaTypeName(className);
    Optional<String> signedObjectTransport = signedObjectRemotingFrame(stackClassNames);
    if (normalized.equals("java.security.SignedObject") && signedObjectTransport.isPresent()) {
      return Optional.of(
          Detection.log(
              "deserialization",
              "deserialization_signed_object",
              95,
              "Remote CLI/remoting transport deserialized a SignedObject wrapper",
              request,
              Map.of(
                  "class", normalized,
                  "transport", signedObjectTransport.orElseThrow())));
    }
    if (dangerousDeserializationType(normalized)) {
      Optional<String> webflowState = webflowClientStateFrame(stackClassNames);
      if (webflowState.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_webflow_state",
                95,
                "WebFlow client state deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", webflowState.orElseThrow())));
      }
	      Optional<String> clusterTransport = clusterMessageTransportFrame(stackClassNames);
	      if (clusterTransport.isPresent()) {
	        Map<String, String> details = new LinkedHashMap<>();
	        details.put("class", normalized);
	        details.put("transport", clusterTransport.orElseThrow());
	        clusterSecurityInterceptorFrame(stackClassNames)
	            .ifPresent(interceptor -> details.put("securityInterceptor", interceptor));
	        return Optional.of(
	            Detection.log(
	                "deserialization",
	                "deserialization_cluster_message",
	                95,
	                "Cluster/message transport deserialized a dangerous gadget class",
	                request,
	                details));
	      }
      Optional<String> loggingTransport = loggingMessageTransportFrame(stackClassNames);
      if (loggingTransport.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_logging_message",
                95,
                "Logging transport deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", loggingTransport.orElseThrow())));
      }
      Optional<String> rmiTransport = rmiTransportFrame(stackClassNames);
      if (rmiTransport.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_rmi_transport",
                95,
                "RMI transport deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", rmiTransport.orElseThrow())));
      }
      Optional<String> remotingTransport = remotingTransportFrame(stackClassNames);
      if (remotingTransport.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_remoting_transport",
                95,
                "Application remoting transport deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", remotingTransport.orElseThrow())));
      }
      Optional<String> jmsObjectMessage = jmsObjectMessageFrame(stackClassNames);
      if (jmsObjectMessage.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_jms_object_message",
                95,
                "JMS ObjectMessage deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", jmsObjectMessage.orElseThrow())));
      }
      boolean gadgetFamily = deserializationGadgetType(normalized);
      return Optional.of(
          Detection.log(
              "deserialization",
              gadgetFamily ? "deserialization_gadget" : "deserialization_blacklist",
              gadgetFamily ? 95 : 100,
              (gadgetFamily
                      ? "Deserialization gadget family matched class "
                      : "Deserialization blacklist matched class ")
                  + normalized,
              request,
              Map.of("class", normalized)));
    }
    return Optional.empty();
  }

  static Optional<Detection> detectRmiRegistryBind(
      String operation,
      String bindingName,
      String remoteClassName,
      RequestContext request,
      List<String> stackClassNames) {
    String normalizedOperation = lower(operation).replaceAll("[^a-z]", "");
    if (!normalizedOperation.equals("bind") && !normalizedOperation.equals("rebind")) {
      return Optional.empty();
    }
    String normalizedRemoteClass = normalizeJavaTypeName(remoteClassName);
    if (!suspiciousRmiRemoteBindType(normalizedRemoteClass)
        || !rmiRegistryTransportStack(stackClassNames)) {
      return Optional.empty();
    }
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_rmi_registry_bind",
            95,
            "RMI Registry bind receives a remote proxy/reference through transport dispatch",
            safeRequest,
            Map.of(
                "operation", normalizedOperation,
                "binding", abbreviate(bindingName),
                "remoteClass", abbreviate(normalizedRemoteClass),
                "source", "rmi-transport")));
  }

  static Optional<Detection> detectSessionDeserialization(
      String sessionId, String mechanism, RequestContext request) {
    if (sessionId == null || sessionId.isBlank()) {
      return Optional.empty();
    }
    String normalized = sessionId.trim();
    if (!suspiciousFileBackedSessionId(normalized)) {
      return Optional.empty();
    }
    String source = mechanism == null || mechanism.isBlank() ? "session" : mechanism;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_session_file",
            request.active() ? 95 : 90,
            "File-backed session deserialization uses a suspicious session identifier",
            request,
            Map.of(
                "sessionId", abbreviate(normalized),
                "mechanism", source)));
  }

  static Optional<Detection> detectPolymorphicType(
      String parser, String className, RequestContext request) {
    if (className == null || className.isBlank()) {
      return Optional.empty();
    }
    String normalized = normalizeJavaTypeName(className);
    if (!dangerousPolymorphicType(normalized)) {
      return Optional.empty();
    }
    int confidence = request.hasParameterIn(className) || request.hasParameterIn(normalized) ? 100 : 95;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_polymorphic_type",
            confidence,
            "Polymorphic deserialization attempted to resolve a dangerous type",
            request,
            Map.of(
                "parser", String.valueOf(parser),
                "class", normalized,
                "originalClass", abbreviate(className))));
  }

  static Optional<Detection> detectFastjsonClassResource(
      String resource, RequestContext request) {
    Optional<String> mechanism = fastjsonClassResourceMechanism(resource);
    if (mechanism.isEmpty()) {
      return Optional.empty();
    }
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    return Optional.of(
        Detection.log(
                "deserialization",
                "deserialization_fastjson_resource_url",
                100,
                "Fastjson autoType attempted to resolve a URL-shaped class resource",
                safeRequest,
                Map.of(
                    "mechanism", mechanism.orElseThrow(),
                    "resource", abbreviate(resource),
                    "source", "ParserConfig.checkAutoType"))
            .withAction("block"));
  }

  static Optional<Detection> detectOpenWireThrowable(Class<?> selected, RequestContext request) {
    if (selected == null || Throwable.class.isAssignableFrom(selected)) return Optional.empty();
    return Optional.of(Detection.log("deserialization", "deserialization_protocol_class", 100,
        "OpenWire selected a non-Throwable constructor for an exception",
        request == null ? RequestContext.empty() : request,
        Map.of("protocol", "OpenWire", "class", selected.getName(), "decision_basis", "non_throwable_constructor")));
  }

  static Optional<Detection> detectHttpInvokerDeserialization(
      String mechanism, RequestContext request) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (!safeRequest.active()) {
      return Optional.empty();
    }
    String source = mechanism == null || mechanism.isBlank() ? "SpringHttpInvoker" : mechanism;
    String contentType = safeRequest.header("content-type").orElse("");
    String normalizedContentType = lower(contentType);
    int confidence =
        normalizedContentType.contains("application/x-java-serialized-object")
            ? 98
            : (normalizedContentType.contains("application/x-java")
                    || normalizedContentType.contains("application/octet-stream"))
                ? 95
                : 90;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_http_invoker",
            confidence,
            "HTTP remote invocation endpoint is deserializing a Java object stream",
            safeRequest,
            Map.of(
                "mechanism", source,
                "method", safeRequest.method(),
                "uri", abbreviate(safeRequest.uri()),
                "contentType", abbreviate(contentType))));
  }

  static Optional<Detection> detectHttpObjectStreamDeserialization(
      String streamClassName, RequestContext request, List<String> stackClassNames) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (!safeRequest.active()) {
      return Optional.empty();
    }
    String source =
        httpObjectStreamSource(
            streamClassName, safeRequest.header("content-type").orElse(""), stackClassNames);
    if (source.isBlank()) {
      return Optional.empty();
    }
    String contentType = safeRequest.header("content-type").orElse("");
    int confidence = "serialized-content-type".equals(source) ? 98 : 95;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_http_object_stream",
            confidence,
            "HTTP request body is being read through a Java ObjectInputStream",
            safeRequest,
            Map.of(
                "source", source,
                "streamClass", abbreviate(streamClassName),
                "method", safeRequest.method(),
                "uri", abbreviate(safeRequest.uri()),
                "contentType", abbreviate(contentType))));
  }

  static Optional<Detection> detectHessianAllocation(Class<?> selected, String basis, RequestContext request) {
    if (!HessianAllocationTypes.listed(selected)) return Optional.empty();
    return Optional.of(Detection.log("deserialization", "deserialization_hessian_type", 95,
        "Hessian selected a listed type for allocation", request == null ? RequestContext.empty() : request,
        Map.of("protocol", "hessian", "class", selected.getName(), "decision_basis", basis)));
  }

  static Optional<Detection> detectXmlRpcSerializableValue(
      String mechanism, RequestContext request) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (!safeRequest.active()) {
      return Optional.empty();
    }
    String source = mechanism == null || mechanism.isBlank() ? "ApacheXmlRpc" : mechanism;
    String contentType = safeRequest.header("content-type").orElse("");
    int confidence =
        lower(contentType).contains("xml")
            || safeRequest.uri().toLowerCase(Locale.ROOT).contains("xmlrpc")
            ? 98
            : 92;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_xmlrpc_serialized",
            confidence,
            "XML-RPC request is deserializing a Java serialized extension value",
            safeRequest,
            Map.of(
                "mechanism", source,
                "method", safeRequest.method(),
                "uri", abbreviate(safeRequest.uri()),
                "contentType", abbreviate(contentType))));
  }

  private static Optional<String> fastjsonClassResourceMechanism(String resource) {
    if (resource == null || resource.isBlank()) {
      return Optional.empty();
    }
    String normalized = lower(resource.trim());
    if (normalized.startsWith("http://")) {
      return Optional.of("http");
    }
    if (normalized.startsWith("https://")) {
      return Optional.of("https");
    }
    if (normalized.startsWith("jar:http://")) {
      return Optional.of("jar:http");
    }
    if (normalized.startsWith("jar:https://")) {
      return Optional.of("jar:https");
    }
    if (normalized.startsWith("jar:file:/proc/self/fd/")) {
      return Optional.of("jar:file:proc-fd");
    }
    return Optional.empty();
  }

  private static boolean suspiciousRmiRemoteBindType(String className) {
    String normalized = lower(className);
    return normalized.contains("$proxy")
        || normalized.startsWith("jdk.proxy")
        || normalized.startsWith("com.sun.proxy.")
        || normalized.equals("sun.rmi.server.unicastref")
        || normalized.equals("sun.rmi.server.unicastref2")
        || normalized.equals("sun.rmi.server.remoteobjectinvocationhandler")
        || normalized.equals("sun.rmi.transport.liveref")
        || normalized.equals("sun.rmi.transport.tcp.tcpendpoint")
        || normalized.endsWith(".rmisocketfactory");
  }

  private static boolean rmiRegistryTransportStack(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return false;
    }
    boolean registry = false;
    boolean transport = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.equals("sun.rmi.registry.registryimpl")
          || normalized.equals("sun.rmi.registry.registryimpl_skel")) {
        registry = true;
      }
      if (normalized.startsWith("sun.rmi.server.unicastserverref")
          || normalized.startsWith("sun.rmi.transport.")
          || normalized.startsWith("sun.rmi.transport.tcp.")) {
        transport = true;
      }
    }
    return registry && transport;
  }

  private static Optional<String> rmiTransportFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean serverDispatch = false;
    boolean transport = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("sun.rmi.server.unicastserverref")
          || normalized.startsWith("sun.rmi.registry.registryimpl")
          || normalized.startsWith("java.rmi.server.remoteobject")) {
        serverDispatch = true;
      }
      if (normalized.startsWith("sun.rmi.transport.")
          || normalized.startsWith("sun.rmi.transport.tcp.")) {
        transport = true;
      }
    }
    return serverDispatch && transport ? Optional.of("rmi-transport") : Optional.empty();
  }

  private static Optional<String> remotingTransportFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean weblogicT3 = false;
    boolean weblogicIiop = false;
    boolean objectStream = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("weblogic.rjvm.")
          || normalized.startsWith("weblogic.socket.")
          || normalized.startsWith("weblogic.protocol.")) {
        weblogicT3 = true;
      }
      if (normalized.startsWith("weblogic.iiop.")
          || normalized.startsWith("weblogic.corba.")
          || normalized.startsWith("weblogic.rmi.internal.")) {
        weblogicIiop = true;
      }
      if (normalized.contains("inboundmsgabbrev")
          || normalized.contains("msgabbrev")
          || normalized.contains("iiopinputstream")
          || normalized.contains("serverchannelinputstream")
          || normalized.startsWith("weblogic.utils.io.")) {
        objectStream = true;
      }
    }
    if (objectStream && weblogicT3) {
      return Optional.of("weblogic-t3");
    }
    if (objectStream && weblogicIiop) {
      return Optional.of("weblogic-iiop");
    }
    return Optional.empty();
  }

  private static Optional<String> jmsObjectMessageFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean objectMessage = false;
    boolean objectStream = false;
    String provider = "";
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.contains(".objectmessage")
          || normalized.endsWith("activemqobjectmessage")
          || normalized.endsWith("messagebody")) {
        objectMessage = true;
      }
      if (normalized.contains("objectinputstream")
          || normalized.contains("classloadingawareobjectinputstream")) {
        objectStream = true;
      }
      if (provider.isBlank() && normalized.startsWith("org.apache.activemq.")) {
        provider = "activemq-object-message";
      } else if (provider.isBlank() && normalized.startsWith("org.apache.qpid.jms.")) {
        provider = "qpid-jms-object-message";
      } else if (provider.isBlank() && normalized.startsWith("com.sun.messaging.jms.")) {
        provider = "openmq-object-message";
      } else if (provider.isBlank() && normalized.startsWith("com.ibm.msg.client.jms.")) {
        provider = "ibm-mq-object-message";
      }
    }
    return !provider.isBlank() && objectMessage && objectStream
        ? Optional.of(provider)
        : Optional.empty();
  }

  private static Optional<String> signedObjectRemotingFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean cli = false;
    boolean objectStream = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("hudson.cli.")
          || normalized.startsWith("jenkins.cli.")
          || normalized.startsWith("hudson.remoting.")
          || normalized.startsWith("org.jenkinsci.remoting.")) {
        cli = true;
      }
      if (normalized.contains("objectinputstream")
          || normalized.contains("objectinputstreamex")
          || normalized.contains("remoting")) {
        objectStream = true;
      }
    }
    return cli && objectStream ? Optional.of("jenkins-cli-remoting") : Optional.empty();
  }

  private static Optional<String> webflowClientStateFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean cas = false;
    boolean webflow = false;
    boolean clientState = false;
    boolean objectStream = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("org.jasig.cas.") || normalized.startsWith("org.apereo.cas.")) {
        cas = true;
      }
      if (normalized.startsWith("org.springframework.webflow.")
          || normalized.contains("webflow")) {
        webflow = true;
      }
      if (normalized.contains("clientflowexecution")
          || normalized.contains("flowexecutionsnapshot")
          || normalized.contains("encryptedtranscoder")
          || normalized.contains("serializedflowexecution")) {
        clientState = true;
      }
      if (normalized.contains("objectinputstream") || normalized.contains("readobject")) {
        objectStream = true;
      }
    }
    if (objectStream && clientState && (cas || webflow)) {
      return Optional.of(cas ? "cas-webflow-state" : "spring-webflow-client-state");
    }
    return Optional.empty();
  }

	  private static Optional<String> clusterMessageTransportFrame(List<String> stackClassNames) {
	    if (stackClassNames == null) {
	      return Optional.empty();
	    }
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("org.apache.catalina.tribes.")
          || normalized.startsWith("org.apache.catalina.ha.")) {
        return Optional.of("tomcat-tribes");
      }
      if (normalized.startsWith("org.jgroups.")
          || normalized.startsWith("org.infinispan.remoting.")) {
        return Optional.of("jgroups");
      }
      if (normalized.startsWith("com.hazelcast.internal.serialization.")
          || normalized.startsWith("com.hazelcast.nio.serialization.")) {
        return Optional.of("hazelcast");
      }
	    }
	    return Optional.empty();
	  }

	  private static Optional<String> clusterSecurityInterceptorFrame(List<String> stackClassNames) {
	    if (stackClassNames == null) {
	      return Optional.empty();
	    }
	    for (String frame : stackClassNames) {
	      String normalized = lower(frame).replace('/', '.');
	      if (normalized.equals("org.apache.catalina.tribes.group.interceptors.encryptinterceptor")) {
	        return Optional.of("tomcat-tribes-encrypt");
	      }
	    }
	    return Optional.empty();
	  }

	  private static Optional<String> loggingMessageTransportFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("org.apache.logging.log4j.core.net.server.")
          || normalized.startsWith("org.apache.logging.log4j.core.net.")
          || normalized.startsWith("org.apache.log4j.net.")) {
        return Optional.of("log4j-socket");
      }
    }
    return Optional.empty();
  }

  private static String httpObjectStreamSource(
      String streamClassName, String contentType, List<String> stackClassNames) {
    String stream = lower(streamClassName);
    if (stream.contains("servletinputstream")
        || stream.contains("coyoteinputstream")
        || stream.contains("servletrequestinputstream")
        || stream.contains("requestinputstream")
        || stream.contains("httpinput")) {
      return "servlet-input-stream";
    }
    String normalizedContentType = lower(contentType);
    if (normalizedContentType.contains("application/x-java-serialized-object")
        || normalizedContentType.contains("application/x-java")) {
      return "serialized-content-type";
    }
    List<String> safeStack = stackClassNames == null ? List.of() : stackClassNames;
    for (String className : safeStack) {
      String item = lower(className);
      if ((item.contains("readonlyaccessfilter")
              || item.contains("jmxinvokerservlet")
              || item.contains("org.jboss.invocation.http.servlet.invokerservlet")
              || item.contains("httpserverilservlet"))
          && (item.contains("jboss") || item.contains("invoker") || item.contains("httpil"))) {
        return "middleware-http-invoker";
      }
    }
    return "";
  }

  private static boolean suspiciousFileBackedSessionId(String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      return false;
    }
    String normalized = sessionId.trim().replace('\\', '/');
    String lower = normalized.toLowerCase(Locale.ROOT);
    return lower.startsWith(".")
        || lower.contains("..")
        || lower.contains("/")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c");
  }
}
