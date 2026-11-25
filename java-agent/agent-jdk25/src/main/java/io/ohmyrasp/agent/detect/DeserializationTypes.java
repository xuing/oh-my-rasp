package io.ohmyrasp.agent.detect;

import java.util.Set;

/** Type names and class families used by deserialization and request classifiers. */
final class DeserializationTypes {
  private DeserializationTypes() {}

  private static final Set<String> DESERIALIZATION_BLACKLIST =
      Set.of(
          "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
          "org.apache.xalan.xsltc.trax.TemplatesImpl",
          "com.sun.rowset.JdbcRowSetImpl",
          "java.lang.Runtime",
          "java.lang.ProcessBuilder",
          "java.lang.ClassLoader",
          "java.net.URLClassLoader",
          "javax.script.ScriptEngineManager",
          "javax.naming.InitialContext",
          "javax.naming.ldap.Rdn$RdnEntry",
          "javax.sql.rowset.BaseRowSet",
          "sun.rmi.registry.RegistryImpl_Stub",
          "org.mozilla.javascript.NativeJavaObject",
          "org.mozilla.javascript.NativeJavaArray",
          "org.mozilla.javascript.ScriptableObject",
          "org.mozilla.javascript.tools.shell.Environment",
          "org.springframework.context.support.FileSystemXmlApplicationContext",
          "org.springframework.context.support.ClassPathXmlApplicationContext",
          "org.apache.commons.collections.functors.InvokerTransformer",
          "org.apache.commons.collections4.functors.InvokerTransformer",
          "org.codehaus.groovy.runtime.ConvertedClosure",
          "org.springframework.beans.factory.ObjectFactory",
          "javax.management.BadAttributeValueExpException",
          "io.ohmyrasp.playground.EvilSerialized");

  static final Set<String> PROTOCOL_CONFIG_INSTANTIATION_TYPES =
      Set.of(
          "org.springframework.context.support.FileSystemXmlApplicationContext",
          "org.springframework.context.support.ClassPathXmlApplicationContext",
          "org.apache.xbean.spring.context.ResourceXmlApplicationContext",
          "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext",
          "com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext");

  private static final Set<String> DESERIALIZATION_GADGET_PREFIXES =
      Set.of(
          "bsh.",
          "com.mchange.v2.c3p0.",
          "com.rometools.rome.feed.impl.",
          "com.sun.syndication.feed.impl.");

  private static final Set<String> DESERIALIZATION_TYPE_PREFIXES =
      Set.of(
          "org.apache.commons.collections.functors.",
          "org.apache.commons.collections4.functors.",
          "org.codehaus.groovy.runtime.",
          "com.sun.org.apache.xpath.internal.",
          "com.sun.org.apache.xml.internal.",
          "com.sun.jndi.",
          "com.sun.xml.internal.ws.",
          "sun.rmi.");

  private static final Set<String> POLYMORPHIC_CONSTRUCTION_BLACKLIST =
      Set.of("org.h2.jdbc.JdbcConnection");

  static int xmlGadgetClassPriority(String className) {
    if (POLYMORPHIC_CONSTRUCTION_BLACKLIST.contains(className)
        || DESERIALIZATION_BLACKLIST.contains(className)) {
      return 0;
    }
    if (deserializationGadgetType(className)) {
      return 1;
    }
    return 2;
  }

  static boolean dangerousDeserializationType(String className) {
    if (className.isBlank()) {
      return false;
    }
    if (DESERIALIZATION_BLACKLIST.contains(className)) {
      return true;
    }
    if (deserializationGadgetType(className)) {
      return true;
    }
    for (String prefix : DESERIALIZATION_TYPE_PREFIXES) {
      if (className.startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  static boolean dangerousPolymorphicType(String className) {
    return POLYMORPHIC_CONSTRUCTION_BLACKLIST.contains(className)
        || dangerousDeserializationType(className);
  }

  static boolean dangerousHessianType(String className) {
    return dangerousDeserializationType(className)
        || POLYMORPHIC_CONSTRUCTION_BLACKLIST.contains(className)
        || PROTOCOL_CONFIG_INSTANTIATION_TYPES.contains(className);
  }

  static boolean deserializationGadgetType(String className) {
    if (className.equals("org.apache.commons.beanutils.BeanComparator")) {
      return true;
    }
    for (String prefix : DESERIALIZATION_GADGET_PREFIXES) {
      if (className.startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  static String normalizeJavaTypeName(String className) {
    if (className == null) {
      return "";
    }
    String normalized = className.trim().replace('/', '.');
    while (normalized.startsWith("[")) {
      normalized = normalized.startsWith("[L") ? normalized.substring(2) : normalized.substring(1);
    }
    if (normalized.endsWith(";")) {
      while (normalized.startsWith("L") && normalized.length() > 1) {
        normalized = normalized.substring(1);
      }
      while (normalized.endsWith(";")) {
        normalized = normalized.substring(0, normalized.length() - 1);
      }
    }
    return normalized;
  }
}
