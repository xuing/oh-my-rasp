package io.ohmyrasp.agent.detect;

import java.util.Set;
import io.ohmyrasp.agent.serialization.StreamTypeNames;

/** Type names and class families used by deserialization and request classifiers. */
final class DeserializationTypes {
  private DeserializationTypes() {}

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
          "com.sun.org.apache.xpath.internal.",
          "com.sun.org.apache.xml.internal.",
          "com.sun.jndi.",
          "com.sun.xml.internal.ws.",
          "sun.rmi.");

  private static final Set<String> POLYMORPHIC_CONSTRUCTION_BLACKLIST =
      Set.of("org.h2.jdbc.JdbcConnection");

  private static boolean listedClass(String name) {
    return StreamTypeNames.explicitlyListed(name) || "io.ohmyrasp.playground.EvilSerialized".equals(name);
  }

  static int xmlGadgetClassPriority(String className) {
    if (POLYMORPHIC_CONSTRUCTION_BLACKLIST.contains(className)
        || listedClass(className)) {
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
    if (className.startsWith("org.codehaus.groovy.runtime.")) {
      return StreamTypeNames.listed(className);
    }
    if (listedClass(className)) {
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
