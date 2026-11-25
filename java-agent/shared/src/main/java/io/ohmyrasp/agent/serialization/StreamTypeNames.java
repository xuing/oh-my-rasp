package io.ohmyrasp.agent.serialization;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/** Binary names and families used by the backport type classifiers. Java names are case-sensitive. */
public final class StreamTypeNames {
  private StreamTypeNames() {}

  private static Set<String> names(String... values) {
    return Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(values)));
  }

  private static final Set<String> EXPLICIT_TYPES =
      names(
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
          "javax.management.BadAttributeValueExpException");

  public static final Set<String> CONFIG_CONTEXT_TYPES =
      names(
          "org.springframework.context.support.FileSystemXmlApplicationContext",
          "org.springframework.context.support.ClassPathXmlApplicationContext",
          "org.apache.xbean.spring.context.ResourceXmlApplicationContext",
          "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext",
          "com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext");

  public static boolean explicitlyListed(String name) { return EXPLICIT_TYPES.contains(name); }

  private static final Pattern DESERIALIZATION_GADGET_CLASS =
      Pattern.compile(
          "^(?:"
              + "com\\.sun\\.org\\.apache\\.xalan\\.internal\\.xsltc\\.trax\\.TemplatesImpl|"
              + "org\\.apache\\.xalan\\.xsltc\\.trax\\.TemplatesImpl|"
              + "com\\.sun\\.rowset\\.JdbcRowSetImpl|"
              + "java\\.lang\\.ProcessBuilder|"
              + "javax\\.script\\.ScriptEngineManager|"
              + "bsh\\.(?:XThis(?:\\$Handler)?|This|NameSpace|Interpreter|BSH[A-Za-z0-9_$]+)|"
              + "org\\.apache\\.commons\\.beanutils\\.BeanComparator|"
              + "org\\.apache\\.commons\\.collections(?:4)?\\.functors\\.(?:Invoker|Instantiate)Transformer|"
              + "org\\.codehaus\\.groovy\\.runtime\\.(?:ConvertedClosure|MethodClosure)|"
              + "org\\.springframework\\.beans\\.factory\\.config\\.(?:PropertyPathFactoryBean|MethodInvokingFactoryBean)"
              + ")$");

  // Additional types whose native serialization Apache restricted in COLLECTIONS-580.
  private static final Pattern NATIVE_COLLECTIONS_FUNCTORS = Pattern.compile(
      "org\\.apache\\.commons\\.collections(?:4)?\\.functors\\.(?:CloneTransformer|ForClosure|WhileClosure|"
          + "InstantiateFactory|PrototypeFactory\\$Prototype(?:Clone|Serialization)Factory)");

  public static boolean listedForConstruction(String name) {
    return name != null && DESERIALIZATION_GADGET_CLASS.matcher(name).matches();
  }

  public static boolean listed(String name) {
    return listedForConstruction(name) || (name != null && name.startsWith("org.apache.commons.collections")
        && NATIVE_COLLECTIONS_FUNCTORS.matcher(name).matches());
  }
}
