package io.ohmyrasp.agent.serialization;

import java.util.regex.Pattern;

/** Binary names and families used by the backport type classifiers. Java names are case-sensitive. */
public final class StreamTypeNames {
  private StreamTypeNames() {}

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
              + "org\\.apache\\.commons\\.collections(?:4)?\\.functors\\.(?:Invoker|Instantiate|Chained|Constant)Transformer|"
              + "org\\.codehaus\\.groovy\\.runtime\\.(?:ConvertedClosure|MethodClosure)|"
              + "org\\.springframework\\.beans\\.factory\\.config\\.(?:PropertyPathFactoryBean|MethodInvokingFactoryBean)"
              + ")$");

  public static boolean listed(String name) { return name != null && DESERIALIZATION_GADGET_CLASS.matcher(name).matches(); }
}
