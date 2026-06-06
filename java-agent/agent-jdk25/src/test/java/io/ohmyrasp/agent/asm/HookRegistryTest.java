package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class HookRegistryTest {
  private final HookRegistry registry = HookRegistry.defaults();

  @Test
  void recognizesJvmAndMiddlewareHookTargets() {
    assertTrue(registry.isDirectTarget("java/lang/ProcessBuilder"));
    assertTrue(registry.isDirectTarget("java/lang/Runtime"));
    assertTrue(registry.isDirectTarget("java.nio.file.Files"));
    assertTrue(registry.isDirectTarget("java/util/zip/ZipInputStream"));
    assertTrue(registry.isDirectTarget("java.util.zip.ZipFile"));
    assertTrue(registry.isDirectTarget("java/sql/DriverManager"));
    assertTrue(registry.isDirectTarget("javax/servlet/http/HttpServlet"));
    assertTrue(registry.isDirectTarget("jakarta.servlet.http.HttpServlet"));
    assertTrue(registry.isDirectTarget("javax/servlet/http/Part"));
    assertTrue(registry.isDirectTarget("jakarta.servlet.http.Part"));
    assertTrue(registry.isDirectTarget("org/apache/catalina/core/ApplicationPart"));
    assertTrue(registry.isDirectTarget("org/apache/commons/fileupload/disk/DiskFileItem"));
    assertTrue(registry.isDirectTarget("com.sun.jndi.ldap.LdapCtx"));
    assertTrue(registry.isDirectTarget("java/net/URLClassLoader"));
    assertTrue(registry.isDirectTarget("java/rmi/server/RMIClassLoader"));
    assertTrue(registry.isDirectTarget("javax/security/auth/login/AppConfigurationEntry"));
    assertTrue(registry.isDirectTarget("org/springframework/context/support/ClassPathXmlApplicationContext"));
    assertTrue(registry.isDirectTarget("org/springframework/beans/factory/xml/XmlBeanDefinitionReader"));
    assertTrue(registry.isDirectTarget("org/apache/xbean/spring/context/ResourceXmlApplicationContext"));
    assertTrue(registry.isDirectTarget("com/sun/jmx/mbeanserver/JmxMBeanServer"));
    assertTrue(registry.isDirectTarget("org/kohsuke/args4j/CmdLineParser"));
    assertTrue(registry.isDirectTarget("org/springframework/expression/spel/standard/SpelExpression"));
    assertTrue(registry.isDirectTarget("ognl/Ognl"));
    assertTrue(registry.isDirectTarget("org/apache/velocity/app/VelocityEngine"));
    assertTrue(registry.isDirectTarget("org/apache/commons/jexl/ExpressionFactory"));
    assertTrue(registry.isDirectTarget("org/apache/commons/jexl2/JexlEngine"));
    assertTrue(registry.isDirectTarget("org/apache/commons/jexl3/internal/Engine"));
    assertTrue(registry.isDirectTarget("javax/el/ExpressionFactory"));
    assertTrue(registry.isDirectTarget("jakarta/el/ExpressionFactory"));
    assertTrue(registry.isDirectTarget("javax/el/ELProcessor"));
    assertTrue(registry.isDirectTarget("org/apache/el/ExpressionFactoryImpl"));
    assertTrue(registry.isDirectTarget("com/sun/org/apache/xpath/internal/jaxp/XPathImpl"));
    assertTrue(registry.isDirectTarget("org/apache/xpath/jaxp/XPathImpl"));
    assertTrue(registry.isDirectTarget("org/jaxen/BaseXPath"));
    assertTrue(registry.isDirectTarget("org/apache/commons/jxpath/JXPathContext"));
    assertTrue(registry.isDirectTarget("org/apache/commons/jxpath/ri/JXPathContextReferenceImpl"));
    assertTrue(registry.isDirectTarget("io/ohmyrasp/playground/VulnerableServlet$PlaygroundScriptEngineImpl"));
    assertTrue(registry.isDirectTarget("org/codehaus/groovy/jsr223/GroovyScriptEngineImpl"));
    assertTrue(registry.isDirectTarget("groovy/lang/GroovyShell"));
    assertTrue(registry.isDirectTarget("org/mozilla/javascript/Context"));
    assertTrue(registry.isDirectTarget("org/mvel2/MVEL"));
    assertTrue(registry.isDirectTarget("it/geosolutions/jaiext/jiffle/Jiffle"));
    assertTrue(registry.isDirectTarget("it/geosolutions/jaiext/jiffle/JiffleBuilder"));
    assertTrue(registry.isDirectTarget("com/sun/tools/javac/api/JavacTool"));
    assertTrue(registry.isDirectTarget("org/codehaus/janino/SimpleCompiler"));
    assertTrue(registry.isDirectTarget("sun/rmi/registry/RegistryImpl"));
    assertTrue(registry.isDirectTarget("java/beans/Expression"));
    assertTrue(registry.isDirectTarget("java/beans/Statement"));
    assertTrue(registry.isDirectTarget("com/sun/beans/decoder/DocumentHandler"));
    assertTrue(registry.isDirectTarget("org/apache/catalina/session/FileStore"));
    assertTrue(registry.isDirectTarget("org/apache/catalina/session/PersistentManagerBase"));
    assertTrue(registry.isDirectTarget("com/alibaba/fastjson/parser/ParserConfig"));
    assertTrue(
        registry.isDirectTarget(
            "com/fasterxml/jackson/databind/jsontype/impl/ClassNameIdResolver"));
    assertTrue(registry.isDirectTarget("com/thoughtworks/xstream/mapper/DefaultMapper"));
    assertTrue(registry.isDirectTarget("org/yaml/snakeyaml/constructor/Constructor"));
    assertTrue(registry.isDirectTarget("org/snakeyaml/engine/v2/constructor/StandardConstructor"));
    assertTrue(registry.isDirectTarget("java/io/ObjectInputStream"));
    assertTrue(registry.isDirectTarget("org/apache/activemq/openwire/v12/BaseDataStreamMarshaller"));
    assertTrue(registry.isDirectTarget("org/springframework/remoting/httpinvoker/HttpInvokerServiceExporter"));
    assertTrue(registry.isDirectTarget("com/caucho/hessian/io/SerializerFactory"));
    assertTrue(registry.isDirectTarget("org/apache/xmlrpc/parser/SerializableParser"));
    assertTrue(registry.isDirectTarget("org/h2/jdbc/JdbcStatement"));
    assertTrue(registry.isDirectTarget("javax/activation/URLDataSource"));
    assertTrue(registry.isDirectTarget("jakarta/activation/URLDataSource"));
    assertTrue(registry.isDirectTarget("com/auth0/jwt/JWTVerifier"));
  }

  @Test
  void leavesUnrelatedJdkClassesAlone() {
    assertFalse(registry.isDirectTarget("java/lang/String"));
    assertFalse(registry.isRetransformTarget("java.util.ArrayList"));
  }
}
