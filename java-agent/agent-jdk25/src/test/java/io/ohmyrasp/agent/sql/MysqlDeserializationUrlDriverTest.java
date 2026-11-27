package io.ohmyrasp.agent.sql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The shared MySQL rule ({@link MysqlDeserializationUrl}) against the drivers' own URL parsers: Connector/J 8.0.33 and
 * 5.1.49 (the last of the lines that deserialize) and MariaDB Connector/J 3.5, each loaded in a class loader of its own
 * from the paths build.gradle.kts passes.
 *
 * <ul>
 *   <li>The rule fires whenever either Connector/J line reads the URL with {@code autoDeserialize} on and
 *       {@code ServerStatusDiffInterceptor} as an interceptor entry or {@code detectCustomCollations} on; it does not
 *       fire where neither does, except the deliberate over-readings in {@link #OVER_READ}.
 *   <li>The host the event shows is the host the driver connects to, or empty; the event never carries the user or
 *       the password, in whichever of the drivers' forms the URL puts them.
 * </ul>
 */
final class MysqlDeserializationUrlDriverTest {
  private static final String SSD = "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";
  private static final String SSD51 = "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor";
  private static final String USER = "Sentinel-User-7";
  private static final String PASSWORD = "Sentinel-Pw-9";
  private static final String DB = "db.internal";

  /** URLs whose options either driver line reads as the deserialization chain. */
  private static final List<String> ATTACKS = List.of(
      "jdbc:mysql://" + USER + ":" + PASSWORD + "@" + DB + ":3306/app?autoDeserialize=true&queryInterceptors=" + SSD,
      "jdbc:mysql://address=(host=" + DB + ")(port=3307)(user=" + USER + ")(password=" + PASSWORD
          + ")(autoDeserialize=true)(queryInterceptors=" + SSD + ")/app",
      "jdbc:mysql://(host=" + DB + ",port=3308,user=" + USER + ",password=" + PASSWORD
          + ",autoDeserialize=yes)/app?queryInterceptors=" + SSD,
      "jdbc:mysql://" + DB + "/app?autoDeserialize=%74rue&queryInterceptors=a.B%2C" + SSD,
      "jdbc:mysql://" + DB + "/app?autoDeserialize= TRUE &queryInterceptors= " + SSD + " , a.B",
      "jdbc:mysql://" + DB + "/app?queryInterceptors=" + SSD + "&autoDeserialize=false&autoDeserialize=true",
      "jdbc:mysql://" + DB + "/app?auto%44eserialize=true&queryInterceptors=" + SSD,
      "jdbc:mysql://" + DB + "/app?statementInterceptors=" + SSD51 + "&autoDeserialize=true",
      "jdbc:mysql://" + DB + "/app?autoDeserialize=yes&detectCustomCollations=true",
      "jdbc:mysql:replication://" + USER + ":" + PASSWORD + "@db1.internal,db2.internal/app?autoDeserialize=true"
          + "&queryInterceptors=" + SSD,
      "jdbc:mysql:loadbalance://(host=db1.internal,user=" + USER + ",password=" + PASSWORD + "),address=(host="
          + "db2.internal)(password=" + PASSWORD + ")(autoDeserialize=true)/app?queryInterceptors=" + SSD,
      "jdbc:mysql://[address=(host=" + DB + ")(user=" + USER + ")(password=" + PASSWORD + "),db2.internal:3310]/app"
          + "?autoDeserialize=true&queryInterceptors=" + SSD,
      "jdbc:mysql://" + DB + "/app?user=" + USER + "&password=" + PASSWORD + "&autoDeserialize=TRUE&queryInterceptors="
          + SSD,
      "jdbc:mysql://" + USER + ":" + PASSWORD + "@[::1]:3306/app?autoDeserialize=true&queryInterceptors=" + SSD,
      "jdbc:mysql://" + DB + "/app?queryInterceptors=" + SSD + "&autoDeserialize=true#fragment",
      // Connector/J 5.1 does not end the query at #.
      "jdbc:mysql://" + DB + "/app?autoDeserialize=true&x=#&statementInterceptors=" + SSD51,
      // Connector/J 8 lets the host's own false win; 5.1 reads the query alone.
      "jdbc:mysql://address=(host=" + DB + ")(autoDeserialize=false)/app?autoDeserialize=true&statementInterceptors="
          + SSD51,
      // Connector/J 8 trims a key.
      "jdbc:mysql://" + DB + "/app?autoDeserialize = true&queryInterceptors = " + SSD);

  /** URLs that name the options' words without the chain: no driver reads them as it. */
  private static final List<String> BENIGN = List.of(
      "jdbc:mysql://" + DB + "/app?autoDeserialize=true&autoDeserialize=false&queryInterceptors=" + SSD,
      "jdbc:mysql://" + DB + "/app?autoDeserialize=true&queryInterceptors=" + SSD + "X",
      "jdbc:mysql://" + DB + "/app?connectionAttributes=autoDeserialize:true,queryInterceptors:" + SSD,
      "jdbc:mysql://" + DB + "/app?autoDeserialize=true&queryInterceptors=com.example.TracingInterceptor",
      "jdbc:mysql://" + DB + "/app?autoDeserialize=true&sessionVariables=queryInterceptors=" + SSD,
      "jdbc:mysql://" + DB + "/app?autoDeserialize=true&queryInterceptors=" + SSD + "&queryInterceptors=a.B",
      "jdbc:mysql://" + DB + "/app?autoDeserialize=true&applicationName=detectCustomCollations=true",
      "jdbc:mysql://" + DB + "/app?password=" + PASSWORD + "&user=" + USER,
      "jdbc:mysql://" + DB + "/app?autoDeserialize=true",
      "jdbc:mysql://" + DB + "/app?autoDeserialize=no&queryInterceptors=" + SSD,
      // Both lines split the query on & and = before decoding: encoded separators carry no option.
      "jdbc:mysql://" + DB + "/app?autoDeserialize%3Dtrue%26queryInterceptors%3D" + SSD,
      "jdbc:mariadb://address=(host=" + DB + ")(port=3307)(user=" + USER + ")(password=" + PASSWORD + ")/app",
      // A / inside a key-value password ends the authority early: Connector/J then reads a piece of the password
      // after its @ as the host. The rule names no host there.
      "jdbc:mysql://[address=(host=" + DB + ")(password=" + USER + "@Pw/9),db2.internal:3310]/app?useSSL=true");

  /**
   * Readings the rule makes on purpose where both drivers read the URL differently, each with its reason: keys are
   * compared ignoring case; {@code 1} counts as on; either line's interceptor key counts with either line's class
   * name; the mariadb scheme is covered as the backports covered it, though MariaDB has no autoDeserialize.
   */
  private static final Map<String, String> OVER_READ = Map.of(
      "jdbc:mysql://" + DB + "/app?autodeserialize=true&queryinterceptors=" + SSD, "keys ignore case",
      "jdbc:mysql://" + DB + "/app?autoDeserialize=1&queryInterceptors=" + SSD, "1 is on",
      "jdbc:mysql://" + DB + "/app?statementInterceptors=" + SSD + "&autoDeserialize=true", "either key, either class",
      "jdbc:mariadb://" + DB + ":3306/app?user=" + USER + "&password=" + PASSWORD
          + "&autoDeserialize=true&queryInterceptors=" + SSD, "the mariadb scheme");

  private static ClassLoader connectorJ8;
  private static ClassLoader connectorJ51;
  private static ClassLoader mariadb;

  @BeforeAll
  static void loadDrivers() throws Exception {
    connectorJ8 = loader("connectorj8");
    connectorJ51 = loader("connectorj51");
    mariadb = loader("mariadb");
  }

  @Test
  void theRuleFiresExactlyWhereADriverReadsTheChain() throws Exception {
    for (String url : ATTACKS) {
      assertTrue(connectorJ8Triggers(url) || connectorJ51Triggers(url), "the oracle reads an attack: " + url);
      assertNotNull(MysqlDeserializationUrl.trigger(url), url);
    }
    for (String url : BENIGN) {
      assertFalse(connectorJ8Triggers(url) || connectorJ51Triggers(url), "the oracle reads no chain: " + url);
      assertEquals(null, MysqlDeserializationUrl.trigger(url), url);
    }
    for (Map.Entry<String, String> over : OVER_READ.entrySet()) {
      assertFalse(connectorJ8Triggers(over.getKey()) || connectorJ51Triggers(over.getKey()), over.getKey());
      assertNotNull(MysqlDeserializationUrl.trigger(over.getKey()), over.getValue() + ": " + over.getKey());
    }
  }

  /**
   * A DNS SRV URL ({@code jdbc:mysql+srv:}, Connector/J 8.0.19 and later) is the same driver with the same options:
   * the rule reads it as it reads {@code jdbc:mysql:}. (Listing its hosts would resolve DNS, so only the scheme is
   * asked of the driver.)
   */
  @Test
  void aDnsSrvUrlIsTheSameDriver() throws Exception {
    String url = "jdbc:mysql+srv://" + USER + ":" + PASSWORD + "@" + DB + "/app?autoDeserialize=true&queryInterceptors="
        + SSD;
    Class<?> connectionUrl = Class.forName("com.mysql.cj.conf.ConnectionUrl", true, connectorJ8);
    assertTrue((Boolean) connectionUrl.getMethod("acceptsUrl", String.class).invoke(null, url));
    assertEquals("autoDeserialize+ServerStatusDiffInterceptor", MysqlDeserializationUrl.trigger(url));
    assertEquals("driver=mysql host=" + DB + " options=autoDeserialize+ServerStatusDiffInterceptor",
        MysqlDeserializationUrl.evidence(url));
  }

  @Test
  void theEventShowsTheDriversHostAndNeverItsCredentials() throws Exception {
    List<String> all = new ArrayList<>(ATTACKS);
    all.addAll(BENIGN);
    all.addAll(OVER_READ.keySet());
    for (String url : all) {
      String evidence = MysqlDeserializationUrl.evidence(url);
      assertFalse(evidence.contains("Sentinel") || evidence.contains("Pw"), evidence + " <- " + url);
      String host = MysqlDeserializationUrl.host(url);
      String expected = url.startsWith("jdbc:mariadb:") ? mariadbHost(url) : connectorJ8Host(url);
      if (expected != null && !expected.contains("Sentinel") && !expected.equals("Pw")) {
        assertEquals(expected, host.startsWith("[") ? host.substring(0, host.indexOf(']') + 1)
            : host.replaceFirst(":\\d+$", ""), url);
      } else {
        assertEquals("", host, "the driver's host is part of a credential: " + url);
      }
    }
  }

  private static boolean connectorJ8Triggers(String url) throws Exception {
    Class<?> connectionUrl = Class.forName("com.mysql.cj.conf.ConnectionUrl", true, connectorJ8);
    Object parsed;
    try {
      parsed = connectionUrl.getMethod("getConnectionUrlInstance", String.class, Properties.class)
          .invoke(null, url, new Properties());
    } catch (InvocationTargetException rejected) {
      return false; // the driver refuses the URL: it never connects
    }
    List<?> hosts;
    try {
      hosts = (List<?>) connectionUrl.getMethod("getHostsList").invoke(parsed);
    } catch (InvocationTargetException rejected) {
      return false;
    }
    for (Object host : hosts) {
      Properties exposed = (Properties) host.getClass().getMethod("exposeAsProperties").invoke(host);
      Class<?> set = Class.forName("com.mysql.cj.jdbc.JdbcPropertySetImpl", true, connectorJ8);
      Object properties = set.getConstructor().newInstance();
      try {
        set.getMethod("initializeProperties", Properties.class).invoke(properties, exposed);
      } catch (InvocationTargetException rejected) {
        continue; // an option value the driver does not accept: no connection
      }
      Class<?> key = Class.forName("com.mysql.cj.conf.PropertyKey", true, connectorJ8);
      boolean autoDeserialize = Boolean.TRUE.equals(value(set, properties, "getBooleanProperty", key, "autoDeserialize"));
      Object interceptors = value(set, properties, "getStringProperty", key, "queryInterceptors");
      boolean collations = Boolean.TRUE.equals(value(set, properties, "getBooleanProperty", key, "detectCustomCollations"));
      if (autoDeserialize && (names(interceptors, SSD) || collations)) return true;
    }
    return false;
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static Object value(Class<?> set, Object properties, String getter, Class<?> key, String name)
      throws Exception {
    Object property = set.getMethod(getter, key).invoke(properties, Enum.valueOf((Class) key, name));
    return property.getClass().getMethod("getValue").invoke(property);
  }

  private static boolean connectorJ51Triggers(String url) throws Exception {
    Object driver = Class.forName("com.mysql.jdbc.NonRegisteringDriver", true, connectorJ51).getConstructor().newInstance();
    Properties parsed = (Properties) driver.getClass().getMethod("parseURL", String.class, Properties.class)
        .invoke(driver, url, null);
    if (parsed == null) return false;
    Class<?> impl = Class.forName("com.mysql.jdbc.ConnectionPropertiesImpl", true, connectorJ51);
    Object properties = impl.getDeclaredConstructor().newInstance();
    Method initialize = impl.getDeclaredMethod("initializeProperties", Properties.class);
    initialize.setAccessible(true);
    try {
      initialize.invoke(properties, parsed);
    } catch (InvocationTargetException rejected) {
      return false;
    }
    boolean autoDeserialize = (Boolean) impl.getMethod("getAutoDeserialize").invoke(properties);
    Object interceptors = impl.getMethod("getStatementInterceptors").invoke(properties);
    boolean collations = (Boolean) impl.getMethod("getDetectCustomCollations").invoke(properties);
    return autoDeserialize && (names(interceptors, SSD51) || collations);
  }

  /** Whether the comma list {@code interceptors} has {@code name} as an entry, as the drivers split it. */
  private static boolean names(Object interceptors, String name) {
    if (interceptors == null) return false;
    for (String entry : interceptors.toString().split(",")) {
      if (entry.trim().equals(name)) return true;
    }
    return false;
  }

  /** The main host Connector/J 8 connects to, or null when it refuses the URL. */
  private static String connectorJ8Host(String url) throws Exception {
    Class<?> connectionUrl = Class.forName("com.mysql.cj.conf.ConnectionUrl", true, connectorJ8);
    try {
      Object parsed = connectionUrl.getMethod("getConnectionUrlInstance", String.class, Properties.class)
          .invoke(null, url, new Properties());
      Object main = connectionUrl.getMethod("getMainHost").invoke(parsed);
      return (String) main.getClass().getMethod("getHost").invoke(main);
    } catch (InvocationTargetException rejected) {
      return null;
    }
  }

  private static String mariadbHost(String url) throws Exception {
    Class<?> configuration = Class.forName("org.mariadb.jdbc.Configuration", true, mariadb);
    Object parsed = configuration.getMethod("parse", String.class).invoke(null, url);
    Object first = ((List<?>) configuration.getMethod("addresses").invoke(parsed)).get(0);
    return (String) first.getClass().getField("host").get(first);
  }

  private static ClassLoader loader(String driver) throws Exception {
    String path = System.getProperty("ohmyrasp.test.jdbc." + driver);
    assertNotNull(path, "build.gradle.kts passes the " + driver + " class path");
    List<URL> urls = new ArrayList<>();
    for (String entry : path.split(File.pathSeparator)) urls.add(new File(entry).toURI().toURL());
    return new URLClassLoader(urls.toArray(new URL[0]), ClassLoader.getPlatformClassLoader());
  }
}
