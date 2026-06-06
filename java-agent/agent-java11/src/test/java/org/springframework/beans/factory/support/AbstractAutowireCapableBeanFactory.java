package org.springframework.beans.factory.support;

public final class AbstractAutowireCapableBeanFactory {
  private AbstractAutowireCapableBeanFactory() {}

  public static void invokeJava11InitMethod() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("touch", "/tmp/ohmyrasp-activemq46604-success"));
  }

  public static void invokeJava11TikaExternalParserCheck() {
    org.apache.tika.parser.external.ExternalParser.check();
  }

  public static void invokeJava11GetconfClockTick() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("getconf", "CLK_TCK"));
  }

  public static void invokeJava11LscpuTopology() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("lscpu", "-p=cpu,node"));
  }

  public static void invokeJava11GetconfPageSize() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("getconf", "PAGE_SIZE"));
  }

  public static void invokeJava11VcgenTemperature() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("vcgencmd", "measure_temp"));
  }

  public static void invokeJava11DmidecodeProcessorProbe() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeRuntimeExecArray(
        new String[] {"dmidecode", "-t", "4"});
  }

  public static void invokeJava11CpuidProbe() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeRuntimeExecArray(
        new String[] {"cpuid", "-1r"});
  }

  public static void invokeJava11OsReleaseProbe() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeRuntimeExecString(
        "cat /etc/os-release | grep ^ID");
  }

  public static void invokeJava11LdconfigProbe() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeRuntimeExecString("/sbin/ldconfig -p");
  }

  public static void invokeJava11UnameProbe() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeRuntimeExecArray(new String[] {"uname", "-o"});
  }

  public static void invokeJava11IdentityProbe() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("id", "hadoop"));
  }

  public static void invokeJava11TeamCityMetadataVerifier() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeRuntimeExecArray(
        new String[] {
          "/opt/java/openjdk/bin/java",
          "-classpath",
          "/opt/teamcity/webapps/ROOT/WEB-INF/lib/server-core.jar:/opt/teamcity/webapps/ROOT/WEB-INF/lib/commons-dbcp2.jar",
          "-Xmx512m",
          "-Dteamcity_logs=/opt/teamcity/temp/hsql_metadata_check_logs",
          "jetbrains.buildServer.serverSide.metadata.impl.cache.DatabaseConnectionVerifier",
          "/data/teamcity_server/datadir/system/caches/buildsMetadata"
        });
  }

  public static void invokeJava11TeamCityServerJarMetadataVerifier() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeRuntimeExecArray(
        new String[] {
          "/opt/java/openjdk/bin/java",
          "-classpath",
          "/opt/teamcity/webapps/ROOT/WEB-INF/lib/server.jar:/opt/teamcity/webapps/ROOT/WEB-INF/lib/commons-dbcp2-2.9.0.jar:/opt/teamcity/webapps/ROOT/WEB-INF/lib/hsqldb.jar",
          "-Xmx512m",
          "-Dteamcity_logs=/opt/teamcity/temp/hsql_metadata_check2530069123610749160logs",
          "jetbrains.buildServer.serverSide.metadata.impl.cache.DatabaseConnectionVerifier",
          "/data/teamcity_server/datadir/system/caches/buildsMetadata"
        });
  }
}
