package org.apache.hadoop.yarn.server.resourcemanager.webapp;

import java.lang.reflect.Proxy;
import java.security.Principal;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authorize.AuthorizationException;
import org.apache.hadoop.yarn.api.protocolrecords.SubmitApplicationRequest;
import org.apache.hadoop.yarn.api.protocolrecords.SubmitApplicationResponse;
import org.apache.hadoop.yarn.server.resourcemanager.ClientRMService;
import org.apache.hadoop.yarn.server.resourcemanager.RMContext;
import org.apache.hadoop.yarn.server.resourcemanager.ResourceManager;
import org.apache.hadoop.yarn.server.resourcemanager.webapp.dao.ApplicationSubmissionContextInfo;
import org.apache.hadoop.yarn.webapp.BadRequestException;

/** Exercise Hadoop 2.8.1 REST admission and DTO conversion with an unstarted, recording client service. */
public final class YarnReleaseSubmitCheck {
  private static final String COMMAND = "java reports.Weekly";

  private static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
    return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler));
  }

  private static final class RecordingClient extends ClientRMService {
    int receipts;
    java.util.List<String> expectedCommands;
    RecordingClient() { super(proxy(RMContext.class, (p, m, a) -> null), null, null, null, null, null); }
    @Override public SubmitApplicationResponse submitApplication(SubmitApplicationRequest request) {
      if (!request.getApplicationSubmissionContext().getAMContainerSpec().getCommands().equals(expectedCommands))
        throw new AssertionError("unexpected job");
      receipts++;
      return SubmitApplicationResponse.newInstance();
    }
  }

  private static long findings() throws java.io.IOException {
    java.nio.file.Path path = java.nio.file.Paths.get(System.getProperty("ohmyrasp.log"));
    if (!java.nio.file.Files.exists(path)) return 0;
    try (java.util.stream.Stream<String> lines = java.nio.file.Files.lines(path)) {
      return lines.filter(line -> line.contains("request_remote_job_submission")).count();
    }
  }

  public static void main(String[] args) throws Exception {
    Configuration conf = new Configuration(false);
    UserGroupInformation.setConfiguration(conf);
    RecordingClient client = new RecordingClient();
    ResourceManager rm = new ResourceManager() {
      @Override public ClientRMService getClientRMService() { return client; }
      @Override public Configuration getConfig() { return conf; }
    };
    RMWebServices resource = new RMWebServices(rm, conf, proxy(HttpServletResponse.class, (p, m, a) -> null));
    for (String scenario : new String[]{"unconfigured", "missing-caller", "invalid", "allowed", "unavailable", "denied", "denied-empty"}) {
      if ("unconfigured".equals(scenario)) System.clearProperty("ohmyrasp.yarn.submitRole");
      else System.setProperty("ohmyrasp.yarn.submitRole", "report-submitters");
      AtomicInteger checks = new AtomicInteger();
      HttpServletRequest request = proxy(HttpServletRequest.class, (p, m, a) -> {
        if ("getUserPrincipal".equals(m.getName())) return "missing-caller".equals(scenario) ? null : (Principal) () -> "analyst";
        if ("getRequestURL".equals(m.getName())) return new StringBuffer("http://reports.invalid/apps");
        if ("getRequestURI".equals(m.getName())) return "/apps";
        if ("isUserInRole".equals(m.getName())) {
          if (!"report-submitters".equals(a[0])) throw new AssertionError("unexpected role");
          checks.incrementAndGet();
          if ("unavailable".equals(scenario)) throw new IllegalStateException("role service unavailable");
          return "allowed".equals(scenario);
        }
        return null;
      });
      ApplicationSubmissionContextInfo report = new ApplicationSubmissionContextInfo();
      report.setApplicationName("Weekly report");
      report.setApplicationId("invalid".equals(scenario) ? "invalid" : "application_1_0001");
      client.expectedCommands = "denied-empty".equals(scenario) ? Collections.emptyList() : Collections.singletonList(COMMAND);
      report.getContainerLaunchContextInfo().setCommands(client.expectedCommands);
      int before = client.receipts;
      long eventsBefore = findings();
      String outcome;
      try {
        Response accepted = resource.submitApplication(report, request);
        if (accepted.getStatus() != 202) throw new AssertionError("unexpected HTTP status");
        outcome = "accepted";
      } catch (AuthorizationException rejected) {
        outcome = "missing-caller";
      } catch (BadRequestException invalid) {
        outcome = "invalid";
      } catch (RuntimeException e) {
        if (!e.getClass().getSimpleName().endsWith("RaspBlockException")) throw e;
        outcome = "blocked";
      }
      boolean nativeRejection = "missing-caller".equals(scenario) || "invalid".equals(scenario);
      boolean roleDenied = scenario.startsWith("denied");
      String expected = nativeRejection ? scenario : roleDenied && "block".equals(args[0]) ? "blocked" : "accepted";
      System.out.println(scenario + "=" + outcome + " receipts=" + (client.receipts - before));
      if (!expected.equals(outcome)
          || findings() - eventsBefore != (roleDenied ? 1 : 0)
          || checks.get() != (nativeRejection || "unconfigured".equals(scenario) ? 0 : 1)
          || client.receipts - before != ("accepted".equals(expected) ? 1 : 0)) throw new AssertionError(scenario);
    }
  }
}
