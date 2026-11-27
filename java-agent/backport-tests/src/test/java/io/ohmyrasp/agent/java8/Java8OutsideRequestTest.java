package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.backport.ControlAccess;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Block scope on the backport lines, as on the primary (OutsideRequestTest there): a finding with request evidence
 * blocks wherever it runs; outside a request an intrinsic finding blocks whatever {@code outside_request} says, an
 * operation-only finding logs whatever it says, and a context-dependent one follows it (block by default).
 */
final class Java8OutsideRequestTest {
  private static final String RMI = "rmi://127.0.0.1:1099/Exploit";
  private static final String PASSWD = "/etc/passwd";
  private static final String METADATA = "http://169.254.169.254/latest/meta-data/";

  /** The one method of a servlet request the YARN submission check calls. */
  public interface RoleRequest {
    boolean isUserInRole(String role);
  }

  @TempDir Path dir;
  private Path log;

  @BeforeEach
  void blockMode() throws Exception {
    log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");
  }

  @AfterEach
  void restore() {
    ControlAccess.poll(dir.resolve("no-control-file.json"));
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.java8.block");
    System.clearProperty("ohmyrasp.yarn.submitRole");
  }

  @Test
  void aContextFindingOutsideARequestBlocksByDefault() {
    assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeFileRead(PASSWD));
    assertTrue(events().contains("\"action\":\"block\""));
  }

  @Test
  void logOnlyOutsideARequestRecordsAContextFindingAndLetsTheOperationRun() throws Exception {
    control("{\"outside_request\":\"log\"}");

    // Another path than the other tests: a backport logs the same path once a second on one thread.
    Java8RaspHooks.beforeFileRead("/etc/shadow");

    assertTrue(events().contains("\"algorithm\":\"java8_file_sensitive_read\""));
    assertTrue(events().contains("\"action\":\"log\""));
  }

  @Test
  void logOnlyLeavesAFindingInsideARequestBlocking() throws Exception {
    control("{\"outside_request\":\"log\"}");
    Java8RaspHooks.beforeHttpRequest(new Java8RaspHooksTest.RequestStub("GET", "/reports", "id=7"));
    try {
      assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeFileRead(PASSWD));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }
  }

  /** A remote JNDI name is the exploit itself: log only does not turn it off. */
  @Test
  void anIntrinsicFindingBlocksOutsideARequestWithLogOnly() throws Exception {
    control("{\"outside_request\":\"log\"}");

    assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJndiLookup(RMI));
    assertTrue(events().contains("\"algorithm\":\"java8_jndi_remote_lookup\""));
    assertTrue(events().contains("\"action\":\"block\""));
  }

  /** A cloud SDK reads instance metadata at start-up: outside a request that is logged whatever the setting. */
  @Test
  void anOperationOnlyFindingLogsOutsideARequestAndBlocksInsideOne() throws Exception {
    Java8RaspHooks.beforeUrlOpen(new URL(METADATA));
    assertTrue(events().contains("\"algorithm\":\"java8_ssrf_cloud_metadata\""));
    assertTrue(events().contains("\"action\":\"log\""));

    Java8RaspHooks.beforeHttpRequest(new Java8RaspHooksTest.RequestStub("GET", "/reports", "id=7"));
    try {
      assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeUrlOpen(new URL(METADATA)));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }
  }

  /** The YARN handler holds the HTTP request: a denial is inside a request with no servlet frame tracked. */
  @Test
  void aHookThatHoldsTheRequestDecidesInsideARequestWithoutAServletFrame() throws Exception {
    control("{\"outside_request\":\"log\"}");
    System.setProperty("ohmyrasp.yarn.submitRole", "submitter");
    RoleRequest request = new RoleRequest() {
      @Override public boolean isUserInRole(String role) {
        return false;
      }
    };

    assertThrows(Java8RaspBlockException.class,
        () -> Java8RaspHooks.afterYarnSubmitPrepared(new Object(), request, RoleRequest.class));
    assertTrue(events().contains("\"algorithm\":\"java8_request_remote_job_submission\""));
  }

  /**
   * An HTTP client exchange submitted inside a request carries it onto the thread that runs the exchange: the
   * metadata destination blocks there with log only, as on the primary. Submitted outside a request it logs.
   */
  @Test
  void anExchangeSubmittedInsideARequestIsInsideItOnTheThreadThatRunsIt() throws Exception {
    control("{\"outside_request\":\"log\"}");
    URI metadata = URI.create(METADATA);
    Object carried = new Object();
    Java8RaspHooks.beforeHttpRequest(new Java8RaspHooksTest.RequestStub("GET", "/reports", "id=7"));
    try {
      Java8RaspHooks.captureHttpSubmission(carried, metadata);
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }
    assertTrue(blockedOnAnotherThread(carried, metadata), "submitted in a request");
    assertFalse(blockedOnAnotherThread(new Object(), metadata), "submitted outside a request");
  }

  /**
   * A CXF XOP attachment reference that opens a host file is intrinsic: read on another thread, with no request behind
   * it and log only, it still blocks, as on the primary.
   */
  @Test
  void anAttachmentThatOpensAHostFileBlocksOutsideARequestWithLogOnly() throws Exception {
    control("{\"outside_request\":\"log\"}");
    final Path report = dir.resolve("weekly.txt");
    Files.write(report, "weekly".getBytes(StandardCharsets.UTF_8));
    final Object source = new Object();
    Object reference = io.ohmyrasp.agent.xml.AttachmentFileRead.beginReference(report.toUri().toString(), null);
    try {
      io.ohmyrasp.agent.xml.AttachmentFileRead.created(source, report.toUri().toURL());
    } finally {
      io.ohmyrasp.agent.xml.AttachmentFileRead.endReference(reference);
    }
    final AtomicReference<Throwable> thrown = new AtomicReference<Throwable>();
    Thread reader = new Thread(new Runnable() {
      @Override public void run() {
        Object read = io.ohmyrasp.agent.xml.AttachmentFileRead.beginRead(source);
        try {
          Java8RaspHooks.beforeFileRead(report.toString());
        } catch (Throwable failure) {
          thrown.set(failure);
        } finally {
          io.ohmyrasp.agent.xml.AttachmentFileRead.endRead(read);
        }
      }
    }, "attachment-reader");
    reader.start();
    reader.join(10_000);
    assertTrue(thrown.get() instanceof Java8RaspBlockException, String.valueOf(thrown.get()));
  }

  private static boolean blockedOnAnotherThread(final Object exchange, final URI uri) throws Exception {
    final AtomicReference<Throwable> thrown = new AtomicReference<Throwable>();
    Thread worker = new Thread(new Runnable() {
      @Override public void run() {
        try {
          Java8RaspHooks.beforeHttpExchange(exchange, new Object(), uri);
        } catch (Throwable failure) {
          thrown.set(failure);
        }
      }
    }, "exchange-worker");
    worker.start();
    worker.join(10_000);
    Throwable failure = thrown.get();
    if (failure != null && !(failure instanceof Java8RaspBlockException)) throw new AssertionError(failure);
    return failure != null;
  }

  @Test
  void aDocumentWithoutTheSettingReturnsToTheStartUpValue() throws Exception {
    control("{\"outside_request\":\"log\"}");
    control("{\"outside_request\":\"sometimes\",\"revision\":2}");
    Java8RaspHooks.beforeFileRead(PASSWD);

    control("{\"revision\":3}");
    assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeFileRead(PASSWD));
  }

  private void control(String json) throws Exception {
    Path file = dir.resolve("control.json");
    Files.write(file, json.getBytes(StandardCharsets.UTF_8));
    ControlAccess.poll(file);
  }

  private String events() {
    try {
      return new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    } catch (java.io.IOException e) {
      throw new AssertionError(e);
    }
  }
}
