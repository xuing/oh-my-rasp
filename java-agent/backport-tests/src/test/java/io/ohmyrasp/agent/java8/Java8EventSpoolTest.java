package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * The backport RaspRuntime event spool: which file a queued event reaches, and what the shutdown
 * hook does with a batch the writer holds. A sink stands in for the file, so the writer's progress
 * is controlled by latches. Every wait is bounded; none decides the outcome by timing.
 */
final class Java8EventSpoolTest {
  private static final long BOUND_SECONDS = 20L;

  @Test
  void queuedEventsAreWrittenToTheTargetTheyWereAcceptedFor() throws Exception {
    RecordingSink sink = new RecordingSink(null, null);
    RaspRuntime.EventSpool spool = new RaspRuntime.EventSpool(sink);
    spool.offer("/logs/a.jsonl", "e1");
    spool.offer("/logs/b.jsonl", "e2");
    spool.offer("/logs/b.jsonl", "e3");
    spool.offer("/logs/a.jsonl", "e4");

    spool.drainOnce(0L);

    assertEquals("[/logs/a.jsonl [e1], /logs/b.jsonl [e2, e3], /logs/a.jsonl [e4]]", sink.records());
  }

  @Test
  void shutdownWaitsForTheBatchTheWriterHoldsAndThenFlushesTheRestOnce() throws Exception {
    CountDownLatch taken = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    RecordingSink sink = new RecordingSink(taken, release);
    final RaspRuntime.EventSpool spool = new RaspRuntime.EventSpool(sink);
    Thread writer = spool.start("ohmyrasp-java8-test-writer");

    spool.offer("/logs/a.jsonl", "e1");
    assertTrue(taken.await(BOUND_SECONDS, TimeUnit.SECONDS), "the writer took e1");
    spool.offer("/logs/a.jsonl", "e2");

    // A budget far above the test's own waits, so the stopper cannot give up on the writer.
    Thread stopper = stopper(spool, TimeUnit.SECONDS.toMillis(60L));
    awaitJoiningOrDone(stopper);
    release.countDown();
    stopper.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    assertFalse(stopper.isAlive(), "shutdown returned");
    assertFalse(writer.isAlive(), "the writer stopped");

    assertEquals("[/logs/a.jsonl [e1], /logs/a.jsonl [e2]]", sink.records(), "each event once, in order");
  }

  @Test
  void shutdownStopsWaitingForAStuckWriterAfterItsBound() throws Exception {
    CountDownLatch taken = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    RecordingSink sink = new RecordingSink(taken, release);
    RaspRuntime.EventSpool spool = new RaspRuntime.EventSpool(sink);
    Thread writer = spool.start("ohmyrasp-java8-test-writer");
    try {
      spool.offer("/logs/a.jsonl", "e1");
      assertTrue(taken.await(BOUND_SECONDS, TimeUnit.SECONDS), "the writer took e1");
      spool.offer("/logs/a.jsonl", "e2");

      // The writer stays blocked; shutdown gives up after its bound and flushes what is queued.
      Thread stopper = stopper(spool, 50L);
      stopper.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(stopper.isAlive(), "shutdown returned while the writer was stuck");
      assertEquals("[/logs/a.jsonl [e2]]", sink.records());
    } finally {
      release.countDown();
      writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    }
    assertEquals("[/logs/a.jsonl [e2], /logs/a.jsonl [e1]]", sink.records(), "nothing written twice");
  }

  private static Thread stopper(final RaspRuntime.EventSpool spool, final long joinMillis) {
    Thread stopper =
        new Thread(
            new Runnable() {
              public void run() {
                spool.shutdown(joinMillis);
              }
            },
            "ohmyrasp-java8-test-stopper");
    stopper.start();
    return stopper;
  }

  /**
   * Waits until {@code stopper} has finished or is waiting in Thread.join for the writer. Either
   * state is final for this test: the writer cannot finish while the test holds its latch. The
   * loop only observes; it is bounded and its sleep decides nothing.
   */
  private static void awaitJoiningOrDone(Thread stopper) throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
    while (System.nanoTime() < deadline) {
      Thread.State state = stopper.getState();
      if (state == Thread.State.TERMINATED) {
        return;
      }
      if (state == Thread.State.WAITING || state == Thread.State.TIMED_WAITING) {
        for (StackTraceElement frame : stopper.getStackTrace()) {
          if ("java.lang.Thread".equals(frame.getClassName()) && "join".equals(frame.getMethodName())) {
            return;
          }
        }
      }
      Thread.sleep(1L);
    }
    fail("the stopper neither finished nor waited for the writer");
  }

  /** Records each batch as "target [lines]"; the first call can wait on a latch before recording. */
  private static final class RecordingSink implements RaspRuntime.Sink {
    private final List<String> records = new ArrayList<String>();
    private final AtomicInteger calls = new AtomicInteger();
    private final CountDownLatch taken;
    private final CountDownLatch release;

    RecordingSink(CountDownLatch taken, CountDownLatch release) {
      this.taken = taken;
      this.release = release;
    }

    public void append(String target, List<String> lines) {
      String record = target + " " + lines;
      if (calls.incrementAndGet() == 1 && taken != null) {
        taken.countDown();
        try {
          release.await(BOUND_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      synchronized (records) {
        records.add(record);
      }
    }

    String records() {
      synchronized (records) {
        return records.toString();
      }
    }
  }
}
