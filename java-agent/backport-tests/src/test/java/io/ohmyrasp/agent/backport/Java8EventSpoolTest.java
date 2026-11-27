package io.ohmyrasp.agent.backport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The backport RaspRuntime event spool: which file a queued event reaches, and what shutdown does
 * with what is queued. All output is the writer thread's: shutdown closes the admission, lets the
 * writer drain for a bounded time and writes nothing itself. The shutdown tests write through the
 * production file sink and its write lock; the test holds that lock to keep the writer from
 * delivering, or gives the spool a sink that never returns. Every wait is bounded at a few
 * seconds, helper threads are daemons, and no sleep decides an outcome.
 */
final class Java8EventSpoolTest {
  private static final long BOUND_SECONDS = 5L;

  @TempDir Path dir;

  @Test
  void queuedEventsAreWrittenToTheTargetTheyWereAcceptedFor() throws Exception {
    RecordingSink sink = new RecordingSink();
    RaspRuntime.EventSpool spool = new RaspRuntime.EventSpool(sink);
    spool.offer("/logs/a.jsonl", "e1");
    spool.offer("/logs/b.jsonl", "e2");
    spool.offer("/logs/b.jsonl", "e3");
    spool.offer("/logs/a.jsonl", "e4");

    spool.drainOnce(0L);

    assertEquals("[/logs/a.jsonl [e1], /logs/b.jsonl [e2, e3], /logs/a.jsonl [e4]]", sink.records());
  }

  /** The writer, not shutdown, writes what was queued before the admission closed: each event once, in order. */
  @Test
  void shutdownLetsTheWriterDrainWhatWasQueuedOnce() throws Exception {
    String log = dir.resolve("events.jsonl").toString();
    final RaspRuntime.EventSpool spool = new RaspRuntime.EventSpool(RaspRuntime.FILE_SINK);
    Thread writer = spool.start("ohmyrasp-java8-test-writer");
    Thread stopper;
    RaspRuntime.WRITE_LOCK.lock();
    try {
      spool.offer(log, "e1");
      awaitQueuedOn(RaspRuntime.WRITE_LOCK); // the writer took e1 and waits for the lock
      spool.offer(log, "e2");
      stopper = stopper(spool, TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      awaitJoiningOrDone(stopper);
      assertTrue(stopper.isAlive(), "shutdown returned while the writer held an undelivered batch");
      spool.offer(log, "late");
    } finally {
      RaspRuntime.WRITE_LOCK.unlock();
    }
    stopper.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    assertFalse(stopper.isAlive(), "shutdown returned");
    assertFalse(writer.isAlive(), "the writer stopped");
    // No waiting: once shutdown has returned, everything it accepted is on disk.
    assertEquals(Arrays.asList("e1", "e2"), lines(log), "each event once, in order");
    assertEquals(1L, spool.droppedCount(), "the event offered after the admission closed is dropped and counted");
  }

  @Test
  void shutdownReturnsInBoundedTimeWhileTheWriteLockStaysHeld() throws Exception {
    String log = dir.resolve("events.jsonl").toString();
    RaspRuntime.EventSpool spool = new RaspRuntime.EventSpool(RaspRuntime.FILE_SINK);
    Thread writer = spool.start("ohmyrasp-java8-test-writer");
    // The test holds the lock as a writer stalled in an output call would.
    RaspRuntime.WRITE_LOCK.lock();
    try {
      spool.offer(log, "e1");
      awaitQueuedOn(RaspRuntime.WRITE_LOCK);
      spool.offer(log, "e2");
      Thread stopper = stopper(spool, 200L);
      stopper.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(stopper.isAlive(), "shutdown waited without bound for the write lock");
    } finally {
      RaspRuntime.WRITE_LOCK.unlock();
    }
    writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    // The writer delivers the batch it held once the lock is free; e2, which the writer had not
    // taken when shutdown gave up waiting, is dropped and counted. Nothing is written twice.
    assertEquals(Collections.singletonList("e1"), lines(log));
    assertEquals(1L, spool.droppedCount());
  }

  /**
   * After the JVM's exit began, an event is dropped and counted: the shutdown hook writes nothing, and an
   * application thread does not take over the writer's output either. (Until this round it was
   * written on the caller's thread.)
   */
  @Test
  void anEventAfterShutdownIsDroppedAndCounted() throws Exception {
    String log = dir.resolve("events.jsonl").toString();
    RaspRuntime.EventSpool spool = new RaspRuntime.EventSpool(RaspRuntime.FILE_SINK);
    spool.start("ohmyrasp-java8-test-writer");
    spool.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    spool.offer(log, "late");
    assertEquals(Collections.<String>emptyList(), lines(log));
    assertEquals(1L, spool.droppedCount());
  }

  /**
   * A sink that never returns, as an output call on a stalled file system or a pipe nobody reads:
   * the writer is stuck in it with the first event and more are queued. Shutdown, the JVM exit
   * hook's part, still returns within its wait, and never calls the sink itself.
   */
  @Test
  void shutdownReturnsInBoundedTimeAndWritesNothingWhileTheSinkBlocksForever() throws Exception {
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch never = new CountDownLatch(1);
    final List<String> callers = Collections.synchronizedList(new ArrayList<String>());
    RaspRuntime.EventSpool spool = new RaspRuntime.EventSpool(new RaspRuntime.Sink() {
      public void append(String target, List<String> lines) {
        callers.add(Thread.currentThread().getName());
        entered.countDown();
        try {
          never.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
    });
    Thread writer = spool.start("ohmyrasp-java8-test-writer");
    try {
      spool.offer("/logs/a.jsonl", "e1");
      assertTrue(entered.await(BOUND_SECONDS, TimeUnit.SECONDS), "the writer never reached the sink");
      spool.offer("/logs/a.jsonl", "e2");
      spool.offer("/logs/a.jsonl", "e3");
      Thread stopper = stopper(spool, 300L);
      stopper.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(stopper.isAlive(), "shutdown waited without bound for a sink that never returns");
      assertEquals(Collections.singletonList("ohmyrasp-java8-test-writer"), callers,
          "only the writer calls the sink");
      assertEquals(2L, spool.droppedCount(), "what the writer had not taken is dropped and counted");
    } finally {
      never.countDown();
      writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    }
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
    stopper.setDaemon(true);
    stopper.start();
    return stopper;
  }

  private static List<String> lines(String log) throws Exception {
    Path path = java.nio.file.Paths.get(log);
    if (!Files.exists(path)) {
      return new ArrayList<String>();
    }
    return Files.readAllLines(path, StandardCharsets.UTF_8);
  }

  /** Waits, bounded, until a thread waits for {@code lock}. The loop only observes. */
  private static void awaitQueuedOn(ReentrantLock lock) throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
    while (!lock.hasQueuedThreads()) {
      if (System.nanoTime() > deadline) {
        fail("the writer never waited for the write lock");
      }
      Thread.sleep(1L);
    }
  }

  /**
   * Waits until {@code stopper} has finished or is waiting in Thread.join for the writer. Either
   * state is final for this test: the writer cannot finish while the test holds the lock. The
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

  /** Records each batch as "target [lines]". */
  private static final class RecordingSink implements RaspRuntime.Sink {
    private final List<String> records = new ArrayList<String>();

    public void append(String target, List<String> lines) {
      synchronized (records) {
        records.add(target + " " + lines);
      }
    }

    String records() {
      synchronized (records) {
        return records.toString();
      }
    }
  }
}
