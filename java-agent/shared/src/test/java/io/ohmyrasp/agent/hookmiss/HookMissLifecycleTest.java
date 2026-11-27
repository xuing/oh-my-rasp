package io.ohmyrasp.agent.hookmiss;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/**
 * When and on which thread the hook-miss worker runs: never created on the thread that reports a miss (a
 * class-loading thread), created once on the thread that commits the start, without the inheritable thread-locals of
 * that thread; and a stopped report takes no more misses, drops what is queued and writes nothing of a line in
 * progress.
 */
final class HookMissLifecycleTest {
  private static final HookExpectations TABLE = HookExpectations.parse("U a/B report m()V\nU a/C report m()V\n");

  @AfterEach
  void stop() {
    HookMisses.stop();
  }

  @Test
  void aMissIsQueuedWithoutAThreadUntilTheStartCommitsAndTheWorkerIsCreatedOnce() throws Exception {
    Recorder recorder = new Recorder();
    HookMisses.startHeld(TABLE, recorder);
    int threadsBefore = workerThreads();

    miss("a/B", null);
    assertNull(HookMisses.workerThread(), "reporting a miss created the worker");
    assertEquals(threadsBefore, workerThreads(), "reporting a miss created a thread");
    assertTrue(recorder.lines.isEmpty(), "a held report wrote a line");

    HookMisses.release();
    Thread worker = HookMisses.workerThread();
    assertNotNull(worker, "the commit did not create the worker");
    assertTrue(HookMisses.awaitIdle(5000), "the worker did not write the queued miss");
    assertEquals(1, recorder.lines.size());

    miss("a/C", null);
    assertTrue(HookMisses.awaitIdle(5000));
    assertEquals(2, recorder.lines.size());
    assertSame(worker, HookMisses.workerThread(), "a later miss got a new worker");
    assertTrue(worker.isAlive() && worker.isDaemon());
    assertNull(worker.getContextClassLoader());
  }

  /** The worker does not run an application's childValue, nor keep the value it would have inherited (JDK 9+). */
  @Test
  void theWorkerInheritsNoInheritableThreadLocal() throws Exception {
    final AtomicInteger childValues = new AtomicInteger();
    InheritableThreadLocal<Object> application = new InheritableThreadLocal<Object>() {
      @Override protected Object childValue(Object parent) {
        childValues.incrementAndGet();
        return parent;
      }
    };
    application.set(new Object());
    final Object[] seen = {"not run"};
    final CountDownLatch written = new CountDownLatch(1);
    HookMisses.startHeld(TABLE, new Recorder() {
      @Override public void write(String diagnostic, String fields) {
        seen[0] = application.get();
        written.countDown();
      }
    });
    miss("a/B", null);
    try {
      HookMisses.release();
    } finally {
      application.remove();
    }
    assertTrue(written.await(5, TimeUnit.SECONDS));
    assertEquals(0, childValues.get(), "creating the worker ran the application's childValue");
    assertNull(seen[0], "the worker inherited the application's value");
  }

  @Test
  void stopEndsTheWorkerDropsTheQueueAndTakesNoMoreMisses() throws Exception {
    Recorder recorder = new Recorder();
    HookMisses.startHeld(TABLE, recorder);
    HookMisses.release();
    Thread worker = HookMisses.workerThread();

    HookMisses.stop();
    worker.join(5000);
    assertFalse(worker.isAlive(), "stop left the worker running");
    assertNull(HookMisses.table());
    miss("a/B", null);
    assertTrue(recorder.lines.isEmpty());
  }

  /** A failed start: what classes loaded during it reported is dropped, and no worker is ever created. */
  @Test
  void aHeldReportThatIsStoppedNeverCreatesAWorker() {
    Recorder recorder = new Recorder();
    HookMisses.startHeld(TABLE, recorder);
    miss("a/B", null);
    HookMisses.stop();
    HookMisses.release();
    assertNull(HookMisses.workerThread());
    assertTrue(recorder.lines.isEmpty());
  }

  /**
   * The worker is reading the origin of a miss (inside the sink's own-I/O mark) when the report is stopped, and
   * the stop does not wait for it beyond its bound: the line it was building is not written once it goes on.
   */
  @Test
  void aLineInProgressWhenTheReportStopsIsNotWritten() throws Exception {
    final CountDownLatch inOrigin = new CountDownLatch(1);
    final CountDownLatch goOn = new CountDownLatch(1);
    Recorder recorder = new Recorder() {
      @Override public boolean enterOwnIo() {
        inOrigin.countDown();
        awaitUninterruptibly(goOn);
        return false;
      }
    };
    HookMisses.startHeld(TABLE, recorder);
    miss("a/B", new ProtectionDomain(new CodeSource(new URL("file:/nonexistent/library-1.0.jar"),
        (Certificate[]) null), null));
    HookMisses.release();
    Thread worker = HookMisses.workerThread();
    assertTrue(inOrigin.await(5, TimeUnit.SECONDS), "the worker did not reach the origin");

    long began = System.nanoTime();
    HookMisses.stop();
    assertTrue(System.nanoTime() - began < TimeUnit.SECONDS.toNanos(3), "stop waited for the stuck worker");
    goOn.countDown();
    worker.join(5000);
    assertFalse(worker.isAlive());
    assertTrue(recorder.lines.isEmpty(), "a stopped report wrote the line it was building: " + recorder.lines);
  }

  @Test
  void awaitIdleReturnsAtOnceForAHeldOrStoppedReport() {
    HookMisses.startHeld(TABLE, new Recorder());
    miss("a/B", null);
    long began = System.nanoTime();
    assertTrue(HookMisses.awaitIdle(5000), "a held report has nothing it will write");
    HookMisses.stop();
    assertTrue(HookMisses.awaitIdle(5000));
    assertTrue(System.nanoTime() - began < TimeUnit.SECONDS.toNanos(1));
  }

  private static void miss(String className, ProtectionDomain domain) {
    HookMisses.miss(TABLE.forClass(className)[0], "U", plainClass(className), domain, HookMisses.NO_AGENT_CALL, null);
  }

  private static int workerThreads() {
    int count = 0;
    for (Thread thread : Thread.getAllStackTraces().keySet()) {
      if (thread.isAlive() && thread.getName().equals("ohmyrasp-hook-miss")) {
        count++;
      }
    }
    return count;
  }

  private static void awaitUninterruptibly(CountDownLatch latch) {
    boolean interrupted = false;
    while (latch.getCount() > 0) {
      try {
        latch.await();
      } catch (InterruptedException e) {
        interrupted = true;
      }
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  /** A class with a method {@code m()V} and no call into the agent. */
  private static byte[] plainClass(String name) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", null);
    writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m", "()V", null, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static class Recorder implements HookMissSink {
    final List<String> lines = Collections.synchronizedList(new ArrayList<String>());

    @Override public void write(String diagnostic, String fields) {
      lines.add(diagnostic + " " + fields);
    }

    @Override public boolean enterOwnIo() {
      return false;
    }

    @Override public void exitOwnIo(boolean entered) {}
  }
}
