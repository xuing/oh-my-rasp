package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ObjectInputFilter;
import java.io.ObjectInputFilter.FilterInfo;
import java.io.ObjectInputFilter.Status;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit coverage for the selective, composable serial-filter guard. These drive
 * {@link DeserializationGuard#check(String)} and {@link
 * DeserializationGuard#mergedFilter} directly so the process-global {@code
 * ObjectInputFilter.Config} (which may only be set once per JVM) is never
 * touched.
 */
final class DeserializationGuardTest {

  // A gadget class present in DetectorEngine.DESERIALIZATION_BLACKLIST.
  private static final String DANGEROUS_GADGET = "java.lang.Runtime";

  @BeforeEach
  void clean() {
    System.clearProperty("ohmyrasp.block");
    System.clearProperty("ohmyrasp.force_block");
    // Ensure no active request leaks in from another test in the same JVM.
    OhMyRaspHooks.exitHttpRequest();
  }

  @AfterEach
  void reset() {
    System.clearProperty("ohmyrasp.block");
    System.clearProperty("ohmyrasp.force_block");
    OhMyRaspHooks.exitHttpRequest();
  }

  @Test
  void benignClassIsUndecidedEvenInBlockMode() {
    System.setProperty("ohmyrasp.block", "true");

    assertEquals(Status.UNDECIDED, DeserializationGuard.check("java.util.ArrayList"));
    assertEquals(Status.UNDECIDED, DeserializationGuard.check("java.lang.String"));
  }

  @Test
  void dangerousGadgetIsRejectedInBlockMode() {
    System.setProperty("ohmyrasp.block", "true");

    assertTrue(OhMyRaspHooks.isDangerousDeserialization(DANGEROUS_GADGET));
    assertEquals(Status.REJECTED, DeserializationGuard.check(DANGEROUS_GADGET));
  }

  @Test
  void dangerousGadgetIsUndecidedWhenBlockingDisabled() {
    // Monitor/legacy safety: without blocking enabled the guard observes but
    // never enforces, so nothing is rejected at the serial-filter level.
    assertFalse(OhMyRaspHooks.blockingEnabled());
    assertEquals(Status.UNDECIDED, DeserializationGuard.check(DANGEROUS_GADGET));
  }

  @Test
  void nullAndBlankClassNamesAreUndecided() {
    System.setProperty("ohmyrasp.block", "true");

    assertEquals(Status.UNDECIDED, DeserializationGuard.check((String) null));
    assertEquals(Status.UNDECIDED, DeserializationGuard.check("   "));
  }

  @Test
  void preExistingUndecidedFilterIsStillConsulted() {
    // A pre-existing filter that returns ALLOWED for its own reasons must still
    // be reached when OhMyRasp's check is UNDECIDED (benign class).
    AtomicInteger delegated = new AtomicInteger();
    ObjectInputFilter previous =
        info -> {
          delegated.incrementAndGet();
          return Status.ALLOWED;
        };

    ObjectInputFilter merged = DeserializationGuard.mergedFilter(previous);
    Status status = merged.checkInput(new FakeFilterInfo(java.util.ArrayList.class));

    assertEquals(1, delegated.get(), "pre-existing filter must be consulted on UNDECIDED");
    assertEquals(Status.ALLOWED, status, "delegated filter's decision must be honored");
  }

  @Test
  void ourRejectionShortCircuitsBeforeDelegating() {
    System.setProperty("ohmyrasp.block", "true");
    AtomicInteger delegated = new AtomicInteger();
    ObjectInputFilter previous =
        info -> {
          delegated.incrementAndGet();
          return Status.ALLOWED;
        };

    ObjectInputFilter merged = DeserializationGuard.mergedFilter(previous);
    Status status = merged.checkInput(new FakeFilterInfo(java.lang.Runtime.class));

    assertEquals(Status.REJECTED, status);
    assertEquals(0, delegated.get(), "a dangerous gadget must be rejected without delegating");
  }

  @Test
  void nullPreviousFilterCollapsesToUndecided() {
    ObjectInputFilter merged = DeserializationGuard.mergedFilter(null);

    assertEquals(
        Status.UNDECIDED, merged.checkInput(new FakeFilterInfo(java.util.ArrayList.class)));
  }

  /** Minimal {@link FilterInfo} that only carries a serial class. */
  private record FakeFilterInfo(Class<?> serialClass) implements FilterInfo {
    @Override
    public long arrayLength() {
      return -1;
    }

    @Override
    public long depth() {
      return 1;
    }

    @Override
    public long references() {
      return 0;
    }

    @Override
    public long streamBytes() {
      return 0;
    }
  }
}
