package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mchange.v2.c3p0.ComboPooledDataSource;
import com.mchange.v2.c3p0.WrapperConnectionPoolDataSource;
import com.mchange.v2.c3p0.impl.DbAuth;
import com.mchange.v2.c3p0.impl.DefaultConnectionTester;
import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;
import io.ohmyrasp.agent.policy.AgentPolicy;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputFilter.FilterInfo;
import java.io.ObjectInputFilter.Status;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import org.codehaus.groovy.runtime.ConvertedClosure;
import org.codehaus.groovy.runtime.GStringImpl;
import org.codehaus.groovy.runtime.MethodClosure;
import org.codehaus.groovy.runtime.NumberAwareComparator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit coverage for serial-filter decisions. The packaged probe exercises filter selection in fresh JVMs.
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
    OhMyRaspHooks.installPolicy(AgentPolicy.absent(), "");
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
  void ordinaryC3p0ValuesPassTheNativeClassFilter() throws Exception {
    System.setProperty("ohmyrasp.block", "true");
    var values = List.of(new DbAuth("report-reader", null), new DefaultConnectionTester());
    var buffer = new ByteArrayOutputStream();
    try (var out = new ObjectOutputStream(buffer)) {
      for (Object value : values) out.writeObject(value);
    }
    try (var in = new ObjectInputStream(new ByteArrayInputStream(buffer.toByteArray()))) {
      in.setObjectInputFilter(DeserializationGuard.filterOrGuard(null));
      for (Object value : values) assertEquals(value, in.readObject());
    }
  }

  @Test
  void c3p0DataSourcesAndReferenceableBasesRetainTheNativeClassPolicy() {
    System.setProperty("ohmyrasp.block", "true");
    for (Class<?> type : List.of(ComboPooledDataSource.class, WrapperConnectionPoolDataSource.class,
        PoolBackedDataSourceBase.class)) {
      assertEquals(Status.REJECTED, DeserializationGuard.check(new FakeFilterInfo(type)), type.getName());
    }
  }

  @Test
  void ordinaryGroovyValuesRoundTripThroughTheClassFilter() throws Exception {
    System.setProperty("ohmyrasp.block", "true");
    var label = new GStringImpl(new Object[]{7}, new String[]{"items: ", ""});
    var numbers = new TreeSet<Integer>(new NumberAwareComparator<>());
    numbers.addAll(List.of(10, 2));
    var bytes = new ByteArrayOutputStream();
    try (var out = new ObjectOutputStream(bytes)) {
      out.writeObject(label);
      out.writeObject(numbers);
    }
    try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      in.setObjectInputFilter(DeserializationGuard.filterOrGuard(null));
      assertEquals("items: 7", ((GStringImpl) in.readObject()).toString());
      TreeSet<?> restored = (TreeSet<?>) in.readObject();
      assertEquals(NumberAwareComparator.class, restored.comparator().getClass());
      assertEquals(List.of(2, 10), List.copyOf(restored));
    }
  }

  @Test
  void listedGroovyInvocationAdaptersRetainTheirTypePolicy() {
    System.setProperty("ohmyrasp.block", "true");
    for (Class<?> adapter : List.of(ConvertedClosure.class, MethodClosure.class)) {
      assertEquals(Status.REJECTED, DeserializationGuard.check(new FakeFilterInfo(adapter)));
    }
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
  void nestedXmlRpcReadsKeepOnlyTheirOwnStreamIdentities() throws Exception {
    var header = new java.io.ByteArrayOutputStream();
    new java.io.ObjectOutputStream(header).close();
    try (var outer = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(header.toByteArray()));
         var inner = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(header.toByteArray()))) {
      XmlRpcReadScope.enter();
      try {
        XmlRpcReadScope.reading(outer);
        assertFalse(XmlRpcReadScope.reads(inner));
        XmlRpcReadScope.enter();
        try {
          XmlRpcReadScope.reading(inner);
          assertTrue(XmlRpcReadScope.reads(outer));
          assertTrue(XmlRpcReadScope.reads(inner));
        } finally { XmlRpcReadScope.exit(); }
        assertTrue(XmlRpcReadScope.reads(outer));
        assertFalse(XmlRpcReadScope.reads(inner));
      } finally { XmlRpcReadScope.exit(); }
      assertFalse(XmlRpcReadScope.reads(outer));
    }
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

    Status status = DeserializationGuard.checkInput(previous, new FakeFilterInfo(java.util.ArrayList.class));

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

    Status status = DeserializationGuard.checkInput(previous, new FakeFilterInfo(java.lang.Runtime.class));

    assertEquals(Status.REJECTED, status);
    assertEquals(0, delegated.get(), "a dangerous gadget must be rejected without delegating");
  }

  @Test
  void nullPreviousFilterCollapsesToUndecided() {
    assertEquals(Status.UNDECIDED, DeserializationGuard.checkInput(
        DeserializationGuard.filterOrGuard(null), new FakeFilterInfo(java.util.ArrayList.class)));
  }

  @Test
  void explicitLogPolicyAlsoAppliesToSerialFilterWithoutRequest() {
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("""
        {"version":1,"status":"active","canary_percent":100,"rules":[
          {"name":"Observe deserialization","hook":"deserialization","algorithm":"deserialization_blacklist",
           "action":"log","severity":"high","expression":"algorithm == \\"deserialization_blacklist\\""}]}
        """), "agent-one");
    assertEquals(Status.UNDECIDED, DeserializationGuard.check(DANGEROUS_GADGET));
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
