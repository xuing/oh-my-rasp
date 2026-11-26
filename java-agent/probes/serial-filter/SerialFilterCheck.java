import io.ohmyrasp.playground.EvilSerialized;
import java.io.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BinaryOperator;

/** Receipt for the selected application filter, the JDK rejection, and an inert marker's data. */
public final class SerialFilterCheck {
  private record Report(String message) implements Serializable {}

  private static boolean read(Object value, ObjectInputFilter filter) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) { out.writeObject(value); }
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      if (filter != null) {
        in.setObjectInputFilter(filter);
        if (in.getObjectInputFilter() != filter) throw new AssertionError("stream filter identity");
      }
      Object result = in.readObject();
      if (!sameContents(value, result)) throw new AssertionError("changed value");
      return true;
    } catch (InvalidClassException rejected) {
      return false;
    }
  }

  private static boolean sameContents(Object expected, Object actual) {
    if (expected == null || actual == null) return expected == actual;
    if (expected.getClass() != actual.getClass()) return false;
    if (expected instanceof Object[] original) {
      Object[] received = (Object[]) actual;
      if (original.length != received.length) return false;
      for (int i = 0; i < original.length; i++) {
        if (!sameContents(original[i], received[i])) return false;
      }
      return true;
    }
    if (expected instanceof EvilSerialized marker) return marker.marker().equals(((EvilSerialized) actual).marker());
    return expected.equals(actual);
  }

  private static void checkRead(String label, Object value, ObjectInputFilter filter,
      String mode, boolean expected) throws Exception {
    try (HttpTransportCheck.Scope scope = mode.equals("bare") ? null
        : new HttpTransportCheck.Scope("main", "weekly", "/reports/" + label)) {
      if (read(value, filter) != expected) throw new AssertionError(label);
    }
  }

  private static void checkArrays(String mode) throws Exception {
    EvilSerialized[] empty = new EvilSerialized[0];
    EvilSerialized[] vacant = new EvilSerialized[2];
    EvilSerialized[][] nested = {null, empty, vacant};
    checkRead("empty", empty, null, mode, true);
    checkRead("all-null", vacant, null, mode, true);
    checkRead("nested-empty", nested, null, mode, true);
    ObjectInputFilter rejectComponent = ObjectInputFilter.Config.createFilter("!" + EvilSerialized.class.getName() + ";*");
    checkRead("component-policy", empty, rejectComponent, mode, false);

    EvilSerialized[] filled = {null, new EvilSerialized("weekly")};
    EvilSerialized[][] nestedFilled = {empty, filled};
    boolean allow = !mode.equals("block");
    AtomicInteger allocations = new AtomicInteger();
    ObjectInputFilter observe = info -> {
      if (info.serialClass() == EvilSerialized[].class && info.arrayLength() == filled.length) allocations.incrementAndGet();
      return ObjectInputFilter.Status.UNDECIDED;
    };
    checkRead("element", filled, observe, mode, allow);
    checkRead("nested-element", nestedFilled, observe, mode, allow);
    if (allocations.get() != 2) throw new AssertionError("array allocation did not reach the application filter");

    AtomicInteger denials = new AtomicInteger();
    ObjectInputFilter limit = info -> {
      if (info.serialClass() == EvilSerialized[].class && info.arrayLength() > 2) {
        denials.incrementAndGet();
        return ObjectInputFilter.Status.REJECTED;
      }
      return ObjectInputFilter.Status.UNDECIDED;
    };
    checkRead("length-limit", new EvilSerialized[]{null, null, new EvilSerialized("weekly")}, limit, mode, false);
    if (denials.get() != 1) throw new AssertionError("application array limit");
  }

  private static void checkC3p0(String mode) throws Exception {
    Class<?> credentials = Class.forName("com.mchange.v2.c3p0.impl.DbAuth");
    Object account = credentials.getConstructor(String.class, String.class).newInstance("report-reader", null);
    Object tester = Class.forName("com.mchange.v2.c3p0.impl.DefaultConnectionTester").getConstructor().newInstance();
    checkRead("c3p0-account", account, null, mode, true);
    checkRead("c3p0-tester", tester, null, mode, true);
    ObjectInputFilter localPolicy = info -> info.serialClass() == credentials
        ? ObjectInputFilter.Status.REJECTED : ObjectInputFilter.Status.UNDECIDED;
    checkRead("c3p0-application-policy", account, localPolicy, mode, false);
    Object poolType = Class.forName("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");
    checkRead("c3p0-pool-type", poolType, null, mode, !mode.equals("block"));
  }

  public static void main(String[] args) throws Exception {
    String setup = args[0], mode = args[1];
    AtomicInteger calls = new AtomicInteger();
    ObjectInputFilter application = info -> {
      if (info.serialClass() == Report.class) {
        calls.incrementAndGet();
        return ObjectInputFilter.Status.REJECTED;
      }
      return ObjectInputFilter.Status.ALLOWED;
    };
    if (setup.equals("startup")) {
      if (ObjectInputFilter.Config.getSerialFilter() == null) throw new AssertionError("startup filter");
      BinaryOperator<ObjectInputFilter> factory = (previous, next) -> next;
      ObjectInputFilter.Config.setSerialFilterFactory(factory);
      if (ObjectInputFilter.Config.getSerialFilterFactory() != factory) throw new AssertionError("startup factory");
    } else if (setup.equals("global")) {
      ObjectInputFilter.Config.setSerialFilter(application);
      if (ObjectInputFilter.Config.getSerialFilter() != application) throw new AssertionError("global filter identity");
    } else if (setup.equals("factory")) {
      BinaryOperator<ObjectInputFilter> factory = (current, next) -> next == null ? application : next;
      ObjectInputFilter.Config.setSerialFilterFactory(factory);
      if (ObjectInputFilter.Config.getSerialFilterFactory() != factory) throw new AssertionError("factory identity");
    }
    if (setup.equals("plain") && args.length > 2) checkC3p0(mode);
    boolean custom = !setup.equals("plain");
    ObjectInputFilter stream = setup.equals("stream") ? application : null;
    checkRead("ordinary", new Report("weekly"), stream, mode, !custom);
    if (calls.get() != (custom && !setup.equals("startup") ? 1 : 0)) throw new AssertionError("application decision");
    if (setup.equals("stream")) checkArrays(mode);
    checkRead("marker", new EvilSerialized("weekly"), stream, mode, !mode.equals("block"));
  }
}
