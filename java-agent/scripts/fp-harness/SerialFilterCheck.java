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
      if (value instanceof Report && value.equals(result)) return true;
      if (result instanceof EvilSerialized marker && marker.marker().equals("weekly")) return true;
      throw new AssertionError("changed value");
    } catch (InvalidClassException rejected) {
      return false;
    }
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
    boolean custom = !setup.equals("plain");
    ObjectInputFilter stream = setup.equals("stream") ? application : null;
    try (HttpTransportCheck.Scope scope = mode.equals("bare") ? null : new HttpTransportCheck.Scope("main", "weekly")) {
      if (read(new Report("weekly"), stream) == custom || calls.get() != (custom && !setup.equals("startup") ? 1 : 0)) {
        throw new AssertionError("application decision");
      }
      boolean delivered = read(new EvilSerialized("weekly"), stream);
      System.out.println("marker=" + delivered);
      if (delivered == mode.equals("block")) throw new AssertionError("marker receipt");
    }
  }
}
