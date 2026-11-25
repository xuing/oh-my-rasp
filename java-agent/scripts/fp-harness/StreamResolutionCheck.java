import bsh.Primitive;
import java.io.*;
import java.lang.reflect.*;
import org.apache.commons.collections.functors.ConstantTransformer;

/** Normal JDK resolution, virtual resolver outcomes and repeated streams on the same thread. */
public final class StreamResolutionCheck {
  private static final Class<?> LISTED = org.apache.commons.beanutils.BeanComparator.class;
  private static final Class<?> REPORT = reports.BeanComparator.class;

  private static final class ReportHandler implements InvocationHandler, Serializable {
    private static final long serialVersionUID = 1L;
    public Object invoke(Object proxy, Method method, Object[] args) { return null; }
  }

  private static Object read(Object value, final String resolver) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) { out.writeObject(value); }
    ByteArrayInputStream source = new ByteArrayInputStream(bytes.toByteArray());
    try (ObjectInputStream in = new ObjectInputStream(source) {
      @Override protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (desc.getName().equals(LISTED.getName()) || desc.getName().equals(REPORT.getName())) {
          if (resolver.equals("migrate")) return REPORT;
          if (resolver.equals("select")) return LISTED;
          if (resolver.equals("reject")) throw new ClassNotFoundException("report retired");
        }
        return super.resolveClass(desc);
      }
    }) { return in.readObject(); }
  }

  private static void check(String label, Object input, String resolver, Class<?> expectedType, boolean listed,
      String mode) throws Exception {
    String outcome;
    try {
      Object result = read(input, resolver);
      if (result.getClass() != expectedType) throw new AssertionError("resolver result: " + label);
      if (result instanceof Primitive && !Integer.valueOf(42).equals(((Primitive) result).getValue()))
        throw new AssertionError("integer value");
      outcome = "read";
    } catch (ClassNotFoundException missing) {
      if (!"reject".equals(resolver) || !"report retired".equals(missing.getMessage())) throw missing;
      outcome = "missing";
    } catch (InvalidClassException rejected) {
      if (!String.valueOf(rejected.getMessage()).contains("filter status: REJECTED")) throw rejected;
      outcome = "blocked";
    } catch (RuntimeException rejected) {
      if (!rejected.getClass().getSimpleName().endsWith("RaspBlockException")) throw rejected;
      outcome = "blocked";
    }
    System.out.println(label + "=" + outcome);
    String expected = resolver.equals("reject") ? "missing" : listed && mode.equals("block") ? "blocked" : "read";
    if (!mode.equals("observe") && !expected.equals(outcome)) throw new AssertionError(label);
  }

  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    Object marker = LISTED.getConstructor().newInstance();
    Object report = REPORT.getConstructor().newInstance();
    Object proxy = Proxy.newProxyInstance(StreamResolutionCheck.class.getClassLoader(),
        new Class<?>[]{ConstantTransformer.class}, new ReportHandler());
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(track, "weekly")) {
      check("integer", new Primitive(42), "default", Primitive.class, false, mode);
      check("case-sensitive", new bsh.BshMonthly(), "default", bsh.BshMonthly.class, false, mode);
      check("rejected-resolver", marker, "reject", null, false, mode);
      check("migrated-report", marker, "migrate", REPORT, false, mode);
      check("custom-resolution", report, "select", LISTED, true, mode);
      check("first-stream", marker, "default", LISTED, true, mode);
      check("second-stream", marker, "default", LISTED, true, mode);
      check("proxy", proxy, "default", proxy.getClass(), true, mode);
    }
  }
}
