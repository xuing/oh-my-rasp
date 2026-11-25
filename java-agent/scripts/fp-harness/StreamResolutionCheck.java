import bsh.Primitive;
import java.io.*;
import java.lang.reflect.*;
import org.apache.xalan.xsltc.trax.TemplatesImpl;

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

  private static Object check(String label, Object input, String resolver, Class<?> expectedType, boolean listed,
      String mode) throws Exception {
    String outcome;
    Object result = null;
    try {
      result = read(input, resolver);
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
    return result;
  }

  // Both API lines have the same public functor methods under different package names.
  private static void checkCommonsCollections(String pkg, Object marker, String mode) throws Exception {
    Class<?> equal = Class.forName(pkg + ".EqualPredicate");
    Object predicate = read(equal.getConstructor(Object.class).newInstance("weekly"), "default");
    Method evaluate = equal.getMethod("evaluate", Object.class);
    if (!Boolean.TRUE.equals(evaluate.invoke(predicate, "weekly")) || !Boolean.FALSE.equals(evaluate.invoke(predicate, "daily"))) {
      throw new AssertionError("equality predicate changed");
    }
    Class<?> constant = Class.forName(pkg + ".ConstantTransformer");
    Constructor<?> constructor = constant.getConstructor(Object.class);
    Object result = read(constructor.newInstance("weekly"), "default");
    if (!"weekly".equals(constant.getMethod("transform", Object.class).invoke(result, "daily"))) {
      throw new AssertionError("constant changed");
    }
    Object wrapper = check("nested constant value", constructor.newInstance(marker), "default", constant, true, mode);
    if (wrapper != null) {
      Object nested = constant.getMethod("getConstant").invoke(wrapper);
      if (nested.getClass() != LISTED) {
        throw new AssertionError("nested value changed");
      }
    }
  }

  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    Object marker = LISTED.getConstructor().newInstance();
    Object report = REPORT.getConstructor().newInstance();
    Object proxy = Proxy.newProxyInstance(StreamResolutionCheck.class.getClassLoader(),
        new Class<?>[]{TemplatesImpl.class}, new ReportHandler());
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(track, "weekly")) {
      if (args.length > 2) {
        checkCommonsCollections("org.apache.commons.collections.functors", marker, mode);
        checkCommonsCollections("org.apache.commons.collections4.functors", marker, mode);
      }
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
