import java.io.*;
import java.lang.reflect.*;
import java.util.HashMap;
import org.apache.commons.beanutils.BeanComparator;

/** Both codecs receive only locally encoded, inert report records. */
public final class HessianAllocationCheck {
  public static final class Monthly extends BeanComparator {
    public static int constructed;
    public int month = 7;
    public Monthly() { constructed++; }
  }
  private final Object factory;
  private final Class<?> factoryType, input, output;

  private HessianAllocationCheck(String pkg) throws Exception {
    factoryType = Class.forName(pkg + ".SerializerFactory");
    factory = factoryType.getDeclaredConstructor().newInstance();
    input = Class.forName(pkg + ".Hessian2Input");
    output = Class.forName(pkg + ".Hessian2Output");
  }

  private byte[] encode(Object value) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    Object out = output.getConstructor(OutputStream.class).newInstance(bytes);
    output.getMethod("writeObject", Object.class).invoke(out, value);
    output.getMethod("flush").invoke(out);
    return bytes.toByteArray();
  }

  private Object decode(byte[] bytes, Class<?> expected) throws Exception {
    Object in = input.getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(bytes));
    input.getMethod("setSerializerFactory", factoryType).invoke(in, factory);
    if (expected == null) return input.getMethod("readObject").invoke(in);
    return input.getMethod("readObject", Class.class).invoke(in, expected);
  }

  private void check(String mode, boolean caucho) throws Exception {
    String listed = BeanComparator.class.getName();
    factoryType.getMethod("getDeserializer", String.class).invoke(factory, listed);
    if (decode(encode(new bsh.BshMonthly()), null).getClass() != bsh.BshMonthly.class)
      throw new AssertionError("ordinary package DTO changed");
    if (((BeanComparator[])decode(encode(new BeanComparator[0]), null)).length != 0)
      throw new AssertionError("empty array changed");
    byte[] bytes = encode(new Monthly());
    if (decode(bytes, reports.BeanComparator.class).getClass() != reports.BeanComparator.class)
      throw new AssertionError("expected-type substitution changed");
    Object selected = factoryType.getMethod("getDeserializer", Class.class).invoke(factory, Monthly.class);
    boolean reflective = selected.getClass().getSimpleName().equals("JavaDeserializer");
    if (!reflective && !selected.getClass().getSimpleName().equals("UnsafeDeserializer"))
      throw new AssertionError("unexpected report deserializer " + selected.getClass());
    // A cached decoder still makes an independent allocation on each read.
    for (int read = 0; read < 2; read++) {
      int before = Monthly.constructed;
      boolean blocked = false;
      try {
        Object restored = decode(bytes, null);
        if (!(restored instanceof Monthly) || ((Monthly)restored).month != 7)
          throw new AssertionError("wrong report");
      } catch (Exception ex) {
        if (!HttpTransportCheck.blocked(ex)) throw ex;
        blocked = true;
      }
      if (Monthly.constructed - before != (reflective && !blocked ? 1 : 0)) throw new AssertionError("constructor receipt");
      if (blocked != "block".equals(mode)) throw new AssertionError("wrong allocation decision");
    }
    if (caucho) {
      Object restricted = factoryType.getDeclaredConstructor().newInstance();
      Object classFactory = factoryType.getMethod("getClassFactory").invoke(restricted);
      classFactory.getClass().getMethod("deny", String.class).invoke(classFactory, listed);
      Object in = input.getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(encode(new BeanComparator())));
      input.getMethod("setSerializerFactory", factoryType).invoke(in, restricted);
      Object mapped = input.getMethod("readObject").invoke(in);
      if (!(mapped instanceof HashMap)) throw new AssertionError("library fallback did not select a map");
    }
  }

  public static void main(String[] args) throws Exception {
    String pkg = args[0];
    new HessianAllocationCheck(pkg).check(args[1], pkg.equals("com.caucho.hessian.io"));
  }
}
