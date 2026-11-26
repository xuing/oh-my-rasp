import java.io.*;
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import com.caucho.hessian.io.SerializerFactory;
import org.apache.dubbo.common.serialize.hessian2.Hessian2Serialization;
import org.apache.dubbo.common.serialize.hessian2.Hessian2SerializerFactory;
import java.util.HashMap;
import org.apache.commons.beanutils.BeanComparator;

/** Both codecs receive only locally encoded, inert report records. */
public final class HessianAllocationCheck {
  public static final class Monthly extends BeanComparator {
    public static int constructed;
    public int month = 7;
    public Monthly() { constructed++; }
  }
  private final SerializerFactory factory;
  private final Hessian2Serialization dubbo;

  private HessianAllocationCheck(boolean rpc) {
    factory = rpc ? null : new SerializerFactory();
    dubbo = rpc ? new Hessian2Serialization() : null;
  }

  private byte[] encode(Object value) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    if (dubbo != null) {
      org.apache.dubbo.common.serialize.ObjectOutput out = dubbo.serialize(null, bytes);
      out.writeObject(value);
      out.flushBuffer();
    } else {
      Hessian2Output out = new Hessian2Output(bytes);
      out.writeObject(value);
      out.flush();
    }
    return bytes.toByteArray();
  }

  private Object decode(byte[] bytes, Class<?> expected) throws Exception {
    ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
    if (dubbo != null) {
      org.apache.dubbo.common.serialize.ObjectInput in = dubbo.deserialize(null, stream);
      return expected == null ? in.readObject() : in.readObject(expected);
    }
    Hessian2Input in = new Hessian2Input(stream);
    in.setSerializerFactory(factory);
    return expected == null ? in.readObject() : in.readObject(expected);
  }

  private void check(String mode) throws Exception {
    String listed = BeanComparator.class.getName();
    if (dubbo != null) Hessian2SerializerFactory.SERIALIZER_FACTORY.getDeserializer(listed);
    else factory.getDeserializer(listed);
    if (decode(encode(new bsh.BshMonthly()), null).getClass() != bsh.BshMonthly.class)
      throw new AssertionError("ordinary package DTO changed");
    if (((BeanComparator[])decode(encode(new BeanComparator[0]), null)).length != 0)
      throw new AssertionError("empty array changed");
    byte[] bytes = encode(new Monthly());
    if (decode(bytes, reports.BeanComparator.class).getClass() != reports.BeanComparator.class)
      throw new AssertionError("expected-type substitution changed");
    Object selected = dubbo != null ? Hessian2SerializerFactory.SERIALIZER_FACTORY.getDeserializer(Monthly.class)
        : factory.getDeserializer(Monthly.class);
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
    if (dubbo == null) {
      SerializerFactory restricted = new SerializerFactory();
      restricted.getClassFactory().deny(listed);
      Hessian2Input in = new Hessian2Input(new ByteArrayInputStream(encode(new BeanComparator())));
      in.setSerializerFactory(restricted);
      if (!(in.readObject() instanceof HashMap)) throw new AssertionError("library fallback did not select a map");
    }
  }

  public static void main(String[] args) throws Exception {
    new HessianAllocationCheck("dubbo".equals(args[0])).check(args[1]);
  }
}
