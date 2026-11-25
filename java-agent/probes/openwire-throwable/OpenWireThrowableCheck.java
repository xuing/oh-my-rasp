import java.lang.reflect.Method;
import org.apache.activemq.openwire.v42.BaseDataStreamMarshaller;

/** Exercise the fixed upstream exception factory in process; no broker or protocol traffic is involved. */
public final class OpenWireThrowableCheck {
  public static void main(String[] args) throws Exception {
    for (String version : args[1].split(",")) {
      String pkg = "org.apache.activemq.openwire.v" + Integer.parseInt(version);
      Method factory = Class.forName(pkg + ".BaseDataStreamMarshaller")
          .getDeclaredMethod("createThrowable", String.class, String.class);
      Object marshaller = Class.forName(pkg + ".ExceptionResponseMarshaller").getDeclaredConstructor().newInstance();
      factory.setAccessible(true);
      Throwable normal = (Throwable)factory.invoke(marshaller, "bsh.ReportException", "weekly report");
      if (normal.getClass() != bsh.ReportException.class || !"weekly report".equals(normal.getMessage()))
        throw new AssertionError("exception changed on v" + version);
      Object invalid = factory.invoke(marshaller, "java.lang.StringBuilder", "weekly report");
      if (!(invalid instanceof IllegalArgumentException)) throw new AssertionError("upstream rejection changed on v" + version);
      Throwable missing = (Throwable)factory.invoke(marshaller, "reports.Absent", "weekly report");
      if (missing.getClass() != Throwable.class) throw new AssertionError("upstream fallback changed on v" + version);
    }
    boolean denied = args[0].equals("block");
    Throwable result = new BaseDataStreamMarshaller().createThrowable("report label", "private report text");
    int expected = denied ? 0 : 1;
    if (!"rejected".equals(result.getMessage()) || BaseDataStreamMarshaller.labelConstructions != 1
        || (result.getCause() instanceof ClassCastException) == denied
        || BaseDataStreamMarshaller.initializations != expected || BaseDataStreamMarshaller.constructions != expected)
      throw new AssertionError("unexpected initializer or constructor outcome");
  }
}
