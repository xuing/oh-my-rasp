import java.io.*;
import java.util.Collections;
import java.util.Enumeration;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter;
import org.springframework.remoting.support.RemoteInvocation;

/** Fixed in-memory report invocations; no endpoint or untrusted stream is used. */
public final class HttpInvokerReadCheck {
  public static final class Request extends HttpTransportCheck.Request {
    Request() { super("weekly"); }
    @Override public Enumeration<String> getHeaderNames() { return Collections.enumeration(Collections.singleton("content-type")); }
    public String getHeader(String name) { return "application/x-java-serialized-object"; }
  }
  private static final class ReportInput extends ServletInputStream {
    private final ByteArrayInputStream input;
    ReportInput(byte[] data) { input = new ByteArrayInputStream(data); }
    public int read() { return input.read(); }
    public boolean isFinished() { return input.available() == 0; }
    public boolean isReady() { return true; }
    public void setReadListener(ReadListener listener) { }
  }
  public interface ReportService { String report(Object label); }
  public static final class Reports implements ReportService {
    int calls;
    public String report(Object label) { calls++; return "report " + label; }
  }
  private static class Exporter extends HttpInvokerServiceExporter {
    Object invokeReport(InputStream in) throws Exception {
      return invokeAndCreateResult(decode(in), getProxy()).getValue();
    }
    RemoteInvocation decode(InputStream in) throws Exception { return readRemoteInvocation(null, in); }
  }
  private static final class LocalExporter extends Exporter {
    @Override protected RemoteInvocation doReadRemoteInvocation(ObjectInputStream stream) {
      return new RemoteInvocation("local", new Class<?>[0], new Object[0]);
    }
  }
  private static byte[] record(Object arg) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(new RemoteInvocation("report", new Class<?>[]{Object.class}, new Object[]{arg}));
    }
    return bytes.toByteArray();
  }

  static void install(String rule) throws Exception {
    Class<?> policy = Class.forName("io.ohmyrasp.agent.policy.AgentPolicy");
    Object parsed = policy.getMethod("parse", String.class).invoke(null, "{\"rules\":[" + rule + "]}");
    Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks").getMethod("installPolicy", policy, String.class)
        .invoke(null, parsed, "report");
  }

  private static void decode(Exporter exporter, InputStream input, boolean denied) throws Exception {
    try {
      RemoteInvocation invocation = exporter.decode(input);
      if (!"report".equals(invocation.getMethodName()) || !"weekly".equals(invocation.getArguments()[0]))
        throw new AssertionError("RPC value changed");
      if (denied) throw new AssertionError("read reached the service");
    } catch (RuntimeException e) {
      if (!denied || !HttpTransportCheck.blocked(e)) throw e;
    }
  }

  public static void main(String[] args) throws Exception {
    String track = args[0];
    boolean main = track.equals("main"), block = args[1].equals("block");
    Class<?> hooks = Class.forName(main ? "io.ohmyrasp.agent.hook.OhMyRaspHooks" :
        "io.ohmyrasp.agent.java" + track + ".Java" + track + "RaspHooks");
    if (main) hooks.getMethod("enterHttpRequest", Object.class, Object.class).invoke(null, new Request(), null);
    else hooks.getMethod("beforeHttpRequest", Object.class).invoke(null, new Request());
    try {
      byte[] valid = record("weekly");
      Exporter exporter = new Exporter();
      Reports service = new Reports();
      exporter.setService(service);
      exporter.setServiceInterface(ReportService.class);
      exporter.afterPropertiesSet();
      if (!"report weekly".equals(exporter.invokeReport(new ReportInput(valid))) || service.calls != 1)
        throw new AssertionError("ordinary RPC did not reach the service");
      // The listed binary name is an inert local DTO without serialization callbacks.
      boolean rejected = false;
      try {
        RemoteInvocation invocation = exporter.decode(new ReportInput(record(new org.apache.commons.beanutils.BeanComparator())));
        if (invocation.getArguments()[0].getClass() != org.apache.commons.beanutils.BeanComparator.class)
          throw new AssertionError("wrong DTO");
      } catch (Exception e) {
        if (!(e instanceof InvalidClassException) && !HttpTransportCheck.blocked(e)) throw e;
        rejected = true;
      }
      if (rejected != block) throw new AssertionError("wrong nested type decision");
      if (!main) return;

      install("{\"hook\":\"deserialization\",\"action\":\"block\"}");
      decode(exporter, new ReportInput(valid), false);
      install("{\"algorithm\":\"deserialization_http_invoker\",\"action\":\"block\"}");
      if (!"local".equals(new LocalExporter().decode(new ReportInput(valid)).getMethodName()))
        throw new AssertionError("local invocation changed");
      decode(exporter, new ReportInput(valid), block);
      install("{\"algorithm\":\"deserialization_http_object_stream\",\"action\":\"block\"}");
      try (ObjectInputStream unused = new ObjectInputStream(new ReportInput(valid))) {
        // Header inspection without an object read.
      }
      decode(exporter, new ByteArrayInputStream(valid), false);
      decode(exporter, new ReportInput(valid), block);
    } finally {
      hooks.getMethod(main ? "exitHttpRequest" : "afterHttpRequest").invoke(null);
    }
  }
}
