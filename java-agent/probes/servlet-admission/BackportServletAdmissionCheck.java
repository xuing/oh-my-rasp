import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.Map;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

/** A container wrapper inherits its public accessors from a non-public superclass. */
public class BackportServletAdmissionCheck extends HttpServlet {
  private int calls;
  private java.lang.reflect.Method fileCheck;
  private boolean parameterProbe;
  private boolean parametersUnavailable;
  private RuntimeException nestedDenial;
  private boolean fileBlocked;

  private class Dispatch extends HttpServletRequestWrapper {
    private final String uri;
    int parameterReads;
    Dispatch(HttpServletRequest base, String uri) { super(base); this.uri = uri; }
    @Override public String getRequestURI() { return uri; }
    @Override public String getHeader(String key) { return "User-Agent".equalsIgnoreCase(key) ? "nacos-server" : null; }
    @Override public String getQueryString() { return parameterProbe ? "file=summary&file=%2Fetc%2Fhosts" : null; }
    @Override public Map<String, String[]> getParameterMap() {
      parameterReads++;
      if (nestedDenial != null) throw nestedDenial;
      if (parametersUnavailable) throw new IllegalStateException("form fields unavailable");
      return Collections.emptyMap();
    }
  }

  private final class Wrapped extends Dispatch {
    Wrapped(HttpServletRequest base, String uri) { super(base, uri); }
  }

  @Override protected void doPost(HttpServletRequest req, HttpServletResponse res) {
    calls++;
    if (parameterProbe) {
      try { fileCheck.invoke(null, "/etc/hosts"); } // Evaluate the hook without reading a file.
      catch (java.lang.reflect.InvocationTargetException e) {
        if (!e.getCause().getClass().getSimpleName().endsWith("RaspBlockException")) throw new AssertionError(e);
        fileBlocked = true;
      } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
    }
  }

  private void check(String uri, boolean denied) throws Exception {
    HttpServletRequest base = (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[]{HttpServletRequest.class}, (proxy, method, args) -> "getMethod".equals(method.getName()) ? "POST" : null);
    Wrapped req = new Wrapped(base, uri);
    ServletResponse res = (ServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[]{HttpServletResponse.class}, (proxy, method, args) -> null);
    int previous = calls;
    boolean blocked = false;
    try { service((ServletRequest) req, res); }
    catch (RuntimeException rejected) {
      if (!rejected.getClass().getSimpleName().endsWith("RaspBlockException")) throw rejected;
      if (nestedDenial != null && rejected != nestedDenial) throw new AssertionError("nested denial changed");
      blocked = true;
    }
    if (blocked != denied || calls - previous != (denied ? 0 : 1) || req.parameterReads == 0)
      throw new AssertionError(uri + " callback count=" + (calls - previous) + ", parameter reads=" + req.parameterReads);
  }

  public static void main(String[] args) throws Exception {
    BackportServletAdmissionCheck servlet = new BackportServletAdmissionCheck();
    servlet.check("/reports", false);
    servlet.check("/admin/reports", "block".equals(args[0]));
    String prefix = "io.ohmyrasp.agent.java" + args[1] + ".Java" + args[1];
    servlet.fileCheck = Class.forName(prefix + "RaspHooks").getMethod("beforeFileRead", Object.class);
    servlet.parameterProbe = true;
    servlet.check("/reports", false);
    if (servlet.fileBlocked) throw new AssertionError("available empty map lost precedence");
    servlet.parametersUnavailable = true;
    servlet.check("/reports", false);
    if (servlet.fileBlocked != "block".equals(args[0])) throw new AssertionError("wrong query-only decision");
    servlet.nestedDenial = (RuntimeException) Class.forName(prefix + "RaspBlockException")
        .getConstructor(String.class).newInstance("previous denial");
    servlet.check("/reports", true);
    servlet.nestedDenial = null;
    servlet.parametersUnavailable = false;
    servlet.parameterProbe = false;
    servlet.check("/reports", false);
  }
}
