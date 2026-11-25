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

  private static class Dispatch extends HttpServletRequestWrapper {
    private final String uri;
    int parameterReads;
    Dispatch(HttpServletRequest base, String uri) { super(base); this.uri = uri; }
    @Override public String getRequestURI() { return uri; }
    @Override public String getHeader(String key) { return "User-Agent".equalsIgnoreCase(key) ? "nacos-server" : null; }
    @Override public Map<String, String[]> getParameterMap() { parameterReads++; return Collections.emptyMap(); }
  }

  private static final class Wrapped extends Dispatch {
    Wrapped(HttpServletRequest base, String uri) { super(base, uri); }
  }

  @Override protected void doPost(HttpServletRequest req, HttpServletResponse res) { calls++; }

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
      blocked = true;
    }
    if (blocked != denied || calls - previous != (denied ? 0 : 1) || req.parameterReads == 0)
      throw new AssertionError(uri + " callback count=" + (calls - previous) + ", parameter reads=" + req.parameterReads);
  }

  public static void main(String[] args) throws Exception {
    BackportServletAdmissionCheck servlet = new BackportServletAdmissionCheck();
    servlet.check("/reports", false);
    servlet.check("/admin/reports", "block".equals(args[0]));
    servlet.check("/reports", false);
  }
}
