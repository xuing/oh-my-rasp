import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import io.dataease.auth.filter.CommunityTokenFilter;
import io.dataease.utils.ServletUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.util.UUID;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

/** Reads the actual downstream receipt and application exception for each invocation. */
public class JwtVerificationCheck {
  private static ServletRequest request() {
    return (ServletRequest) Proxy.newProxyInstance(JwtVerificationCheck.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class}, (proxy, method, args) -> {
          if ("getMethod".equals(method.getName())) return "GET";
          if ("getRequestURI".equals(method.getName())) return "/api/users/reports";
          if ("getParameterMap".equals(method.getName())) return Collections.emptyMap();
          if ("getHeaderNames".equals(method.getName())) return Collections.enumeration(Collections.singletonList("x-de-token"));
          if ("getHeader".equals(method.getName()) && "x-de-token".equalsIgnoreCase((String) args[0])) return ServletUtils.selected;
          return null;
        });
  }

  public static void main(String[] args) throws Exception {
    String mode = args[0];
    CommunityTokenFilter filter = new CommunityTokenFilter();
    filter.first = Algorithm.HMAC256(UUID.randomUUID().toString());
    filter.current = Algorithm.HMAC256(UUID.randomUUID().toString());
    ServletUtils.selected = JWT.create().withClaim("report", "weekly").sign(filter.current);
    filter.other = JWT.create().withClaim("report", "monthly").sign(filter.current);
    ServletRequest request = request();
    filter.differentRequest = request();
    AtomicInteger receipts = new AtomicInteger();
    SecurityException denied = new SecurityException("offline receiver always denies");
    FilterChain chain = (req, res) -> { receipts.incrementAndGet(); throw denied; };
    boolean primary = "main".equals(args[1]);
    Class<?> hooks = Class.forName(primary ? "io.ohmyrasp.agent.hook.OhMyRaspHooks"
        : "io.ohmyrasp.agent.java" + args[1] + ".Java" + args[1] + "RaspHooks");
    if (primary) hooks.getMethod("enterHttpRequest", Object.class, Object.class).invoke(null, request, null);
    else hooks.getMethod("beforeHttpRequest", Object.class).invoke(null, request);
    try {
      checkScenarios(mode, filter, request, receipts, denied, chain);
    } finally {
      hooks.getMethod(primary ? "exitHttpRequest" : "afterHttpRequest").invoke(null);
    }
  }

  private static void checkScenarios(String mode, CommunityTokenFilter filter, ServletRequest request,
      AtomicInteger receipts, SecurityException denied, FilterChain chain) throws Exception {
    for (String scenario : new String[]{"stop", "rethrow", "unrelated", "retry", "different-request", "string", "decoded"}) {
      filter.scenario = scenario;
      int before = receipts.get();
      String outcome = "stopped";
      try {
        filter.doFilter(request, null, chain);
      } catch (RuntimeException failure) {
        if (failure == denied) outcome = "receiver";
        else if (failure instanceof SignatureVerificationException) outcome = "verifier";
        else if (failure.getClass().getSimpleName().endsWith("RaspBlockException")) outcome = "agent";
        else throw failure;
      }
      String expected = "stop".equals(scenario) ? "stopped" : "rethrow".equals(scenario) ? "verifier" :
          ("block".equals(mode) && ("decoded".equals(scenario) || "string".equals(scenario))) ? "agent" : "receiver";
      System.out.println(scenario + "=" + outcome);
      if (!mode.equals("observe") && (!outcome.equals(expected)
          || receipts.get() != before + (expected.equals("receiver") ? 1 : 0))) throw new AssertionError(scenario);
    }
  }
}
