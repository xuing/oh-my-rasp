package io.dataease.auth.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.dataease.utils.ServletUtils;
import jakarta.servlet.*;
import java.io.IOException;

/** Offline call-site fixture. The receiving chain always rejects and serves no resource. */
public final class CommunityTokenFilter {
  public String scenario;
  public String other;
  public Algorithm first, current;
  public ServletRequest differentRequest;

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    String selected = ServletUtils.getToken();
    String input = "unrelated".equals(scenario) ? other : selected;
    try {
      DecodedJWT decoded = JWT.decode(input);
      if ("decoded".equals(scenario)) first.verify(decoded);
      else JWT.require(first).build().verify(input);
    } catch (JWTVerificationException rejected) {
      if ("stop".equals(scenario)) return;
      if ("rethrow".equals(scenario)) throw rejected;
      if ("retry".equals(scenario)) JWT.require(current).build().verify(input);
    }
    chain.doFilter("different-request".equals(scenario) ? differentRequest : request, response);
  }
}
