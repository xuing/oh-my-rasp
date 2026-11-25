package io.ohmyrasp.agent.rules.product.dataease;

/** One CommunityTokenFilter invocation. Nothing survives its stack frame. */
public final class FilterVerification {
  private final Object request;
  private final Object chain;
  private String token;
  private Object decoded;
  private boolean verifying;
  private String rejection;

  public FilterVerification(Object request, Object chain) {
    this.request = request;
    this.chain = chain;
  }

  public void selected(String value) {
    if (value == null || !value.equals(token)) {
      decoded = null;
      rejection = null;
    }
    token = value;
  }

  public void decoded(String value, Object result) {
    if (token != null && token.equals(value)) decoded = result;
  }

  public void verifying(Object operand) {
    verifying = token != null && !token.isEmpty()
        && (operand instanceof String ? token.equals(operand) : decoded != null && operand == decoded);
  }

  public void verified() {
    if (verifying) rejection = null;
    verifying = false;
  }

  public void caught(Throwable failure) {
    if (verifying) {
      String name = failure.getClass().getName();
      if ("com.auth0.jwt.exceptions.SignatureVerificationException".equals(name)
          || "com.auth0.jwt.exceptions.AlgorithmMismatchException".equals(name)) rejection = name;
    }
    verifying = false;
  }

  public String continuing(Object nextChain, Object nextRequest) {
    return nextChain == chain && nextRequest == request ? rejection : null;
  }
}
