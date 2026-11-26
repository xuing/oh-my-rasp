package io.ohmyrasp.agent.hook.nonpublic;

import java.beans.Statement;
import javax.xml.transform.stream.StreamSource;

/**
 * Objects whose classes are not public, in a package of their own, each overriding a method that a public
 * type declares: what a container hands a hook when it wraps a request, an expression or an XML source in an
 * implementation class. A hook in io.ohmyrasp.agent.hook reaches a non-public class of its own package by
 * reflection, so a test that keeps them beside the hook would pass for the wrong reason.
 */
public final class NonPublicTypes {
  private NonPublicTypes() {}

  /** The part of the servlet request API the hooks read. */
  public interface RequestLike {
    String getMethod();

    String getRequestURI();

    boolean isUserInRole(String role);
  }

  /** The part of the expression API the hooks read. */
  public interface ExpressionLike {
    String getExpressionString();
  }

  public static Object request(String method, String uri) {
    return new Request(method, uri);
  }

  public static Object expression(String text) {
    return new Expression(text);
  }

  public static Object statement(Object target, String methodName, Object... arguments) {
    return new HiddenStatement(target, methodName, arguments);
  }

  public static Object xmlSource(String systemId) {
    return new HiddenSource(systemId);
  }

  private static final class Request implements RequestLike {
    private final String method;
    private final String uri;

    Request(String method, String uri) {
      this.method = method;
      this.uri = uri;
    }

    @Override
    public String getMethod() {
      return method;
    }

    @Override
    public String getRequestURI() {
      return uri;
    }

    @Override
    public boolean isUserInRole(String role) {
      return false;
    }
  }

  private static final class Expression implements ExpressionLike {
    private final String text;

    Expression(String text) {
      this.text = text;
    }

    @Override
    public String getExpressionString() {
      return text;
    }
  }

  /** A java.beans.Statement (public) whose accessors are overridden in a non-public class. */
  private static final class HiddenStatement extends Statement {
    private final Object target;
    private final String methodName;
    private final Object[] arguments;

    HiddenStatement(Object target, String methodName, Object[] arguments) {
      super(target, methodName, arguments);
      this.target = target;
      this.methodName = methodName;
      this.arguments = arguments;
    }

    @Override
    public Object getTarget() {
      return target;
    }

    @Override
    public String getMethodName() {
      return methodName;
    }

    @Override
    public Object[] getArguments() {
      return arguments;
    }
  }

  /** A javax.xml.transform.stream.StreamSource (public) whose system id is overridden in a non-public class. */
  private static final class HiddenSource extends StreamSource {
    private final String systemId;

    HiddenSource(String systemId) {
      this.systemId = systemId;
    }

    @Override
    public String getSystemId() {
      return systemId;
    }
  }
}
