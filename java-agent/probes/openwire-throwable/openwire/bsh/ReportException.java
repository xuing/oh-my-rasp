package bsh;

/** A valid exception under a package prefix formerly blocked by the agent. */
public final class ReportException extends Exception {
  public ReportException(String message) { super(message); }
}
