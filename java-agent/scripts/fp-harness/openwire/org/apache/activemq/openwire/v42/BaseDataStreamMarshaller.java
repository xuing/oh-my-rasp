package org.apache.activemq.openwire.v42;

/** Fixed call-site fixture. Input never selects the class or the constructor argument. */
public final class BaseDataStreamMarshaller {
  public static int initializations, constructions;
  public static final class ReportValue {
    static { initializations++; }
    public ReportValue(String ignored) { constructions++; }
  }
  public Throwable createThrowable(String name, String message) {
    try {
      ReportValue.class.getConstructor(String.class).newInstance("weekly");
      return new Exception("constructed");
    } catch (Exception rejected) {
      return new Exception("rejected", rejected);
    }
  }
}
