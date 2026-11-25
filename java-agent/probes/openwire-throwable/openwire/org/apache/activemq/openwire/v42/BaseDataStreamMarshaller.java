package org.apache.activemq.openwire.v42;

/** Fixed call-site fixture. Input never selects the class or the constructor argument. */
public final class BaseDataStreamMarshaller {
  public static int labelConstructions, initializations, constructions;
  public static final class ReportLabel {
    public ReportLabel() { labelConstructions++; }
  }
  public static final class ReportValue {
    static { initializations++; }
    public ReportValue(String ignored) { constructions++; }
  }
  public Throwable createThrowable(String name, String message) {
    try {
      ReportLabel.class.getConstructor().newInstance();
      return (Throwable)(Object)ReportValue.class.getConstructor(String.class).newInstance("weekly");
    } catch (Exception rejected) {
      return new Exception("rejected", rejected);
    }
  }
}
