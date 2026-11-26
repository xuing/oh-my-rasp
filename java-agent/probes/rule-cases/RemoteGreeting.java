/** The class the driver's loopback listener serves to a remote class loader; never on the driver's class path. */
public class RemoteGreeting {
  @Override public String toString() { return "served over loopback"; }
}
