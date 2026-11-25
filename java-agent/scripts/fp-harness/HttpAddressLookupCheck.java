import io.ohmyrasp.agent.net.NetworkHost;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/** Counts resolver calls in a fresh JVM so agent-side address comparisons cannot leak DNS queries. */
public final class HttpAddressLookupCheck extends InetAddressResolverProvider {
  private static final AtomicInteger calls = new AtomicInteger();

  @Override public String name() { return "address-check"; }

  @Override public InetAddressResolver get(Configuration configuration) {
    return new InetAddressResolver() {
      @Override public Stream<InetAddress> lookupByName(String host, LookupPolicy policy) throws UnknownHostException {
        calls.incrementAndGet();
        throw new UnknownHostException(host);
      }

      @Override public String lookupByAddress(byte[] address) throws UnknownHostException {
        calls.incrementAndGet();
        throw new UnknownHostException("reverse lookup");
      }
    };
  }

  public static void main(String[] args) throws Exception {
    try {
      InetAddress.getByName("resolver-control.example.invalid");
    } catch (UnknownHostException expected) {
      // The configured provider rejects the control lookup.
    }
    int before = calls.get();
    if (before == 0) throw new AssertionError("test resolver was not installed");
    for (String value : new String[]{"printer.example.invalid", ".abc:def", "ffff::bad::face", "fe80::a%FloorA"}) {
      String host = NetworkHost.normalize(value);
      NetworkHost.destinationKey(host);
      NetworkHost.isLoopback(host);
      NetworkHost.isInternal(host);
      NetworkHost.isMetadata(host);
    }
    if (calls.get() != before) throw new AssertionError("address classification invoked DNS");
  }
}
