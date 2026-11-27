package io.ohmyrasp.agent.net;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

/**
 * The cloud metadata addresses are kept as bytes so that preloading NetworkHost initialises no JDK networking class;
 * the bytes must mean exactly the addresses the JDK parses from their usual spellings.
 */
final class NetworkHostTest {
  @Test
  void eachMetadataSpellingIsRecognisedByNameAndByAddress() throws Exception {
    for (String literal : new String[] {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254",
        "fd00:0ec2:0:0:0:0:0:0254", "::ffff:169.254.169.254"}) {
      assertTrue(NetworkHost.isMetadata(literal), literal);
      assertTrue(NetworkHost.isMetadata(InetAddress.getByName(literal)), literal);
    }
  }

  @Test
  void neighbouringAndOtherAddressesAreNot() throws Exception {
    for (String literal : new String[] {"169.254.169.253", "169.254.170.3", "100.100.100.201", "fd00:ec2::255",
        "127.0.0.1", "10.0.0.1", "::1"}) {
      assertFalse(NetworkHost.isMetadata(literal), literal);
      assertFalse(NetworkHost.isMetadata(InetAddress.getByName(literal)), literal);
    }
    assertFalse(NetworkHost.isMetadata((InetAddress) null));
  }
}
