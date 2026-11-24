package io.ohmyrasp.agent.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.regex.Pattern;

/** Address classification for URL sinks. Never resolve an application hostname from a hook. */
public final class NetworkHost {
  private static final Pattern IPV4 = Pattern.compile("[0-9]{1,10}(?:\\.[0-9]{1,10}){0,3}");
  private static final Pattern IPV6 = Pattern.compile("[0-9a-f:.]+");

  private NetworkHost() {}

  public static String normalize(String host) {
    if (host == null) {
      return "";
    }
    String name = host.toLowerCase(Locale.ROOT);
    if (name.startsWith("[") && name.endsWith("]")) {
      return name.substring(1, name.length() - 1);
    }
    return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
  }

  private static InetAddress address(String name) {
    if (name.indexOf(':') >= 0) {
      int scope = name.indexOf('%');
      if (scope >= 0) {
        name = name.substring(0, scope);
      }
      if (name.indexOf(':') < 0 || !IPV6.matcher(name).matches()) {
        return null;
      }
    } else {
      if (!IPV4.matcher(name).matches()) {
        return null;
      }
      String[] octets = name.split("\\.");
      // Java accepts one to four decimal parts. The final part fills the remaining bytes.
      long packed = 0;
      for (int i = 0; i < octets.length; i++) {
        int bits = i + 1 == octets.length ? 8 * (4 - i) : 8;
        long part = Long.parseLong(octets[i]);
        if (part >= (1L << bits)) {
          return null;
        }
        packed = (packed << bits) | part;
      }
      byte[] bytes = {(byte) (packed >>> 24), (byte) (packed >>> 16),
          (byte) (packed >>> 8), (byte) packed};
      try {
        return InetAddress.getByAddress(bytes);
      } catch (UnknownHostException impossible) {
        throw new AssertionError(impossible);
      }
    }
    // A colon forces the JDK IPv6 literal parser. Scope names are irrelevant to the range.
    try {
      return InetAddress.getByName(name);
    } catch (UnknownHostException invalidLiteral) {
      return null;
    }
  }

  public static boolean isLoopback(String name) {
    if (name.equals("localhost")) {
      return true;
    }
    InetAddress ip = address(name);
    return ip != null && ip.isLoopbackAddress();
  }

  public static boolean isInternal(String name) {
    if (name.equals("localhost") || name.equals("0")) {
      return true;
    }
    InetAddress ip = address(name);
    if (ip == null) {
      return false;
    }
    byte[] bytes = ip.getAddress();
    return ip.isLoopbackAddress() || ip.isAnyLocalAddress() || ip.isSiteLocalAddress()
        || ip.isLinkLocalAddress() || (bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc);
  }

  public static boolean isMetadata(String name) {
    if (name.equals("169.254.169.254") || name.equals("169.254.170.2")
        || name.equals("100.100.100.200") || name.equals("metadata.google.internal")) {
      return true;
    }
    if (name.indexOf(':') < 0) {
      return false;
    }
    InetAddress ip = address(name);
    if (ip == null) {
      return false;
    }
    String literal = ip.getHostAddress();
    return literal.equals("fd00:ec2:0:0:0:0:0:254") || literal.equals("169.254.169.254")
        || literal.equals("169.254.170.2") || literal.equals("100.100.100.200");
  }
}
