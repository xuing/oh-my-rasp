package io.ohmyrasp.agent.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** Address classification for URL sinks. Never resolve an application hostname from a hook. */
public final class NetworkHost {
  private static final Pattern IPV4 = Pattern.compile("[0-9]{1,10}(?:\\.[0-9]{1,10}){0,3}");
  private static final Pattern IPV6 = Pattern.compile("[0-9a-f:.]+");

  private static final List<InetAddress> METADATA_ADDRESSES = Arrays.asList(
      address("169.254.169.254"), address("169.254.170.2"), address("100.100.100.200"),
      address("fd00:ec2::254"));

  private NetworkHost() {}

  public static String normalize(String host) {
    if (host == null) {
      return "";
    }
    String name = host;
    if (host.startsWith("[") && host.endsWith("]")) {
      name = host.substring(1, host.length() - 1);
    } else if (host.endsWith(".") && !host.endsWith("..") && host.indexOf(':') < 0) {
      name = host.substring(0, host.length() - 1);
    }
    int zone = name.indexOf('%');
    if (zone >= 0 && name.indexOf(':') >= 0) {
      // The zone can be an OS interface name. Preserve its spelling for destination comparisons.
      return name.substring(0, zone).toLowerCase(Locale.ROOT) + name.substring(zone);
    }
    return name.toLowerCase(Locale.ROOT);
  }

  /** Identifies an HTTP destination without consulting DNS or interface state. */
  public static String destinationKey(String host) {
    String name = normalize(host);
    if (name.indexOf(':') < 0) return name;
    InetAddress ip = address(name);
    if (ip == null) return name;
    int zone = name.indexOf('%');
    return ip.getHostAddress() + (zone < 0 ? "" : name.substring(zone));
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
      if (name.isEmpty() || name.charAt(0) < '0' || name.charAt(0) > '9' || !IPV4.matcher(name).matches()) {
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
    // Brackets require an IPv6 literal even for malformed input. Never fall back to DNS.
    try {
      return InetAddress.getByName("[" + name + "]");
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
    return name.equals("localhost") || isInternal(address(name));
  }

  static boolean isInternal(InetAddress ip) {
    if (ip == null) {
      return false;
    }
    byte[] bytes = ip.getAddress();
    return ip.isLoopbackAddress() || ip.isAnyLocalAddress() || ip.isSiteLocalAddress()
        || ip.isLinkLocalAddress() || (bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc);
  }

  public static boolean isMetadata(String name) {
    if (name.equals("metadata.google.internal")) return true;
    InetAddress ip = address(name);
    // A proxy can interpret nonstandard IPv4 spellings differently from the local JVM.
    return isMetadata(ip) && (name.indexOf(':') >= 0 || name.equals(ip.getHostAddress()));
  }

  static boolean isMetadata(InetAddress ip) {
    return ip != null && METADATA_ADDRESSES.contains(ip);
  }
}
