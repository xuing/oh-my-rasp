package io.ohmyrasp.agent.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.Properties;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

/**
 * The baked shirudo settings, META-INF/ohmyrasp-shirudo.properties, read from the agent's own JAR file or class
 * directory, on every line. The file is opened directly: a jar: URL built from the JAR's path breaks when a
 * directory name ends in "!", and a class-relative lookup would search the application class path first.
 *
 * <p>A JAR without the file is a general agent JAR and has no baked settings. A JAR whose manifest says
 * {@code OhMyRasp-Shirudo-Upatch: true} must carry them: when it does not, or the file cannot be read, the
 * start fails rather than run unlocked. A malformed line keeps the keys read before it, so a damaged later line
 * cannot erase an already-read lock_config or mode.
 */
public final class BakedProperties {
  /** The file's path inside the JAR. */
  public static final String ENTRY = "META-INF/ohmyrasp-shirudo.properties";
  /** The manifest attribute of a shirudo upatch JAR. */
  public static final String UPATCH_ATTRIBUTE = "OhMyRasp-Shirudo-Upatch";

  private BakedProperties() {}

  /**
   * The baked settings of the agent that {@code own} belongs to, or null when it has none. {@code own}'s code
   * source names the agent's JAR or directory; a class the bootstrap loader defined records none, and the
   * agent is then the one the system class loader loaded {@code entryClass} from.
   *
   * @throws IllegalStateException when the agent declares baked settings it does not carry, or they cannot be
   *     read
   */
  public static Properties read(Class<?> own, String entryClass) {
    File location = location(own);
    if (location == null) {
      try {
        location = location(Class.forName(entryClass, false, ClassLoader.getSystemClassLoader()));
      } catch (ClassNotFoundException | LinkageError e) {
        return null;
      }
    }
    return location == null ? null : read(location);
  }

  /** The baked settings in a JAR file or class directory, or null when it has none. */
  public static Properties read(File location) {
    if (location.isDirectory()) {
      File file = new File(location, ENTRY);
      if (!file.isFile()) {
        return null;
      }
      try {
        InputStream in = new FileInputStream(file);
        try {
          return load(in);
        } finally {
          in.close();
        }
      } catch (IOException e) {
        throw new IllegalStateException("cannot read the baked settings " + file + ": " + e, e);
      }
    }
    try {
      JarFile jar = new JarFile(location);
      try {
        ZipEntry entry = jar.getEntry(ENTRY);
        if (entry == null) {
          Manifest manifest = jar.getManifest();
          if (manifest != null && "true".equalsIgnoreCase(manifest.getMainAttributes().getValue(UPATCH_ATTRIBUTE))) {
            throw new IllegalStateException(location + " is a shirudo upatch JAR without " + ENTRY);
          }
          return null;
        }
        InputStream in = jar.getInputStream(entry);
        try {
          return load(in);
        } finally {
          in.close();
        }
      } finally {
        jar.close();
      }
    } catch (IOException e) {
      throw new IllegalStateException("cannot read the baked settings in " + location + ": " + e, e);
    }
  }

  private static Properties load(InputStream in) throws IOException {
    Properties props = new Properties();
    try {
      props.load(new InputStreamReader(in, StandardCharsets.UTF_8));
    } catch (IllegalArgumentException malformed) {
      // A malformed unicode escape: the keys before the bad line stay.
    }
    return props;
  }

  private static File location(Class<?> type) {
    ProtectionDomain domain = type.getProtectionDomain();
    CodeSource source = domain == null ? null : domain.getCodeSource();
    URL url = source == null ? null : source.getLocation();
    if (url == null) {
      return null;
    }
    try {
      return new File(url.toURI());
    } catch (URISyntaxException | IllegalArgumentException e) {
      return new File(url.getPath());
    }
  }
}
