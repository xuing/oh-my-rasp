package io.ohmyrasp.agent.xml;

import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.HashSet;
import java.util.Set;

/** Local code origins of classes actually defined by the built-in system loader. */
public final class SystemArchiveOrigins {
  private static Instrumentation instrumentation;
  private static final Set<URI> origins = new HashSet<URI>();
  private static long scannedAt = -1;

  private SystemArchiveOrigins() {}

  public static synchronized void initialize(Instrumentation vm) {
    if (instrumentation == null && vm != null && vm.getClass().getClassLoader() == null
        && !java.lang.reflect.Proxy.isProxyClass(vm.getClass())) instrumentation = vm;
  }

  static synchronized boolean contains(ClassLoader loader, URI archive) {
    if (instrumentation == null || loader != ClassLoader.getSystemClassLoader()
        || loader.getClass().getClassLoader() != null) return false;
    if (origins.contains(archive)) return true;
    try {
      long loaded = ManagementFactory.getClassLoadingMXBean().getTotalLoadedClassCount();
      if (loaded != scannedAt) {
        for (Class<?> type : instrumentation.getInitiatedClasses(loader)) {
          if (type.getClassLoader() != loader) continue;
          ProtectionDomain domain = type.getProtectionDomain();
          CodeSource source = domain == null ? null : domain.getCodeSource();
          URL location = source == null ? null : source.getLocation();
          if (location != null && "file".equals(location.getProtocol())) {
            try { origins.add(location.toURI()); } catch (URISyntaxException unavailable) { /* No local origin. */ }
          }
        }
        scannedAt = loaded;
      }
      return origins.contains(archive);
    } catch (LinkageError | RuntimeException unavailable) {
      return false;
    }
  }
}
