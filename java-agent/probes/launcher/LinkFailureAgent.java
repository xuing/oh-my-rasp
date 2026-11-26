import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;

/**
 * A probe agent that starts the Java 8 line by hand, on a JVM where the Java 8 JAR's Boot-Class-Path has
 * put that line on the bootstrap loader, which on Java 9 and later cannot see java.sql. The start must
 * fail before the line registers any transformer, so it reports how many of the line's transformer
 * classes were loaded.
 */
public class LinkFailureAgent {
  public static void premain(String args, Instrumentation instrumentation) {
    try {
      Class<?> line = Class.forName("io.ohmyrasp.agent.java8.OhMyRaspJava8Agent", true,
          ClassLoader.getSystemClassLoader());
      System.out.println("link-check: line loader=" + line.getClassLoader());
      line.getMethod("premain", String.class, Instrumentation.class).invoke(null, "", instrumentation);
      System.out.println("link-check: started");
    } catch (Throwable failure) {
      Throwable cause = failure instanceof InvocationTargetException ? failure.getCause() : failure;
      System.out.println("link-check: failed " + cause);
    }
    int transformers = 0;
    for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
      if (loaded.getName().matches("io\\.ohmyrasp\\.agent\\.java8\\.Java8\\w*Transformer")) {
        transformers++;
      }
    }
    System.out.println("link-check: transformer classes loaded=" + transformers);
  }
}
