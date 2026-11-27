import java.nio.file.*;
import java.util.Iterator;
import java.util.concurrent.*;
import java.util.stream.Stream;

/** Lazy walks over the same root retain their own origin until directory acquisition. */
public class DirectoryWalkCheck {
  private static HttpTransportCheck.Scope scope(String track, String input, String uri) throws Exception {
    return track.equals("off") ? null : new HttpTransportCheck.Scope(track, input, uri);
  }

  private static Stream<Path> start(String track, Path tree, boolean selected, boolean follow, int depth) throws Exception {
    try (HttpTransportCheck.Scope ignored = scope(track, selected ? tree.toString() : "weekly", "/origin")) {
      return Files.walk(tree, depth, follow ? new FileVisitOption[]{FileVisitOption.FOLLOW_LINKS} : new FileVisitOption[0]);
    }
  }

  /**
   * The consumer's own request. In carried mode (the agent runs with outside_request=log) it serves none: only the
   * request that created the walk, which the walk carries, makes the listing a request's, and it still blocks.
   */
  private static HttpTransportCheck.Scope consumerScope(String track, String mode, Path tree) throws Exception {
    return mode.equals("carried") ? null : scope(track, tree.resolve("config").toString(), "/consumer");
  }

  private static void consume(String track, String mode, String label, Stream<Path> walk, Path tree,
      boolean expectBlock, boolean hasChildren) throws Exception {
    int children = 0;
    boolean denied = false;
    try (Stream<Path> entries = walk; HttpTransportCheck.Scope ignored = consumerScope(track, mode, tree)) {
      Iterator<Path> it = entries.iterator();
      while (it.hasNext()) if (it.next().getNameCount() > tree.getNameCount() + 1) children++;
    } catch (Exception e) {
      if (!HttpTransportCheck.blocked(e)) throw e;
      denied = true;
    }
    System.out.println("row," + label + "," + expectBlock + "," + denied + "," + (children != 0));
    if (denied && children != 0) throw new AssertionError("received protected names before denial");
    if (!denied && (children != 0) != hasChildren) throw new AssertionError("unexpected traversal depth");
    boolean blocking = mode.equals("block") || mode.equals("carried");
    if (!mode.equals("observe") && denied != (blocking && expectBlock)) throw new AssertionError(label);
  }

  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    Path tree = Files.createTempDirectory("report-catalog");
    Path symlink = Files.createSymbolicLink(tree.resolve("config"), Paths.get("/etc"));
    ExecutorService pool = Executors.newFixedThreadPool(2);
    int initialDescriptors = DirectoryCheck.descriptorCount(Paths.get("/etc"));
    try {
      for (int i = 0; i < rounds; i++) {
        try (Stream<Path> selected = start(track, tree, true, true, 2);
             Stream<Path> normal = start(track, tree, false, true, 2)) {
          CountDownLatch ready = new CountDownLatch(2);
          Future<?> a = pool.submit(() -> {
            ready.countDown(); ready.await(); consume(track, mode, "selected", selected, tree, true, true); return null;
          });
          Future<?> b = pool.submit(() -> {
            ready.countDown(); ready.await(); consume(track, mode, "fixed", normal, tree, false, true); return null;
          });
          a.get(15, TimeUnit.SECONDS);
          b.get(15, TimeUnit.SECONDS);
        }
        consume(track, mode, "no-follow", start(track, tree, true, false, 2), tree, false, false);
        consume(track, mode, "depth-one", start(track, tree, true, true, 1), tree, false, false);
        if (DirectoryCheck.descriptorCount(Paths.get("/etc")) != initialDescriptors)
          throw new AssertionError("protected directory descriptors leaked after a walk");
      }
    } finally {
      pool.shutdownNow();
      Files.delete(symlink);
      Files.delete(tree);
    }
  }
}
