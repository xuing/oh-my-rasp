import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** A shared part can be delivered to one request and unrelated to a simultaneous request. */
public class MultipartIsolationCheck {
  private static boolean read(MultipartAccessCheck.Request request, MultipartAccessCheck.Attachment part,
      boolean acquire, CyclicBarrier gate) throws Exception {
    MultipartAccessCheck.enter(request);
    try {
      if (acquire) request.transport.getPart("attachment");
      gate.await(10, TimeUnit.SECONDS);
      if (!"weekly.jar".equals(part.getSubmittedFileName())) throw new AssertionError("wrong filename");
      return false;
    } catch (Exception failure) {
      if (!HttpTransportCheck.blocked(failure)) throw failure;
      return true;
    } finally { MultipartAccessCheck.exit(); }
  }

  private static void checkIsolation(ExecutorService workers, MultipartAccessCheck.Attachment part,
      boolean bothAcquire, boolean block) throws Exception {
    MultipartAccessCheck.Request origin = new MultipartAccessCheck.Request();
    MultipartAccessCheck.Request neighbor = new MultipartAccessCheck.Request();
    origin.part = neighbor.part = part;
    origin.policy = neighbor.policy = "role:operator";
    neighbor.authorized = bothAcquire;
    CyclicBarrier gate = new CyclicBarrier(2);
    Future<Boolean> a = workers.submit(() -> read(origin, part, true, gate));
    Future<Boolean> b = workers.submit(() -> read(neighbor, part, bothAcquire, gate));
    if (a.get(15, TimeUnit.SECONDS) != block || b.get(15, TimeUnit.SECONDS))
      throw new AssertionError("request ownership crossed threads");
    MultipartAccessCheck.enter(origin);
    try {
      origin.transport.getPart("attachment");
      MultipartAccessCheck.enter(neighbor);
      try {
        if (!"weekly.jar".equals(part.getSubmittedFileName())) throw new AssertionError();
      } finally { MultipartAccessCheck.exit(); }
      boolean denied = false;
      try { part.getSubmittedFileName(); }
      catch (Exception failure) {
        if (!HttpTransportCheck.blocked(failure)) throw failure;
        denied = true;
      }
      if (denied != block) throw new AssertionError("origin did not resume after nested dispatch");
    } finally { MultipartAccessCheck.exit(); }
  }

  public static void main(String[] args) throws Exception {
    MultipartAccessCheck.track(args[0]);
    boolean block = args[1].equals("block");
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    ExecutorService workers = Executors.newFixedThreadPool(2);
    MultipartAccessCheck.Attachment part = new MultipartAccessCheck.Attachment("weekly.jar") {
      @Override public String getSubmittedFileName() { return "weekly.jar"; }
    };
    try {
      for (int n = 0; n < rounds; n++) {
        checkIsolation(workers, part, true, block);
        checkIsolation(workers, part, false, block);
        System.out.println("row," + n + ",ok");
      }
    } finally { workers.shutdownNow(); }
  }
}
