import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * An application for the launcher probe. It always prints that it ran. Given a track ("8", "11", "17"
 * or "main"), it also opens the system hosts file inside a request that names that file, which every
 * line blocks in block mode (the file-read probe's "file-channel" case), and prints whether it was.
 */
public class LauncherCheck {
  public static void main(String[] args) throws Exception {
    System.out.println("launcher-check: application ran");
    if (args.length == 0) {
      return;
    }
    boolean blocked = false;
    HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(args[0], "/etc/hosts");
    try {
      FileChannel channel = FileChannel.open(Paths.get("/etc/hosts"), StandardOpenOption.READ);
      channel.close();
    } catch (Exception e) {
      if (!HttpTransportCheck.blocked(e)) {
        throw e;
      }
      blocked = true;
    } finally {
      scope.close();
    }
    System.out.println("launcher-check: blocked=" + blocked);
  }
}
