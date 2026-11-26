import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Writes a script file into a private web root during a request. The agent's own event spool sits
 * in the same web root and also ends in .jsp, so the agent's write of the event matches the rule it
 * reports. Only private temporary files are written.
 */
public final class OwnWritesCheck {
  public static void main(String[] args) throws Exception {
    String track = args[0];
    Path target = Paths.get(args[1]);
    boolean denied = false;
    try (HttpTransportCheck.Scope ignored = new HttpTransportCheck.Scope(track, "weekly")) {
      try (FileOutputStream out = new FileOutputStream(target.toFile())) {
        out.write(1);
      }
    } catch (Exception failure) {
      if (!HttpTransportCheck.blocked(failure)) throw failure;
      denied = true;
    }
    System.out.println("row,denied," + denied + ",created," + Files.exists(target));
    System.out.println("done");
  }
}
