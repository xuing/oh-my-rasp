import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/** Each JDK pipeline stage is checked on its own platform launch. */
public class ProcessPipelineCheck {
  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    String script = "true|true";
    Path errorOutput = Files.createTempFile("pipeline-report", ".txt");
    try {
      for (int n = 0; n < rounds; n++) {
        ProcessLaunchCheck.check(track, mode, "pipeline-report", "weekly", false, () -> {
          List<Process> jobs = ProcessBuilder.startPipeline(Arrays.asList(
              new ProcessBuilder("/usr/bin/printf", "%s", "weekly report"), new ProcessBuilder("/bin/cat")));
          ProcessLaunchCheck.exited(jobs.get(1), "weekly report");
          ProcessLaunchCheck.exited(jobs.get(0), "");
        });
        for (int stage = 0; stage < 2; stage++) {
          final boolean first = stage == 0;
          Files.writeString(errorOutput, "previous");
          boolean blocked = ProcessLaunchCheck.check(track, mode, first ? "first-stage" : "second-stage", script, true, () -> {
            ProcessBuilder governed = new ProcessBuilder("/bin/sh", "-c", script).redirectError(errorOutput.toFile());
            ProcessBuilder normal = first ? new ProcessBuilder("/bin/cat") : new ProcessBuilder("/bin/true");
            List<Process> jobs = ProcessBuilder.startPipeline(first ? Arrays.asList(governed, normal) : Arrays.asList(normal, governed));
            ProcessLaunchCheck.exited(jobs.get(1), "");
            ProcessLaunchCheck.exited(jobs.get(0), "");
          });
          if (blocked != Files.readString(errorOutput).equals("previous")) throw new AssertionError("stage redirect receipt");
        }
      }
    } finally {
      Files.delete(errorOutput);
    }
  }
}
