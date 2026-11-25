import java.lang.reflect.Method;
import java.util.Arrays;

/** Explicit reflection policy applies to dispatch at the launch API, including under force-block. */
public class ProcessPolicyCheck {
  private static void install(String selector, String action) throws Exception {
    Class<?> type = Class.forName("io.ohmyrasp.agent.policy.AgentPolicy");
    String rule = "{\"rules\":[{" + selector + ",\"action\":\"" + action + "\"}]}";
    Object value = type.getMethod("parse", String.class).invoke(null, rule);
    Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks").getMethod("installPolicy", type, String.class)
        .invoke(null, value, "process-policy");
  }

  public static void main(String[] args) throws Exception {
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    Method invoke = ProcessBuilder.class.getMethod("start");
    for (String mode : Arrays.asList("broad", "log", "block")) {
      install(mode.equals("broad") ? "\"hook\":\"command\"" : "\"algorithm\":\"command_reflect\"",
          mode.equals("broad") ? "block" : mode);
      for (int round = 0; round < rounds; round++) {
        try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope("main", "weekly")) {
          ProcessLaunchCheck.class.getMethod("ordinary").invoke(null);
          boolean denied = false;
          try {
            ProcessBuilder builder = new ProcessBuilder("/usr/bin/printf", "%s", "weekly");
            ProcessLaunchCheck.exited((Process) invoke.invoke(builder), "weekly");
          } catch (Exception e) {
            if (!HttpTransportCheck.blocked(e)) throw e;
            denied = true;
          }
          if (denied != mode.equals("block")) throw new AssertionError(mode);
        }
      }
    }
  }
}
