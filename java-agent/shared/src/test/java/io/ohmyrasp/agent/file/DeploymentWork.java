package io.ohmyrasp.agent.file;

/**
 * What the stand-in Tomcat operations of this test tree do while they run: by default the script-write rule's
 * decision on the path they write ("true" when it is protected). A test sets {@link #body} to do more.
 */
public final class DeploymentWork {
  /** The work inside an operation. */
  public interface Body {
    String run(String path) throws Exception;
  }

  public static final Body DECIDE = new Body() {
    @Override public String run(String path) {
      return String.valueOf(ScriptFileWrite.protectedWrite(path));
    }
  };

  public static volatile Body body = DECIDE;

  private DeploymentWork() {}

  /** Called by the stand-ins with the path they write. */
  public static String inside(String path) throws Exception {
    return body.run(path);
  }
}
