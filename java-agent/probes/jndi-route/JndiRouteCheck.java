import fixture.ldap.ldapURLContextFactory;
import java.util.Hashtable;
import javax.naming.*;
import javax.naming.spi.NamingManager;

/** Compare the JDK's actual provider, Name calls and result of each lookup. */
public final class JndiRouteCheck {
  private static final String URL = "ldap://reports.invalid/weekly";

  private static final class ReportName extends CompositeName {
    final String display;
    int displayCalls, componentCalls;
    ReportName(String component, String display) throws InvalidNameException {
      this.display = display;
      add(component);
    }
    @Override public String toString() { displayCalls++; return display; }
    @Override public String get(int position) { componentCalls++; return super.get(position); }
  }

  private static void check(String mode, String label, boolean remote, boolean direct,
      ReportName operand, boolean builder, java.util.concurrent.Callable<Object> lookup) throws Exception {
    int starts = ldapURLContextFactory.factories, roots = ldapURLContextFactory.roots, reads = ldapURLContextFactory.reads;
    boolean denied = false;
    try {
      if (!"weekly".equals(lookup.call())) throw new AssertionError(label);
    } catch (RuntimeException e) {
      if (!e.getClass().getSimpleName().endsWith("RaspBlockException")) throw e;
      denied = true;
    }
    System.out.println(label + "=" + (denied ? "blocked" : "read") + " displayCalls=" + (operand == null ? 0 : operand.displayCalls));
    if ("observe".equals(mode)) return;
    boolean expected = remote && "block".equals(mode);
    int successful = expected ? 0 : 1;
    if (denied != expected || ldapURLContextFactory.reads - reads != successful
        || ldapURLContextFactory.roots - roots != (remote ? successful : 0)
        || ldapURLContextFactory.factories - starts != (remote && !direct ? successful : 0)) throw new AssertionError(label);
    if (operand != null && (operand.displayCalls != 0 || operand.componentCalls !=
        (builder ? 0 : 1 + (remote ? successful : 0)))) throw new AssertionError(label + " changed Name accesses");
  }

  public static void main(String[] args) throws Exception {
    String mode = args[1];
    Hashtable<String,Object> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, ldapURLContextFactory.class.getName());
    env.put(Context.URL_PKG_PREFIXES, "fixture");
    InitialContext ctx = new InitialContext(env);
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(args[0], "weekly")) {
      JaasDirectoryCheck.declarations();
      JaasDirectoryCheck.login(mode, false);
      ReportName local = new ReportName("weekly", URL);
      check(mode, "local-component", false, false, local, false, () -> ctx.lookup(local));
      check(mode, "leading-space", false, false, null, false, () -> ctx.lookup(" " + URL));
      ReportName remote = new ReportName(URL, "weekly");
      check(mode, "url-component", true, false, remote, false, () -> ctx.lookup(remote));
      check(mode, "string", true, false, null, false, () -> ctx.lookup(URL));
      check(mode, "repeat", true, false, null, false, () -> ctx.lookup(URL));
      check(mode, "link", true, false, null, false, () -> ctx.lookupLink(URL));
      check(mode, "direct", true, true, null, false, () -> new ldapURLContextFactory.ReportURLContext().lookup(URL));
      if ("main".equals(args[0]) && "block".equals(mode)) JaasDirectoryCheck.generalPolicyOnly();
      NamingManager.setInitialContextFactoryBuilder(environment -> new ldapURLContextFactory());
      JaasDirectoryCheck.login(mode, true);
      ReportName custom = new ReportName(URL, URL);
      check(mode, "builder", false, false, custom, true, () -> ctx.lookup(custom));
      check(mode, "builder-string", false, false, null, true, () -> ctx.lookup(URL));
    } finally { ctx.close(); }
  }
}
