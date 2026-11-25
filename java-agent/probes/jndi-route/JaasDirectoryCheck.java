import com.sun.security.auth.module.JndiLoginModule;
import fixture.ldap.ldapURLContextFactory;
import java.util.HashMap;
import java.util.Map;
import javax.naming.Context;
import javax.security.auth.Subject;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginException;

/** The fixture directory rejects the report account locally. No credentials leave this JVM. */
public final class JaasDirectoryCheck {
  private static final String DIRECTORY = "ldap://reports.invalid/empty";

  static void declarations() {
    Map<String, Object> options = new HashMap<>();
    options.put("user.provider.url", DIRECTORY);
    new AppConfigurationEntry(JndiLoginModule.class.getName(),
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
    options.clear();
    int[] displays = {0};
    options.put("description", new Object() {
      @Override public String toString() { displays[0]++; return "user.provider.url=" + DIRECTORY; }
    });
    new AppConfigurationEntry(JndiLoginModule.class.getName(),
        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
    if (displays[0] != 0) throw new AssertionError("agent formatted an unused JAAS option");
  }

  static void generalPolicyOnly() throws Exception {
    Class<?> policy = Class.forName("io.ohmyrasp.agent.policy.AgentPolicy");
    java.lang.reflect.Method install = Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks")
        .getMethod("installPolicy", policy, String.class);
    Object parsed = policy.getMethod("parse", String.class).invoke(null,
        "{\"rules\":[{\"algorithm\":\"jndi_disable_all\",\"action\":\"block\"}]}");
    install.invoke(null, parsed, "directory-check");
    try {
      login("block", false);
    } finally {
      install.invoke(null, policy.getMethod("absent").invoke(null), "directory-check");
    }
  }

  static void login(String mode, boolean builder) throws Exception {
    System.setProperty(Context.URL_PKG_PREFIXES, "fixture");
    System.setProperty(Context.INITIAL_CONTEXT_FACTORY, ldapURLContextFactory.class.getName());
    Map<String, String> options = new HashMap<>();
    options.put("user.provider.url", DIRECTORY);
    options.put("group.provider.url", DIRECTORY);
    JndiLoginModule module = new JndiLoginModule();
    module.initialize(new Subject(), callbacks -> {
      for (javax.security.auth.callback.Callback callback : callbacks) {
        if (callback instanceof NameCallback) ((NameCallback) callback).setName("reports");
        if (callback instanceof PasswordCallback) ((PasswordCallback) callback).setPassword("fixture".toCharArray());
      }
    }, new HashMap<String, Object>(), options);
    int reads = ldapURLContextFactory.reads;
    boolean blocked = false;
    try {
      module.login();
      throw new AssertionError("empty directory accepted a login");
    } catch (LoginException expected) {
      // The local provider reported that the directory did not exist.
    } catch (RuntimeException e) {
      if (!HttpTransportCheck.blocked(e)) throw e;
      blocked = true;
    }
    boolean deny = !builder && "block".equals(mode);
    if (blocked != deny || ldapURLContextFactory.reads - reads != (deny ? 0 : 1))
      throw new AssertionError("login result or directory read count differed, builder=" + builder);
  }
}
