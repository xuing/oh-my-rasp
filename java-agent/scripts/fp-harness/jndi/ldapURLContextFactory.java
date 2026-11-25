package fixture.ldap;

import com.sun.jndi.toolkit.url.GenericURLContext;
import java.lang.reflect.Proxy;
import java.util.Hashtable;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.InitialContextFactory;
import javax.naming.spi.ObjectFactory;
import javax.naming.spi.ResolveResult;

/** Both providers return a fixed report. No sockets or external directories are used. */
public final class ldapURLContextFactory implements ObjectFactory, InitialContextFactory {
  public static int roots, reads, factories;
  public static Context directory() {
    return (Context) Proxy.newProxyInstance(ldapURLContextFactory.class.getClassLoader(), new Class<?>[]{Context.class},
        (proxy, method, args) -> {
          if ("lookup".equals(method.getName()) || "lookupLink".equals(method.getName())) {
            reads++;
            return "weekly";
          }
          return null;
        });
  }
  public Context getInitialContext(Hashtable<?,?> environment) { return directory(); }
  public Object getObjectInstance(Object object, Name name, Context ctx, Hashtable<?,?> environment) {
    factories++;
    return new ReportURLContext();
  }
  public static final class ReportURLContext extends GenericURLContext {
    public ReportURLContext() { super(null); }
    @Override protected ResolveResult getRootURLContext(String url, Hashtable<?,?> environment) {
      roots++;
      return new ResolveResult(directory(), new CompositeName());
    }
  }
}
