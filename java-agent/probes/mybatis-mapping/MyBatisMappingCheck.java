import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.ibatis.executor.statement.PreparedStatementHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.reflection.SystemMetaObject;
import org.apache.ibatis.scripting.xmltags.XMLLanguageDriver;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.RowBounds;

/** Real mapper compilation with a recording JDBC receiver. No connection to a database is made. */
public class MyBatisMappingCheck {
  public static class Report {
    int reads;
    public Object getOrders() {
      reads++;
      return Collections.emptyList();
    }
  }

  private final Configuration configuration = new Configuration();
  private final Map<String,Object> parameters = new HashMap<String,Object>();
  private final Report report = new Report();
  private final Connection connection;
  private int calls;
  private boolean monitoring;

  private MyBatisMappingCheck() {
    parameters.put("request", report);
    parameters.put("week", 7);
    parameters.put("second", "; select 7");
    connection = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[]{Connection.class}, (self, method, args) -> {
          if (!method.getName().equals("prepareStatement")) throw new AssertionError(method);
          calls++;
          return null;
        });
  }

  private MappedStatement mapper(String template) {
    SqlSource source = new XMLLanguageDriver().createSqlSource(configuration, "<script>" + template + "</script>", Map.class);
    return new MappedStatement.Builder(configuration, "report", source, SqlCommandType.SELECT).build();
  }

  private void prepare(MappedStatement ms, BoundSql bound, boolean mustBlock) throws Exception {
    int previous = calls;
    boolean blocked = false;
    try {
      new PreparedStatementHandler(null, ms, parameters, RowBounds.DEFAULT, null, bound).prepare(connection, null);
    } catch (RuntimeException failure) {
      for (Throwable t = failure; t != null; t = t.getCause()) {
        if (t.getClass().getSimpleName().endsWith("RaspBlockException")) blocked = true;
      }
      if (!blocked) throw failure;
    }
    boolean expectedBlock = mustBlock && !monitoring;
    if (blocked != expectedBlock || calls != previous + (expectedBlock ? 0 : 1)) {
      throw new AssertionError("unexpected decision or JDBC receiver call count");
    }
  }

  private void run() throws Exception {
    MappedStatement safe = mapper("select #{week} order by 1");
    prepare(safe, safe.getBoundSql(parameters), false);
    if (report.reads != 0) throw new AssertionError("agent read unused orders property");

    MappedStatement dynamic = mapper("select #{week} ${second}");
    BoundSql bound = dynamic.getBoundSql(parameters);
    String rendered = bound.getSql();
    prepare(dynamic, bound, true);

    // A text-preserving plugin copy belongs to this same BoundSql and prepare call.
    String copy = new String(rendered);
    SystemMetaObject.forObject(bound).setValue("sql", copy);
    prepare(dynamic, bound, true);
    // The scoped decision must have been popped even on the preceding exceptional exit.
    connection.prepareStatement(copy);
    SystemMetaObject.forObject(bound).setValue("sql", "select ?");
    prepare(dynamic, bound, false);

    MappedStatement fixed = mapper("select #{week} ; select 7");
    BoundSql independent = fixed.getBoundSql(parameters);
    if (!rendered.equals(independent.getSql())) throw new AssertionError("expected equal SQL text");
    prepare(fixed, independent, false);
  }

  private void managedRules() throws Exception {
    Class<?> hooks = Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks");
    Class<?> policy = Class.forName("io.ohmyrasp.agent.policy.AgentPolicy");
    String json = "{\"rules\":[{\"algorithm\":\"sql_policy\",\"action\":\"log\"},"
        + "{\"algorithm\":\"sql_identifier_injection\",\"action\":\"log\"}]}";
    Object parsed = policy.getMethod("parse", String.class).invoke(null, json);
    hooks.getMethod("installPolicy", policy, String.class).invoke(null, parsed, "fixture");
    parameters.put("sort", ",sleep(0)");
    MappedStatement ms = mapper("select #{week} order by 1 ${sort}");
    BoundSql bound = ms.getBoundSql(parameters);
    prepare(ms, bound, false);
    prepare(ms, bound, false);
  }

  public static void main(String[] args) throws Exception {
    MyBatisMappingCheck check = new MyBatisMappingCheck();
    check.monitoring = args.length == 1 && args[0].equals("monitor");
    if (args.length == 1 && args[0].equals("managed")) check.managedRules();
    else check.run();
  }
}
