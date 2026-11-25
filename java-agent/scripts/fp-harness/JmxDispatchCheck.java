import java.lang.management.ManagementFactory;
import java.util.Collections;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.EnumSet;
import javax.management.*;

public class JmxDispatchCheck {
  public interface ReportsMBean {
    int updateSelection(Object selection);
    int publish(String label, boolean write) throws Exception;
    int inspectUpdate(String label) throws Exception;
    int reportFailure();
    int setConfigSource(String source) throws Exception;
  }

  public static final class Reports implements ReportsMBean {
    final Path entry;
    Reports(Path entry) { this.entry = entry; }
    int received;
    public int inspectUpdate(String label) throws Exception {
      try (SeekableByteChannel ch = entry.getFileSystem().provider().newByteChannel(entry, EnumSet.of(StandardOpenOption.WRITE))) {
        return (int) ch.size();
      }
    }
    public int publish(String label, boolean write) throws Exception {
      if (write) {
        // A nested dispatch that fails must restore this call's selected arguments.
        try {
          ManagementFactory.getPlatformMBeanServer().invoke(new ObjectName("reports:type=Catalog"), "reportFailure", null, null);
          throw new AssertionError("nested operation did not throw");
        } catch (RuntimeMBeanException expected) {
          if (!(expected.getTargetException() instanceof IllegalStateException)) throw expected;
        }
      }
      // Open only this fixture's own file; the management argument is never used as an arbitrary path.
      try (SeekableByteChannel channel = entry.getFileSystem().provider().newByteChannel(entry,
          write ? EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)
                : EnumSet.of(StandardOpenOption.READ))) {
        if (write) channel.write(ByteBuffer.wrap(new byte[]{42}));
        return (int) channel.size();
      }
    }
    public int updateSelection(Object selection) { return ++received; }
    public int reportFailure() { throw new IllegalStateException("report unavailable"); }
    public int setConfigSource(String source) throws Exception {
      // The normal branch parses a fixed local fixture via the selected URL. No network is used.
      java.net.URL local = new java.net.URL(null, source, new java.net.URLStreamHandler() {
        protected java.net.URLConnection openConnection(java.net.URL location) {
          return new java.net.URLConnection(location) {
            public void connect() {}
            public java.io.InputStream getInputStream() {
              return new java.io.ByteArrayInputStream("<reports/>".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
          };
        }
      });
      try (java.io.InputStream in = local.openStream()) {
        String root = javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(in).getDocumentElement().getTagName();
        if (!"reports".equals(root)) throw new AssertionError(root);
      }
      return ++received;
    }
  }

  static final class Selection implements Iterable<String> {
    int rendered, iterated;
    public String toString() { rendered++; return "/reports/weekly.jsp"; }
    public java.util.Iterator<String> iterator() {
      iterated++;
      return Collections.singletonList("weekly").iterator();
    }
  }

  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    boolean observe = "observe".equals(mode);
    MBeanServer server = ManagementFactory.getPlatformMBeanServer();
    ObjectName name = new ObjectName("reports:type=Catalog");
    Path directory = Files.createTempDirectory("managed-report");
    Path entry = directory.resolve("weekly report.jsp");
    try (SeekableByteChannel seed = entry.getFileSystem().provider().newByteChannel(entry,
        EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
      seed.write(ByteBuffer.wrap(new byte[]{7}));
    }
    Reports reports = new Reports(entry);
    server.registerMBean(new StandardMBean(reports, ReportsMBean.class), name);
    Selection selection = new Selection();
    String source = "https://catalog.example.invalid/config.xml";
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(track, "weekly")) {
      boolean denied = false;
      try {
        server.invoke(name, "updateSelection", new Object[]{selection}, new String[]{"java.lang.Object"});
      } catch (Exception ex) {
        if (!HttpTransportCheck.blocked(ex)) throw ex;
        denied = true;
      }
      System.out.println("object," + reports.received + "," + selection.rendered + "," + selection.iterated + "," + denied);
      if (!observe && (reports.received != 1 || selection.rendered != 0 || selection.iterated != 0 || denied))
        throw new AssertionError("agent consumed the application's argument");
      ObjectName timerName = new ObjectName("reports:type=Schedule");
      javax.management.timer.Timer timer = new javax.management.timer.Timer();
      server.registerMBean(timer, timerName);
      String note = "See the report guide at " + source + " or /reports/weekly.jsp";
      boolean textDenied = false;
      try {
        Integer id = (Integer) server.invoke(timerName, "addNotification",
            new Object[]{"weekly", note, null, new java.util.Date(System.currentTimeMillis() + 86400000L)},
            new String[]{"java.lang.String", "java.lang.String", "java.lang.Object", "java.util.Date"});
        if (!note.equals(timer.getNotificationMessage(id))) throw new AssertionError("timer lost the notification text");
      } catch (Exception ex) {
        if (!HttpTransportCheck.blocked(ex)) throw ex;
        textDenied = true;
      } finally { server.unregisterMBean(timerName); }
      System.out.println("notes," + textDenied);
      if (!observe && textDenied) throw new AssertionError("ordinary notes rejected");
      String[] signature = {"java.lang.String", "boolean"};
      server.invoke(name, "publish", new Object[]{entry.toString(), false}, signature);
      server.invoke(name, "inspectUpdate", new Object[]{entry.resolveSibling("other.jsp").toString()},
          new String[]{"java.lang.String"});
      boolean writeDenied = false;
      try {
        server.invoke(name, "publish", new Object[]{entry.toString(), true}, signature);
      } catch (Exception ex) {
        if (!HttpTransportCheck.blocked(ex)) throw ex;
        writeDenied = true;
      }
      if (!observe && writeDenied != "block".equals(mode)) throw new AssertionError("incorrect file-open decision");
      System.out.println("write," + writeDenied);
      // Reopen the same entry outside the managed call, in the same HTTP request.
      try (SeekableByteChannel open = entry.getFileSystem().provider().newByteChannel(entry,
          EnumSet.of(StandardOpenOption.WRITE))) {
        if (open.size() != 1) throw new AssertionError("unexpected file size");
      }
      boolean missing = false;
      try {
        server.invoke(new ObjectName("reports:type=Absent"), "setConfigSource", new Object[]{source}, new String[]{"java.lang.String"});
      } catch (InstanceNotFoundException expected) {
        missing = true;
      } catch (Exception ex) {
        if (!HttpTransportCheck.blocked(ex)) throw ex;
      }
      System.out.println("missing," + missing);
      if (!observe && !missing) throw new AssertionError("missing MBean result changed");
      try {
        server.invoke(name, "reportFailure", null, null);
        throw new AssertionError("managed operation did not throw");
      } catch (RuntimeMBeanException expected) {
        if (!(expected.getTargetException() instanceof IllegalStateException)) throw expected;
      }
      int calls = reports.received;
      denied = false;
      try {
        server.invoke(name, "setConfigSource", new Object[]{source}, new String[]{"java.lang.String"});
      } catch (Exception ex) {
        if (!HttpTransportCheck.blocked(ex)) throw ex;
        if (!observe && !ex.getClass().getSimpleName().endsWith("RaspBlockException"))
          throw new AssertionError("JMX wrapped the agent's block", ex);
        denied = true;
      }
      if (!observe && (denied != "block".equals(mode) || reports.received != calls + (denied ? 0 : 1)))
        throw new AssertionError("incorrect dispatch outcome");
      System.out.println("selected," + denied);
    } finally {
      server.unregisterMBean(name);
      byte[] result = Files.readAllBytes(entry);
      Files.delete(entry);
      Files.delete(directory);
      if (!observe && (result.length != 1 || result[0] != ("block".equals(mode) ? 7 : 42)))
        throw new AssertionError("incorrect file contents after dispatch");
    }
  }
}
