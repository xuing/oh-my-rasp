import java.io.*;
import java.util.Collections;
import java.util.List;
import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.parser.SerializableParser;

/** Only prebuilt report values reach the library's parser; no RPC endpoint is started. */
public final class XmlRpcReadCheck {
  private static byte[] encode(Object value) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) { out.writeObject(value); }
    return bytes.toByteArray();
  }

  private static Object read(byte[] bytes) throws XmlRpcException {
    SerializableParser parser = new SerializableParser();
    parser.setResult(bytes);
    return parser.getResult();
  }

  private static void checkNestedType(boolean block) throws Exception {
    boolean rejected = false;
    try {
      Object item = ((List<?>)read(encode(Collections.singletonList(
          new org.apache.commons.beanutils.BeanComparator())))).get(0);
      if (item.getClass() != org.apache.commons.beanutils.BeanComparator.class) throw new AssertionError("wrong DTO");
    } catch (Exception e) {
      if (!(e.getCause() instanceof InvalidClassException) && !HttpTransportCheck.blocked(e)) throw e;
      rejected = true;
    }
    if (rejected != block) throw new AssertionError("incorrect nested type decision");
  }

  public static void main(String[] args) throws Exception {
    boolean primary = "main".equals(args[0]), block = "block".equals(args[1]);
    byte[] report = encode("weekly");
    // Worker dispatch carries no servlet request. Only this parser's stream establishes the transport.
    if (!"weekly".equals(read(report))) throw new AssertionError("worker value changed");
    checkNestedType(block);
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(args[0], "weekly")) {
      if (!"weekly".equals(read(report))) throw new AssertionError("normal extension value changed");
      checkNestedType(block);
      if (!primary) return;

      HttpInvokerReadCheck.install("{\"hook\":\"deserialization\",\"action\":\"block\"}");
      if (!"weekly".equals(read(report))) throw new AssertionError("broad rule intercepted an ordinary extension");
      HttpInvokerReadCheck.install("{\"algorithm\":\"deserialization_xmlrpc_serialized\",\"action\":\"block\"}");
      try {
        read(new byte[]{1, 2});
        throw new AssertionError("invalid header accepted");
      } catch (XmlRpcException invalid) {
        if (!(invalid.getCause() instanceof IOException)) throw invalid;
      }
    }
    boolean blocked = false;
    try {
      if (!"weekly".equals(read(report))) throw new AssertionError("wrong report");
    } catch (RuntimeException e) {
      if (!HttpTransportCheck.blocked(e)) throw e;
      blocked = true;
    }
    if (blocked != block) throw new AssertionError("incorrect extension policy decision");

    // A plain stream on a worker thread is not the parser's: outside a request it is decided as on every line,
    // blocked in block mode (outside_request is block by default).
    HttpInvokerReadCheck.install("{\"algorithm\":\"deserialization_gadget\",\"action\":\"block\"}");
    byte[] localData = encode(new org.apache.commons.beanutils.BeanComparator());
    boolean localRejected = false;
    try (ObjectInputStream local = new ObjectInputStream(new ByteArrayInputStream(localData))) {
      if (local.readObject().getClass() != org.apache.commons.beanutils.BeanComparator.class)
        throw new AssertionError("local worker record changed");
    } catch (InvalidClassException rejected) {
      localRejected = true;
    }
    if (localRejected != block) throw new AssertionError("incorrect local worker stream decision");
  }
}
