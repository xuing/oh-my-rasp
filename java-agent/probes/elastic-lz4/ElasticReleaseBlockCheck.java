import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import net.jpountz.lz4.LZ4FastDecompressor;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.ReleasableBytesReference;
import org.elasticsearch.transport.Compression;
import org.elasticsearch.transport.Lz4TransportDecompressor;

/** Only valid blocks from the release compressor. The decoder records its visible input extent. */
public final class ElasticReleaseBlockCheck {
  private static final class RecordingDecoder extends LZ4FastDecompressor {
    private final LZ4FastDecompressor delegate;
    private final boolean misreport;
    int calls;
    boolean shared;
    RecordingDecoder(LZ4FastDecompressor delegate, boolean misreport) {
      this.delegate = delegate;
      this.misreport = misreport;
    }
    @Override public int decompress(byte[] src, int off, byte[] dst, int dstOff, int dstLen) {
      int consumed = delegate.decompress(src, off, dst, dstOff, dstLen);
      calls++;
      shared |= off != 0 || src.length != consumed;
      return misreport ? consumed - 1 : consumed;
    }
    @Override public int decompress(ByteBuffer src, int off, ByteBuffer dst, int dstOff, int dstLen) {
      throw new AssertionError("expected a release with the legacy array call");
    }
  }

  public static void main(String[] args) throws Exception {
    boolean block = args[0].equals("block");
    byte[] line = "quarterly report\n".getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream plain = new ByteArrayOutputStream();
    for (int i = 0; i < 9000; i++) plain.write(line);
    ByteArrayOutputStream wire = new ByteArrayOutputStream();
    try (OutputStream compressor = Compression.Scheme.lz4OutputStream(wire)) { plain.writeTo(compressor); }
    if (wire.size() >= plain.size()) throw new AssertionError("fixture did not compress");
    byte[] storage = new byte[wire.size() + 23];
    System.arraycopy(wire.toByteArray(), 0, storage, 11, wire.size());
    BytesArray input = new BytesArray(storage, 11, wire.size());
    check(input, plain.toByteArray(), block, false);
    if (block) check(input, plain.toByteArray(), true, true);
  }

  private static void check(BytesArray input, byte[] expected, boolean block, boolean misreport) throws Exception {
    Constructor<?> ctor = Lz4TransportDecompressor.class.getConstructors()[0];
    Class<?> pool = ctor.getParameterTypes()[0];
    if (pool.isInterface()) pool = Class.forName("org.elasticsearch.transport.BytesRefRecycler");
    try (Lz4TransportDecompressor decoder = (Lz4TransportDecompressor)
        ctor.newInstance(pool.getField("NON_RECYCLING_INSTANCE").get(null))) {
      Field field = Lz4TransportDecompressor.class.getDeclaredField("decompressor");
      field.setAccessible(true);
      RecordingDecoder recording = new RecordingDecoder((LZ4FastDecompressor) field.get(decoder), misreport);
      field.set(decoder, recording);
      try {
        if (decoder.decompress(input) != input.length()) throw new AssertionError("input extent");
        if (misreport) throw new AssertionError("consumption mismatch accepted");
      } catch (IOException rejected) {
        if (!misreport || !rejected.getMessage().contains("block length mismatch")) throw rejected;
      }
      if (recording.calls == 0 || recording.shared == block) throw new AssertionError("decoder input isolation");
      ByteArrayOutputStream decoded = new ByteArrayOutputStream();
      ReleasableBytesReference page;
      while ((page = decoder.pollDecompressedPage(true)) != null) {
        try { page.writeTo(decoded); } finally { page.close(); }
      }
      if (!Arrays.equals(misreport ? new byte[0] : expected, decoded.toByteArray())) throw new AssertionError("output content");
      System.out.println("decoder calls=" + recording.calls + " shared=" + recording.shared + " delivered=" + decoded.size());
    }
  }
}
