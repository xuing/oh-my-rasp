package io.ohmyrasp.agent.rules.product.elasticsearch;

import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;

/** Isolate one declared transport block before the legacy, source-length-less decoder sees it. */
public final class Lz4TransportBlock {
  private Lz4TransportBlock() {}

  public static int decode(Object decoder, byte[] src, int offset, byte[] dst, int dstOffset, int dstLength,
      int compressedLength, MethodHandle original, boolean enforce) throws Throwable {
    if (!enforce) return (int) original.invoke(decoder, src, offset, dst, dstOffset, dstLength);
    if (compressedLength < 0 || offset < 0 || offset > src.length - compressedLength) {
      throw new IOException("Invalid Elasticsearch LZ4 transport block extent");
    }
    byte[] block = offset == 0 && compressedLength == src.length
        ? src : Arrays.copyOfRange(src, offset, offset + compressedLength);
    int consumed = (int) original.invoke(decoder, block, 0, dst, dstOffset, dstLength);
    if (consumed != compressedLength) throw new IOException("Elasticsearch LZ4 transport block length mismatch");
    return consumed;
  }
}
