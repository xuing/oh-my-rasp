package io.ohmyrasp.agent.rules.product.elasticsearch;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Replace only the legacy array decode in Elasticsearch's compressed transport block reader. */
public final class Lz4TransportVisitor {
  public static final String OWNER = "org/elasticsearch/transport/Lz4TransportDecompressor";
  private static final String CODEC = "net/jpountz/lz4/LZ4FastDecompressor";
  private static final String FAST = "([BI[BII)I";

  private Lz4TransportVisitor() {}

  public static MethodVisitor wrap(MethodVisitor mv, int access, String name, String desc, final String hooks) {
    if ((access & Opcodes.ACC_STATIC) != 0 || !"decodeBlock".equals(name)
        || !"(Lorg/elasticsearch/common/bytes/BytesReference;)I".equals(desc)) return mv;
    return new MethodVisitor(Opcodes.ASM9, mv) {
      private boolean readBlockExtent;

      @Override public void visitFieldInsn(int op, String owner, String field, String signature) {
        super.visitFieldInsn(op, owner, field, signature);
        if (op == Opcodes.GETFIELD && OWNER.equals(owner) && "compressedLength".equals(field) && "I".equals(signature)) {
          readBlockExtent = true;
        }
      }

      @Override public void visitMethodInsn(int op, String owner, String method, String signature, boolean itf) {
        if (readBlockExtent && op == Opcodes.INVOKEVIRTUAL && CODEC.equals(owner)
            && "decompress".equals(method) && FAST.equals(signature)) {
          // Link the existing decoder in the application's own class loader. The bootstrap helper
          // has no dependency on Elasticsearch or on its chosen LZ4 library.
          mv.visitVarInsn(Opcodes.ALOAD, 0);
          mv.visitFieldInsn(Opcodes.GETFIELD, OWNER, "compressedLength", "I");
          mv.visitLdcInsn(new Handle(Opcodes.H_INVOKEVIRTUAL, CODEC, method, signature, false));
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "enforceElasticLz4Bounds", "()Z", false);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getInternalName(Lz4TransportBlock.class), "decode",
              "(Ljava/lang/Object;[BI[BIIILjava/lang/invoke/MethodHandle;Z)I", false);
        } else {
          super.visitMethodInsn(op, owner, method, signature, itf);
        }
      }
    };
  }

  public abstract static class Transformer implements ClassFileTransformer {
    private final String hooks;
    protected Transformer(Class<?> hooks) { this.hooks = Type.getInternalName(hooks); }
    @Override public byte[] transform(ClassLoader loader, String name, Class<?> redefined, ProtectionDomain domain, byte[] bytes) {
      if (!OWNER.equals(name)) return null;
      ClassReader reader = new ClassReader(bytes);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
        @Override public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
          return wrap(super.visitMethod(access, name, desc, signature, exceptions), access, name, desc, hooks);
        }
      }, 0);
      return writer.toByteArray();
    }
  }
}
