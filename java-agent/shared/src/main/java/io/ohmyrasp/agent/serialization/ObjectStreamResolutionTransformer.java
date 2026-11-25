package io.ohmyrasp.agent.serialization;

import io.ohmyrasp.agent.rules.product.activemq.OpenWireThrowableVisitor;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Backport transformer for JDK stream resolution and OpenWire exception construction. */
public abstract class ObjectStreamResolutionTransformer implements ClassFileTransformer {
  private static final String STREAM = "java/io/ObjectInputStream";
  private final String hooks;

  protected ObjectStreamResolutionTransformer(Class<?> hooks) { this.hooks = org.objectweb.asm.Type.getInternalName(hooks); }

  @Override public final byte[] transform(ClassLoader loader, String name, Class<?> redefined,
      ProtectionDomain domain, byte[] bytes) {
    boolean openWire = OpenWireThrowableVisitor.matches(name);
    if (bytes == null || (!STREAM.equals(name) && !openWire)) return null;
    try {
      return weave(bytes, openWire);
    } catch (RuntimeException error) {
      if (Boolean.getBoolean("ohmyrasp.debug")) System.err.println("[OHMYRASP] deserialization transform failed for " + name + ": " + error);
      return null;
    }
  }

  private byte[] weave(byte[] bytes, final boolean openWire) {
    ClassReader reader = new ClassReader(bytes);
    ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
    reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
      @Override public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        MethodVisitor original = super.visitMethod(access, name, desc, signature, exceptions);
        if (openWire) return OpenWireThrowableVisitor.wrap(original, name, desc, hooks);
        if (!"readNonProxyDesc".equals(name) && !"readProxyDesc".equals(name)) return original;
        return new MethodVisitor(Opcodes.ASM9, original) {
          @Override public void visitMethodInsn(int op, String owner, String method, String descriptor, boolean itf) {
            super.visitMethodInsn(op, owner, method, descriptor, itf);
            if (op != Opcodes.INVOKEVIRTUAL || !STREAM.equals(owner)) return;
            String hook;
            if ("resolveClass".equals(method) && "(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;".equals(descriptor)) {
              hook = "afterObjectStreamClassResolve";
            } else if ("resolveProxyClass".equals(method) && "([Ljava/lang/String;)Ljava/lang/Class;".equals(descriptor)) {
              hook = "afterObjectStreamProxyResolve";
            } else return;
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, hook, "(Ljava/lang/Class;)V", false);
          }
        };
      }
    }, 0);
    return writer.toByteArray();
  }
}
