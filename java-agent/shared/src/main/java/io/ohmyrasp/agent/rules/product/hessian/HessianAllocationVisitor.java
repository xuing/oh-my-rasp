package io.ohmyrasp.agent.rules.product.hessian;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

/** Inspect the class selected at Hessian's built-in allocation calls. */
public final class HessianAllocationVisitor {
  private static final String CAUCHO = "com/caucho/hessian/io/";
  private static final String LITE = "com/alibaba/com/caucho/hessian/io/";

  private HessianAllocationVisitor() {}

  private static String decoder(String owner) {
    if (owner.startsWith(CAUCHO)) return owner.substring(CAUCHO.length());
    if (owner.startsWith(LITE)) return owner.substring(LITE.length());
    return "";
  }

  public static boolean matches(String owner) {
    if (owner == null) return false;
    switch (decoder(owner)) {
      case "JavaDeserializer": case "UnsafeDeserializer": case "BeanDeserializer":
      case "MapDeserializer": case "CollectionDeserializer":
      case "StringValueDeserializer": case "SqlDateDeserializer": return true;
      default: return false;
    }
  }

  public static MethodVisitor wrap(String owner, final MethodVisitor delegate, int access, String name, String desc, final String hooks) {
    String codec = decoder(owner);
    boolean map = "MapDeserializer".equals(codec);
    boolean collection = "CollectionDeserializer".equals(codec);
    boolean materializes;
    switch (codec) {
      case "MapDeserializer":
        materializes = ("createMap".equals(name) && "()Ljava/util/Map;".equals(desc))
            || ("readMap".equals(name) && desc.endsWith(")Ljava/lang/Object;"));
        break;
      case "CollectionDeserializer": materializes = "createList".equals(name) && "()Ljava/util/Collection;".equals(desc); break;
      case "StringValueDeserializer": materializes = "create".equals(name) && "(Ljava/lang/String;)Ljava/lang/Object;".equals(desc); break;
      case "SqlDateDeserializer": materializes = "create".equals(name) && "(J)Ljava/lang/Object;".equals(desc); break;
      case "JavaDeserializer": case "BeanDeserializer": case "UnsafeDeserializer":
        materializes = "instantiate".equals(name) && "()Ljava/lang/Object;".equals(desc);
        break;
      default: return delegate;
    }
    if (!materializes) return delegate;
    return new MethodNode(Opcodes.ASM9, access, name, desc, null, null) {
      @Override public void visitEnd() {
        for (AbstractInsnNode insn : instructions.toArray()) {
          if (insn.getOpcode() != Opcodes.INVOKEVIRTUAL) continue;
          MethodInsnNode call = (MethodInsnNode)insn;
          InsnList guard = new InsnList();
          String basis;
          if ("java/lang/reflect/Constructor".equals(call.owner) && "newInstance".equals(call.name)
              && "([Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) {
            basis = "hessian_constructor";
            guard.add(new InsnNode(Opcodes.DUP2));
            guard.add(new InsnNode(Opcodes.POP));
            guard.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, call.owner, "getDeclaringClass", "()Ljava/lang/Class;", false));
          } else if (("java/lang/Class".equals(call.owner) && "newInstance".equals(call.name)
                      && "()Ljava/lang/Object;".equals(call.desc))
              || ("sun/misc/Unsafe".equals(call.owner) && "allocateInstance".equals(call.name)
                      && "(Ljava/lang/Class;)Ljava/lang/Object;".equals(call.desc))) {
            basis = "java/lang/Class".equals(call.owner) ? "hessian_class_new_instance" : "hessian_unsafe_allocation";
            guard.add(new InsnNode(Opcodes.DUP));
          } else continue;
          AbstractInsnNode use = call.getNext();
          while (use != null && use.getOpcode() < 0) use = use.getNext();
          if (map || collection) {
            if (!(use instanceof TypeInsnNode) || use.getOpcode() != Opcodes.CHECKCAST
                || !(map ? "java/util/Map" : "java/util/Collection").equals(((TypeInsnNode)use).desc)) continue;
          } else if (use == null || use.getOpcode() != Opcodes.ARETURN) continue;
          guard.add(new LdcInsnNode(basis));
          guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks, "beforeHessianAllocation", "(Ljava/lang/Class;Ljava/lang/String;)V", false));
          instructions.insertBefore(call, guard);
        }
        accept(delegate);
      }
    };
  }

  public abstract static class Transformer implements ClassFileTransformer {
    private final String hooks;
    protected Transformer(Class<?> hooks) { this.hooks = Type.getInternalName(hooks); }
    @Override public byte[] transform(ClassLoader loader, final String owner, Class<?> redefined, ProtectionDomain domain, byte[] bytes) {
      if (!matches(owner) || bytes == null) return null;
      try {
        ClassReader reader = new ClassReader(bytes);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
          @Override public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            return wrap(owner, mv, access, name, desc, hooks);
          }
        }, 0);
        return writer.toByteArray();
      } catch (RuntimeException error) {
        if (Boolean.getBoolean("ohmyrasp.debug")) System.err.println("[OHMYRASP] Hessian transform failed for " + owner + ": " + error);
        return null;
      }
    }
  }
}
