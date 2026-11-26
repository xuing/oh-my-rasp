import io.ohmyrasp.agent.shaded.asm.ClassReader;
import io.ohmyrasp.agent.shaded.asm.Opcodes;
import io.ohmyrasp.agent.shaded.asm.tree.*;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import javax.management.BadAttributeValueExpException;

/** Inspect the installed JDK reader through the packaged transformer, without creating a legacy stream. */
public final class JmxAttributeLayoutCheck {
  private static final String OWNER = "javax/management/BadAttributeValueExpException";

  private static int displayCalls(byte[] bytes, String expectedHook) {
    ClassNode type = new ClassNode();
    new ClassReader(bytes).accept(type, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    int calls = 0, guards = 0;
    for (MethodNode method : type.methods) {
      for (AbstractInsnNode insn : method.instructions) {
        if (!(insn instanceof MethodInsnNode)) continue;
        MethodInsnNode call = (MethodInsnNode) insn;
        if ("jmxAttributeDisplayReceiver".equals(call.name)) guards++;
        if (!"readObject".equals(method.name) || call.getOpcode() != Opcodes.INVOKEVIRTUAL
            || !"java/lang/Object".equals(call.owner) || !"toString".equals(call.name)) continue;
        AbstractInsnNode next = insn.getNext();
        if (!(next instanceof FieldInsnNode) || next.getOpcode() != Opcodes.PUTFIELD
            || !OWNER.equals(((FieldInsnNode) next).owner) || !"val".equals(((FieldInsnNode) next).name)) continue;
        calls++;
        if (expectedHook != null) {
          AbstractInsnNode prev = insn.getPrevious();
          if (!(prev instanceof MethodInsnNode) || prev.getOpcode() != Opcodes.INVOKESTATIC
              || !expectedHook.equals(((MethodInsnNode) prev).owner)
              || !"jmxAttributeDisplayReceiver".equals(((MethodInsnNode) prev).name)) throw new AssertionError("missing receiver guard");
        }
      }
    }
    if (guards != (expectedHook == null ? 0 : calls)) throw new AssertionError("unexpected receiver guard");
    return calls;
  }

  public static void main(String[] args) throws Exception {
    ByteArrayOutputStream original = new ByteArrayOutputStream();
    try (InputStream in = BadAttributeValueExpException.class.getResourceAsStream("BadAttributeValueExpException.class")) {
      byte[] buffer = new byte[4096];
      for (int n; (n = in.read(buffer)) != -1;) original.write(buffer, 0, n);
    }
    byte[] bytes = original.toByteArray();
    String track = args[0];
    String prefix = "io.ohmyrasp.agent.java" + track + ".Java" + track;
    boolean primary = "main".equals(track);
    String name = primary ? "io.ohmyrasp.agent.asm.OhMyRaspTransformer" : prefix + "DeserializationTransformer";
    ClassFileTransformer transformer = (ClassFileTransformer)Class.forName(name).getConstructor().newInstance();
    byte[] result = primary ? (byte[])transformer.getClass().getMethod("transform", Class.forName("java.lang.Module"),
        ClassLoader.class, String.class, Class.class, ProtectionDomain.class, byte[].class)
        .invoke(transformer, null, null, OWNER, null, null, bytes)
        : transformer.transform(null, OWNER, null, null, bytes);
    String hooks = primary ? "io.ohmyrasp.agent.hook.OhMyRaspHooks" : prefix + "RaspHooks";
    int sites = displayCalls(bytes, null);
    if (result == null || displayCalls(result, hooks.replace('.', '/')) != sites) throw new AssertionError("JMX reader changed");
    System.out.println("Guarded legacy display calls in this JDK reader: " + sites);
  }
}
