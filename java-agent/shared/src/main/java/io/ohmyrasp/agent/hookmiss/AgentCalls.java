package io.ohmyrasp.agent.hookmiss;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Calls into the agent in class files and in a visitor chain, counted the way the hook-targets probe counts them
 * ({@code probes/hook-targets/HookMap.java}): a method instruction whose owner is under {@code io/ohmyrasp/agent/}
 * (the relocated ASM excluded), and a string constant that names an agent class, which the reflective hooks load
 * by name.
 */
public final class AgentCalls {
  /** The agent's package, in internal form. The relocated ASM is under it and never counts. */
  static final String AGENT = "io/ohmyrasp/agent/";
  static final String SHADED = "io/ohmyrasp/agent/shaded/";
  private static final String AGENT_DOTTED = "io.ohmyrasp.agent.";
  private static final String SHADED_DOTTED = "io.ohmyrasp.agent.shaded.";
  private static final byte[] AGENT_BYTES = AGENT.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
  private static final byte[] AGENT_DOTTED_BYTES = AGENT_DOTTED.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

  private AgentCalls() {}

  /**
   * Whether a class file names the agent anywhere. A library class does not, so when its input does not and its
   * output does, the transform added a reference to the agent; only a class that some earlier transformer already
   * rewrote needs {@link #count}.
   */
  public static boolean mentionsAgent(byte[] classFile) {
    return contains(classFile, AGENT_BYTES) || contains(classFile, AGENT_DOTTED_BYTES);
  }

  /** The calls into the agent in a class file. */
  public static int count(byte[] classFile) {
    final int[] calls = new int[1];
    new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        return new Counter(null, calls, 0);
      }
    }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    return calls[0];
  }

  /** Whether a method instruction calls into the agent. */
  static boolean isAgentCall(String owner) {
    return owner != null && owner.startsWith(AGENT) && !owner.startsWith(SHADED);
  }

  /** Whether a constant names an agent class, as the reflective hooks' class-name constants do. */
  static boolean isAgentName(Object constant) {
    if (!(constant instanceof String)) {
      return false;
    }
    String text = (String) constant;
    return text.startsWith(AGENT_DOTTED) && !text.startsWith(SHADED_DOTTED);
  }

  private static boolean contains(byte[] haystack, byte[] needle) {
    byte first = needle[0];
    int last = haystack.length - needle.length;
    outer:
    for (int i = 0; i <= last; i++) {
      if (haystack[i] != first) {
        continue;
      }
      for (int j = 1; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return true;
    }
    return false;
  }

  /**
   * Passes a method through and adds each call into the agent to {@code counts[slot]}. The slot can be set after
   * the counter is in the chain, when it is known which unit's visitor it sits behind; {@code -1} counts nothing.
   */
  public static final class Counter extends MethodVisitor {
    private int[] counts;
    private int slot;

    public Counter(MethodVisitor delegate, int[] counts, int slot) {
      super(Opcodes.ASM9, delegate);
      this.counts = counts;
      this.slot = slot;
    }

    /** Counts into {@code counts[slot]} from now on. */
    public void countInto(int[] counts, int slot) {
      this.counts = counts;
      this.slot = slot;
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
      if (slot >= 0 && isAgentCall(owner)) {
        counts[slot]++;
      }
      super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    }

    @Override
    public void visitLdcInsn(Object value) {
      if (slot >= 0 && isAgentName(value)) {
        counts[slot]++;
      }
      super.visitLdcInsn(value);
    }
  }
}
