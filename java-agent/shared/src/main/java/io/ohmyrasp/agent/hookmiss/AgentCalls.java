package io.ohmyrasp.agent.hookmiss;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * The calls into the agent that a finished class file makes, per method, counted the way the hook-targets probe
 * counts them ({@code probes/hook-targets/HookMap.java}): a method instruction whose owner is under
 * {@code io/ohmyrasp/agent/} (the relocated ASM excluded), and a string constant that names an agent class and
 * starts the reflective sequence the EL, JEXL and OSGi hooks emit.
 *
 * <p>This reads a class file after the transformer made it. It never sits in a transformer's visitor chain, so
 * nothing it does can change what the transformer returns.
 */
public final class AgentCalls {
  /** The agent's package, in internal form. The relocated ASM is under it and never counts. */
  static final String AGENT = "io/ohmyrasp/agent/";
  static final String SHADED = "io/ohmyrasp/agent/shaded/";
  private static final String AGENT_DOTTED = "io.ohmyrasp.agent.";
  private static final String SHADED_DOTTED = "io.ohmyrasp.agent.shaded.";
  /** A class file larger than this is not read: the report gives no verdict for it. */
  static final int MAX_CLASS_BYTES = 4 << 20;
  /** How many instructions after the hook's name constant the reflective sequence may take to call it. */
  private static final int REFLECTIVE_REACH = 24;

  private AgentCalls() {}

  /**
   * For each method of the class that {@code pairs} look for (name and descriptor), the names of the agent
   * methods it calls; a method with no such call is absent. Null when the class cannot be read or is larger than
   * {@link #MAX_CLASS_BYTES}: the report has no verdict for it.
   */
  public static Map<String, Set<String>> inMethods(byte[] classFile, final HookExpectation[] pairs) {
    if (classFile == null || classFile.length > MAX_CLASS_BYTES) {
      return null;
    }
    final Map<String, Set<String>> found = new HashMap<String, Set<String>>();
    try {
      new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
          if (!looksFor(pairs, name, descriptor)) {
            return null;
          }
          Set<String> calls = new HashSet<String>();
          found.put(name + descriptor, calls);
          return new Scan(calls);
        }
      }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    } catch (RuntimeException unreadable) {
      return null;
    }
    return found;
  }

  private static boolean looksFor(HookExpectation[] pairs, String name, String descriptor) {
    for (HookExpectation pair : pairs) {
      if (!pair.looksFor(name)) {
        continue;
      }
      String method = name + descriptor;
      for (String candidate : pair.methods) {
        if (candidate.equals(method)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Whether one of the methods {@code pair} looks for calls, in {@code calls} (from {@link #inMethods}), one of the
   * agent methods the recorded maps show the unit calling from it. A method recorded with no callee accepts any
   * call into the agent.
   */
  public static boolean applied(HookExpectation pair, Map<String, Set<String>> calls) {
    for (int i = 0; i < pair.methods.length; i++) {
      Set<String> have = calls.get(pair.methods[i]);
      if (have == null || have.isEmpty()) {
        continue;
      }
      String[] wanted = pair.callees[i];
      if (wanted.length == 0) {
        return true;
      }
      for (String callee : wanted) {
        if (have.contains(callee)) {
          return true;
        }
      }
    }
    return false;
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

  private static boolean isIdentifier(Object constant) {
    if (!(constant instanceof String)) {
      return false;
    }
    String text = (String) constant;
    if (text.isEmpty() || !Character.isJavaIdentifierStart(text.charAt(0))) {
      return false;
    }
    for (int i = 1; i < text.length(); i++) {
      if (!Character.isJavaIdentifierPart(text.charAt(i))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Collects the agent methods one method body calls. A reflective hook is the sequence
   *
   * <pre>
   * ClassLoader.getSystemClassLoader(); ldc "agent.Class"; ClassLoader.loadClass(String); ldc "method";
   * ... Class.getMethod(String, Class[]); ... Method.invoke(Object, Object[])
   * </pre>
   *
   * and counts as a call of {@code method}; a constant that names an agent class anywhere else is not one.
   */
  private static final class Scan extends MethodVisitor {
    private static final int IDLE = 0;
    private static final int CLASS_NAMED = 1;
    private static final int CLASS_LOADED = 2;
    private static final int METHOD_NAMED = 3;

    private final Set<String> calls;
    private int state = IDLE;
    private boolean afterSystemLoader;
    private String hook;
    private boolean gotMethod;
    private int reach;

    Scan(Set<String> calls) {
      super(Opcodes.ASM9);
      this.calls = calls;
    }

    /** Any instruction the sequence does not use. */
    private void other() {
      afterSystemLoader = false;
      if (state == CLASS_NAMED || state == CLASS_LOADED) {
        state = IDLE;
      } else if (state == METHOD_NAMED && ++reach >= REFLECTIVE_REACH) {
        state = IDLE;
      }
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
      if (isAgentCall(owner)) {
        calls.add(name);
      }
      boolean systemLoader = opcode == Opcodes.INVOKESTATIC && "java/lang/ClassLoader".equals(owner)
          && "getSystemClassLoader".equals(name) && "()Ljava/lang/ClassLoader;".equals(descriptor);
      if (state == CLASS_NAMED) {
        boolean load = opcode == Opcodes.INVOKEVIRTUAL && "java/lang/ClassLoader".equals(owner)
            && "loadClass".equals(name) && "(Ljava/lang/String;)Ljava/lang/Class;".equals(descriptor);
        state = load ? CLASS_LOADED : IDLE;
      } else if (state == CLASS_LOADED) {
        state = IDLE;
      } else if (state == METHOD_NAMED) {
        if (!gotMethod) {
          gotMethod = opcode == Opcodes.INVOKEVIRTUAL && "java/lang/Class".equals(owner) && "getMethod".equals(name)
              && "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;".equals(descriptor);
        } else if (opcode == Opcodes.INVOKEVIRTUAL && "java/lang/reflect/Method".equals(owner)
            && "invoke".equals(name) && "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(descriptor)) {
          calls.add(hook);
          state = IDLE;
        }
        if (++reach >= REFLECTIVE_REACH) {
          state = IDLE;
        }
      }
      afterSystemLoader = systemLoader;
    }

    @Override
    public void visitLdcInsn(Object value) {
      boolean sequenceStart = afterSystemLoader && state == IDLE && isAgentName(value);
      if (state == CLASS_LOADED && isIdentifier(value)) {
        hook = (String) value;
        state = METHOD_NAMED;
        gotMethod = false;
        reach = 0;
        afterSystemLoader = false;
        return;
      }
      other();
      if (sequenceStart) {
        state = CLASS_NAMED;
      }
    }

    @Override
    public void visitInsn(int opcode) {
      other();
    }

    @Override
    public void visitIntInsn(int opcode, int operand) {
      other();
    }

    @Override
    public void visitVarInsn(int opcode, int varIndex) {
      other();
    }

    @Override
    public void visitTypeInsn(int opcode, String type) {
      other();
    }

    @Override
    public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
      other();
    }

    @Override
    public void visitInvokeDynamicInsn(String name, String descriptor, org.objectweb.asm.Handle handle,
        Object... arguments) {
      other();
    }

    @Override
    public void visitJumpInsn(int opcode, org.objectweb.asm.Label label) {
      other();
    }

    @Override
    public void visitIincInsn(int varIndex, int increment) {
      other();
    }

    @Override
    public void visitTableSwitchInsn(int min, int max, org.objectweb.asm.Label dflt, org.objectweb.asm.Label... labels) {
      other();
    }

    @Override
    public void visitLookupSwitchInsn(org.objectweb.asm.Label dflt, int[] keys, org.objectweb.asm.Label[] labels) {
      other();
    }

    @Override
    public void visitMultiANewArrayInsn(String descriptor, int numDimensions) {
      other();
    }
  }
}
