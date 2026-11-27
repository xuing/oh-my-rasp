package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * The order of the entry class's start, read from its bytecode: the tests start the line before any test runs
 * (LineStartListener) and pass no Instrumentation, so no test that calls premain would notice a transformer
 * registered before the JAR is on the bootstrap search, before the classes are preloaded or before the line starts.
 */
final class Java8EntryOrderTest {
  @Test
  void theEntryStartsTheLineBeforeItRegistersATransformer() throws Exception {
    Map<String, List<String>> calls = calls(OhMyRaspJava8Agent.class);
    List<String> install = calls.get("install");
    assertTrue(install != null, "no install method: " + calls.keySet());
    String[] order = {
      "OhMyRaspJava8Agent.appendSelfToBootstrap",
      "OhMyRaspJava8Agent.requireBootstrapDefined",
      "Preload.classes",
      "Java8RaspLine.start",
      "OhMyRaspJava8Agent.installTransformer",
    };
    int previous = -1;
    for (String call : order) {
      int at = install.indexOf(call);
      assertTrue(at > previous, call + " must come after " + (previous < 0 ? "the start" : order[indexOf(order, call) - 1])
          + " in install(): " + install);
      previous = at;
    }
    assertEquals(1, count(install, "Java8RaspLine.start"), install.toString());
    for (Map.Entry<String, List<String>> method : calls.entrySet()) {
      if (method.getValue().contains("Instrumentation.addTransformer")) {
        assertEquals("register", method.getKey(), "only register adds a transformer, and records it for the undo");
      }
      if (method.getValue().contains("OhMyRaspJava8Agent.register")) {
        assertEquals("installTransformer", method.getKey(), "only installTransformer registers transformers");
      }
    }
    assertTrue(calls.get("premain").contains("OhMyRaspJava8Agent.install"), calls.get("premain").toString());
    assertTrue(calls.get("agentmain").contains("OhMyRaspJava8Agent.install"), calls.get("agentmain").toString());
  }

  @Test
  void aFailedBootstrapAppendFailsTheStartBeforeAnyTransformer() throws Exception {
    final List<String> registered = new ArrayList<String>();
    Instrumentation failing = (Instrumentation) Proxy.newProxyInstance(
        Java8EntryOrderTest.class.getClassLoader(), new Class<?>[] {Instrumentation.class},
        new InvocationHandler() {
          @Override
          public Object invoke(Object proxy, Method method, Object[] args) {
            if (method.getName().equals("appendToBootstrapClassLoaderSearch")) {
              throw new UnsupportedOperationException("this JVM refuses the append");
            }
            if (method.getName().equals("addTransformer")) {
              registered.add(String.valueOf(args[0]));
            }
            return method.getReturnType() == boolean.class ? Boolean.TRUE : null;
          }
        });
    int threadsBefore = agentThreads();

    IllegalStateException failure =
        assertThrows(IllegalStateException.class, () -> OhMyRaspJava8Agent.premain("", failing));

    assertTrue(failure.getMessage().contains("bootstrap search"), failure.getMessage());
    assertEquals(new ArrayList<String>(), registered, "no transformer is registered after a failed append");
    assertEquals(threadsBefore, agentThreads(), "a failed start leaves no thread");
  }

  private static int agentThreads() {
    int count = 0;
    for (Thread thread : Thread.getAllStackTraces().keySet()) {
      if (thread.getName().startsWith("ohmyrasp-java8-") && thread.isAlive()) {
        count++;
      }
    }
    return count;
  }

  /** Method name -> the methods it calls, in bytecode order, as SimpleOwner.name. */
  static Map<String, List<String>> calls(Class<?> type) throws Exception {
    final Map<String, List<String>> calls = new LinkedHashMap<String, List<String>>();
    InputStream input = type.getResourceAsStream(type.getSimpleName() + ".class");
    try {
      new ClassReader(input).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
            String[] exceptions) {
          final List<String> made = new ArrayList<String>();
          calls.put(name, made);
          return new MethodVisitor(Opcodes.ASM9) {
            @Override
            public void visitMethodInsn(int opcode, String owner, String called, String desc, boolean isInterface) {
              made.add(owner.substring(owner.lastIndexOf('/') + 1) + "." + called);
            }
          };
        }
      }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    } finally {
      input.close();
    }
    return calls;
  }

  private static int count(List<String> values, String value) {
    int found = 0;
    for (String each : values) {
      if (each.equals(value)) {
        found++;
      }
    }
    return found;
  }

  private static int indexOf(String[] values, String value) {
    for (int i = 0; i < values.length; i++) {
      if (values[i].equals(value)) {
        return i;
      }
    }
    return -1;
  }
}
