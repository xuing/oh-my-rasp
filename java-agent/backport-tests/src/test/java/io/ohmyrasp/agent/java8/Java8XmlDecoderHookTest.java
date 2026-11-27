package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.backport.ControlAccess;
import io.ohmyrasp.agent.hook.HookActivation;
import java.beans.Expression;
import java.beans.Statement;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * XMLDecoder's {@code <method>}, {@code <property>} and {@code <new>} elements reach their operation without a
 * {@code java.beans.Statement}: the line's transformer rewrites the decoder classes of the JDK running the test, and
 * the entries it calls classify as the statement path does, with no stack to walk.
 */
final class Java8XmlDecoderHookTest {
  private static final String HOOKS = Type.getInternalName(Java8RaspHooks.class);
  private static final String INVOKE = "sun/reflect/misc/MethodUtil.invoke"
      + "(Ljava/lang/reflect/Method;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";

  private static final List<String> DECODER_STACK =
      Arrays.asList("java.beans.XMLDecoder", "com.sun.beans.decoder.DocumentHandler");

  @TempDir Path dir;

  @AfterEach
  void clearProperties() {
    HookActivation.activate();
    ControlAccess.poll(dir.resolve("no-control-file.json"));
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.java8.block");
    System.clearProperty("ohmyrasp.debug");
  }

  @Test
  void everyMethodUtilInvokeOfTheMethodAndPropertyElementsIsObservedWithItsOperands() throws Exception {
    assertEquals(1, observedInvokes("com/sun/beans/decoder/MethodElementHandler"));
    // getPropertyValue and setPropertyValue, each with and without an index.
    assertEquals(4, observedInvokes("com/sun/beans/decoder/PropertyElementHandler"));
  }

  @Test
  void theNewElementIsObservedAtTheEntryOfItsOwnBody() throws Exception {
    List<String> calls = new ArrayList<String>();
    read(transformed("com/sun/beans/decoder/NewElementHandler"), "getValueObject",
        "(Ljava/lang/Class;[Ljava/lang/Object;)Lcom/sun/beans/decoder/ValueObject;", calls);
    assertTrue(calls.size() > 3, String.valueOf(calls));
    assertEquals(Arrays.asList("ALOAD 1", "ALOAD 2",
        HOOKS + ".beforeXmlDecoderNew(Ljava/lang/Class;[Ljava/lang/Object;)V"), calls.subList(0, 3));
  }

  @Test
  void blocksAProcessBuilderStartedByAMethodElement() throws Exception {
    final Path log = blockMode();
    final ProcessBuilder target = new ProcessBuilder("sh", "-c", "id");
    blocked(new Executable() {
      @Override public void execute() throws Throwable {
        Java8RaspHooks.beforeXmlDecoderInvoke(new Object[0], ProcessBuilder.class.getMethod("start"), target);
      }
    });
    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_xml_decoder_runtime_execution\""), text);
    assertTrue(text.contains("java.lang.ProcessBuilder start sh -c id"), text);
  }

  @Test
  void blocksAScriptWriterBuiltByANewElement() throws Exception {
    Path log = blockMode();
    blocked(new Executable() {
      @Override public void execute() {
        Java8RaspHooks.beforeXmlDecoderNew(PrintWriter.class, new Object[] {"/tmp/webapps/ROOT/shell.jsp"});
      }
    });
    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_xml_decoder_script_file_write\""), text);
  }

  @Test
  void passesAnOrdinaryCallItsOwnArguments() throws Exception {
    Path log = blockMode();
    Object[] arguments = {"7"};
    assertSame(arguments, Java8RaspHooks.beforeXmlDecoderInvoke(
        arguments, Integer.class.getMethod("valueOf", String.class), Integer.class));
    Java8RaspHooks.beforeXmlDecoderNew(StringBuilder.class, new Object[] {"weekly"});
    Java8RaspHooks.beforeXmlDecoderNew(null, new Object[0]);
    assertSame(arguments, Java8RaspHooks.beforeXmlDecoderInvoke(arguments, null, null));
    assertFalse(Files.exists(log));
  }

  @Test
  void anOperationNoRuleCanMatchNeverTouchesItsArguments() throws Exception {
    Path log = blockMode();
    Watched watched = new Watched();
    List<Object> bean = new ArrayList<Object>();
    Java8RaspHooks.beforeXmlDecoderInvoke(new Object[] {watched}, ArrayList.class.getMethod("add", Object.class), bean);
    Java8RaspHooks.beforeXmlDecoderNew(StringBuilder.class, new Object[] {watched});
    Java8RaspHooks.beforeJavaBeansStatement(new Statement(bean, "add", new Object[] {watched}), DECODER_STACK);
    Java8RaspHooks.beforeJavaBeansStatement(new Expression(bean, "add", new Object[] {watched}));
    assertEquals(new ArrayList<String>(), watched.calls);
    assertFalse(Files.exists(log));
  }

  @Test
  void aCandidateWithAnEndlessIterableArgumentReturns() throws Exception {
    blockMode();
    final Endless endless = new Endless();
    blocked(new Executable() {
      @Override public void execute() throws Throwable {
        Java8RaspHooks.beforeXmlDecoderInvoke(
            new Object[] {endless}, Runtime.class.getMethod("exec", String[].class), Runtime.getRuntime());
      }
    });
    assertTrue(endless.taken <= 64, "elements taken: " + endless.taken);
  }

  @Test
  void withTheHooksOffAnEntryReturnsItsArgumentsAndDoesNothing() throws Exception {
    Path log = blockMode();
    Watched watched = new Watched();
    Object[] arguments = {watched};
    HookActivation.deactivate();
    assertSame(arguments, Java8RaspHooks.beforeXmlDecoderInvoke(
        arguments, ProcessBuilder.class.getMethod("start"), new ProcessBuilder("sh", "-c", "id")));
    Java8RaspHooks.beforeXmlDecoderNew(PrintWriter.class, new Object[] {"/tmp/webapps/ROOT/shell.jsp", watched});
    HookActivation.activate();
    assertEquals(new ArrayList<String>(), watched.calls);
    assertFalse(Files.exists(log));
  }

  @Test
  void aNullArgumentsArrayIsPassedOnAndTheTargetStillDecides() throws Exception {
    final Path log = blockMode();
    assertNull(Java8RaspHooks.beforeXmlDecoderInvoke(
        null, Integer.class.getMethod("valueOf", String.class), Integer.class));
    Java8RaspHooks.beforeXmlDecoderNew(PrintWriter.class, null);
    assertFalse(Files.exists(log));
    blocked(new Executable() {
      @Override public void execute() throws Throwable {
        Java8RaspHooks.beforeXmlDecoderInvoke(
            null, ProcessBuilder.class.getMethod("start"), new ProcessBuilder("sh", "-c", "id"));
      }
    });
  }

  @Test
  void anInternalFailureReturnsAndItsReportCannotThrow() throws Exception {
    blockMode();
    System.setProperty("ohmyrasp.debug", "true");
    PrintStream err = System.err;
    System.setErr(new PrintStream(new ByteArrayOutputStream(), true));
    try {
      Object[] arguments = {new Failing()};
      assertSame(arguments, Java8RaspHooks.beforeXmlDecoderInvoke(
          arguments, Runtime.class.getMethod("exec", String[].class), Runtime.getRuntime()));
      Java8RaspHooks.beforeXmlDecoderNew(PrintWriter.class, new Object[] {new Failing()});
      Java8RaspHooks.beforeJavaBeansStatement(
          new Statement(Runtime.getRuntime(), "exec", new Object[] {new Failing()}), DECODER_STACK);
    } finally {
      System.setErr(err);
    }
  }

  @Test
  void withDetectionOffAnEntryClassifiesNothingAndLeavesTheRepeatStateAlone() throws Exception {
    Path log = logMode();
    ProcessBuilder target = new ProcessBuilder("sh", "-c", "detection-off");
    control("{\"mode\":\"off\"}");
    Watched watched = new Watched();
    Java8RaspHooks.beforeXmlDecoderInvoke(new Object[] {watched}, ProcessBuilder.class.getMethod("start"), target);
    Java8RaspHooks.beforeJavaBeansStatement(new Statement(target, "start", new Object[] {watched}), DECODER_STACK);
    Java8RaspHooks.beforeXmlDecoderNew(PrintWriter.class, new Object[] {"/tmp/webapps/ROOT/off.jsp", watched});
    assertEquals(new ArrayList<String>(), watched.calls);
    assertFalse(Files.exists(log));

    // Back to the start-up settings (log): the same operations are logged, not taken for repeats of unlogged ones.
    ControlAccess.poll(dir.resolve("no-control-file.json"));
    Java8RaspHooks.beforeXmlDecoderInvoke(new Object[0], ProcessBuilder.class.getMethod("start"), target);
    Java8RaspHooks.beforeJavaBeansStatement(new Statement(target, "start", new Object[0]), DECODER_STACK);
    assertEquals(2, occurrences(read(log), "java.lang.ProcessBuilder start sh -c detection-off"), read(log));
  }

  @Test
  void aFindingAtAnElementDoesNotSuppressTheSameOneAtAStatement() throws Exception {
    Path log = logMode();
    ProcessBuilder target = new ProcessBuilder("sh", "-c", "two-paths");
    Java8RaspHooks.beforeXmlDecoderInvoke(new Object[0], ProcessBuilder.class.getMethod("start"), target);
    Java8RaspHooks.beforeJavaBeansStatement(new Statement(target, "start", new Object[0]), DECODER_STACK);
    // The same path again is a repeat.
    Java8RaspHooks.beforeJavaBeansStatement(new Statement(target, "start", new Object[0]), DECODER_STACK);
    assertEquals(2, occurrences(read(log), "java.lang.ProcessBuilder start sh -c two-paths"), read(log));
  }

  private void control(String json) throws Exception {
    Path file = dir.resolve("control.json");
    Files.write(file, json.getBytes(StandardCharsets.UTF_8));
    ControlAccess.poll(file);
  }

  private static String read(Path log) throws Exception {
    return Files.exists(log) ? new String(Files.readAllBytes(log), StandardCharsets.UTF_8) : "";
  }

  private static int occurrences(String text, String part) {
    int count = 0;
    for (int at = text.indexOf(part); at >= 0; at = text.indexOf(part, at + part.length())) {
      count++;
    }
    return count;
  }

  /** An argument that records any call the agent makes on it. */
  private static final class Watched implements Iterable<Object> {
    final List<String> calls = new ArrayList<String>();

    @Override public Iterator<Object> iterator() {
      calls.add("iterator");
      return Collections.emptyIterator();
    }

    @Override public String toString() {
      calls.add("toString");
      return "watched";
    }
  }

  /** Hands out nulls and blanks for ever; gives up after 100000, so a test without a bound fails instead of hanging. */
  private static final class Endless implements Iterable<Object> {
    int taken;

    @Override public Iterator<Object> iterator() {
      return new Iterator<Object>() {
        @Override public boolean hasNext() {
          return true;
        }

        @Override public Object next() {
          if (++taken > 100000) {
            throw new IllegalStateException("not bounded");
          }
          return taken % 2 == 0 ? null : " ";
        }

        @Override public void remove() {
          throw new UnsupportedOperationException();
        }
      };
    }
  }

  /** A failure whose own description throws, as an application's exception may. */
  private static final class Unprintable extends RuntimeException {
    private static final long serialVersionUID = 1L;

    @Override public String getMessage() {
      throw new IllegalStateException("getMessage");
    }

    @Override public String toString() {
      throw new IllegalStateException("toString");
    }
  }

  private static final class Failing implements Iterable<Object> {
    @Override public Iterator<Object> iterator() {
      throw new Unprintable();
    }
  }

  private static Path blockMode() throws Exception {
    Path log = logMode();
    System.setProperty("ohmyrasp.java8.block", "true");
    return log;
  }

  private static Path logMode() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xml-decoder-elements", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    return log;
  }

  private static void blocked(Executable call) {
    assertThrows(Java8RaspBlockException.class, call);
  }

  /**
   * The number of {@code MethodUtil.invoke} calls in the class, after checking that each one is preceded by the
   * stack copy and the hook: {@code DUP_X2 POP DUP2_X1} turns {@code [method, target, arguments]} into {@code
   * [method, target, arguments, method, target]}, and the hook takes the top three and returns the arguments.
   */
  private static int observedInvokes(String className) throws Exception {
    List<String> instructions = new ArrayList<String>();
    read(transformed(className), null, null, instructions);
    String hook = HOOKS + ".beforeXmlDecoderInvoke"
        + "([Ljava/lang/Object;Ljava/lang/reflect/Method;Ljava/lang/Object;)[Ljava/lang/Object;";
    int invokes = 0;
    for (int i = 0; i < instructions.size(); i++) {
      if (!instructions.get(i).equals(INVOKE)) {
        continue;
      }
      invokes++;
      assertTrue(i >= 4, className + ": the call has nothing before it");
      assertEquals(Arrays.asList("DUP_X2", "POP", "DUP2_X1", hook), instructions.subList(i - 4, i),
          className + ": MethodUtil.invoke #" + invokes + " is not observed");
    }
    assertTrue(invokes > 0, className + " calls MethodUtil.invoke nowhere");
    return invokes;
  }

  private static byte[] transformed(String className) throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    // A .class resource is never encapsulated, also in a module that does not open its package.
    InputStream input = ClassLoader.getSystemResourceAsStream(className + ".class");
    assertNotNull(input, className);
    try {
      byte[] buffer = new byte[8192];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        output.write(buffer, 0, count);
      }
    } finally {
      input.close();
    }
    byte[] transformed =
        new Java8JavaBeansTransformer().transform(null, className, null, null, output.toByteArray());
    assertNotNull(transformed, className + " is not rewritten");
    return transformed;
  }

  /** The instructions that matter here, of one method or (name null) of every method, in order. */
  private static void read(byte[] classFile, final String method, final String descriptor, final List<String> out) {
    new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(
          int access, String name, String desc, String signature, String[] exceptions) {
        if (method != null && !(method.equals(name) && descriptor.equals(desc))) {
          return null;
        }
        return new MethodVisitor(Opcodes.ASM9) {
          @Override
          public void visitInsn(int opcode) {
            out.add(opcode == Opcodes.DUP_X2 ? "DUP_X2" : opcode == Opcodes.POP ? "POP"
                : opcode == Opcodes.DUP2_X1 ? "DUP2_X1" : "insn " + opcode);
          }

          @Override
          public void visitVarInsn(int opcode, int varIndex) {
            out.add((opcode == Opcodes.ALOAD ? "ALOAD " : "var " + opcode + " ") + varIndex);
          }

          @Override
          public void visitMethodInsn(
              int opcode, String owner, String name, String desc, boolean isInterface) {
            out.add(owner + "." + name + desc);
          }
        };
      }
    }, 0);
  }
}
