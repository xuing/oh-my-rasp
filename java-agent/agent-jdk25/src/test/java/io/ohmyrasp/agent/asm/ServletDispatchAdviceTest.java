package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;

public class ServletDispatchAdviceTest {
  public static class Fixture {
    public static Runnable cleanup;

    public static void service(Runnable work, Runnable enter) {
      try {
        work.run();
      } catch (IllegalArgumentException handled) {
        // Simulate a container that handles a failing dispatch locally.
      }
    }
  }

  private Class<?> instrumentFixture() throws IOException {
    ClassReader reader;
    try (var input = Fixture.class.getResourceAsStream("ServletDispatchAdviceTest$Fixture.class")) {
      reader = new ClassReader(input);
    }
    var writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
    reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        var visitor = super.visitMethod(access, name, desc, signature, exceptions);
        if (!name.equals("service")) return visitor;
        return new ServletDispatchAdvice(Opcodes.ASM9, visitor, access, name, desc) {
          private void runCallback(int argument) {
            loadArg(argument);
            invokeInterface(Type.getType(Runnable.class), new Method("run", "()V"));
          }

          @Override protected void enterDispatch() { runCallback(1); }
          @Override protected void exitDispatch() {
            getStatic(Type.getType(Fixture.class), "cleanup", Type.getType(Runnable.class));
            invokeInterface(Type.getType(Runnable.class), new Method("run", "()V"));
          }
        };
      }
    }, ClassReader.EXPAND_FRAMES);
    byte[] code = writer.toByteArray();
    return new ClassLoader(Fixture.class.getClassLoader()) {
      Class<?> defineFixture() { return defineClass(Fixture.class.getName(), code, 0, code.length); }
    }.defineFixture();
  }

  @Test
  void cleansUpOnceAfterNormalHandledAndEscapingExits() throws Exception {
    Class<?> fixture = instrumentFixture();
    var service = fixture.getMethod("service", Runnable.class, Runnable.class);
    var calls = new StringBuilder();
    Runnable enter = () -> calls.append('>');
    fixture.getField("cleanup").set(null, (Runnable) () -> calls.append('<'));
    Runnable normal = () -> calls.append('.');
    Runnable handled = () -> { throw new IllegalArgumentException(); };
    RuntimeException failure = new IllegalStateException("application failure");
    Runnable escapes = () -> { throw failure; };

    service.invoke(null, normal, enter);
    service.invoke(null, handled, enter);
    assertSame(failure, assertThrows(InvocationTargetException.class,
        () -> service.invoke(null, escapes, enter)).getCause());
    // Entry owns its rollback. An entry failure must not pop the caller's scope.
    assertSame(failure, assertThrows(InvocationTargetException.class,
        () -> service.invoke(null, normal, escapes)).getCause());
    assertEquals(">.<><><", calls.toString());
  }
}
