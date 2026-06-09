package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class SqlCallsiteClassVisitorTest {
  @Test
  void injectsJavaCompilationHookBeforeCompilerGetTaskCallsite() throws IOException {
    byte[] transformed = transform(classBytes(JavaCompilerCallsiteFixture.class));
    AtomicInteger hookCalls = new AtomicInteger();
    AtomicInteger compilerCalls = new AtomicInteger();

    new ClassReader(transformed)
        .accept(
            new ClassVisitor(OhMyRaspTransformer.api()) {
              @Override
              public MethodVisitor visitMethod(
                  int access, String name, String descriptor, String signature, String[] exceptions) {
                MethodVisitor methodVisitor =
                    super.visitMethod(access, name, descriptor, signature, exceptions);
                return new MethodVisitor(OhMyRaspTransformer.api(), methodVisitor) {
                  @Override
                  public void visitMethodInsn(
                      int opcode,
                      String owner,
                      String methodName,
                      String methodDescriptor,
                      boolean isInterface) {
                    if (opcode == Opcodes.INVOKESTATIC
                        && owner.equals("io/ohmyrasp/agent/hook/OhMyRaspHooks")
                        && methodName.equals("beforeJavaCompilationUnits")
                        && methodDescriptor.equals("(Ljava/lang/Object;)V")) {
                      hookCalls.incrementAndGet();
                    }
                    if (opcode == Opcodes.INVOKEINTERFACE
                        && owner.equals("javax/tools/JavaCompiler")
                        && methodName.equals("getTask")) {
                      compilerCalls.incrementAndGet();
                    }
                    super.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface);
                  }
                };
              }
            },
            0);

    assertEquals(1, hookCalls.get());
    assertEquals(1, compilerCalls.get());
  }

  private static byte[] transform(byte[] original) {
    ClassReader reader = new ClassReader(original);
    ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
    reader.accept(new SqlCallsiteClassVisitor(writer), ClassReader.EXPAND_FRAMES);
    return writer.toByteArray();
  }

  private static byte[] classBytes(Class<?> type) throws IOException {
    String resource = "/" + type.getName().replace('.', '/') + ".class";
    try (InputStream input = type.getResourceAsStream(resource)) {
      if (input == null) {
        throw new IOException("missing class resource " + resource);
      }
      return input.readAllBytes();
    }
  }

  @SuppressWarnings("unused")
  private static final class JavaCompilerCallsiteFixture {
    Boolean compile(JavaCompiler compiler, Iterable<? extends JavaFileObject> units) {
      return compiler.getTask(null, null, null, List.of("-proc:none"), null, units).call();
    }
  }
}
