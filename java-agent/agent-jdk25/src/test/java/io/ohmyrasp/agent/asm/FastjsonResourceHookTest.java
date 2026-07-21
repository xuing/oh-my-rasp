package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicInteger;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.junit.jupiter.api.Test;

final class FastjsonResourceHookTest {
  @Test
  void rewritesFastjson1283ClassResourceLookup() throws Exception {
    byte[] transformed =
        new OhMyRaspTransformer()
            .transform(
                null,
                null,
                "com/alibaba/fastjson/parser/ParserConfig",
                null,
                null,
                classBytes(com.alibaba.fastjson.parser.ParserConfig.class));

    assertNotNull(transformed);
    AtomicInteger resourceLookups = new AtomicInteger();
    AtomicInteger hookCalls = new AtomicInteger();
    AtomicInteger guardedLookups = new AtomicInteger();
    new ClassReader(transformed)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public MethodVisitor visitMethod(
                  int access,
                  String name,
                  String descriptor,
                  String signature,
                  String[] exceptions) {
                if (!"checkAutoType".equals(name)) {
                  return null;
                }
                return new MethodVisitor(Opcodes.ASM9) {
                  private boolean hookImmediatelyBefore;

                  @Override
                  public void visitMethodInsn(
                      int opcode,
                      String owner,
                      String invokedName,
                      String invokedDescriptor,
                      boolean isInterface) {
                    boolean hook =
                        "io/ohmyrasp/agent/hook/OhMyRaspHooks".equals(owner)
                            && "beforeFastjsonClassResource".equals(invokedName)
                            && "(Ljava/lang/String;)V".equals(invokedDescriptor);
                    boolean resourceLookup =
                        "java/lang/ClassLoader".equals(owner)
                            && "getResourceAsStream".equals(invokedName)
                            && "(Ljava/lang/String;)Ljava/io/InputStream;"
                                .equals(invokedDescriptor);
                    if (hook) {
                      hookCalls.incrementAndGet();
                      hookImmediatelyBefore = true;
                    } else {
                      if (resourceLookup) {
                        resourceLookups.incrementAndGet();
                        if (hookImmediatelyBefore) {
                          guardedLookups.incrementAndGet();
                        }
                      }
                      hookImmediatelyBefore = false;
                    }
                  }
                };
              }
            },
            0);

    assertEquals(2, resourceLookups.get(), "Fastjson 1.2.83 has two ClassLoader branches");
    assertEquals(resourceLookups.get(), hookCalls.get(), "every resource lookup must be hooked");
    assertEquals(
        resourceLookups.get(),
        guardedLookups.get(),
        "the hook must be the final call before ClassLoader I/O");
  }

  private static byte[] classBytes(Class<?> type) throws Exception {
    try (InputStream input = type.getResourceAsStream(type.getSimpleName() + ".class")) {
      if (input == null) {
        throw new IllegalStateException("Missing class resource for " + type.getName());
      }
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        output.write(buffer, 0, count);
      }
      return output.toByteArray();
    }
  }
}
