package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class Base64HookTest {
  @Test
  void registersBase64DecoderTarget() {
    HookRegistry registry = HookRegistry.defaults();
    assertTrue(registry.isDirectTarget("java/util/Base64$Decoder"));
    assertTrue(registry.isRetransformTarget("java.util.Base64$Decoder"));
  }

  @Test
  void instrumentsBase64DecoderDecode0WithTailUnderflowGuard() throws IOException {
    byte[] original = classBytes(Base64.Decoder.class);
    byte[] transformed =
        new OhMyRaspTransformer()
            .transform(null, null, "java/util/Base64$Decoder", null, null, original);

    assertNotNull(transformed);
    AtomicInteger hookCalls = new AtomicInteger();
    AtomicBoolean urlReadBeforeHook = new AtomicBoolean();
    AtomicBoolean mimeReadBeforeHook = new AtomicBoolean();

    new ClassReader(transformed)
        .accept(
            new ClassVisitor(OhMyRaspTransformer.api()) {
              @Override
              public MethodVisitor visitMethod(
                  int access,
                  String name,
                  String descriptor,
                  String signature,
                  String[] exceptions) {
                if (!"decode0".equals(name) || !"([BII[B)I".equals(descriptor)) {
                  return null;
                }
                return new MethodVisitor(OhMyRaspTransformer.api()) {
                  @Override
                  public void visitFieldInsn(
                      int opcode, String owner, String fieldName, String fieldDescriptor) {
                    if (hookCalls.get() == 0
                        && opcode == Opcodes.GETFIELD
                        && "java/util/Base64$Decoder".equals(owner)
                        && "Z".equals(fieldDescriptor)) {
                      if ("isURL".equals(fieldName)) {
                        urlReadBeforeHook.set(true);
                      } else if ("isMIME".equals(fieldName)) {
                        mimeReadBeforeHook.set(true);
                      }
                    }
                  }

                  @Override
                  public void visitMethodInsn(
                      int opcode,
                      String owner,
                      String invokedName,
                      String invokedDescriptor,
                      boolean isInterface) {
                    if (opcode == Opcodes.INVOKESTATIC
                        && "io/ohmyrasp/agent/hook/OhMyRaspHooks".equals(owner)
                        && "beforeBase64Decode".equals(invokedName)
                        && "([BIIZZ)V".equals(invokedDescriptor)) {
                      hookCalls.incrementAndGet();
                    }
                  }
                };
              }
            },
            0);

    assertEquals(1, hookCalls.get());
    assertTrue(urlReadBeforeHook.get());
    assertTrue(mimeReadBeforeHook.get());
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
}
