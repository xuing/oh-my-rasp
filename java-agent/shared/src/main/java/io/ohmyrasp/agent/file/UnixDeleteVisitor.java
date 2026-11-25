package io.ohmyrasp.agent.file;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Check the entry at the unlink/rmdir boundary. The provider has already performed its own validation. */
public final class UnixDeleteVisitor {
  private static final String PROVIDER = "sun/nio/fs/UnixFileSystemProvider";
  private static final String SECURE = "sun/nio/fs/UnixSecureDirectoryStream";
  private static final String DISPATCHER = "sun/nio/fs/UnixNativeDispatcher";
  private static final String UNIX_PATH = "(Lsun/nio/fs/UnixPath;)V";
  private static final boolean PROVIDER_HOOK = supportedProvider();

  private UnixDeleteVisitor() {}

  private static boolean supportedProvider() {
    try (InputStream bytes = Object.class.getResourceAsStream("/" + PROVIDER + ".class")) {
      if (bytes == null) return false;
      final boolean[] calls = new boolean[2];
      new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exceptions) {
          if (!"implDelete".equals(name) || !"(Ljava/nio/file/Path;Z)Z".equals(desc)) return null;
          return new MethodVisitor(Opcodes.ASM9) {
            @Override public void visitMethodInsn(int op, String owner, String name, String descriptor, boolean itf) {
              if (op == Opcodes.INVOKESTATIC && DISPATCHER.equals(owner) && UNIX_PATH.equals(descriptor)) {
                if ("unlink".equals(name)) calls[0] = true;
                if ("rmdir".equals(name)) calls[1] = true;
              }
            }
          };
        }
      }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
      return calls[0] && calls[1];
    } catch (IOException | RuntimeException unavailable) {
      return false;
    }
  }

  public static boolean usesNativeBoundary(Path path) {
    if (!PROVIDER_HOOK) return false;
    for (Class<?> type = path.getFileSystem().provider().getClass(); type != null; type = type.getSuperclass()) {
      if (type.getClassLoader() == null && "sun.nio.fs.UnixFileSystemProvider".equals(type.getName())) return true;
    }
    return false;
  }

  public static MethodVisitor wrap(String owner, MethodVisitor visitor, String name, String desc, final String hooks) {
    final boolean secure = SECURE.equals(owner) && ("(Ljava/nio/file/Path;I)V".equals(desc)
        || "(Ljava/nio/file/Path;ZI)V".equals(desc));
    if (!"implDelete".equals(name) || (!secure && !(PROVIDER.equals(owner) && "(Ljava/nio/file/Path;Z)Z".equals(desc)))) return visitor;
    return new AdviceAdapter(Opcodes.ASM9, visitor, 0, name, desc) {
      private int flags, bytes;

      @Override protected void onMethodEnter() {
        if (secure) {
          // The JDK's lock-release handler covers instructions before unlinkat as well.
          flags = newLocal(Type.INT_TYPE);
          push(0); storeLocal(flags);
          bytes = newLocal(Type.getType(byte[].class));
          visitInsn(ACONST_NULL); storeLocal(bytes);
        }
      }

      @Override public void visitMethodInsn(int op, String target, String method, String descriptor, boolean itf) {
        if (op == Opcodes.INVOKESTATIC && DISPATCHER.equals(target)) {
          if (!secure && UNIX_PATH.equals(descriptor) && ("unlink".equals(method) || "rmdir".equals(method))) {
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeHostDelete", "(Ljava/nio/file/Path;)V", false);
          } else if (secure && "unlinkat".equals(method) && "(I[BI)V".equals(descriptor)) {
            // Preserve the actual descriptor at the call, including after its directory is renamed.
            storeLocal(flags);
            storeLocal(bytes);
            dup();
            loadThis();
            loadArg(0);
            loadLocal(flags);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeSecureDelete",
                "(ILjava/nio/file/SecureDirectoryStream;Ljava/nio/file/Path;I)V", false);
            loadLocal(bytes);
            loadLocal(flags);
          }
        }
        super.visitMethodInsn(op, target, method, descriptor, itf);
      }
    };
  }
}
