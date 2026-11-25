package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

/** Observe java.io path opens and the Windows NIO dispatcher's writable CreateFile overload. */
final class WindowsStreamWriteAdvice {
  static final String DISPATCHER = "sun/nio/fs/WindowsNativeDispatcher";
  private static final int WRITE_ACCESS = 0x40000000 | 0x10000000 | 0x2 | 0x4; // generic write/all, write data, append data

  private WindowsStreamWriteAdvice() {}

  static MethodVisitor wrap(String owner, MethodVisitor visitor, int access, String name, String descriptor) {
    boolean nio = DISPATCHER.equals(owner) && "CreateFile".equals(name) && "(Ljava/lang/String;IIJII)J".equals(descriptor);
    boolean random = "java/io/RandomAccessFile".equals(owner) && "open".equals(name) && "(Ljava/lang/String;I)V".equals(descriptor);
    boolean output = "java/io/FileOutputStream".equals(owner) && "open".equals(name) && "(Ljava/lang/String;Z)V".equals(descriptor);
    if (!nio && !random && !output) return visitor;
    return new EntryAdvice(visitor, access, name, descriptor) {
      @Override protected void onMethodEnter() {
        loadArg(0);
        if (output) push(1);
        else {
          loadArg(1);
          if (nio) push(WRITE_ACCESS);
          else visitFieldInsn(GETSTATIC, "java/io/RandomAccessFile", "O_RDWR", "I");
          visitInsn(IAND);
        }
        invokeHook("beforeWindowsStreamWrite", "(Ljava/lang/String;I)V");
      }
    };
  }
}
