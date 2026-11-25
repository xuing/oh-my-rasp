package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.http.MultipartFilenameVisitor;
import io.ohmyrasp.agent.http.MultipartCollectionVisitor;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.*;

public final class Java17MultipartUploadTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java17RaspHooks.class);

  @Override public byte[] transform(ClassLoader loader, final String owner, Class<?> loaded,
      ProtectionDomain domain, byte[] bytes) {
    if (owner == null || bytes == null || owner.startsWith("io/ohmyrasp/agent/")) return null;
    try {
      boolean known = MultipartFilenameVisitor.known(owner, true);
      if (loader == null && !known) return null;
      var reader = new ClassReader(bytes);
      boolean caller = MultipartFilenameVisitor.multipartCaller(reader);
      if (!known && !caller && !MultipartFilenameVisitor.mentionsGetter(reader)) return null;
      var writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      final boolean[] changed = {false};
      ClassVisitor methods = new ClassVisitor(Opcodes.ASM9, writer) {
        @Override public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exceptions) {
          MethodVisitor original = super.visitMethod(access, name, desc, sig, exceptions);
          if (original == null) return null;
          MethodVisitor result = MultipartFilenameVisitor.wrap(owner, original, access, name, desc, HOOKS, true);
          if (result != original) changed[0] = true;
          return result;
        }
      };
      MultipartCollectionVisitor accesses = caller ? new MultipartCollectionVisitor(methods, HOOKS) : null;
      reader.accept(accesses == null ? methods : accesses, ClassReader.EXPAND_FRAMES);
      return changed[0] || (accesses != null && accesses.changed()) ? writer.toByteArray() : null;
    } catch (Throwable failure) {
      if (Boolean.getBoolean("ohmyrasp.debug")) System.err.println("[OHMYRASP-JAVA17] multipart transform failed for " + owner + ": " + failure);
      return null;
    }
  }
}
