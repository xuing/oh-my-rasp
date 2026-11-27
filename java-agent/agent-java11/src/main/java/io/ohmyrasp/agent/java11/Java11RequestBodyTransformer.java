package io.ohmyrasp.agent.java11;

import io.ohmyrasp.agent.hookmiss.HookMissScope;
import io.ohmyrasp.agent.http.RequestBodyVisitor;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * Records what the application reads of a request body: the read methods of every class whose direct superclass
 * is a servlet input stream, and of Tomcat's reader (see RequestBodyVisitor). Matched by superclass, so every
 * class an application loader defines has its header read once, when it loads.
 */
public final class Java11RequestBodyTransformer implements ClassFileTransformer, HookMissScope {
  private static final Type HOOKS = Type.getType(Java11RaspHooks.class);

  /**
   * Every class the hook-miss table names for this transformer is checked, as on the primary agent, except a class
   * whose loader cannot see the agent, which {@link #transform} leaves alone on purpose.
   */
  @Override
  public boolean inScope(ClassLoader loader, String className) {
    return RequestBodyVisitor.loaderSeesAgent(loader);
  }

  @Override
  public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain, byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || className.startsWith("io/ohmyrasp/agent/")
        || !RequestBodyVisitor.loaderSeesAgent(loader)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      final boolean containerReader = RequestBodyVisitor.isReader(className);
      if (!containerReader && !RequestBodyVisitor.isStream(reader.getSuperName())) return null;
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      final boolean[] changed = {false};
      reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
            String[] exceptions) {
          MethodVisitor original = super.visitMethod(access, name, descriptor, signature, exceptions);
          if (original == null) return null;
          MethodVisitor result = RequestBodyVisitor.wrap(containerReader, original, className, access, name, descriptor, HOOKS);
          if (result != original) changed[0] = true;
          return result;
        }
      }, ClassReader.EXPAND_FRAMES);
      return changed[0] ? writer.toByteArray() : null;
    } catch (Throwable failure) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA11] request body transform failed for " + className + ": " + failure);
      }
      return null;
    }
  }
}
