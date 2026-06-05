package io.ohmyrasp.agent.java8;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public final class Java8DeserializationTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_OBJECT_STREAM_CLASS_RESOLVE =
      Method.getMethod("void beforeObjectStreamClassResolve(java.lang.Object)");
  private static final Method BEFORE_OBJECT_STREAM_PROXY_RESOLVE =
      Method.getMethod("void beforeObjectStreamProxyResolve(java.lang.String[])");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !shouldTransform(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new DeserializationClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println(
            "[OHMYRASP-JAVA8] deserialization transform failed for "
                + className
                + ": "
                + throwable);
      }
      return null;
    }
  }

  private static boolean shouldTransform(String className) {
    return "java/io/ObjectInputStream".equals(className)
        || "sun/rmi/server/MarshalInputStream".equals(className)
        || "org/springframework/core/ConfigurableObjectInputStream".equals(className)
        || "org/springframework/remoting/rmi/CodebaseAwareObjectInputStream".equals(className);
  }

  private static final class DeserializationClassVisitor extends ClassVisitor {
    DeserializationClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null) {
        return null;
      }
      if ("resolveClass".equals(name)
          && "(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;".equals(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_OBJECT_STREAM_CLASS_RESOLVE);
          }
        };
      }
      if ("resolveProxyClass".equals(name)
          && "([Ljava/lang/String;)Ljava/lang/Class;".equals(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_OBJECT_STREAM_PROXY_RESOLVE);
          }
        };
      }
      return methodVisitor;
    }
  }
}
