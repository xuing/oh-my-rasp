package io.ohmyrasp.agent.java11;

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

public final class Java11ClassLoaderTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java11RaspHooks.class);
  private static final Method BEFORE_CLASSLOADER_URLS =
      Method.getMethod("void beforeClassLoaderUrls(java.lang.Object)");
  private static final Method BEFORE_CLASSLOADER_URL =
      Method.getMethod("void beforeClassLoaderUrl(java.lang.Object)");
  private static final Method BEFORE_RMI_CLASSLOADER_CODEBASE =
      Method.getMethod("void beforeRmiClassLoaderCodebase(java.lang.String)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !isTarget(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new ClassLoaderClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println(
            "[OHMYRASP-JAVA11] classloader transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "java/net/URLClassLoader".equals(className)
        || "java/rmi/server/RMIClassLoader".equals(className);
  }

  private static final class ClassLoaderClassVisitor extends ClassVisitor {
    private final String className;

    ClassLoaderClassVisitor(String className, ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null) {
        return null;
      }
      if ("java/net/URLClassLoader".equals(className)) {
        if ("<init>".equals(name) && descriptor.startsWith("([Ljava/net/URL;")) {
          return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
            @Override
            protected void onMethodEnter() {
              loadArg(0);
              invokeStatic(HOOKS, BEFORE_CLASSLOADER_URLS);
            }
          };
        }
        if ("addURL".equals(name) && "(Ljava/net/URL;)V".equals(descriptor)) {
          return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
            @Override
            protected void onMethodEnter() {
              loadArg(0);
              invokeStatic(HOOKS, BEFORE_CLASSLOADER_URL);
            }
          };
        }
      }
      if ("java/rmi/server/RMIClassLoader".equals(className) && isRmiCodebaseMethod(name)) {
        if (descriptor.startsWith("(Ljava/lang/String;")) {
          return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
            @Override
            protected void onMethodEnter() {
              loadArg(0);
              invokeStatic(HOOKS, BEFORE_RMI_CLASSLOADER_CODEBASE);
            }
          };
        }
        if (descriptor.startsWith("(Ljava/net/URL;")) {
          return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
            @Override
            protected void onMethodEnter() {
              loadArg(0);
              invokeStatic(HOOKS, BEFORE_CLASSLOADER_URL);
            }
          };
        }
      }
      return methodVisitor;
    }

    private static boolean isRmiCodebaseMethod(String name) {
      return "loadClass".equals(name) || "loadProxyClass".equals(name) || "getClassLoader".equals(name);
    }
  }
}
