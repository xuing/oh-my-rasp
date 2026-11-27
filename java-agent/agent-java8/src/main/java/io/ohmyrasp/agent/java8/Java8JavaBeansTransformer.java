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

/**
 * XMLDecoder's object graph. {@code <object>} and {@code <void>} run as {@code java.beans.Expression.getValue()} and
 * {@code Statement.execute()}, observed at their entry. Three elements reach the same operations without either:
 * {@code <method>} and {@code <property>} call {@code sun.reflect.misc.MethodUtil.invoke} from {@code
 * MethodElementHandler} and {@code PropertyElementHandler}, observed at each such call; {@code <new>} runs {@code
 * NewElementHandler.getValueObject(Class, Object[])}, observed at its entry (the other subclasses of that handler
 * override the method and do not call it). {@code MethodUtil.invoke} itself is not hooked: {@code Statement} calls it
 * too (already observed), and so do JMX and Swing.
 *
 * <p>{@code <field>} is not hooked: a public field read or write starts no process and writes no file by itself, the
 * classification has nothing a field access can match, and whatever object it yields still has to pass an observed
 * element to do anything.
 *
 * <p>The decoder catches what these calls throw and hands it to {@code DocumentHandler.handleException}, whose entry
 * rethrows the line's block.
 */
public final class Java8JavaBeansTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_JAVA_BEANS_STATEMENT =
      Method.getMethod("void beforeJavaBeansStatement(java.lang.Object)");
  private static final Method RETHROW_IF_JAVA8_RASP_BLOCK =
      Method.getMethod("void rethrowIfJava8RaspBlock(java.lang.Object)");
  private static final Method BEFORE_XML_DECODER_NEW =
      Method.getMethod("void beforeXmlDecoderNew(java.lang.Class, java.lang.Object[])");
  private static final String METHOD_ELEMENT = "com/sun/beans/decoder/MethodElementHandler";
  private static final String PROPERTY_ELEMENT = "com/sun/beans/decoder/PropertyElementHandler";
  private static final String NEW_ELEMENT = "com/sun/beans/decoder/NewElementHandler";

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
      reader.accept(new JavaBeansClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println(
            "[OHMYRASP-JAVA8] JavaBeans transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "java/beans/Expression".equals(className)
        || "java/beans/Statement".equals(className)
        || "com/sun/beans/decoder/DocumentHandler".equals(className)
        || METHOD_ELEMENT.equals(className)
        || PROPERTY_ELEMENT.equals(className)
        || NEW_ELEMENT.equals(className);
  }

  private static final class JavaBeansClassVisitor extends ClassVisitor {
    private final String className;

    JavaBeansClassVisitor(String className, ClassVisitor delegate) {
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
      if ("java/beans/Expression".equals(className)
          && "getValue".equals(name)
          && "()Ljava/lang/Object;".equals(descriptor)) {
        return statementAdvice(methodVisitor, access, name, descriptor);
      }
      if ("java/beans/Statement".equals(className)
          && "execute".equals(name)
          && "()V".equals(descriptor)) {
        return statementAdvice(methodVisitor, access, name, descriptor);
      }
      if ("com/sun/beans/decoder/DocumentHandler".equals(className)
          && "handleException".equals(name)
          && "(Ljava/lang/Exception;)V".equals(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, RETHROW_IF_JAVA8_RASP_BLOCK);
          }
        };
      }
      if (METHOD_ELEMENT.equals(className) || PROPERTY_ELEMENT.equals(className)) {
        return new DecoderInvokeCallSite(methodVisitor);
      }
      if (NEW_ELEMENT.equals(className)
          && "getValueObject".equals(name)
          && "(Ljava/lang/Class;[Ljava/lang/Object;)Lcom/sun/beans/decoder/ValueObject;".equals(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            loadArg(1);
            invokeStatic(HOOKS, BEFORE_XML_DECODER_NEW);
          }
        };
      }
      return methodVisitor;
    }

    private static MethodVisitor statementAdvice(
        MethodVisitor methodVisitor, int access, String name, String descriptor) {
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeStatic(HOOKS, BEFORE_JAVA_BEANS_STATEMENT);
        }
      };
    }
  }

  /**
   * Before each {@code MethodUtil.invoke(method, target, arguments)}, the hook gets the same three operands and
   * returns the arguments, which the call then takes. Stack operations only: no local and no branch is added, so the
   * method's stack map frames stay as they are.
   */
  private static final class DecoderInvokeCallSite extends MethodVisitor {
    DecoderInvokeCallSite(MethodVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
      if (opcode == Opcodes.INVOKESTATIC
          && "sun/reflect/misc/MethodUtil".equals(owner)
          && "invoke".equals(name)
          && "(Ljava/lang/reflect/Method;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(descriptor)) {
        // [method, target, arguments] -> [arguments, method, target, arguments] -> [arguments, method, target]
        // -> [method, target, arguments, method, target]; the hook takes the top three and returns the arguments.
        super.visitInsn(Opcodes.DUP_X2);
        super.visitInsn(Opcodes.POP);
        super.visitInsn(Opcodes.DUP2_X1);
        super.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS.getInternalName(), "beforeXmlDecoderInvoke",
            "([Ljava/lang/Object;Ljava/lang/reflect/Method;Ljava/lang/Object;)[Ljava/lang/Object;", false);
      }
      super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    }
  }
}
