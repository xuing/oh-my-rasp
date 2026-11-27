package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * XMLDecoder's object graph. The call-producing branches of {@code <object>} and {@code <void>} run as {@code
 * java.beans.Expression.getValue()}, observed at its entry as {@code Statement.execute()} is; their {@code field} and
 * {@code idref} branches make no call. Three elements reach the same operations without an {@code Expression}:
 * {@code <method>} and {@code <property>} call {@code sun.reflect.misc.MethodUtil.invoke} from {@code
 * MethodElementHandler} and {@code PropertyElementHandler}, observed at each such call; {@code <new>} runs {@code
 * NewElementHandler.getValueObject(Class, Object[])}, observed at its entry (the other subclasses of that handler
 * override the method and do not call it). {@code MethodUtil.invoke} itself is not hooked: {@code Statement} calls it
 * too (already observed), and so do JMX and Swing. {@code Expression.execute()} calls {@code invoke()} directly and is
 * not hooked either: no decoder class calls it.
 *
 * <p>{@code <field>} is not hooked. It reads or assigns an accessible public field (an instance's or a static one), so
 * a document can change state through it, and an access to a static field initializes the declaring class and runs
 * its static initializer. The two XMLDecoder rules classify neither: they classify a runtime execution primitive and
 * a script writer being constructed.
 *
 * <p>The decoder catches what these calls throw and hands it to {@code DocumentHandler.handleException}, whose entry
 * rethrows the agent's block.
 */
final class JavaBeansHookModule implements HookModule {
  private static final String METHOD_ELEMENT = "com/sun/beans/decoder/MethodElementHandler";
  private static final String PROPERTY_ELEMENT = "com/sun/beans/decoder/PropertyElementHandler";
  private static final String NEW_ELEMENT = "com/sun/beans/decoder/NewElementHandler";

  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/beans/Expression")
        || className.equals("java/beans/Statement")
        || className.equals("com/sun/beans/decoder/DocumentHandler")
        || className.equals(METHOD_ELEMENT)
        || className.equals(PROPERTY_ELEMENT)
        || className.equals(NEW_ELEMENT);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (className.equals("java/beans/Expression")
        && methodName.equals("getValue")
        && descriptor.equals("()Ljava/lang/Object;")) {
      return advice(methodVisitor, access, methodName, descriptor);
    }
    if (className.equals("java/beans/Statement")
        && methodName.equals("execute")
        && descriptor.equals("()V")) {
      return advice(methodVisitor, access, methodName, descriptor);
    }
    if (className.equals("com/sun/beans/decoder/DocumentHandler")
        && methodName.equals("handleException")
        && descriptor.equals("(Ljava/lang/Exception;)V")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("rethrowIfOhMyRaspBlock", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (className.equals(METHOD_ELEMENT) || className.equals(PROPERTY_ELEMENT)) {
      return new DecoderInvokeCallSite(methodVisitor);
    }
    if (className.equals(NEW_ELEMENT)
        && methodName.equals("getValueObject")
        && descriptor.equals("(Ljava/lang/Class;[Ljava/lang/Object;)Lcom/sun/beans/decoder/ValueObject;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(1);
          invokeHook("beforeXmlDecoderNew", "(Ljava/lang/Class;[Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }

  private static MethodVisitor advice(
      MethodVisitor methodVisitor, int access, String methodName, String descriptor) {
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        loadThis();
        invokeHook("beforeJavaBeansStatement", "(Ljava/lang/Object;)V");
      }
    };
  }

  /**
   * Before each {@code MethodUtil.invoke(method, target, arguments)}, the hook gets the same three operands and
   * returns the arguments, which the call then takes. Stack operations only: no local and no branch is added, so the
   * method's stack map frames stay as they are.
   */
  private static final class DecoderInvokeCallSite extends MethodVisitor {
    DecoderInvokeCallSite(MethodVisitor delegate) {
      super(OhMyRaspTransformer.api(), delegate);
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
        super.visitMethodInsn(Opcodes.INVOKESTATIC, "io/ohmyrasp/agent/hook/OhMyRaspHooks", "beforeXmlDecoderInvoke",
            "([Ljava/lang/Object;Ljava/lang/reflect/Method;Ljava/lang/Object;)[Ljava/lang/Object;", false);
      }
      super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    }
  }
}
