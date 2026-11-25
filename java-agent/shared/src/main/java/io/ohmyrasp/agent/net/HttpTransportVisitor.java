package io.ohmyrasp.agent.net;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;

/** Observes the URL handed to a JDK HTTP transport, after response-cache selection. */
public final class HttpTransportVisitor {
  private static final String URL_CLASS = "java/net/URL";
  private static final String NETWORK = "sun/net/NetworkClient";
  private static final String HTTP2_POOL = "jdk/internal/net/http/Http2ClientImpl";
  private static final String HTTP2_CONNECTION = "jdk/internal/net/http/Http2Connection";
  private static final String CONNECTION = "jdk/internal/net/http/HttpConnection";
  private static final String MULTI = "jdk/internal/net/http/MultiExchange";
  private static final String EXCHANGE = "jdk/internal/net/http/Exchange";
  private static final String REQUEST = "jdk/internal/net/http/HttpRequestImpl";
  private static final String HTTP_CLIENT = "sun/net/www/http/HttpClient";
  private static final String HTTPS_CLIENT = "sun/net/www/protocol/https/HttpsClient";
  private static final String HOOK_DESCRIPTOR = "(Ljava/lang/Object;Ljava/net/URL;Z)V";
  private static final Type URL_TYPE = Type.getObjectType(URL_CLASS);

  private HttpTransportVisitor() {}

  public static boolean matches(String owner) {
    return HTTP2_POOL.equals(owner) || NETWORK.equals(owner) || HTTP_CLIENT.equals(owner) || CONNECTION.equals(owner) || MULTI.equals(owner) || EXCHANGE.equals(owner) || URL_CLASS.equals(owner) || "sun/net/www/protocol/http/HttpURLConnection".equals(owner)
        || "sun/net/www/protocol/https/AbstractDelegateHttpsURLConnection".equals(owner);
  }

  public static MethodVisitor wrap(String owner, MethodVisitor visitor, int access, String name,
      String descriptor, final String hooks) {
    if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return visitor;
    if (HTTP2_POOL.equals(owner)) {
      if (!name.equals("getConnectionFor") || !descriptor.equals(
          "(Ljdk/internal/net/http/HttpRequestImpl;Ljdk/internal/net/http/Exchange;)Ljava/util/concurrent/CompletableFuture;")) return visitor;
      return new MethodNode(Opcodes.ASM9, access, name, descriptor, null, null) {
        @Override public void visitEnd() {
          // Inspect a selected pooled connection before the JDK changes reservation counters.
          MethodInsnNode firstReservation = null;
          for (AbstractInsnNode instruction : instructions.toArray()) {
            if (!(instruction instanceof MethodInsnNode)) continue;
            MethodInsnNode call = (MethodInsnNode) instruction;
            if (call.getOpcode() == Opcodes.INVOKEVIRTUAL && HTTP2_CONNECTION.equals(call.owner)
                && ((call.name.equals("tryReserveForPoolCheckout") && call.desc.equals("()Z"))
                    || (call.name.equals("reserveStream") && call.desc.equals("(ZZ)Z")))) {
              firstReservation = call;
              break;
            }
          }
          if (firstReservation != null && maxLocals <= 65533) {
            boolean flags = firstReservation.desc.equals("(ZZ)Z");
            int slot = maxLocals;
            InsnList guard = new InsnList();
            if (flags) {
              guard.add(new VarInsnNode(Opcodes.ISTORE, slot + 1));
              guard.add(new VarInsnNode(Opcodes.ISTORE, slot));
              maxLocals += 2;
            }
            guard.add(new InsnNode(Opcodes.DUP));
            guard.add(new FieldInsnNode(Opcodes.GETFIELD, HTTP2_CONNECTION, "connection", "L" + CONNECTION + ";"));
            guard.add(new FieldInsnNode(Opcodes.GETFIELD, CONNECTION, "address", "Ljava/net/InetSocketAddress;"));
            guard.add(new VarInsnNode(Opcodes.ALOAD, 1));
            guard.add(new InsnNode(Opcodes.SWAP));
            guard.add(new VarInsnNode(Opcodes.ALOAD, 1));
            guard.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, REQUEST, "uri", "()Ljava/net/URI;", false));
            guard.add(new InsnNode(Opcodes.SWAP));
            guard.add(new VarInsnNode(Opcodes.ALOAD, 1));
            guard.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, REQUEST, "proxy", "()Ljava/net/InetSocketAddress;", false));
            guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks, "beforeResolvedHttpExchange",
                "(Ljava/lang/Object;Ljava/net/URI;Ljava/net/InetSocketAddress;Ljava/net/InetSocketAddress;)V", false));
            if (flags) {
              guard.add(new VarInsnNode(Opcodes.ILOAD, slot));
              guard.add(new VarInsnNode(Opcodes.ILOAD, slot + 1));
            }
            instructions.insertBefore(firstReservation, guard);
          }
          accept(visitor);
        }
      };
    }
    if (CONNECTION.equals(owner)) {
      if ((access & Opcodes.ACC_STATIC) == 0 || !name.equals("getConnection") || !descriptor.startsWith(
          "(Ljava/net/InetSocketAddress;Ljdk/internal/net/http/HttpClientImpl;Ljdk/internal/net/http/HttpRequestImpl;")) return visitor;
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override protected void onMethodEnter() {
          loadArg(2);
          loadArg(2);
          mv.visitMethodInsn(INVOKEVIRTUAL, REQUEST, "uri", "()Ljava/net/URI;", false);
          loadArg(0);
          loadArg(2);
          mv.visitMethodInsn(INVOKEVIRTUAL, REQUEST, "proxy", "()Ljava/net/InetSocketAddress;", false);
          mv.visitMethodInsn(INVOKESTATIC, hooks, "beforeResolvedHttpExchange",
              "(Ljava/lang/Object;Ljava/net/URI;Ljava/net/InetSocketAddress;Ljava/net/InetSocketAddress;)V", false);
        }
      };
    }
    if ((access & Opcodes.ACC_STATIC) != 0) return visitor;
    if (HTTP_CLIENT.equals(owner)) {
      if (!name.equals("openServer") || !descriptor.equals("()V")) return visitor;
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override protected void onMethodEnter() {
          loadThis();
          loadThis();
          getField(Type.getObjectType(HTTP_CLIENT), "url", URL_TYPE);
          loadThis();
          getField(Type.getObjectType(NETWORK), "proxy", Type.getType(java.net.Proxy.class));
          mv.visitMethodInsn(INVOKESTATIC, hooks, "beginHttpRoute", "(Ljava/lang/Object;Ljava/net/URL;Ljava/net/Proxy;)V", false);
        }
      };
    }
    if (NETWORK.equals(owner)) {
      if (!name.equals("doConnect") || !descriptor.equals("(Ljava/lang/String;I)Ljava/net/Socket;")) return visitor;
      return new MethodVisitor(Opcodes.ASM9, visitor) {
        @Override public void visitMethodInsn(int opcode, String target, String method, String desc, boolean itf) {
          if (opcode == Opcodes.INVOKEVIRTUAL && target.equals("java/net/Socket") && method.equals("connect")
              && (desc.equals("(Ljava/net/SocketAddress;)V") || desc.equals("(Ljava/net/SocketAddress;I)V"))) {
            if (desc.equals("(Ljava/net/SocketAddress;I)V")) {
              mv.visitInsn(Opcodes.DUP2);
              mv.visitInsn(Opcodes.POP);
            } else mv.visitInsn(Opcodes.DUP);
            mv.visitVarInsn(Opcodes.ALOAD, 0);
            mv.visitInsn(Opcodes.SWAP);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeHttpDial", "(Ljava/lang/Object;Ljava/net/SocketAddress;)V", false);
          }
          super.visitMethodInsn(opcode, target, method, desc, itf);
        }
      };
    }
    if (MULTI.equals(owner)) {
      if (!name.equals("responseAsync") || !descriptor.equals("(Ljava/util/concurrent/Executor;)Ljava/util/concurrent/CompletableFuture;")) {
        return visitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override protected void onMethodEnter() {
          loadThis();
          loadThis();
          mv.visitFieldInsn(GETFIELD, MULTI, "request", "L" + REQUEST + ";");
          mv.visitMethodInsn(INVOKEVIRTUAL, REQUEST, "uri", "()Ljava/net/URI;", false);
          mv.visitMethodInsn(INVOKESTATIC, hooks, "captureHttpSubmission", "(Ljava/lang/Object;Ljava/net/URI;)V", false);
        }
        @Override protected void onMethodExit(int opcode) {
          if (opcode == ARETURN) {
            dup();
            loadThis();
            mv.visitMethodInsn(INVOKESTATIC, hooks, "finishHttpSubmission",
                "(Ljava/util/concurrent/CompletableFuture;Ljava/lang/Object;)V", false);
          }
        }
      };
    }
    if (EXCHANGE.equals(owner)) {
      return new MethodVisitor(Opcodes.ASM9, visitor) {
        @Override public void visitMethodInsn(int opcode, String target, String method, String desc, boolean itf) {
          if (opcode == Opcodes.INVOKESTATIC && target.equals("jdk/internal/net/http/ExchangeImpl")
              && method.equals("get") && desc.equals("(Ljdk/internal/net/http/Exchange;Ljdk/internal/net/http/HttpConnection;)Ljava/util/concurrent/CompletableFuture;")) {
            mv.visitVarInsn(Opcodes.ALOAD, 0);
            mv.visitFieldInsn(Opcodes.GETFIELD, EXCHANGE, "multi", "L" + MULTI + ";");
            mv.visitVarInsn(Opcodes.ALOAD, 0);
            mv.visitFieldInsn(Opcodes.GETFIELD, EXCHANGE, "request", "L" + REQUEST + ";");
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, REQUEST, "uri", "()Ljava/net/URI;", false);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeHttpExchange", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/net/URI;)V", false);
          }
          super.visitMethodInsn(opcode, target, method, desc, itf);
        }
      };
    }
    if (URL_CLASS.equals(owner)) {
      if (!name.equals("openConnection") || !(descriptor.equals("()Ljava/net/URLConnection;")
          || descriptor.equals("(Ljava/net/Proxy;)Ljava/net/URLConnection;"))) return visitor;
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override protected void onMethodEnter() {
          loadThis();
          mv.visitMethodInsn(INVOKESTATIC, hooks, "beforeUrlConnectionFactory", "(Ljava/net/URL;)V", false);
        }
      };
    }
    if (!matches(owner) || name.equals("<init>")) return visitor;
    return new MethodNode(Opcodes.ASM9, access, name, descriptor, null, null) {
      @Override public void visitEnd() {
        int scratch = maxLocals;
        boolean acquires = false;
        for (AbstractInsnNode insn : instructions.toArray()) {
          if (insn instanceof FieldInsnNode && (name.equals("followRedirect0") || name.equals("followRedirect"))) {
            FieldInsnNode field = (FieldInsnNode) insn;
            if (field.getOpcode() == Opcodes.PUTFIELD && field.name.equals("url") && field.desc.equals(URL_TYPE.getDescriptor())) {
              InsnList redirect = new InsnList();
              redirect.add(new InsnNode(Opcodes.DUP2));
              redirect.add(new VarInsnNode(Opcodes.ALOAD, 0));
              redirect.add(new FieldInsnNode(Opcodes.GETFIELD, "java/net/URLConnection", "url", URL_TYPE.getDescriptor()));
              redirect.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks, "captureHttpRedirect",
                  "(Ljava/lang/Object;Ljava/net/URL;Ljava/net/URL;)V", false));
              instructions.insertBefore(insn, redirect);
            }
          }
          if (!(insn instanceof MethodInsnNode)) continue;
          MethodInsnNode call = (MethodInsnNode) insn;
          if (call.getOpcode() == Opcodes.INVOKESTATIC && call.name.equals("New")
              && (HTTP_CLIENT.equals(call.owner) || HTTPS_CLIENT.equals(call.owner))
              && Type.getReturnType(call.desc).equals(Type.getObjectType(HTTP_CLIENT))) {
            inspectAcquisition(call, scratch);
            acquires = true;
          } else if (call.getOpcode() == Opcodes.INVOKEVIRTUAL && HTTP_CLIENT.equals(call.owner)
              && call.name.equals("writeRequests") && call.desc.startsWith("(Lsun/net/www/MessageHeader;")) {
            Type[] args = Type.getArgumentTypes(call.desc);
            int[] slots = slots(args, 0, scratch);
            if (slots == null) continue;
            InsnList guard = new InsnList();
            save(guard, args, slots, 0);
            guard.add(new InsnNode(Opcodes.DUP)); // actual HttpClient used for this write
            guard.add(new VarInsnNode(Opcodes.ALOAD, 0));
            guard.add(new InsnNode(Opcodes.DUP));
            guard.add(new FieldInsnNode(Opcodes.GETFIELD, "java/net/URLConnection", "url", URL_TYPE.getDescriptor()));
            guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks, "beforeHttpWrite",
                "(Ljava/lang/Object;Ljava/lang/Object;Ljava/net/URL;)V", false));
            restore(guard, args, slots, 0);
            instructions.insertBefore(call, guard);
          }
        }
        if (acquires) {
          accept(new ScopedMethodAdvice(Opcodes.ASM9, visitor, access, name, descriptor) {
            @Override protected void enterDispatch() {
              loadThis();
              mv.visitMethodInsn(INVOKESTATIC, Type.getInternalName(HttpTransportObservation.class),
                  "enterAcquisition", "(Ljava/lang/Object;)V", false);
            }
            @Override protected void exitDispatch() {
              mv.visitMethodInsn(INVOKESTATIC, Type.getInternalName(HttpTransportObservation.class),
                  "exitAcquisition", "()V", false);
            }
          });
        } else {
          accept(visitor);
        }
      }

      private void inspectAcquisition(MethodInsnNode call, int scratch) {
        Type[] args = Type.getArgumentTypes(call.desc);
        int index = 0;
        while (index < args.length && !URL_TYPE.equals(args[index])) index++;
        if (index == args.length) return;
        int[] slots = slots(args, index + 1, scratch);
        if (slots == null) return;
        InsnList guard = new InsnList();
        save(guard, args, slots, index + 1);
        guard.add(new InsnNode(Opcodes.DUP));
        guard.add(new VarInsnNode(Opcodes.ALOAD, 0));
        guard.add(new InsnNode(Opcodes.SWAP));
        guard.add(new InsnNode(Opcodes.ICONST_0));
        guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks, "beforeHttpTransport", HOOK_DESCRIPTOR, false));
        restore(guard, args, slots, index + 1);
        instructions.insertBefore(call, guard);
      }

      private int[] slots(Type[] args, int first, int scratch) {
        int[] slots = new int[args.length];
        int end = scratch;
        for (int i = first; i < args.length; i++) {
          slots[i] = end;
          end += args[i].getSize();
        }
        if (end > 65535) return null;
        maxLocals = Math.max(maxLocals, end);
        return slots;
      }
    };
  }

  private static void save(InsnList guard, Type[] args, int[] slots, int first) {
    for (int i = args.length - 1; i >= first; i--)
      guard.add(new VarInsnNode(args[i].getOpcode(Opcodes.ISTORE), slots[i]));
  }

  private static void restore(InsnList guard, Type[] args, int[] slots, int first) {
    for (int i = first; i < args.length; i++)
      guard.add(new VarInsnNode(args[i].getOpcode(Opcodes.ILOAD), slots[i]));
  }
}
