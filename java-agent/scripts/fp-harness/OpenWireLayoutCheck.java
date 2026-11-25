import io.ohmyrasp.agent.java11.Java11DeserializationTransformer;
import io.ohmyrasp.agent.shaded.asm.ClassReader;
import io.ohmyrasp.agent.shaded.asm.Opcodes;
import io.ohmyrasp.agent.shaded.asm.Type;
import io.ohmyrasp.agent.shaded.asm.tree.*;
import java.io.InputStream;
import java.util.Collections;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Read the Vulhub-version libraries as ZIP entries. Only the agent belongs on the classpath. */
public final class OpenWireLayoutCheck {
  private static boolean call(AbstractInsnNode insn, int opcode, String owner, String name, String desc) {
    if (!(insn instanceof MethodInsnNode)) return false;
    MethodInsnNode method = (MethodInsnNode)insn;
    return method.getOpcode() == opcode && owner.equals(method.owner) && name.equals(method.name) && desc.equals(method.desc);
  }

  private static void verify(byte[] bytes, String owner) {
    ClassNode type = new ClassNode();
    new ClassReader(bytes).accept(type, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    int resolutions = 0, constructions = 0;
    for (MethodNode method : type.methods) {
      if (!"createThrowable".equals(method.name) || !"(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Throwable;".equals(method.desc)) continue;
      for (AbstractInsnNode insn : method.instructions) {
        if (call(insn, Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                 "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;")) {
          AbstractInsnNode loader = insn.getPrevious();
          if (!call(loader, Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader", "()Ljava/lang/ClassLoader;")
              || !(loader.getPrevious() instanceof LdcInsnNode)
              || !Type.getObjectType(owner).equals(((LdcInsnNode)loader.getPrevious()).cst)
              || loader.getPrevious().getPrevious().getOpcode() != Opcodes.ICONST_0)
            throw new AssertionError(owner + " has a different class resolution path");
          resolutions++;
        }
        if (call(insn, Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Constructor", "newInstance",
                 "([Ljava/lang/Object;)Ljava/lang/Object;")) {
          AbstractInsnNode hook = insn.getPrevious();
          if (!call(hook, Opcodes.INVOKESTATIC, "io/ohmyrasp/agent/java11/Java11RaspHooks",
                    "beforeOpenWireThrowable", "(Ljava/lang/Class;)V")
              || !call(hook.getPrevious(), Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Constructor",
                       "getDeclaringClass", "()Ljava/lang/Class;"))
            throw new AssertionError(owner + " missing guard at constructor invocation");
          constructions++;
        }
      }
    }
    if (resolutions != 1 || constructions != 1) throw new AssertionError(owner + " has an unrecognized marshaller layout");
  }

  public static void main(String[] paths) throws Exception {
    Java11DeserializationTransformer agent = new Java11DeserializationTransformer();
    if (paths.length == 0) throw new IllegalArgumentException("provide the OpenWire artifact paths");
    for (String path : paths) {
      int count = 0;
      try (JarFile jar = new JarFile(path)) {
        for (JarEntry entry : Collections.list(jar.entries())) {
          if (!entry.getName().matches("org/apache/activemq/openwire/v[0-9]+/BaseDataStreamMarshaller\\.class")) continue;
          String owner = entry.getName().substring(0, entry.getName().length() - ".class".length());
          try (InputStream input = jar.getInputStream(entry)) {
            byte[] transformed = agent.transform(null, owner, null, null, input.readAllBytes());
            if (transformed == null) throw new AssertionError(owner + " was not transformed");
            verify(transformed, owner);
          }
          count++;
        }
      }
      if (count == 0) throw new AssertionError(path + " contained no versioned marshallers");
      System.out.println(path + " verified constructor sites: " + count);
    }
  }
}
