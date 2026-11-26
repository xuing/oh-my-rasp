package io.ohmyrasp.agent.launch;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * Writes the agent JARs' entry classes (Premain-Class and Agent-Class), one per kind of JAR, as class
 * files of version 49 (Java 5). javac no longer emits that version; the entries need it so that a Java
 * 6 or 7 JVM can load them and survive our Java 8 launcher.
 *
 * <p>Each entry is the bytecode of this Java 5 source, with {@code XEntry} its own name:
 *
 * <pre>
 * public final class XEntry {
 *   private XEntry() {}
 *   public static void premain(String agentArgs, Instrumentation instrumentation) {
 *     launch("premain", agentArgs, instrumentation);
 *   }
 *   public static void agentmain(String agentArgs, Instrumentation instrumentation) {
 *     launch("agentmain", agentArgs, instrumentation);
 *   }
 *   private static void launch(String method, String agentArgs, Instrumentation instrumentation) {
 *     try {
 *       AgentLauncher.start(method, agentArgs, instrumentation, XEntry.class);
 *     } catch (Throwable failure) {
 *       // Below Java 8, AgentLauncher (class-file version 52) fails to link here.
 *       try {
 *         System.err.println(new StringBuilder()
 *             .append("{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"unsupported-java\",\"java_version\":\"")
 *             .append(System.getProperty("java.specification.version"))
 *             .append("\",\"entry\":\"io.ohmyrasp.agent.launch.XEntry\",\"exception\":\"")
 *             .append(failure.getClass().getName())
 *             .append("\"}").toString());
 *       } catch (Throwable ignored) {
 *       }
 *     }
 *   }
 * }
 * </pre>
 *
 * Version 49 class files carry no stack map frames, so the method bodies are emitted with maxima only.
 * They use only {@code java.lang}, {@code java.lang.instrument} and {@code System.err}'s
 * {@code java.io.PrintStream}, all present in Java 5, and concatenate with {@code StringBuilder}.
 */
public final class EntryGenerator {
  /** The entry classes, one per kind of agent JAR; the build packs each into its own JARs only. */
  static final String[] ENTRIES = {
    "UniversalEntry", "PrimaryEntry", "Java17Entry", "Java11Entry", "Java8Entry"
  };

  static final String PACKAGE = "io/ohmyrasp/agent/launch/";
  private static final String LAUNCHER = PACKAGE + "AgentLauncher";
  private static final String INSTRUMENTATION = "Ljava/lang/instrument/Instrumentation;";
  private static final String ENTRY_DESCRIPTOR = "(Ljava/lang/String;" + INSTRUMENTATION + ")V";
  private static final String LAUNCH_DESCRIPTOR = "(Ljava/lang/String;Ljava/lang/String;" + INSTRUMENTATION + ")V";
  private static final String BUILDER = "java/lang/StringBuilder";
  private static final String APPEND = "(Ljava/lang/String;)Ljava/lang/StringBuilder;";

  private EntryGenerator() {}

  public static void main(String[] args) throws IOException {
    if (args.length != 1) {
      throw new IllegalArgumentException("usage: EntryGenerator OUTPUT-DIRECTORY");
    }
    File directory = new File(args[0], PACKAGE);
    if (!directory.isDirectory() && !directory.mkdirs()) {
      throw new IOException("cannot create " + directory);
    }
    for (String entry : ENTRIES) {
      OutputStream out = new FileOutputStream(new File(directory, entry + ".class"));
      try {
        out.write(generate(PACKAGE + entry));
      } finally {
        out.close();
      }
    }
  }

  /** The class file of the entry with internal name {@code entry}. */
  static byte[] generate(String entry) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_5, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER, entry, null,
        "java/lang/Object", null);

    MethodVisitor init = writer.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
    init.visitCode();
    init.visitVarInsn(Opcodes.ALOAD, 0);
    init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    init.visitInsn(Opcodes.RETURN);
    init.visitMaxs(0, 0);
    init.visitEnd();

    for (String method : new String[] {"premain", "agentmain"}) {
      MethodVisitor visitor = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, method,
          ENTRY_DESCRIPTOR, null, null);
      visitor.visitCode();
      visitor.visitLdcInsn(method);
      visitor.visitVarInsn(Opcodes.ALOAD, 0);
      visitor.visitVarInsn(Opcodes.ALOAD, 1);
      visitor.visitMethodInsn(Opcodes.INVOKESTATIC, entry, "launch", LAUNCH_DESCRIPTOR, false);
      visitor.visitInsn(Opcodes.RETURN);
      visitor.visitMaxs(0, 0);
      visitor.visitEnd();
    }

    MethodVisitor launch = writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "launch",
        LAUNCH_DESCRIPTOR, null, null);
    launch.visitCode();
    Label start = new Label();
    Label end = new Label();
    Label failed = new Label();
    Label printStart = new Label();
    Label printEnd = new Label();
    Label printFailed = new Label();
    Label done = new Label();
    launch.visitTryCatchBlock(start, end, failed, "java/lang/Throwable");
    launch.visitTryCatchBlock(printStart, printEnd, printFailed, "java/lang/Throwable");
    // try { AgentLauncher.start(method, agentArgs, instrumentation, XEntry.class); }
    launch.visitLabel(start);
    launch.visitVarInsn(Opcodes.ALOAD, 0);
    launch.visitVarInsn(Opcodes.ALOAD, 1);
    launch.visitVarInsn(Opcodes.ALOAD, 2);
    launch.visitLdcInsn(Type.getObjectType(entry));
    launch.visitMethodInsn(Opcodes.INVOKESTATIC, LAUNCHER, "start",
        "(Ljava/lang/String;Ljava/lang/String;" + INSTRUMENTATION + "Ljava/lang/Class;)V", false);
    launch.visitLabel(end);
    launch.visitJumpInsn(Opcodes.GOTO, done);
    // catch (Throwable failure) { try { System.err.println(...); } catch (Throwable ignored) {} }
    launch.visitLabel(failed);
    launch.visitVarInsn(Opcodes.ASTORE, 3);
    launch.visitLabel(printStart);
    launch.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "err", "Ljava/io/PrintStream;");
    launch.visitTypeInsn(Opcodes.NEW, BUILDER);
    launch.visitInsn(Opcodes.DUP);
    launch.visitMethodInsn(Opcodes.INVOKESPECIAL, BUILDER, "<init>", "()V", false);
    append(launch, "{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"unsupported-java\",\"java_version\":\"");
    launch.visitLdcInsn("java.specification.version");
    launch.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "getProperty",
        "(Ljava/lang/String;)Ljava/lang/String;", false);
    launch.visitMethodInsn(Opcodes.INVOKEVIRTUAL, BUILDER, "append", APPEND, false);
    append(launch, "\",\"entry\":\"" + entry.replace('/', '.') + "\",\"exception\":\"");
    launch.visitVarInsn(Opcodes.ALOAD, 3);
    launch.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false);
    launch.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getName", "()Ljava/lang/String;", false);
    launch.visitMethodInsn(Opcodes.INVOKEVIRTUAL, BUILDER, "append", APPEND, false);
    append(launch, "\"}");
    launch.visitMethodInsn(Opcodes.INVOKEVIRTUAL, BUILDER, "toString", "()Ljava/lang/String;", false);
    launch.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
    launch.visitLabel(printEnd);
    launch.visitJumpInsn(Opcodes.GOTO, done);
    launch.visitLabel(printFailed);
    launch.visitInsn(Opcodes.POP);
    launch.visitLabel(done);
    launch.visitInsn(Opcodes.RETURN);
    launch.visitMaxs(0, 0);
    launch.visitEnd();

    writer.visitEnd();
    return writer.toByteArray();
  }

  private static void append(MethodVisitor visitor, String text) {
    visitor.visitLdcInsn(text);
    visitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, BUILDER, "append", APPEND, false);
  }
}
