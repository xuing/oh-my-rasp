package io.ohmyrasp.agent.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.OhMyRaspAgent;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** The generated entry classes, as the build packs them (EntryGenerator, shared/src/entryGenerator). */
class LauncherEntriesTest {
  private static final String[] ENTRIES = {
    "UniversalEntry", "PrimaryEntry", "Java17Entry", "Java11Entry", "Java8Entry"
  };
  private static final String PACKAGE = "io/ohmyrasp/agent/launch/";

  @TempDir File temp;

  @BeforeEach
  void resetFakeLine() {
    OhMyRaspAgent.starts = 0;
  }

  @Test
  void entriesAreJava5ClassFilesThatUseOnlyJava5PlatformTypes() throws IOException {
    for (String entry : ENTRIES) {
      byte[] bytes = classBytes(PACKAGE + entry);
      assertEquals(49, ((bytes[6] & 0xff) << 8) | (bytes[7] & 0xff), entry + " class-file version");
      final List<String> used = new ArrayList<String>();
      new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
            String[] exceptions) {
          used.add(descriptor);
          return new MethodVisitor(Opcodes.ASM9) {
            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean itf) {
              used.add(owner);
              used.add(descriptor);
            }

            @Override
            public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
              used.add(owner);
              used.add(descriptor);
            }

            @Override
            public void visitTypeInsn(int opcode, String type) {
              used.add(type);
            }

            @Override
            public void visitLdcInsn(Object value) {
              if (value instanceof Type) {
                used.add(((Type) value).getInternalName());
              }
            }

            @Override
            public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrap, Object... args) {
              used.add("invokedynamic");
            }
          };
        }
      }, 0);
      for (String reference : used) {
        for (String type : typesIn(reference)) {
          assertTrue(type.equals(PACKAGE + entry) || type.equals(PACKAGE + "AgentLauncher")
              || type.equals("java/io/PrintStream") || type.startsWith("java/lang/instrument/")
              || (type.startsWith("java/lang/") && type.indexOf('/', "java/lang/".length()) < 0),
              entry + " uses " + type);
        }
      }
    }
  }

  @Test
  void eachEntryStartsTheLineItsJarHoldsThroughTheLauncher() throws Exception {
    for (String entry : ENTRIES) {
      // A JAR-like directory: the entry, the launcher and the primary line's entry class. The launcher
      // finds the primary line there and loads it by name through the system class loader (the fake).
      File jar = new File(temp, entry);
      copy(PACKAGE + entry, jar);
      copy(PACKAGE + "AgentLauncher", jar);
      copy("io/ohmyrasp/agent/OhMyRaspAgent", jar);
      // Parent null: this entry and launcher are their own classes, so each loop gets a fresh state.
      URLClassLoader loader = new URLClassLoader(new URL[] {jar.toURI().toURL()}, null);
      try {
        int before = OhMyRaspAgent.starts;
        String output = premain(loader.loadClass(PACKAGE.replace('/', '.') + entry));
        assertEquals(before + 1, OhMyRaspAgent.starts, entry + " did not start the line: " + output);
        assertEquals("", output, entry);
      } finally {
        loader.close();
      }
    }
  }

  @Test
  void anEntryWhoseLauncherCannotLinkPrintsOneLineAndReturns() throws Exception {
    for (String entry : ENTRIES) {
      ClassLoader loader = new RefusingLauncherLoader(PACKAGE + entry, classBytes(PACKAGE + entry));
      String output = premain(loader.loadClass(PACKAGE.replace('/', '.') + entry));
      assertEquals("{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"unsupported-java\",\"java_version\":\""
          + System.getProperty("java.specification.version") + "\",\"entry\":\"io.ohmyrasp.agent.launch." + entry
          + "\",\"exception\":\"java.lang.UnsupportedClassVersionError\"}", output);
    }
    assertEquals(0, OhMyRaspAgent.starts);
  }

  /** Calls the entry's premain with standard error captured; it must return normally. */
  private static String premain(Class<?> entry) throws Exception {
    Method premain = entry.getMethod("premain", String.class, Instrumentation.class);
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    PrintStream original = System.err;
    System.setErr(new PrintStream(captured, true, "UTF-8"));
    try {
      premain.invoke(null, "", null);
    } finally {
      System.setErr(original);
    }
    return captured.toString("UTF-8").trim();
  }

  /** Defines the entry from its bytes and fails AgentLauncher the way a Java 6 or 7 JVM does. */
  private static final class RefusingLauncherLoader extends ClassLoader {
    private final String entry;
    private final byte[] bytes;

    RefusingLauncherLoader(String entry, byte[] bytes) {
      super(null);
      this.entry = entry.replace('/', '.');
      this.bytes = bytes;
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
      if (name.equals(entry)) {
        return defineClass(name, bytes, 0, bytes.length);
      }
      if (name.equals("io.ohmyrasp.agent.launch.AgentLauncher")) {
        throw new UnsupportedClassVersionError(
            "io/ohmyrasp/agent/launch/AgentLauncher : Unsupported major.minor version 52.0");
      }
      throw new ClassNotFoundException(name);
    }
  }

  private static List<String> typesIn(String reference) {
    List<String> types = new ArrayList<String>();
    if (reference.startsWith("(")) {
      for (Type argument : Type.getArgumentTypes(reference)) {
        add(types, argument);
      }
      add(types, Type.getReturnType(reference));
    } else if (reference.startsWith("L") || reference.startsWith("[")) {
      add(types, Type.getType(reference));
    } else {
      types.add(reference);
    }
    return types;
  }

  private static void add(List<String> types, Type type) {
    Type element = type.getSort() == Type.ARRAY ? type.getElementType() : type;
    if (element.getSort() == Type.OBJECT) {
      types.add(element.getInternalName());
    }
  }

  private static byte[] classBytes(String internalName) throws IOException {
    InputStream in = LauncherEntriesTest.class.getClassLoader().getResourceAsStream(internalName + ".class");
    assertTrue(in != null, "missing " + internalName + ".class on the test classpath");
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      for (int n; (n = in.read(buffer)) != -1;) {
        out.write(buffer, 0, n);
      }
      return out.toByteArray();
    } finally {
      in.close();
    }
  }

  private static void copy(String internalName, File root) throws IOException {
    File target = new File(root, internalName + ".class");
    assertTrue(target.getParentFile().isDirectory() || target.getParentFile().mkdirs());
    FileOutputStream out = new FileOutputStream(target);
    try {
      out.write(classBytes(internalName));
    } finally {
      out.close();
    }
  }
}
