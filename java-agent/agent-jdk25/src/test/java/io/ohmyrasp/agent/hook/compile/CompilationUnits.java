package io.ohmyrasp.agent.hook.compile;

import java.net.URI;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;

/**
 * Java source units whose classes are not public, in a package of their own. A hook in
 * io.ohmyrasp.agent.hook reaches a non-public class of its own package by reflection, so a test that
 * keeps them beside the hook would pass for the wrong reason.
 */
public final class CompilationUnits {
  private CompilationUnits() {}

  /** The usual way to compile a string: an anonymous subclass. */
  public static JavaFileObject anonymous(String text) {
    return new SimpleJavaFileObject(URI.create("string:///Demo.java"), JavaFileObject.Kind.SOURCE) {
      @Override
      public CharSequence getCharContent(boolean ignoreEncodingErrors) {
        return text;
      }
    };
  }

  /** A named, package-private subclass. */
  public static JavaFileObject packagePrivate(String text) {
    return new HiddenSource(text);
  }

  private static final class HiddenSource extends SimpleJavaFileObject {
    private final String text;

    HiddenSource(String text) {
      super(URI.create("string:///Demo.java"), JavaFileObject.Kind.SOURCE);
      this.text = text;
    }

    @Override
    public CharSequence getCharContent(boolean ignoreEncodingErrors) {
      return text;
    }
  }
}
