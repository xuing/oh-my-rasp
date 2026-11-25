package io.ohmyrasp.agent.file;

/** The data-stream component of a Windows file operand. An empty name denotes the default data. */
public record WindowsDataStream(String file, String name) {
  public static WindowsDataStream parse(String path) {
    if (path == null || path.indexOf(':') < 0) return null;
    int start = path.startsWith("\\\\?\\") ? 4 : 0;
    if (path.startsWith("\\\\.\\")) return null;
    if (path.length() >= start + 2 && isDriveLetter(path.charAt(start)) && path.charAt(start + 1) == ':')
      start += 2;
    int separator = path.indexOf(':', start);
    if (separator < 0) return null;
    int leaf = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1;
    if (separator <= Math.max(leaf, start)) return null;

    int type = path.indexOf(':', separator + 1);
    if (type >= 0 && !path.substring(type + 1).equalsIgnoreCase("$DATA")) return null;
    String name = path.substring(separator + 1, type < 0 ? path.length() : type);
    if (name.isEmpty() && type < 0) return null;
    for (int i = 0; i < name.length(); i++) {
      if ("<>\"|?*".indexOf(name.charAt(i)) >= 0 || name.charAt(i) == 0) return null;
    }
    return new WindowsDataStream(path.substring(0, separator), name);
  }

  private static boolean isDriveLetter(char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
  }
}
