package io.ohmyrasp.agent.process;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Word boundaries for a single simple command made entirely of literal POSIX shell words. */
final class LiteralShellCommand {
  final List<String> words;
  private final String source;
  private final int start;
  private final int end;

  private LiteralShellCommand(List<String> words, String source, int start, int end) {
    this.words = words;
    this.source = source;
    this.start = start;
    this.end = end;
  }

  boolean matchesSource(Pattern indicator) {
    return !words.isEmpty() && indicator.matcher(source).region(start, end).find();
  }

  /** Returns null for expansions, control syntax, incomplete input or a second command. */
  static LiteralShellCommand parse(String source) {
    List<String> words = new ArrayList<String>();
    StringBuilder word = new StringBuilder();
    int start = -1, end = 0;
    char quote = 0;
    boolean inWord = false;
    boolean finished = false;
    for (int i = 0; i < source.length(); i++) {
      char c = source.charAt(i);
      if (quote == 0) {
        if (!inWord && c == '#') {
          int newline = source.indexOf('\n', i);
          if (newline < 0) break;
          i = newline;
          c = '\n';
        }
        if (c == ' ' || c == '\t' || c == '\n' || c == ';') {
          if (c == ';' && (finished || (!inWord && words.isEmpty()))) return null;
          if (inWord) {
            words.add(word.toString());
            word.setLength(0);
            inWord = false;
          }
          if ((c == '\n' || c == ';') && !words.isEmpty()) finished = true;
          continue;
        }
        if (finished) return null;
      }
      int position = i;
      if (c == '\\' && quote != '\'') {
        if (++i == source.length()) return null;
        char next = source.charAt(i);
        if (next == '\n') continue;
        if (quote == '"' && "\\$`\"".indexOf(next) < 0) word.append('\\');
        word.append(next);
      } else if (quote != 0 && c == quote) {
        quote = 0;
      } else if (quote == 0 && (c == '\'' || c == '"')) {
        quote = c;
      } else {
        if (quote == '"' && (c == '$' || c == '`')) return null;
        if (quote == 0 && !(Character.isLetterOrDigit(c) || "_./-:@%+=,#".indexOf(c) >= 0)) return null;
        word.append(c);
      }
      if (start < 0) start = position;
      end = i + 1;
      inWord = true;
    }
    if (quote != 0) return null;
    if (inWord) words.add(word.toString());
    return new LiteralShellCommand(words, source, start, end);
  }
}
