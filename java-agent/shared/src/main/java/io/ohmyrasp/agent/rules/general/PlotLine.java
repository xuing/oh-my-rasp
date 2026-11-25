package io.ohmyrasp.agent.rules.general;

/** Project command text onto its ASCII syntax, retaining lexical state between successful writes. */
final class PlotLine {
  private boolean unknown;
  private boolean comment;
  private char quote;
  private boolean escaped;
  private boolean continuation;
  private boolean carriageReturn;

  PlotLine(boolean unknown) { this.unknown = unknown; }

  PlotLine(PlotLine previous) {
    unknown = previous.unknown;
    comment = previous.comment;
    quote = previous.quote;
    escaped = previous.escaped;
    continuation = previous.continuation;
    carriageReturn = previous.carriageReturn;
  }

  String code(byte[] bytes, int offset, int length) {
    StringBuilder out = new StringBuilder(length);
    for (int i = offset; i < offset + length; i++) {
      char c = (char) (bytes[i] & 0xff);
      if (c == '\r' || c == '\n') {
        out.append(c);
        if (!(carriageReturn && c == '\n')) {
          if (!continuation) {
            unknown = false;
            comment = false;
            quote = 0;
          }
          escaped = false;
          continuation = false;
        }
        carriageReturn = c == '\r';
        continue;
      }
      carriageReturn = false;
      boolean space = c == ' ' || c == '\t';
      if (!space) continuation = c == '\\';
      if (unknown || comment || (quote == 0 && c == '#')) {
        comment = true;
        out.append('~');
      } else if (quote != 0) {
        out.append('~');
        if (escaped) escaped = false;
        else if (quote == '"' && c == '\\') escaped = true;
        else if (c == quote) quote = 0;
      } else {
        out.append(c);
        // The opening delimiter is significant to a command taking a string operand.
        if (c == '\'' || c == '"' || c == '`') quote = c;
      }
    }
    return out.toString();
  }
}
