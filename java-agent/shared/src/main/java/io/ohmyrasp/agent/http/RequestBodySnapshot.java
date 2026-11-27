package io.ohmyrasp.agent.http;

/**
 * What a request's body showed the agent at one moment: the text recorded so far (at most
 * {@link RequestBody#MAX_UNITS} characters), the values extracted from it, and whether the cap cut it.
 * Immutable: a rule that reads it on another thread sees one consistent state.
 */
public final class RequestBodySnapshot {
  private final String text;
  private final int kind;
  private final int version;
  private final boolean truncated;
  private volatile BodyValues values;

  RequestBodySnapshot(String text, int kind, int version, boolean truncated) {
    this.text = text == null ? "" : text;
    this.kind = kind;
    this.version = version;
    this.truncated = truncated;
  }

  /** A snapshot of a body handed over whole, with the content type the request names (null when it names none). */
  public static RequestBodySnapshot of(String text, String contentType) {
    int kind = RequestBody.kindOf(contentType);
    return new RequestBodySnapshot(text, kind == RequestBody.NONE ? RequestBody.AUTO : kind, 1, false);
  }

  public String text() { return text; }

  /** How many records into the request this state was taken; a later state has a larger number. */
  public int version() { return version; }

  /** Whether the body went on past the cap, so that the text is a prefix of it. */
  public boolean truncated() { return truncated; }

  /** The values for matching against sink arguments: see {@link BodyValues}. Extracted once, on first use. */
  public BodyValues values() {
    BodyValues extracted = values;
    if (extracted == null) {
      extracted = extract(text, kind);
      values = extracted;
    }
    return extracted;
  }

  static BodyValues extract(String text, int kind) {
    if (text.isEmpty()) return BodyValues.EMPTY;
    switch (kind) {
      case RequestBody.JSON: return BodyValues.json(text);
      case RequestBody.FORM: return BodyValues.form(text);
      case RequestBody.TEXT: return BodyValues.text(text);
      case RequestBody.AUTO: {
        String trimmed = text.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[") ? BodyValues.json(trimmed) : BodyValues.text(trimmed);
      }
      default: return BodyValues.EMPTY;
    }
  }
}
