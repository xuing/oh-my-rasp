package io.ohmyrasp.agent.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.ohmyrasp.agent.http.ArchiveUploadPolicy.Decision;
import org.junit.jupiter.api.Test;

public class ArchiveUploadPolicyTest {
  public static class Request {
    String policy = "role:installer";
    String dispatcher = "REQUEST";
    String method = "POST";
    String contentType = "multipart/form-data; boundary=files";
    String pathInfo = "/import";
    boolean granted;
    boolean reenter;

    public String getContentType() { return contentType; }
    public String getDispatcherType() { return dispatcher; }
    public String getMethod() { return method; }
    public String getServletPath() { return "/releases"; }
    public String getPathInfo() { return pathInfo; }
    public Request getServletContext() { return this; }

    public String getInitParameter(String key) {
      return key.equals("ohmyrasp.archiveUpload.POST/releases/import") ? policy : null;
    }

    public boolean isUserInRole(String role) {
      if (reenter) assertEquals(Decision.UNAVAILABLE, ArchiveUploadPolicy.decide(this));
      return granted && role.equals("installer");
    }
  }

  @Test
  void readsCurrentAuthorizationAndMatchesTheExactOperation() {
    Request request = new Request();
    assertEquals(Decision.ROLE_DENIED, ArchiveUploadPolicy.decide(request));
    request.granted = true;
    request.reenter = true;
    assertEquals(Decision.ALLOWED, ArchiveUploadPolicy.decide(request));
    request.method = "PUT";
    assertEquals(Decision.UNSPECIFIED, ArchiveUploadPolicy.decide(request));
    request.method = "POST";
    request.pathInfo = "/import/status";
    assertEquals(Decision.UNSPECIFIED, ArchiveUploadPolicy.decide(request));
    request.pathInfo = "/import";
    request.dispatcher = "INCLUDE";
    assertEquals(Decision.UNAVAILABLE, ArchiveUploadPolicy.decide(request));
  }

  @Test
  void denialEvidenceIdentifiesTheDeclarationUsedForThatRoleCheck() {
    Request r = new Request();
    var denied = ArchiveUploadPolicy.inspect(r);
    assertEquals(Decision.ROLE_DENIED, denied.decision);
    assertEquals("9b60cd77fabe9d03c1e1d38131aebe8300e167eaaba367a304cfb31fd7838b02", denied.policyDigest);
    r.granted = true;
    assertEquals(null, ArchiveUploadPolicy.inspect(r).policyDigest);
    r.policy = "deny";
    assertEquals(Decision.DENY_ALL, ArchiveUploadPolicy.inspect(r).decision);
  }

  @Test
  void cannotInferADenialFromMissingOrInvalidAuthorization() {
    Request request = new Request();
    request.policy = null;
    assertEquals(Decision.UNSPECIFIED, ArchiveUploadPolicy.decide(request));
    for (String invalid : new String[]{"", "allow", "role:", "role:*", "role:**"}) {
      request.policy = invalid;
      assertEquals(Decision.UNAVAILABLE, ArchiveUploadPolicy.decide(request));
    }
    request.policy = "deny";
    assertEquals(Decision.DENY_ALL, ArchiveUploadPolicy.decide(request));
    request.contentType = "text/plain";
    assertEquals(Decision.UNAVAILABLE, ArchiveUploadPolicy.decide(request));
    Request failure = new Request() {
      @Override public boolean isUserInRole(String role) { throw new IllegalStateException(); }
    };
    assertEquals(Decision.UNAVAILABLE, ArchiveUploadPolicy.decide(failure));
    assertEquals(Decision.ROLE_DENIED, ArchiveUploadPolicy.decide(new Request()));
  }
}
