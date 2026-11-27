package io.ohmyrasp.agent.xml;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

class AttachmentFileReadTest {
  @Test
  void deferredReadFollowsOnlyTheDataSourceCreatedForTheLocalReference() throws Exception {
    var report = Path.of("weekly report.txt").toAbsolutePath();
    var url = report.toUri().toURL();
    var origin = new Object();
    var selected = new Object();
    var ordinary = new Object();
    Object local = AttachmentFileRead.beginReference(report.toUri().toString(), origin);
    try {
      AttachmentFileRead.created(selected, url);
      Object content = AttachmentFileRead.beginReference("cid:weekly", origin);
      try {
        AttachmentFileRead.created(ordinary, url);
      } finally {
        AttachmentFileRead.endReference(content);
      }
    } finally {
      AttachmentFileRead.endReference(local);
    }
    CompletableFuture.runAsync(() -> {
      Object read = AttachmentFileRead.beginRead(selected);
      try {
        assertTrue(AttachmentFileRead.selected(report.toString()));
        assertSame(origin, AttachmentFileRead.origin());
        assertFalse(AttachmentFileRead.selected(report + ".other"));
        assertFalse(AttachmentFileRead.repeated());
        assertTrue(AttachmentFileRead.repeated());
        Object other = AttachmentFileRead.beginRead(ordinary);
        try {
          assertFalse(AttachmentFileRead.selected(report.toString()));
        } finally {
          AttachmentFileRead.endRead(other);
        }
        assertTrue(AttachmentFileRead.selected(report.toString()));
      } finally {
        AttachmentFileRead.endRead(read);
      }
      assertNull(AttachmentFileRead.origin());
    }).join();
  }
}
