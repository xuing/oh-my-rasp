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
    AttachmentFileRead.beginReference(report.toUri().toString(), origin);
    try {
      AttachmentFileRead.created(selected, url);
      AttachmentFileRead.beginReference("cid:weekly", origin);
      try {
        AttachmentFileRead.created(ordinary, url);
      } finally {
        AttachmentFileRead.endReference();
      }
    } finally {
      AttachmentFileRead.endReference();
    }
    CompletableFuture.runAsync(() -> {
      AttachmentFileRead.beginRead(selected);
      try {
        assertTrue(AttachmentFileRead.selected(report.toString()));
        assertSame(origin, AttachmentFileRead.origin());
        assertFalse(AttachmentFileRead.selected(report + ".other"));
        assertFalse(AttachmentFileRead.repeated());
        assertTrue(AttachmentFileRead.repeated());
        AttachmentFileRead.beginRead(ordinary);
        try {
          assertFalse(AttachmentFileRead.selected(report.toString()));
        } finally {
          AttachmentFileRead.endRead();
        }
        assertTrue(AttachmentFileRead.selected(report.toString()));
      } finally {
        AttachmentFileRead.endRead();
      }
      assertNull(AttachmentFileRead.origin());
    }).join();
  }
}
