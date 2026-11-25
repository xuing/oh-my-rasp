package io.ohmyrasp.agent.file;

import static org.junit.jupiter.api.Assertions.assertSame;

import java.io.File;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class HostDirectoryTest {
  @Test
  void sharedEmptyArrayDoesNotTransferAnotherListingsSelectedFile() throws Exception {
    String[] empty = {};
    var gate = new CyclicBarrier(2);
    var pool = Executors.newFixedThreadPool(2);
    Callable<Void> listing = () -> {
      var argument = new File("");
      var selected = new File("working-directory");
      HostDirectory.listed(selected, empty, argument);
      gate.await(5, TimeUnit.SECONDS);
      assertSame(selected, HostDirectory.selectedFile(argument, empty));
      assertSame(argument, HostDirectory.selectedFile(argument, empty));
      return null;
    };
    try {
      var first = pool.submit(listing);
      var second = pool.submit(listing);
      first.get(10, TimeUnit.SECONDS);
      second.get(10, TimeUnit.SECONDS);
    } finally {
      pool.shutdownNow();
    }
  }
}
