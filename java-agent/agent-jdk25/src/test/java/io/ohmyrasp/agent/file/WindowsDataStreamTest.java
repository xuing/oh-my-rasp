package io.ohmyrasp.agent.file;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class WindowsDataStreamTest {
  @Test
  void separatesTheFileOperandFromADataStream() {
    for (String file : List.of("weekly.csv", "C:\\exports\\weekly.csv", "D:weekly.csv",
        "\\\\server\\share\\weekly.csv", "\\\\?\\C:\\exports\\weekly.csv", ".\\a")) {
      assertEquals(new WindowsDataStream(file, ""), WindowsDataStream.parse(file + "::$DaTa"));
      assertEquals(new WindowsDataStream(file, "author (old)"), WindowsDataStream.parse(file + ":author (old)"));
      assertEquals(new WindowsDataStream(file, "$DATA"), WindowsDataStream.parse(file + ":$DATA:$DATA"));
    }
    for (String file : List.of("C:weekly.csv", "C:\\exports\\weekly.csv", "weekly.csv::$INDEX",
        "weekly.csv:", "weekly.csv:author:type", "weekly.csv:x:$DATA:z", "bad:parent/weekly.csv",
        "C:\\exports\\:x", "\\\\.\\device:name", "weekly.csv:a?b"))
      assertNull(WindowsDataStream.parse(file), file);
  }
}
