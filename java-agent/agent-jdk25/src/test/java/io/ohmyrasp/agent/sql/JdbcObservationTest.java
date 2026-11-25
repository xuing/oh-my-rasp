package io.ohmyrasp.agent.sql;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class JdbcObservationTest {
  @Test void identicalSqlOnAnotherReceiverOrAfterReturnHasAnIndependentReceipt() {
    Object first = new Object();
    Object second = new Object();
    String sql = "select 7";
    JdbcObservation.enter(first, sql);
    try {
      assertFalse(JdbcObservation.repeated(first, sql));
      JdbcObservation.enter(first, new String(sql));
      try { assertTrue(JdbcObservation.repeated(first, sql)); }
      finally { JdbcObservation.exit(); }
      JdbcObservation.enter(second, sql);
      try { assertFalse(JdbcObservation.repeated(second, sql)); }
      finally { JdbcObservation.exit(); }
      assertTrue(JdbcObservation.repeated(first, sql));
    } finally { JdbcObservation.exit(); }

    JdbcObservation.enter(first, sql);
    try { assertFalse(JdbcObservation.repeated(first, sql)); }
    finally { JdbcObservation.exit(); }
  }
}
