package io.ohmyrasp.agent.sql;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class JdbcObservationTest {
  @Test void identicalSqlOnAnotherReceiverOrAfterReturnHasAnIndependentReceipt() {
    Object first = new Object();
    Object second = new Object();
    String sql = "select 7";
    Object outer = JdbcObservation.enter(first, sql);
    try {
      assertFalse(JdbcObservation.repeated(first, sql));
      Object delegated = JdbcObservation.enter(first, new String(sql));
      try { assertTrue(JdbcObservation.repeated(first, sql)); }
      finally { JdbcObservation.exit(delegated); }
      Object other = JdbcObservation.enter(second, sql);
      try { assertFalse(JdbcObservation.repeated(second, sql)); }
      finally { JdbcObservation.exit(other); }
      assertTrue(JdbcObservation.repeated(first, sql));
    } finally { JdbcObservation.exit(outer); }

    Object again = JdbcObservation.enter(first, sql);
    try { assertFalse(JdbcObservation.repeated(first, sql)); }
    finally { JdbcObservation.exit(again); }
  }
}
