package reports;

import java.io.Serializable;

/** An ordinary record with the same simple name and stream format after a package migration. */
public final class BeanComparator implements Serializable {
  private static final long serialVersionUID = 1L;
  public final int count = 42;
}
