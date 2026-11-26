package org.apache.commons.beanutils;

import java.io.Serializable;

/** Inert stand-in for a listed binary name, with no serialization callbacks. */
public class BeanComparator implements Serializable {
  private static final long serialVersionUID = 1L;
  public final int count = 42;
}
