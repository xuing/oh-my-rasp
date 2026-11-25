package io.dataease.utils;

/** Test-only selection of the current report credential. */
public final class ServletUtils {
  public static String selected;
  public static String getToken() { return selected; }
}
