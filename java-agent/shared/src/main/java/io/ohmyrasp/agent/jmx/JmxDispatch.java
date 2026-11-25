package io.ohmyrasp.agent.jmx;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.management.ObjectName;

/** A management argument remains application-owned; its display methods and iterators may have side effects. */
public final class JmxDispatch {
  private JmxDispatch() {}

  public static String name(Object bean) {
    if (bean instanceof String) return (String) bean;
    return bean != null && bean.getClass() == ObjectName.class ? bean.toString() : "";
  }

  /** Recognize a complete location or a property assignment whose value is a location. */
  public static boolean isLocationArgument(String argument) {
    if (argument == null) return false;
    String value = argument.trim();
    int equals = value.indexOf('=');
    int colon = value.indexOf(':');
    if (colon < 1) return false;
    if (equals >= 0 && equals < colon) {
      if (equals == 0) return false;
      for (int i = 0; i < equals; i++) {
        char ch = value.charAt(i);
        if (!Character.isLetterOrDigit(ch) && ch != '.' && ch != '-' && ch != '_') return false;
      }
      value = value.substring(equals + 1).trim();
    }
    try {
      return new URI(value).isAbsolute();
    } catch (URISyntaxException invalid) {
      return false;
    }
  }

  public static List<String> strings(Object arguments) {
    if (arguments instanceof String) return Collections.singletonList((String) arguments);
    if (!(arguments instanceof Object[])) return Collections.emptyList();
    List<String> text = new ArrayList<String>();
    for (Object argument : (Object[]) arguments) {
      if (argument instanceof String) text.add((String) argument);
      else if (argument instanceof String[]) Collections.addAll(text, (String[]) argument);
    }
    return text;
  }
}
