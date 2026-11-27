package io.ohmyrasp.agent.rules.product.rocketmq;

import java.util.List;
import java.util.function.IntFunction;
import java.util.function.IntPredicate;

/** Execution boundaries for server launchers that consume mutable configuration. */
public final class RocketMqFilterServer {
  private static final String OWNER = "org.apache.rocketmq.broker.filtersrv.FilterServerManager";
  private static final String DELEGATE = "org.apache.rocketmq.broker.filtersrv.FilterServerUtil";

  private RocketMqFilterServer() {}

  private static boolean isOwner(String name) {
    return name != null && (OWNER.equals(name) || name.startsWith(OWNER + "$"));
  }

  // Anonymous classes, not lambdas: the backport command decision runs these, and a lambda links at run time.
  public static boolean directlyCallsProcessApi(final StackTraceElement[] stack) {
    return directOwner(stack.length, new IntFunction<String>() {
      public String apply(int i) {
        return stack[i].getClassName();
      }
    }, new IntPredicate() {
      public boolean test(int i) {
        return isProcessApi(stack[i]);
      }
    }) != null;
  }

  /** Class-name stack captured inside a process API entry hook, innermost frame first. */
  public static String directOwner(final List<String> stack) {
    if (stack == null) {
      return null;
    }
    return directOwner(stack.size(), new IntFunction<String>() {
      public String apply(int i) {
        return stack.get(i);
      }
    }, new IntPredicate() {
      public boolean test(int i) {
        return "java.lang.ProcessImpl".equals(stack.get(i)) || "java.lang.ProcessBuilder".equals(stack.get(i))
            || "java.lang.Runtime".equals(stack.get(i));
      }
    });
  }

  private static String directOwner(int depth, IntFunction<String> name, IntPredicate processApi) {
    for (int i = 0; i < depth; i++) {
      if (processApi.test(i)) {
        do {
          i++;
        } while (i < depth && processApi.test(i));
        if (i == depth) {
          return null;
        }
        String caller = name.apply(i);
        if (DELEGATE.equals(caller) && i + 1 < depth) {
          caller = name.apply(i + 1);
        }
        return isOwner(caller) ? caller : null;
      }
    }
    return null;
  }

  private static boolean isProcessApi(StackTraceElement frame) {
    return ("java.lang.ProcessImpl".equals(frame.getClassName()) && "start".equals(frame.getMethodName()))
        || ("java.lang.ProcessBuilder".equals(frame.getClassName())
            && ("start".equals(frame.getMethodName()) || "startPipeline".equals(frame.getMethodName())))
        || ("java.lang.Runtime".equals(frame.getClassName()) && "exec".equals(frame.getMethodName()));
  }
}
