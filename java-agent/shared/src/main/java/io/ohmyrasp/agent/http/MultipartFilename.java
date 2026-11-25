package io.ohmyrasp.agent.http;

import java.lang.ref.WeakReference;
import io.ohmyrasp.agent.util.WeakOwners;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/** Classify the receiver's actual multipart contracts without invoking application getters. */
public final class MultipartFilename {
  public static final int PART = 1;
  public static final int SPRING = 2;
  public static final int KNOWN = 4;
  public static final int SERVLET_REQUEST = 8;
  public static final int SPRING_REQUEST = 16;
  private static final int SERVLET = 32;
  private static final WeakOwners<WeakReference<Object>> WRAPPED = new WeakOwners<WeakReference<Object>>();
  private static final ClassValue<Integer> CONTRACTS = new ClassValue<Integer>() {
    @Override protected Integer computeValue(Class<?> type) {
      String name = type.getName();
      if ((name.equals("javax.servlet.http.Part") || name.equals("jakarta.servlet.http.Part"))
          && hasGetter(type, "getSubmittedFileName")) return PART;
      if (name.equals("org.springframework.web.multipart.MultipartFile") && hasGetter(type, "getOriginalFilename")) return SPRING;
      if (type.isInterface() && (name.equals("javax.servlet.http.HttpServletRequest")
          || name.equals("jakarta.servlet.http.HttpServletRequest"))) return SERVLET_REQUEST;
      if (type.isInterface() && name.equals("org.springframework.web.multipart.MultipartRequest")) return SPRING_REQUEST;
      if (type.isInterface() && (name.equals("javax.servlet.Servlet") || name.equals("jakarta.servlet.Servlet"))) return SERVLET;
      int mask = type.getSuperclass() == null ? 0 : get(type.getSuperclass());
      for (Class<?> contract : type.getInterfaces()) mask |= get(contract);
      return mask;
    }
  };

  private static final ThreadLocal<Scope> CURRENT = new ThreadLocal<Scope>();

  private MultipartFilename() {}

  private static boolean hasGetter(Class<?> type, String name) {
    if (!type.isInterface()) return false;
    try {
      java.lang.reflect.Method method = type.getMethod(name);
      return method.getReturnType() == String.class && !java.lang.reflect.Modifier.isStatic(method.getModifiers());
    } catch (NoSuchMethodException absent) {
      return false;
    }
  }

  private static int contracts(Class<?> type) {
    try { return CONTRACTS.get(type); }
    catch (LinkageError | SecurityException unavailable) { return 0; }
  }

  /** On attach a getter may belong to an inherited class that does not itself implement the API. */
  public static Set<Class<?>> loadedOwners(Class<?>[] classes) {
    Set<Class<?>> owners = Collections.newSetFromMap(new IdentityHashMap<Class<?>, Boolean>());
    for (Class<?> type : classes) {
      if (type.isArray() || type.isPrimitive()) continue;
      try {
        if (type.getClassLoader() == null) continue;
      } catch (SecurityException unavailable) {
        continue;
      }
      int mask = contracts(type);
      if ((mask & SERVLET) != 0) {
        // Active servlet classes can contain already-loaded bulk consumers.
        for (Class<?> owner = type; owner != null && owner != Object.class; owner = owner.getSuperclass()) owners.add(owner);
      }
      if ((mask & PART) != 0) addOwner(owners, type, "getSubmittedFileName");
      if ((mask & SPRING) != 0) addOwner(owners, type, "getOriginalFilename");
      if ((mask & SERVLET_REQUEST) != 0) {
        addOwner(owners, type, "getPart", String.class);
        addOwner(owners, type, "getParts");
      }
      if ((mask & SPRING_REQUEST) != 0) {
        addOwner(owners, type, "getFile", String.class);
        addOwner(owners, type, "getFiles", String.class);
      }
    }
    return owners;
  }

  private static void addOwner(Set<Class<?>> owners, Class<?> type, String name, Class<?>... parameters) {
    try { owners.add(type.getMethod(name, parameters).getDeclaringClass()); }
    catch (NoSuchMethodException | LinkageError | SecurityException unavailable) {
      // Earlier Servlet versions have no submitted-name contract.
    }
  }

  public static void wrapped(Object wrapper, Object request) {
    if (request == null || wrapper == request) WRAPPED.remove(wrapper);
    else WRAPPED.put(wrapper, new WeakReference<Object>(request));
  }

  private static boolean wraps(Object wrapper, Object request) {
    WeakReference<Object> parent = WRAPPED.get(wrapper);
    if (parent == null) return false;
    Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
    while (parent != null) {
      Object next = parent.get();
      if (next == request) return true;
      if (next == null || !seen.add(next)) break;
      parent = WRAPPED.get(next);
    }
    return false;
  }

  static boolean source(Object dispatch, Object lookup, int kind) {
    return dispatch != null && (contracts(lookup.getClass()) & kind) != 0
        && (dispatch == lookup || wraps(lookup, dispatch) || wraps(dispatch, lookup));
  }

  static int partKinds(Object value) { return value == null ? 0 : contracts(value.getClass()) & (PART | SPRING); }

  private static final class Scope {
    final Scope parent;
    final Object receiver;
    final int kind;
    Object request;
    String filename, basis, algorithm, policyDigest;
    Scope(Scope parent, Object receiver, int kind) { this.parent = parent; this.receiver = receiver; this.kind = kind; }
  }

  public static void enter(Object receiver, int kind) {
    boolean eligible = kind == KNOWN || (contracts(receiver.getClass()) & kind) != 0;
    Scope parent = CURRENT.get();
    if (eligible || parent != null) CURRENT.set(new Scope(parent, eligible ? receiver : null, kind));
  }

  public static boolean eligible() {
    Scope scope = CURRENT.get();
    return scope != null && scope.receiver != null;
  }

  public static Object receiver() {
    Scope scope = CURRENT.get();
    return scope == null ? null : scope.receiver;
  }

  public static int kind() {
    Scope scope = CURRENT.get();
    return scope == null ? 0 : scope.kind;
  }

  public static void exit() {
    Scope scope = CURRENT.get();
    if (scope == null) return;
    if (scope.parent == null) CURRENT.remove();
    else CURRENT.set(scope.parent);
  }

  /** A delegate and its wrapper may expose the same decision. Each denial still evaluates live. */
  public static boolean repeated(Object request, String filename, String algorithm, String basis, String policyDigest) {
    Scope scope = CURRENT.get();
    if (scope == null || scope.receiver == null) return false;
    boolean repeat = scope.request == request && filename.equals(scope.filename)
        && algorithm.equals(scope.algorithm) && basis.equals(scope.basis) && java.util.Objects.equals(policyDigest, scope.policyDigest);
    Scope parent = scope.parent;
    if (parent != null && parent.receiver == scope.receiver) {
      parent.request = request;
      parent.filename = filename;
      parent.algorithm = algorithm;
      parent.basis = basis;
      parent.policyDigest = policyDigest;
    }
    return repeat;
  }
}
