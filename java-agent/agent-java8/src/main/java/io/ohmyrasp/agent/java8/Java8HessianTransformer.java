package io.ohmyrasp.agent.java8;

import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor;

public final class Java8HessianTransformer extends HessianAllocationVisitor.Transformer {
  public Java8HessianTransformer() { super(Java8RaspHooks.class); }
}
