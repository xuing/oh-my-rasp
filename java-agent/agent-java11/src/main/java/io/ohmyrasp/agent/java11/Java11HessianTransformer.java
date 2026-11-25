package io.ohmyrasp.agent.java11;

import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor;

public final class Java11HessianTransformer extends HessianAllocationVisitor.Transformer {
  public Java11HessianTransformer() { super(Java11RaspHooks.class); }
}
