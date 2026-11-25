package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor;

public final class Java17HessianTransformer extends HessianAllocationVisitor.Transformer {
  public Java17HessianTransformer() { super(Java17RaspHooks.class); }
}
