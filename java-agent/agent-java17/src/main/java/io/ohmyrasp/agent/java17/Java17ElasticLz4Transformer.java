package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.rules.product.elasticsearch.Lz4TransportVisitor;

public final class Java17ElasticLz4Transformer extends Lz4TransportVisitor.Transformer {
  public Java17ElasticLz4Transformer() { super(Java17RaspHooks.class); }
}
