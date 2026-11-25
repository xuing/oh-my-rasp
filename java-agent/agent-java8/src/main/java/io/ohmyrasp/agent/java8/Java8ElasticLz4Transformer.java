package io.ohmyrasp.agent.java8;

import io.ohmyrasp.agent.rules.product.elasticsearch.Lz4TransportVisitor;

public final class Java8ElasticLz4Transformer extends Lz4TransportVisitor.Transformer {
  public Java8ElasticLz4Transformer() { super(Java8RaspHooks.class); }
}
