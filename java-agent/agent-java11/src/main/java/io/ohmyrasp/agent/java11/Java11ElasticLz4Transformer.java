package io.ohmyrasp.agent.java11;

import io.ohmyrasp.agent.rules.product.elasticsearch.Lz4TransportVisitor;

public final class Java11ElasticLz4Transformer extends Lz4TransportVisitor.Transformer {
  public Java11ElasticLz4Transformer() { super(Java11RaspHooks.class); }
}
