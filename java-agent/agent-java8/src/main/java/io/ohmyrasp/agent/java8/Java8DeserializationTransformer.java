package io.ohmyrasp.agent.java8;

import io.ohmyrasp.agent.serialization.ObjectStreamResolutionTransformer;

public final class Java8DeserializationTransformer extends ObjectStreamResolutionTransformer {
  public Java8DeserializationTransformer() { super(Java8RaspHooks.class); }
}
