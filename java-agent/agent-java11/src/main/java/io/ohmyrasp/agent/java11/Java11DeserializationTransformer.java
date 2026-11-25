package io.ohmyrasp.agent.java11;

import io.ohmyrasp.agent.serialization.ObjectStreamResolutionTransformer;

public final class Java11DeserializationTransformer extends ObjectStreamResolutionTransformer {
  public Java11DeserializationTransformer() { super(Java11RaspHooks.class); }
}
