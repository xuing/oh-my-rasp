package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.serialization.ObjectStreamResolutionTransformer;

public final class Java17DeserializationTransformer extends ObjectStreamResolutionTransformer {
  public Java17DeserializationTransformer() { super(Java17RaspHooks.class); }
}
