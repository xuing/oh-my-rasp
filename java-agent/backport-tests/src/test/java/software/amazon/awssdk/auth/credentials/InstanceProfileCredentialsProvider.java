package software.amazon.awssdk.auth.credentials;

import io.ohmyrasp.agent.java8.Java8RaspHooks;
import java.net.URL;

/** A stand-in with the AWS SDK 2.x credential provider's name: its frame is what OutsideRequest.scopeHere reads. */
public final class InstanceProfileCredentialsProvider {
  private InstanceProfileCredentialsProvider() {}

  public static void read(URL metadata) {
    Java8RaspHooks.beforeUrlOpen(metadata);
  }
}
