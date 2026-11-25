package com.auth0.jwt.exceptions;

public final class SignatureVerificationException extends RuntimeException {
  public SignatureVerificationException(String message) {
    super(message);
  }
}
