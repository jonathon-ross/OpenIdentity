package org.openidentity.oauth;
import java.util.Objects;
public record ValidatedDpopProof(String jkt){public ValidatedDpopProof{Objects.requireNonNull(jkt);if(!jkt.matches("[A-Za-z0-9_-]{43}"))throw new IllegalArgumentException("invalid jkt");}}
