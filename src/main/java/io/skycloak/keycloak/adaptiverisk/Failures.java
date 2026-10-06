package io.skycloak.keycloak.adaptiverisk;

/** A snapshot of Keycloak's brute force record for a user: how many failures, and when the last one was. */
public record Failures(int count, long lastFailureAt) {
}
