package io.skycloak.keycloak.adaptiverisk.store;

import io.skycloak.keycloak.adaptiverisk.LoginSignals;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JpaProfileStoreTest {

    private final List<LockModeType> locks = new ArrayList<>();

    /** An entity manager whose profile query records its lock mode and finds no row. */
    private EntityManager entityManager() {
        TypedQuery<?> query = (TypedQuery<?>) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{TypedQuery.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "setLockMode" -> {
                        locks.add((LockModeType) args[0]);
                        yield proxy;
                    }
                    case "getResultList" -> List.of();
                    default -> proxy;
                });
        return (EntityManager) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{EntityManager.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "createNamedQuery" -> {
                        assertEquals(RiskProfileEntity.FIND_BY_USER, args[0]);
                        yield query;
                    }
                    case "persist" -> null;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    @Test
    void recordingASuccessLocksTheProfileRowForTheTransaction() {
        new JpaProfileStore(entityManager()).recordSuccess("realm", "user",
                new LoginSignals("device-hash-a", null, null, 9, 1_780_000_000_000L, null), Duration.ofDays(90));

        assertEquals(List.of(LockModeType.PESSIMISTIC_WRITE), locks);
    }

    @Test
    void loadingAProfileTakesNoLock() {
        new JpaProfileStore(entityManager()).load("realm", "user");

        assertEquals(List.of(LockModeType.NONE), locks);
    }
}
