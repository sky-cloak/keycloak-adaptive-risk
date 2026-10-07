package io.skycloak.keycloak.adaptiverisk.store;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JpaProfileStoreTest {

    @Test
    void theWriteLocksTheRowItReadsSoItMergesIntoTheLatestVersion() {
        // MySQL and MariaDB default to REPEATABLE READ, where a plain re-read returns the request's
        // snapshot; a locking read returns the committed row.
        assertTrue(JpaProfileStore.lockingSelect("PostgreSQL").endsWith(" FOR UPDATE"));
        assertTrue(JpaProfileStore.lockingSelect("MySQL").endsWith(" FOR UPDATE"));
        assertTrue(JpaProfileStore.lockingSelect("MariaDB").endsWith(" FOR UPDATE"));
        assertTrue(JpaProfileStore.lockingSelect("Oracle").endsWith(" FOR UPDATE"));
        assertTrue(JpaProfileStore.lockingSelect("H2").endsWith(" FOR UPDATE"));
    }

    @Test
    void sqlServerGetsItsOwnLockHintBecauseItHasNoForUpdate() {
        String select = JpaProfileStore.lockingSelect("Microsoft SQL Server");

        assertFalse(select.contains("FOR UPDATE"), select);
        assertTrue(select.contains("WITH (UPDLOCK, ROWLOCK)"), select);
    }
}
