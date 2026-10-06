package io.skycloak.keycloak.adaptiverisk.store;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * One row per user per realm. The schema is a contract, created by
 * META-INF/skycloak-adaptive-risk-changelog.xml; change it only through a new changeset.
 */
@Entity(name = "SkycloakAdaptiveRiskProfile")
@Table(name = "SKYCLOAK_ADAPTIVE_RISK_PROFILE")
@NamedQueries({
        @NamedQuery(name = RiskProfileEntity.FIND_BY_USER,
                query = "select p from SkycloakAdaptiveRiskProfile p where p.realmId = :realmId and p.userId = :userId"),
        @NamedQuery(name = RiskProfileEntity.DELETE_BY_USER,
                query = "delete from SkycloakAdaptiveRiskProfile p where p.realmId = :realmId and p.userId = :userId"),
        @NamedQuery(name = RiskProfileEntity.DELETE_BY_REALM,
                query = "delete from SkycloakAdaptiveRiskProfile p where p.realmId = :realmId"),
})
public class RiskProfileEntity {

    static final String FIND_BY_USER = "skycloakAdaptiveRiskFindByUser";
    static final String DELETE_BY_USER = "skycloakAdaptiveRiskDeleteByUser";
    static final String DELETE_BY_REALM = "skycloakAdaptiveRiskDeleteByRealm";

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "USER_ID", length = 255, nullable = false)
    private String userId;

    @Column(name = "LOGIN_COUNT", nullable = false)
    private int loginCount;

    @Column(name = "LAST_LOGIN_AT", nullable = false)
    private long lastLoginAt;

    /** JSON lists of hashed devices, network prefixes, countries and hours, each with its last-seen time. */
    @Column(name = "HISTORY")
    private String history;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public int getLoginCount() {
        return loginCount;
    }

    public void setLoginCount(int loginCount) {
        this.loginCount = loginCount;
    }

    public long getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(long lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public String getHistory() {
        return history;
    }

    public void setHistory(String history) {
        this.history = history;
    }
}
