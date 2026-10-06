package io.skycloak.keycloak.adaptiverisk;

import io.skycloak.keycloak.adaptiverisk.store.JpaProfileStore;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowCallback;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.function.Function;

/**
 * 'Adaptive Risk - Evaluate (Skycloak)'. Never challenges the user: it scores the login, stores
 * the level in the authentication session for 'Condition - risk level', and succeeds.
 *
 * <p>Learning happens only in {@link #onTopFlowSuccess}, so a login denied or abandoned at
 * step-up teaches the profile nothing. Both the evaluation and the learning fail open.
 */
public class AdaptiveRiskAuthenticator implements AuthenticationFlowCallback {

    static final String NOTE_RETENTION_DAYS = Evaluation.NOTE_PREFIX + "retention-days";

    private static final Logger log = Logger.getLogger(AdaptiveRiskAuthenticator.class);

    private final KeycloakSession session;
    private final TrustedHeaders headers;

    public AdaptiveRiskAuthenticator(KeycloakSession session, TrustedHeaders headers) {
        this.session = session;
        this.headers = headers;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        Evaluation.ALL_NOTES.forEach(authSession::removeAuthNote);
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        if (user == null) {
            // Nothing to compare with. The condition will not match and says so.
            RiskMetrics.count(Evaluation.Outcome.SKIPPED, null, realm.getName());
            log.debugf("Adaptive risk skipped: no user identified yet (realm=%s)", realm.getName());
            context.success();
            return;
        }

        Evaluation evaluation;
        try {
            evaluation = evaluate(context, realm, user);
        } catch (RuntimeException e) {
            logFailure(realm, e);
            evaluation = new Evaluation(Evaluation.Outcome.ERROR, user.getId(), Assessment.evaluationError(),
                    null, null, null, 0);
        }

        evaluation.notes().forEach(authSession::setAuthNote);
        evaluation.eventDetails().forEach(context.getEvent()::detail);
        RiskMetrics.count(evaluation.outcome(), evaluation.assessment().level(), realm.getName());
        log.debugf("Adaptive risk %s: score=%d level=%s reasons=%s (realm=%s)", evaluation.outcome().code(),
                evaluation.assessment().score(), evaluation.assessment().level().code(),
                evaluation.assessment().reasonCodes(), realm.getName());
        context.success();
    }

    private Evaluation evaluate(AuthenticationFlowContext context, RealmModel realm, UserModel user) {
        long now = Time.currentTimeMillis();
        int hour = Instant.ofEpochMilli(now).atOffset(ZoneOffset.UTC).getHour();
        RiskSettings settings = RiskSettings.fromConfig(config(context.getAuthenticatorConfig()));

        HttpHeaders http = context.getHttpRequest().getHttpHeaders();
        Function<String, String> header = http::getHeaderString;
        Cookie cookie = http.getCookies().get(DeviceCookie.NAME);
        String presented = cookie == null ? null : cookie.getValue();
        boolean hasDevice = DeviceCookie.isValid(presented);
        String deviceId = hasDevice ? presented : DeviceCookie.newId();

        String network = Networks.prefix(headers.clientAddress(header, context.getConnection().getRemoteAddr()));
        String country = headers.country(header);
        LoginSignals signals = new LoginSignals(hasDevice ? DeviceCookie.hash(deviceId) : null, network, country,
                hour, now, failures(realm, user));

        Assessment assessment = Evaluation.assess(settings,
                () -> JpaProfileStore.of(session).load(realm.getId(), user.getId()),
                () -> signals);
        if (assessment.failed()) {
            log.warnf("Adaptive risk evaluation failed open to low: the profile could not be read (realm=%s)",
                    realm.getName());
        }
        return new Evaluation(Evaluation.outcomeOf(assessment), user.getId(), assessment, country, deviceId,
                network, hour);
    }

    /** Keycloak writes failure records only when brute force detection is on; null means skip the reason. */
    private Failures failures(RealmModel realm, UserModel user) {
        if (!realm.isBruteForceProtected()) {
            return null;
        }
        UserLoginFailureModel record = session.loginFailures().getUserLoginFailure(realm, user.getId());
        return record == null ? new Failures(0, 0L) : new Failures(record.getNumFailures(), record.getLastFailure());
    }

    /**
     * Called when the sub-flow holding the evaluator succeeds, in the request that finishes the login.
     * Step-up may have happened in a later request than the evaluation, so the details are attached
     * again to this request's event, and the retention is kept for {@link #onTopFlowSuccess}.
     */
    @Override
    public void onParentFlowSuccess(AuthenticationFlowContext context) {
        try {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            Evaluation evaluation = Evaluation.fromNotes(authSession::getAuthNote);
            if (evaluation == null) {
                return;
            }
            evaluation.eventDetails().forEach(context.getEvent()::detail);
            RiskSettings settings = RiskSettings.fromConfig(config(context.getAuthenticatorConfig()));
            authSession.setAuthNote(NOTE_RETENTION_DAYS, Long.toString(settings.retention().toDays()));
        } catch (Throwable t) {
            log.warnf("Adaptive risk could not annotate the login event: %s", t.getClass().getName());
        }
    }

    /** The whole flow succeeded: learn this login and set the device cookie. Never fails the login. */
    @Override
    public void onTopFlowSuccess(AuthenticationFlowModel topFlow) {
        try {
            AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
            if (authSession == null) {
                return;
            }
            Evaluation evaluation = Evaluation.fromNotes(authSession::getAuthNote);
            Duration retention = retention(authSession.getAuthNote(NOTE_RETENTION_DAYS));
            Evaluation.ALL_NOTES.forEach(authSession::removeAuthNote);
            authSession.removeAuthNote(NOTE_RETENTION_DAYS);

            UserModel user = authSession.getAuthenticatedUser();
            if (evaluation == null || !evaluation.outcome().learns() || evaluation.deviceId() == null
                    || user == null || !user.getId().equals(evaluation.userId())) {
                return;
            }
            RealmModel realm = authSession.getRealm();
            setDeviceCookie(realm, evaluation.deviceId());

            LoginSignals login = new LoginSignals(DeviceCookie.hash(evaluation.deviceId()), evaluation.network(),
                    evaluation.country(), evaluation.hourUtc(), Time.currentTimeMillis(), null);
            String realmId = realm.getId();
            String userId = user.getId();
            // Own transaction: a failed write (for example two first logins racing on the unique key)
            // must not roll back the login itself.
            KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(),
                    s -> JpaProfileStore.of(s).recordSuccess(realmId, userId, login, retention));
        } catch (Throwable t) {
            log.warnf("Adaptive risk could not record a successful login; the login is unaffected: %s",
                    t.getClass().getName());
        }
    }

    private void setDeviceCookie(RealmModel realm, String deviceId) {
        var uri = session.getContext().getUri();
        String realmPath = RealmsResource.realmBaseUrl(uri).build(realm.getName()).getRawPath() + "/";
        boolean secure = "https".equalsIgnoreCase(uri.getBaseUri().getScheme());
        session.getContext().getHttpResponse().setCookieIfAbsent(DeviceCookie.build(deviceId, realmPath, secure));
    }

    private static Duration retention(String days) {
        try {
            return Duration.ofDays(Math.max(1, Long.parseLong(days)));
        } catch (RuntimeException e) {
            return Duration.ofDays(RiskSettings.DEFAULT_RETENTION_DAYS);
        }
    }

    private static Map<String, String> config(AuthenticatorConfigModel model) {
        return model == null ? null : model.getConfig();
    }

    private static void logFailure(RealmModel realm, RuntimeException e) {
        log.warnf("Adaptive risk evaluation failed open to low: %s (realm=%s)", e.getClass().getName(), realm.getName());
        log.debug("Adaptive risk evaluation failure", e);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Never challenges, so no action.
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions.
    }

    @Override
    public void close() {
        // Stateless.
    }
}
