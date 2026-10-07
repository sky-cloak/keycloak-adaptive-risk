# Design

How keycloak-adaptive-risk works inside Keycloak. The why is in
[adr/0001](adr/0001-score-login-risk-in-keycloak-from-user-history.md); what admins configure is
in the [README](../README.md).

## Components

| Piece | Class | Role |
|---|---|---|
| Evaluator | `AdaptiveRiskAuthenticator` (`skycloak-adaptive-risk`) | Scores the login, stores the result on the authentication session, adds event details, learns on success. Never challenges. |
| Condition | `RiskLevelCondition` (`skycloak-adaptive-risk-condition`) | Matches the stored level against its configured level, at least or exactly. |
| Scorer | `RiskScorer` | Pure function: settings, profile and login signals in, score, level and reasons out. |
| Profile | `RiskProfile` | One user's bounded history, with recording, aging and eviction. |
| Storage | `RiskProfileEntity`, `JpaProfileStore`, `IsolatedStatement`, `RiskProfileEntityProviderFactory` | Table declaration and Liquibase changelog, savepoint-isolated SQL reads and writes, and cleanup on user and realm removal. |
| Request signals | `TrustedHeaders`, `Networks`, `DeviceCookie` | Client address and country from the trusted headers, network prefix, device cookie. |
| Metric | `RiskMetrics` | `skycloak_adaptive_risk_evaluations{level, outcome, realm}`. |

The scorer and the profile hold no Keycloak types, so all scoring rules are unit tested
directly. Keycloak glue stays in the two authenticators and the store.

## One login, step by step

```
request 1  GET  auth endpoint              -> login form
request 2  POST username/password          -> Username Password Form succeeds
                                           -> Evaluator: read profile, score, store notes,
                                              add event details, success()
                                           -> Condition high?   -> Deny access (LOGIN_ERROR)
                                           -> Condition medium? -> OTP form shown
request 3  POST OTP code (only if shown)   -> OTP succeeds
                                           -> forms sub-flow succeeds:
                                              onParentFlowSuccess re-adds event details
                                           -> top flow succeeds:
                                              onTopFlowSuccess sets cookie, writes profile
                                           -> LOGIN event with the risk details
```

### Evaluation

1. Clear the extension's notes from the authentication session, so a restarted flow never sees
   a stale level.
2. No user yet: count `outcome=skipped`, store nothing, succeed. The condition then does not
   match and logs a warning.
3. Build the login signals:
   - device: the `SKYCLOAK_ADAPTIVE_RISK_DEVICE` cookie when it is well formed (43 base64url
     characters), hashed with SHA-256. Otherwise the device is missing and a new random ID is
     prepared for the cookie.
   - network: the address from the trusted IP header (first entry if it holds a list), else
     Keycloak's resolved address, reduced to IPv4 /24 or IPv6 /48. Only IP literals are
     parsed; nothing is ever resolved through DNS.
   - country: the trusted country header, upper-cased, two characters; Cloudflare's `XX`
     (unknown) is treated as absent.
   - hour: UTC hour of `Time.currentTimeMillis()`.
   - failures: Keycloak's brute force record (`session.loginFailures()`), or none when brute
     force detection is off.
4. Read the profile (one indexed read on `REALM_ID, USER_ID`) and score.
5. Store the result in authentication session notes (`skycloak.adaptive-risk.*`): outcome,
   user ID, score, level, reasons, country, device ID, network prefix, hour. Notes live only
   as long as the authentication session and never leave the server.
6. Add `risk_score`, `risk_level`, `risk_reasons` and `risk_country` to the request's event,
   count the metric, and succeed.

### Scoring

The score is the capped sum of the weights of the reasons that fired:

| Reason | Default weight | Rule |
|---|---|---|
| `new_device` | 30 | Device hash missing or not in the profile. |
| `new_network` | 15 | Network prefix known and not in the profile. |
| `new_country` | 30 | Country known, the profile has countries, and this one is not among them. |
| `rapid_country_change` | 40 | Country known, differs from the last successful login's country, and that login was at most 120 minutes ago. |
| `recent_failures` | 25 | Brute force record has at least 3 failures and the last one is at most 60 minutes old. |
| `unusual_hour` | 10 | No past successful login at this UTC hour or at hour plus or minus one (wrapping at midnight). |

`new_country` needs a country baseline: a profile learned before the country header was set
has no countries, and flagging every user's first country after the header appears would step
up a whole realm at once. `rapid_country_change` can fire for a country the user has visited
before; both country reasons can fire together (70 by default, high).

**Learning.** While the profile has fewer successful logins than `learning-logins` (3), the
history reasons are not evaluated. The reasons are `learning` plus `recent_failures` if it
fired, and the score is `learning-score` (0) plus that weight. Admins who want new users
challenged set a learning score at or above a threshold.

The level is **high** at or above `high-threshold` (60), **medium** at or above
`medium-threshold` (30), otherwise **low**. Weights, thresholds and scores are clamped to 0 to
100, counts and windows to 0 and above, the retention to at least one day. Unparseable values
fall back to their defaults, so an evaluator with no configuration scores with the defaults,
which the unit tests pin.

### Learning, only on full success

The evaluator implements `AuthenticationFlowCallback`, and its factory
`AuthenticationFlowCallbackFactory`. Keycloak calls:

- `onParentFlowSuccess(context)` when the sub-flow holding the evaluator succeeds, in the request
  that finishes the login. It re-adds the event details to that request's event (step-up may
  have happened in a later request than the evaluation) and notes the configured retention.
- `onTopFlowSuccess(topFlow)` when the whole top flow succeeds. It reads the notes, clears
  them, and, when the evaluation outcome was `evaluated` or `learning` and the authenticated
  user is the evaluated user, sets the device cookie and records the login.

A login denied or abandoned at step-up never reaches `onTopFlowSuccess`, so it teaches nothing.
An `error` outcome skipped step-up, so it does not teach either. Keycloak only runs these
callbacks for steps inside a sub-flow, which is why the README places the evaluator in
**forms**.

The cookie is set with `HttpResponse.setCookieIfAbsent`, because Keycloak 26 keeps its own
cookie builder private: random 256-bit ID, HttpOnly, Secure when the base URI is HTTPS,
SameSite=Lax, path `/realms/<realm>/`, max age one year. A browser that already had a valid
cookie gets the same value back, which renews its expiry.

## Storage

Table `SKYCLOAK_ADAPTIVE_RISK_PROFILE`, created by `META-INF/skycloak-adaptive-risk-changelog.xml`
through the `JpaEntityProvider` `skyrisk-profile` (Keycloak tracks it in
`DATABASECHANGELOG_SKYRISK_PR`, named after the first ten letters of that ID):

| Column | Type | Content |
|---|---|---|
| `ID` | VARCHAR(36), primary key | Generated ID. |
| `REALM_ID` | VARCHAR(36) | Realm ID. |
| `USER_ID` | VARCHAR(255) | User ID (255 so federated user IDs fit). |
| `LOGIN_COUNT` | INT | Successful logins recorded. |
| `LAST_LOGIN_AT` | BIGINT | Epoch milliseconds of the last successful login. |
| `HISTORY` | CLOB | JSON: `lastCountry`, and `devices`, `networks`, `countries`, `hours`, each mapping a value to its last-seen epoch milliseconds. |

A unique constraint on `(REALM_ID, USER_ID)` keeps one row per user per realm and is the index
of the per-login read and of realm cleanup. There are no foreign keys, so the table never
blocks Keycloak's own deletes.

Each write refreshes the entries the login touched, drops entries unseen for the retention
(90 days), then evicts the least recently seen entries beyond the caps (20 devices, 50 networks,
20 countries; hours are at most 24). Entries are only aged on write, so a user returning after
a long absence is still compared with their old history once, and the successful login then
replaces it.

**Transactions.** Every statement of the extension is plain SQL that every database Keycloak
supports accepts, run on the request's own connection, in the request's own transaction, isolated
by a JDBC savepoint (`store/IsolatedStatement`). Per-login and per-user statements carry a 2 second
query timeout. On PostgreSQL a failed statement aborts the transaction it runs in; rolling back to
the savepoint undoes only the extension's statement, so a missing, locked or overloaded table
fails the evaluation open (or skips the learning) while the login carries on. Using the request's
connection, rather than a transaction of its own, means the extension never takes a second pooled
connection: under a busy pool a second connection would make every login wait for the pool's
acquisition timeout. Keycloak's connection pool refuses `rollback(Savepoint)` on a connection
enlisted in a transaction, so the savepoint and the statement go to the physical connection under
it (`Connection.unwrap`), which is the one in the transaction; this also holds with XA
transactions enabled. The query timeout is reset before the statement closes, because H2 applies
it to the whole session. If a connection ever allows no savepoint, the statements run unisolated
(as in 0.1.0) and a warning is logged once.

The write runs in the login's transaction, so a login that rolls back teaches nothing. A user's
first login inserts the row. A later login reads the row with a lock (`FOR UPDATE`; a lock hint on
SQL Server), so it merges into the latest version on every isolation level (MySQL and MariaDB
default to repeatable read) and concurrent logins of one user queue, then updates it. A missing
row is never locked: on InnoDB that takes a gap lock, and two concurrent first logins holding gap
locks deadlock on insert. When two first logins race, the losing insert fails on the unique key
inside its savepoint and that login is simply not learned; re-reading after a duplicate key could
deadlock on InnoDB, and one learning login is a small price.

The row lock lasts until the login's transaction commits, a few milliseconds later. If something
later in the same request wrote a row referencing the user while an admin deleted that user, the
two could deadlock and the database would cancel one side; the user being deleted mid-login is
the only way to get there.

If a database ever rolls back the whole transaction instead of the statement (InnoDB does after a
deadlock), the rollback to the savepoint fails. The extension then marks the request's transaction
rollback-only, so the request fails instead of carrying on half undone.

**Cleanup.** The entity provider factory listens for `UserModel.UserRemovedEvent` and
`RealmModel.RealmRemovedEvent` and deletes the matching rows in the removal's transaction, so the
rows go if and only if the user or realm goes. A user's delete has the 2 second timeout; a realm's
deletes every profile of the realm and has none, so a realm with millions of profiles can still be
removed. The price: a realm removal waits on a locked profile table (a long admin transaction, a
table rewrite) until the lock goes or Keycloak's transaction timeout ends it. A missing table means there is nothing to delete and never blocks the removal. Any other
failure, such as the timeout on a locked table, fails the removal cleanly so the admin can retry
it, rather than leaving the profile behind. The table itself stays if the extension is removed.

## Fail open

| Failure | Result |
|---|---|
| Profile read fails or takes longer than 2 seconds, JSON parse or scoring throws | Level low, reasons `evaluation_error`, `outcome=error` metric, warning log naming only the realm (the exception is logged at debug). The login continues. |
| Building the signals throws (for example the brute force store) | Same as above. |
| Adding event details on parent flow success throws | Warning log; the login continues without re-added details. |
| Cookie or profile write throws | Warning log; the login, which already succeeded, is unaffected. |
| Profile table missing on user or realm removal | Warning log; the removal goes ahead. |
| Profile delete fails otherwise (for example a user's delete timing out on a locked table) | The removal fails and can be retried once the table is free; no profile is left behind. |
| Micrometer missing or failing | Ignored. |

Every statement of the extension is isolated by a savepoint, so none of these failures can abort
the transaction of the login or of the removal, including on PostgreSQL.

## Event details and logs

The extension adds exactly four details: `risk_score`, `risk_level`, `risk_reasons` (reason
codes joined by commas, or `none` because Keycloak drops empty details) and `risk_country`
(only when known). Keycloak itself adds the username and IP to events as it always does; the
extension adds no username, email, IP, network prefix or device ID to events, and its logs carry
only the realm name, score, level and reasons.

The details reach every event consumer (the admin console's Events, event listeners, SIEM
exports). A `LOGIN_ERROR` in the evaluating request (Deny access) carries them. A `LOGIN_ERROR`
raised in a later request, such as a wrong OTP code, does not, because Keycloak creates a new
event per request and no extension hook runs before that error.

## Contracts

Changing any of these needs a migration and a deprecation window: the provider IDs
`skycloak-adaptive-risk`, `skycloak-adaptive-risk-condition` and `skyrisk-profile`; the config
keys; the reason codes; the event detail names; the metric name and tags; the table schema; the
cookie name.

## Tests

- Unit (`mvn test`): every reason and its boundary, thresholds, weights, learning, the cap,
  profile caps, eviction order, aging, JSON round trip, settings parsing and defaults, header
  and prefix parsing, the device cookie, the condition, note round trip, event details, fail
  open, and provider registration.
- Integration (`mvn verify`, `*IT`): Testcontainers boots `quay.io/keycloak/keycloak` with the
  jar on PostgreSQL (or on the embedded development database with `-Dkeycloak.db=dev-file`) and
  imports a realm with the README flow, then drives browser logins over HTTP: learning logins
  pass without step-up and set the cookie, a known browser stays low with the details on its
  `LOGIN` event, a fresh browser after learning gets the OTP form and abandoning it teaches
  nothing, passing the OTP form finishes the login with the details on its `LOGIN` event and
  teaches the device, a high learning score is denied with the details on `LOGIN_ERROR`, and
  deleting a user and a realm with profiles succeeds. On PostgreSQL they also check that a
  missing profile table and a locked one both fail open with a redeemable code, that a user can
  still be deleted while the table is missing, and that a locked table fails a deletion quickly
  instead of leaving the profile behind, and that a realm with three million profiles can still be
  deleted. Keycloak runs with a pool of two connections, and two
  concurrent logins must each finish within 3 seconds, which catches any second connection taken
  by the extension; four concurrent first logins of one user must all succeed. CI runs this on Keycloak 26.2.5 and 26.7.4,
  each on both databases.
