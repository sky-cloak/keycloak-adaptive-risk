# keycloak-adaptive-risk

Risk-based authentication for Keycloak 26. Each browser login is scored from 0 to 100
against **that user's own login history** (device, network, country, hour, recent failed
attempts), and the score comes with named reasons. A **Condition - risk level** step then
lets your own flow decide what happens: nothing for low risk, OTP or WebAuthn for medium,
Deny access for high.

- Pure Java, one small jar, no bundled libraries, no native code, no external calls.
- Country from your proxy's header or from a GeoIP database file you supply.
- Explainable: every login event carries `risk_score`, `risk_level` and `risk_reasons`.
- Learns only from logins that fully succeeded, so a login stopped at step-up teaches it nothing.
- Fails open: if scoring fails, or the profile table is missing or slow to answer, the login
  continues as low risk and the failure is counted.

Built and maintained by [Skycloak](https://skycloak.io). It works on any Keycloak 26.2 or
later 26.x installation. See [docs/design.md](docs/design.md) for how it works and
[docs/adr](docs/adr) for why it is built this way.

## Install

Download `keycloak-adaptive-risk.jar` from the [latest release](../../releases/latest), copy it
into Keycloak's providers directory, and rebuild or restart Keycloak:

```bash
cp keycloak-adaptive-risk.jar /opt/keycloak/providers/
bin/kc.sh build   # optimized images; start-dev and auto-build do this for you
```

Or in a Dockerfile:

```dockerfile
ADD --chmod=0644 https://github.com/sky-cloak/keycloak-adaptive-risk/releases/download/v0.2.0/keycloak-adaptive-risk.jar /opt/keycloak/providers/keycloak-adaptive-risk.jar
RUN /opt/keycloak/bin/kc.sh build
```

On first start, Keycloak creates the extension's table (`SKYCLOAK_ADAPTIVE_RISK_PROFILE`) through
the extension's own Liquibase changelog. Removing the jar leaves the table in place.

## Environment variables

All three are optional and apply to the whole Keycloak installation.

| Variable | Meaning |
|---|---|
| `SKYCLOAK_ADAPTIVE_RISK_CLIENT_IP_HEADER` | Name of a request header holding the client IP, for example `CF-Connecting-IP` or `X-Real-IP`. When unset, or when a request does not carry the header, Keycloak's own resolved client address is used. |
| `SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER` | Name of a request header holding the ISO country code of the client, for example `CF-IPCountry` or `CloudFront-Viewer-Country`. When unset, or when a request does not carry the header, the GeoIP database below is asked instead. |
| `SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE` | Path to a GeoIP country database in the MaxMind DB format (`.mmdb`), used for the country when no country header gives one. See [Where the country comes from](#where-the-country-comes-from). |

**When is a header safe to trust?** Only when the proxy in front of Keycloak **always sets it
and overwrites whatever the client sent**. Cloudflare's `CF-Connecting-IP` and `CF-IPCountry`
qualify when every request reaches Keycloak through Cloudflare and Keycloak is not reachable
directly. `X-Forwarded-For` usually does not: many proxies append to it, so its leftmost entry
is whatever the client wrote. If you have no such header, leave the IP variable unset and
configure Keycloak's own [proxy settings](https://www.keycloak.org/server/reverseproxy)
(`--proxy-headers`) correctly, because the extension then uses the address Keycloak resolved.

## Where the country comes from

The two country reasons need the client's country. The extension takes it from the first of
these that answers, and skips both reasons when none does:

1. **A country header set by your proxy or CDN** (`SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER`). Most
   edges can add one: Cloudflare sends `CF-IPCountry` when IP Geolocation is on, Amazon CloudFront
   sends `CloudFront-Viewer-Country` when your origin request policy includes it, and nginx with
   the GeoIP2 module can set one with `proxy_set_header X-Country-Code $geoip2_country_code;`.
   The same trust rule as for the IP header applies: the proxy must overwrite any value the
   client sent.
2. **A GeoIP database file** (`SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE`), looked up with the client
   address the extension uses for the network. Any country database in the MaxMind DB format
   works, and city databases up to 128 MB (GeoLite2 City fits; DB-IP City Lite is larger and
   is refused), for example [DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite)
   (free, CC BY 4.0, which requires attribution) or
   [MaxMind GeoLite2 Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
   (free account). The extension ships no database: you download it and keep it current under
   its own license.

```bash
docker run ... \
  -v /srv/geoip:/opt/keycloak/geoip:ro \
  -e SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE=/opt/keycloak/geoip/country.mmdb \
  quay.io/keycloak/keycloak:26.2.5 start ...
```

The file must be readable by the user Keycloak runs as. It is read into memory at startup; after
that the extension checks at most once a minute whether it changed and, if so, reads it again in
the background, so updating it needs no restart. **Update it by writing the new release next to
it and renaming it into place** (`mv country.mmdb.new country.mmdb`), never by overwriting it in
place, and mount the directory rather than the single file: a single-file mount keeps showing the
old file after a rename. A missing or damaged file never fails a login: country lookups are off
(or keep using the last good file) and Keycloak's log says why. Placeholder codes such as `XX`,
`ZZ`, `EU` and `AP` count as unknown.

**Running on Skycloak:** on [Skycloak](https://skycloak.io)'s managed Keycloak, install Adaptive
Risk from the extension marketplace; the client IP and country header settings come pre-filled.

## Recommended browser flow

1. In the admin console, go to **Authentication**, duplicate the built-in **browser** flow,
   and remove its **Conditional OTP** sub-flow (the steps below replace it).
2. In the **forms** sub-flow, after **Username Password Form**, add the step
   **Adaptive Risk - Evaluate (Skycloak)** as **Required**. Open its gear icon to change any
   setting below, or leave it unconfigured to use the defaults.
3. Still in **forms**, add a sub-flow **Deny high risk** as **Conditional**, containing:
   - **Condition - risk level (Skycloak)**, Required, configured with level `high`, match `at-least`
   - **Deny access**, Required
4. Then add a sub-flow **Step up medium risk** as **Conditional**, containing:
   - **Condition - risk level (Skycloak)**, Required, configured with level `medium`, match `exactly`
   - **Condition - user configured**, Required
   - **OTP Form** (or **WebAuthn Authenticator**), Required
5. Bind the new flow as the realm's browser flow.

```
browser (copy)
├── Cookie                                   Alternative
└── forms                                    Alternative
    ├── Username Password Form               Required
    ├── Adaptive Risk - Evaluate (Skycloak)  Required
    ├── Deny high risk                       Conditional
    │   ├── Condition - risk level (high, at-least)     Required
    │   └── Deny access                                  Required
    └── Step up medium risk                  Conditional
        ├── Condition - risk level (medium, exactly)    Required
        ├── Condition - user configured                  Required
        └── OTP Form                                     Required
```

With this flow, a medium-risk user who has no second factor signs in with the password only.
If you prefer, deny those users instead with a third sub-flow.

> **Never let a medium or high risk login enroll a new second factor.** If the step-up
> sub-flow could register a new OTP or passkey (for example an OTP Form without
> **Condition - user configured**, which falls back to the Configure OTP required action), an
> attacker holding a stolen password would simply enroll their own factor and pass. Only ask
> for factors the user already has, and let users enroll new ones from a low-risk session.

Keep the evaluator inside a sub-flow such as **forms**, as above: Keycloak runs the callbacks
the extension learns from only for steps inside a sub-flow.

## Settings of the evaluator (gear icon)

| Field | Default | Meaning |
|---|---|---|
| `medium-threshold` | 30 | Scores at or above this are **medium**. |
| `high-threshold` | 60 | Scores at or above this are **high**. |
| `learning-logins` | 3 | Successful logins a user needs before history reasons fire. |
| `learning-score` | 0 | Score of a login while the user's profile is learning (`recent_failures` is added on top). |
| `weight-new-device` | 30 | Weight of `new_device`. |
| `weight-new-network` | 15 | Weight of `new_network`. |
| `weight-new-country` | 30 | Weight of `new_country`. |
| `weight-rapid-country-change` | 40 | Weight of `rapid_country_change`. |
| `weight-recent-failures` | 25 | Weight of `recent_failures`. |
| `weight-unusual-hour` | 10 | Weight of `unusual_hour`. |
| `failure-count` | 3 | Failed attempts that make `recent_failures` fire. |
| `failure-window-minutes` | 60 | How recent the last failed attempt must be. |
| `rapid-country-change-minutes` | 120 | Window for `rapid_country_change`. |
| `retention-days` | 90 | Profile entries unseen for this long are dropped. |

The score is the sum of the weights of the reasons that fired, capped at 100. A weight of 0
turns a reason off. Scores and thresholds are clamped to 0 to 100.

## Settings of the condition (gear icon)

| Field | Default | Meaning |
|---|---|---|
| `risk-level` | `medium` | `low`, `medium` or `high`. |
| `match` | `at-least` | `at-least` matches this level and above; `exactly` matches only this level. |

The condition does not match, and logs a warning, when no evaluation ran earlier in the flow.

## Reasons

| Code | Fires when |
|---|---|
| `new_device` | The browser has no device cookie, or its device is unknown for this user. |
| `new_network` | The IPv4 /24 or IPv6 /48 has never been seen for this user. |
| `new_country` | The country has never been seen for this user. Needs a country (header or GeoIP database), and a profile that already holds at least one country. |
| `rapid_country_change` | The country differs from the one of the last successful login, and that login was less than 2 hours ago. Needs a country (header or GeoIP database). |
| `recent_failures` | Keycloak's brute force record shows 3 or more failed attempts, the last one within the hour. Needs **brute force detection** on in the realm; skipped otherwise. |
| `unusual_hour` | No past successful login at this UTC hour or the hour on either side. |
| `learning` | The user has fewer successful logins than `learning-logins`. History reasons (all of the above except `recent_failures`) do not fire, and the score is the learning score plus `recent_failures`. |
| `evaluation_error` | Scoring failed, or reading the profile failed or took longer than 2 seconds. The login continues as low risk. |

## Event details

Every evaluated login adds these details to its `LOGIN` event, and to the `LOGIN_ERROR` event
when the login is refused in the step that evaluated it (for example by Deny access):

| Detail | Example | Meaning |
|---|---|---|
| `risk_score` | `45` | 0 to 100. |
| `risk_level` | `medium` | `low`, `medium` or `high`. |
| `risk_reasons` | `new_device,new_network` | Comma-separated reason codes, or `none`. |
| `risk_country` | `CA` | Present only when the country is known, from the header or the GeoIP database. |

No username, email, IP address or device ID is added to events or logs by the extension.
Turn on **Save events** in the realm's event settings to see them under **Events**, or ship
them to your SIEM through an event listener.

## Metric

`skycloak_adaptive_risk_evaluations{level, outcome, realm}` (Micrometer counter, exposed when
Keycloak runs with `--metrics-enabled=true`):

| `outcome` | Meaning |
|---|---|
| `evaluated` | Scored against a learned profile. |
| `learning` | Scored while the profile is learning. |
| `skipped` | No user was identified yet (the evaluator is placed before the user is known). `level` is `none`. |
| `error` | Scoring failed and the login continued as low. |

**Alert on `outcome="error"`**: while it grows, step-up is silently off.

## What the profile stores, and for how long

One row per user per realm, written only when a login fully succeeds:

- the number of successful logins and the time of the last one;
- up to 20 devices, as SHA-256 hashes of the random device cookie, never the cookie itself;
- up to 50 networks, as IPv4 /24 or IPv6 /48 prefixes, never full IP addresses;
- up to 20 countries, and the country of the last login;
- the UTC hours of past logins.

Each list keeps the most recently seen entries and drops entries unseen for `retention-days`
(90 by default) whenever it is written. Deleting a user or a realm deletes its rows.

The device cookie, `SKYCLOAK_ADAPTIVE_RISK_DEVICE`, holds a random ID. It is HttpOnly, Secure
on HTTPS, scoped to the realm path, and lasts one year.

## Limits

- Only browser flows are scored. Logins that run no browser flow (password grant, client
  credentials, token exchange) are not.
- There is no global threat intelligence such as IP reputation: risk is relative to the user's
  own history.
- Users who clear cookies or move between networks are stepped up more often.
- An attacker who passes step-up once teaches the profile their device.
- A `LOGIN_ERROR` raised in a later request than the evaluation (for example a wrong OTP code)
  does not carry the risk details, because Keycloak starts a new event for each request.

## Build

```bash
mvn test                                  # unit tests
mvn verify                                # unit tests, jar, and integration tests (needs Docker)
mvn -Dkeycloak.db=dev-file verify         # integration tests on Keycloak's embedded database instead of PostgreSQL
mvn -Dkeycloak.version=26.7.4 verify      # compile and test against another Keycloak 26.x
mvn -Dkeycloak.url=http://localhost:8080 verify
                                          # integration tests against a Keycloak you started
```

The integration tests boot `quay.io/keycloak/keycloak` with the jar on PostgreSQL through
Testcontainers.
To run them against your own Keycloak instead, start it with the jar installed, admin
`admin`/`admin`, the two header variables set to `X-Test-Client-IP` and `X-Test-Country`, and a
GeoIP database placing `198.51.100.0/24` in `NZ`.

## Release

Push a tag `vX.Y.Z` that matches the version in `pom.xml`. The release workflow builds the jar
and attaches `keycloak-adaptive-risk.jar` to a GitHub release.

## License

Apache 2.0
