# 0002. The country can come from a GeoIP database the operator supplies, read by a built-in reader

## Status

Accepted.

## Context

The two country reasons need the client's country. Version 0.1 took it only from a request
header set by the proxy in front of Keycloak. That works behind edges that add one, but many
deployments have no such edge: a plain load balancer, an ingress controller, a reverse proxy
without a GeoIP module. For them the country reasons were silently off.

The common source of IP-to-country data is a database file in the MaxMind DB format, offered for
free by more than one provider under different licenses (DB-IP Lite under CC BY 4.0, MaxMind
GeoLite2 under an end-user license that requires an account). The extension promises one jar
with no bundled libraries, so it can be dropped into any Keycloak's providers directory without
version conflicts.

Four options were considered. Bundling a database in the jar would tie releases to monthly data
updates, grow the jar by megabytes, and redistribute data under licenses the operator should
accept themselves. Depending on MaxMind's reader library would make operators install a second
jar, and keep it compatible with whatever else their Keycloak loads. Calling a hosted
geolocation API would add a network call to every login, which ADR 0001 rules out. Reading the
format with a small reader written for the extension keeps one jar and no network call, at the
cost of owning that reader.

## Decision

The extension reads an optional GeoIP database file named by
`SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE`, in the MaxMind DB format, with a reader of its own that
implements only what a lookup needs and checks every offset it reads. The operator downloads the
database and keeps it current; the extension ships none. The country header, when present and
usable, still wins over the database. The file is held in memory and reloaded when it changes.
A missing or damaged database never fails a login and never counts as an evaluation error: it
only leaves the country unknown.

## Consequences

Deployments without a country header can turn the country reasons on by mounting one file. The
reader is code the project maintains: it is tested against files built by a test-only writer of
the published format and was checked against a real database, and any format change upstream
would need a change here. Each Keycloak node holds the database in memory, about 10 MB for a
country database. Country accuracy and freshness are those of the database the operator chose.
