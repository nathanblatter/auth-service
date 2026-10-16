# auth-service design

Status: living document. Decisions marked **DECIDED** came from Nathan (see flightdeck
project `auth-service`). Everything marked *proposed* is the implementer's call and can be
overturned; when it is, update this file and log the why in flightdeck.

## What it is

Auth as a service for every one of Nathan's products: FinForge, Flightdeck, email-api,
AI Therapist, Journal, future apps. A product registers as a **service**, gets a credential,
and has production-grade auth without writing any of it. "My own Okta."

**DECIDED:** headless API at `https://auth.nathanblatter.com`. Products render their own
screens and call the API. The only UI this project ships is a passkey-protected admin
console for minting and managing service credentials.

**DECIDED:** Go, on AWS serverless: API Gateway (HTTP API) → Lambda → DynamoDB, an SQS
queue feeding a worker Lambda, CloudWatch, all in one CloudFormation (SAM) template.
Not the Mac mini: auth for apps that live elsewhere must survive a home outage.

**DECIDED:** end-user login methods are passkeys, Sign in with Google, Sign in with Apple.
No account linking: an account created with Google signs in only with Google.

**DECIDED:** customers of each product are separate pools. Nathan himself has one owner
identity that spans every tenant.

**Rejected (Nathan, 2026-10-15):** billing/entitlements inside auth; a separate AWS
staging environment.

## Vocabulary

| Term | Meaning |
|---|---|
| **Service** | A registered product (FinForge, Flightdeck, ...). It is also the tenant: its users belong to it and to nothing else. |
| **Service credential** | A long-lived secret minted in the admin console for one service. Shown once, stored hashed, listed by service name + last four. The service's backend exchanges it for short-lived service tokens. |
| **Service token** | A 15-minute JWT (`sub = svc:<service_id>`) that a service backend uses to call the auth API. |
| **Owner** | Nathan. Cross-tenant admin identity. Authenticates with a passkey (later: plus a backup passkey and recovery codes). |
| **User** | An end user of one service. Logs in with exactly one method. (Not in slice 1.) |
| **Signing key** | A KMS asymmetric key (ECC P-256) whose private half never leaves KMS. Several may be published at once for rotation. |

## Slice 1 (this is what exists in the repo today)

1. Repo, lint, tests, CI, SAM template, GitHub-OIDC deploy pipeline.
2. Signing: `Signer` interface with a local ECDSA implementation (dev/tests) and a KMS
   implementation (prod). JWKS endpoint. ES256 compact JWS issue + verify, hand-rolled
   (about 150 lines) so the KMS signer plugs in without a custom library signing method.
3. Services and credentials: admin API to create a service, mint a credential, list
   credentials by last four, revoke. Every mint and revoke writes an audit row.
4. `POST /v1/token` with `grant_type=client_credentials` exchanging a service credential
   for a service token. `GET /v1/me` proves the verification path.
5. Local dev: `docker compose up` runs DynamoDB Local; `make dev` runs the API on
   `localhost:4400` with a throwaway in-memory signing key.

**Interim admin auth (*proposed*):** `/admin/*` also accepts
`Authorization: Bearer <admin token>`. Only the SHA-256 of the token is stored, in SSM
Parameter Store at `/auth-service/prod/admin-token-hash`; the Lambda reads it at cold start.
Locally, `AUTH_ADMIN_TOKEN` in `.env` is used directly. It bootstraps the first passkey and
remains as break-glass until auth-service-4; see "Owner and the admin console".

## Owner and the admin console (auth-service-2)

The owner (Nathan) is the one cross-tenant identity. He authenticates to the console with a
**passkey** (WebAuthn, resident key, user verification required), implemented with
`go-webauthn`. The RP ID is the issuer's host, so passkeys only work on
`auth.nathanblatter.com` (or `localhost` in dev); the execute-api URL cannot register them.

- `GET /admin` serves the console: one embedded HTML file, no build step, strict CSP.
- Ceremony state (`webauthn.SessionData`) lives in the table under `CHALLENGE#<id>` for
  5 minutes and is consumed on finish, so a challenge can't be replayed.
- A successful login opens a **1-hour session** (**DECIDED** by Nathan, 2026-10-15): random
  token in an `HttpOnly; Secure; SameSite=Strict; Path=/admin` cookie, SHA-256 stored under
  `SESSION#<hash>`. Sign-in, denial and passkey registration are audited.
- CSRF: a cookie-authenticated write must carry an `Origin` header equal to the issuer.
- Bootstrap: with zero passkeys registered the console asks for the interim admin token and
  uses it to register the first passkey. *Proposed, Nathan did not pick:* the bearer token
  stays valid as break-glass alongside passkeys until auth-service-4 (backup passkey and
  recovery codes) exists, so a lost single passkey cannot lock him out of every service.
- Audit actors are `admin:passkey`, `admin:recovery` or `admin:token`, so the log shows which
  path was used.
- **Recovery (auth-service-4):** any number of passkeys can be registered (a second device is
  the backup). Ten offline **recovery codes** (80-bit, `xxxx-xxxx-xxxx-xxxx`, stored hashed
  under `OWNER#me / RECOVERY#<sha256>`) are generated in the console and shown once; a new set
  replaces the old. `POST /admin/recover` with an unused code opens a 1-hour **recovery
  session** that can manage passkeys but cannot approve connectors. Codes are single use and
  attempts count against the login brute-force limit.

## Permissions: scopes and roles (auth-service-10)

**DECIDED (Nathan, 2026-10-15):** per-service scope catalog, roles as named bundles.

- A service declares `scopes` (its permission catalog, e.g. `read write`) and `roles`
  (`admin = read write`, `viewer = read`) in the console (`PUT /admin/services/{id}/permissions`).
  Roles may only bundle catalog scopes.
- A connector authorization's scope = requested ∩ allowed; empty request = everything allowed.
  Requesting a scope outside the catalog is `invalid_scope`, not a silent trim. For the owner,
  "allowed" is the whole catalog. The approval screen shows the exact grant.
- Service (machine) tokens keep the fixed scope `service`: they identify a backend to this API,
  not a person to a product.
- Roles are stored now and become live in slice 3: each user of a service holds roles, and
  "allowed" for that user is the union of their roles' scopes. Teams (auth-service-15) assign
  roles at the organisation level.
- Enforcement is the consumer's job: `client.RequireScope("write")` / `claims.HasScope`.

## Step-up verification (auth-service-17)

Sessions record `verified_at`, the time of the last passkey assertion (login or step-up).
Sensitive actions (mint a credential, approve a connector, generate recovery codes) require a
**passkey session verified within 5 minutes**; otherwise they answer `401 step_up_required`
and the console re-runs Face ID via `/admin/step-up/begin` + `/finish`, then retries. Recovery
sessions never pass. The break-glass token passes for minting and recovery codes (bootstrap
needs it) but never for connector approval. Everything else (reads, revoke, deny, logout) works
on any live session.

## Log out everywhere (auth-service-11) and the audit log (auth-service-7)

`POST /admin/logout-everywhere` stamps `sessions_not_before = now` on the owner row. Console
sessions created before it fail validation; connector refresh tokens issued before it are
refused at the token endpoint (with an audit row), so every connector must be re-approved.
Already-issued access JWTs run out within the hour. No index or scan is needed: it is one
timestamp compared on use.

`GET /admin/audit?month=YYYY-MM&limit=&cursor=` pages one month of `AUDIT#` rows newest
first; the console has a card for it. Events now cover sign-ins (`owner.login`,
`owner.login_denied`, `recovery.*`), credential and key changes, every OAuth step, and
`owner.logout_everywhere`.

## Connector OAuth (auth-service-23, slice 2)

**DECIDED (Nathan, 2026-10-15):** the OAuth 2.1 authorization server for Claude connectors is
central, in this service; apps only serve `/mcp` and verify JWTs. The approval page is the
admin console, confirmed with the owner passkey. Tokens: 1h access, 30d rotating refresh.

Flow for a connector (Claude on the phone) to reach FinForge:

1. FinForge serves `/.well-known/oauth-protected-resource/mcp` naming this issuer, and
   answers `/mcp` without a token with `WWW-Authenticate: Bearer resource_metadata=…`
   (both come from the Go client).
2. Claude reads `/.well-known/oauth-authorization-server` here, registers itself at
   `POST /oauth/register` (RFC 7591; `nbc_` ids, optional `nbcs_` secret stored hashed),
   then opens `GET /oauth/authorize` with PKCE S256 and `resource=https://finforge…/mcp`
   (RFC 8707, mandatory; it is how the request maps to a **service**, via the resources
   registered on that service in the console).
3. Untrusted `client_id`/`redirect_uri` → hard 400, never a redirect. Other faults bounce to
   the client with an OAuth error. A good request is parked (`AUTHZ#<id>`, 10 min) and the
   browser is sent to `/admin?approve=<id>`.
4. The console shows client, service, resource and scope. **Approve requires a live passkey
   session**; the break-glass token may view and deny, never approve. Approve mints a
   5-minute code (`nbac_`, hashed) and returns the client's redirect URL.
5. `POST /oauth/token` (also reachable as `/v1/token`) exchanges the code: client auth,
   redirect match, PKCE verify. Result: ES256 access JWT (`sub=owner`, `aud=<service id>`,
   `scope`, `client_id`, 1h) plus an opaque refresh token (`nbrt_`, hashed, 30d) that starts
   a **family**.
6. Refresh rotates: the presented token is marked used and a new one issued in the same
   family. Presenting a used token is replay → the whole family is revoked and audited.

Everything is audited (`oauth.client.register`, `oauth.authorize.request`, `oauth.approve`,
`oauth.deny`, `oauth.token`, `oauth.refresh`, `oauth.refresh.reuse`, `oauth.token.denied`).
Registrations and failed exchanges count against the brute-force limiter.

Table rows: `CLIENT#<id>`, `AUTHZ#<id>` (ttl), `CODE#<sha256>` (ttl), `REFRESH#<sha256>`
(GSI1 `FAMILY#<id>`, ttl), `RESOURCE#<url>` lock → service id, and `resources` list on the
service row.

## End users (auth-service-3, slice 3)

**DECIDED (Nathan, 2026-10-15):** passkeys + Sign in with Google now, Apple later. No account
linking: a user has exactly one login method for life. Customers of each product are separate
pools. Each app renders its own screens (headless).

### Shape

A service is **owner-only** (no `login_url`; connectors are approved by Nathan in the console,
slice 2) or a **user pool** (has a `login_url`). A user-pool service is itself a first-party
OAuth client of this server: its web app runs the normal authorization-code + PKCE flow and gets
tokens for the signed-in user. Users belong to exactly one service: `USER#<svc>#<id>`.

### Login flow (Hydra-style: the app owns the screen, we own the ceremony)

1. App → `GET /oauth/authorize` (its own `client_id`, PKCE, `resource` = its resource URL).
2. The service has a `login_url`, so the request is parked and the browser is sent to
   `login_url?login_challenge=<id>`. First-party clients skip consent.
3. The app's login page offers the methods it wants:
   - **Passkey:** app backend (service token) calls `POST /v1/login/passkey/begin`
     `{login_challenge}` → WebAuthn assertion options; browser runs `navigator.credentials.get`;
     backend calls `POST /v1/login/passkey/finish` `{login_challenge, credential}` →
     `{redirect_to}`; the app sends the browser there (its own `redirect_uri` with `code`).
   - **Google:** the page links to `GET /v1/login/google/start?login_challenge=<id>`; we redirect
     to Google, Google calls back `/v1/login/google/callback`, we exchange the code, read
     `userinfo` (sub, email, email_verified, name), find-or-create the user, complete the
     authorization and redirect the browser to the app's `redirect_uri` with `code`.
   - **Sign-up with a passkey:** `POST /v1/users` creates a user (method `passkey`,
     `email`, `name`), then `POST /v1/users/{id}/passkeys/begin` + `/finish` registers the
     credential (service token). Passkey users must register before they can log in.
4. App exchanges the code at `/oauth/token`; refresh as usual.

WebAuthn is bound to the **app's** origin, not ours: each user-pool service declares `rp_id`
(e.g. `finforge.nathanblatter.com`) and `origins` (`https://finforge.nathanblatter.com`), and
a `webauthn.WebAuthn` instance is built per service. Ceremony state lives in `CHALLENGE#` rows
as for the owner.

### Tokens for users

`sub = usr:<id>`, `aud = <service id>`, `scope` = requested ∩ allowed, `client_id`, plus
`email` when known. **Allowed** for a user = the union of the scopes of the user's roles; new
users get the service's `default_roles`. Refresh tokens carry `sub` and honour a per-user
`sessions_not_before` (log out everywhere, auth-service-11, applied per user).

### Rows

| Entity | PK | SK | GSI1PK | GSI1SK |
|---|---|---|---|---|
| User | `USER#<svc>#<id>` | `META` | `USERS#<svc>` | `<created_at>` |
| Identity lock (one method, one identity) | `IDENT#<svc>#google:<sub>` or `IDENT#<svc>#email:<email>` | `META` → user id | | |
| User passkey | `USER#<svc>#<id>` | `PASSKEY#<cred id>` | `UPK#<svc>#<cred id>` | user id |

Service row gains `login_url`, `rp_id`, `origins`, `default_roles`.

### Google

Config: `AUTH_GOOGLE_CLIENT_ID` (template parameter) and the client secret in SSM
`/auth-service/prod/google-client-secret`, read at cold start like the admin token hash.
Nathan creates the OAuth client in Google Cloud Console with redirect URI
`https://auth.nathanblatter.com/v1/login/google/callback`. We request `openid email profile`,
verify `email_verified`, and key the identity on Google's stable `sub`. The state parameter is
the `login_challenge` plus a random nonce stored in the challenge row. Apple follows the same
provider interface when Nathan buys the developer account.

### User management (service token)

`GET /v1/users`, `GET /v1/users/{id}`, `PATCH /v1/users/{id}` (`roles`, `status`),
`POST /v1/users/{id}/logout-everywhere`, `GET /v1/users/{id}/export` and `DELETE /v1/users/{id}`
(auth-service-13). Deletion removes the user row, identity lock and passkeys in one go;
refresh tokens fail at the token endpoint because the subject no longer resolves; access
tokens expire within the hour. The export never includes key material. The product is
responsible for confirming the user's intent (and its own step-up) before calling delete.

## Tokens

*Proposed.* JWT, ES256, header `{"alg":"ES256","kid":"<kms key id>","typ":"at+jwt"}`.

| Claim | Value |
|---|---|
| `iss` | `https://auth.nathanblatter.com` (from `AUTH_ISSUER`) |
| `sub` | `svc:<service_id>` for service tokens; `usr:<user_id>` later |
| `aud` | the service id the token is for; for service tokens, `auth` (the auth API itself) |
| `scope` | space-separated scopes |
| `iat`, `exp`, `jti` | standard |

Lifetimes: service token 15 min. (User access tokens, refresh tokens and sessions are
designed in slice 2 along with the OAuth 2.1 code flow for the Claude connectors.)

Verification by a consumer: fetch `/.well-known/jwks.json`, cache by `kid`, verify
signature, `iss`, `aud`, `exp`. The Go client library (auth-service-12) will wrap this.

## Signing keys and rotation (auth-service-5)

*Proposed.* Keys are `AWS::KMS::Key` resources in the template (`ECC_NIST_P256`,
`SIGN_VERIFY`). `AUTH_SIGNING_KEY_IDS` is a comma-separated list; the **first** key signs,
**all** of them are published in JWKS. Rotation is a template change:

1. Add `SigningKeyB` to the template, set `AUTH_SIGNING_KEY_IDS = B,A`, deploy. New tokens
   are signed by B; A-signed tokens still verify.
2. After the longest token lifetime has passed, drop A from the list and the template
   (KMS schedules deletion with a 30-day window).

Nobody gets logged out. No private key material exists outside KMS. Cost is about
$1 per key per month.

## Storage (DynamoDB single table)

*Proposed.* One table, `PK`/`SK` strings, one GSI (`GSI1PK`/`GSI1SK`), on-demand billing,
point-in-time recovery on (auth-service-9).

| Entity | PK | SK | GSI1PK | GSI1SK | Attributes |
|---|---|---|---|---|---|
| Service | `SERVICE#<id>` | `META` | `SERVICES` | `<slug>` | name, slug, created_at, status |
| Slug lock | `SLUG#<slug>` | `META` | | | service_id (conditional put gives slug uniqueness) |
| Credential | `SERVICE#<id>` | `CRED#<cred_id>` | `CRED#<cred_id>` | `SERVICE#<id>` | hash, last4, created_at, revoked_at |
| Audit event | `AUDIT#<yyyy-mm>` | `<rfc3339 ts>#<rand>` | | | kind, actor, service_id, detail, ip |
| Owner passkey | `OWNER#me` | `PASSKEY#<cred id>` | | | name, created_at, data (webauthn.Credential JSON) |
| WebAuthn challenge | `CHALLENGE#<id>` | `META` | | | data, expires_at, ttl |
| Console session | `SESSION#<sha256>` | `META` | | | created_at, expires_at, ip, ttl |

Credential format: `nbk_<cred_id>_<secret>`. `cred_id` is 12 chars of base32, `secret` is
32 random bytes base64url. The id lets us look up the row directly; the stored value is
SHA-256 of the whole string, compared in constant time. The secret has 256 bits of entropy
so a plain hash (not a slow hash) is appropriate.

Users, sessions, refresh tokens, passkeys, OAuth clients and codes get rows in slice 2.

## Request path

```
client ─▶ API Gateway HTTP API ─▶ Lambda (cmd/api, Go, arm64)
                                    ├─ DynamoDB (table above)
                                    ├─ KMS Sign / GetPublicKey
                                    └─ SQS ─▶ Lambda (cmd/worker): email via email-api, later
```

Inside the Lambda, API Gateway v2 events are adapted to `net/http` so the same handler runs
locally with `make dev`. No framework; `net/http` with Go 1.22+ pattern routing.

## Security notes

- Secrets at rest are SHA-256 hashes; comparison is constant-time.
- API Gateway stage throttling caps raw volume (bill protection). Brute force
  (auth-service-6) is handled by **failure counters** in the table (`RATE#<key>` with a window
  end): 30 failed exchanges per IP per 10 min, 10 failed exchanges per service id per 15 min
  (locks that service's token endpoint), 20 failed passkey ceremonies per IP per 10 min.
  Successes are never throttled. The counter store failing open is deliberate: an outage of
  the table already stops everything else.
- `/admin/*` additionally refuses requests whose token is missing or wrong without revealing
  which. Admin actions are audited.
- Lambda role has least privilege: the table, the signing keys, the queue, the SSM parameter.
- Deploys run from GitHub Actions via an OIDC-assumed role scoped to this repo's `main`
  branch; no long-lived AWS keys anywhere.

## DNS and TLS

`nathanblatter.com` is on Cloudflare, so Route 53 from the reference diagram is not used
(*proposed*: nothing to gain from a second DNS host). An ACM certificate for
`auth.nathanblatter.com` is DNS-validated with a CNAME in Cloudflare, and a second CNAME
points the hostname at the API Gateway custom domain. Cloudflare proxy stays off (grey
cloud) so TLS terminates at API Gateway with the ACM cert.

## Open questions for Nathan

- Sign in with Apple needs the paid Apple Developer account (~$99/yr).
- HIPAA: sign the AWS BAA before AI Therapist logins move here (auth-service-18).
- Admin console behaviours noted as proposed in auth-service-2: show secret once (done in
  slice 1), store hashed (done), revoke (done), rotate (trivial: mint new, revoke old).
