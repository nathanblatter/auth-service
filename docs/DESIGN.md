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

**Interim admin auth (*proposed*, replaced by auth-service-2):** until the owner passkey
exists, `/admin/*` accepts `Authorization: Bearer <admin token>`. Only the SHA-256 of the
token is stored, in SSM Parameter Store at `/auth-service/prod/admin-token-hash`; the Lambda
reads it at cold start. Locally, `AUTH_ADMIN_TOKEN` in `.env` is used directly.

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
- API Gateway stage throttling caps requests (bill protection). Per-IP brute-force limits
  (auth-service-6) need a shared counter; planned as DynamoDB counters with TTL in slice 2.
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
