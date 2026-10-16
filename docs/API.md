# auth-service API reference

Base URL: `https://auth.nathanblatter.com`. All responses are JSON. Times are RFC 3339 UTC.
Every secret is shown exactly once at creation and stored only as a SHA-256 hash.

## Concepts

| Term | What it is |
|---|---|
| **Service** | A registered product (FinForge, Flightdeck, …). Has a `slug`, an `id` (`svc_…`), and zero or more **resources**: the URLs (RFC 8707 resource identifiers, e.g. an MCP endpoint) that connector tokens for this service are issued for. |
| **Service credential** | A long-lived secret (`nbk_<id>_<secret>`) a service's backend holds. Exchanged for **service tokens**. Minted and revoked in the admin console; listed by its last four characters. |
| **Service token** | 15-minute ES256 JWT with `sub=svc:<id>`, `aud=auth`. Authenticates a service to this API. |
| **Connector token** | 1-hour ES256 JWT issued through the OAuth 2.1 flow with `sub=owner`, `aud=<service id>`, plus a 30-day rotating refresh token. What Claude presents to your `/mcp`. |
| **Owner** | Nathan. Signs into the admin console with a passkey. Approves connectors. |

## Authentication models

| Model | Header | Used by |
|---|---|---|
| Service token | `Authorization: Bearer <jwt>` | service backends calling `/v1/*` |
| Connector token | `Authorization: Bearer <jwt>` | Claude (or any OAuth client) calling **your** API, verified by you via JWKS |
| Admin session | cookie `auth_admin_session` (HttpOnly, Secure, SameSite=Strict, `Path=/admin`) | the console. Writes also require `Origin: https://auth.nathanblatter.com` |
| Admin bearer | `Authorization: Bearer <admin token>` | break-glass / bootstrap only |

Admin endpoints marked **fresh** additionally require that the passkey was used in the last
5 minutes; otherwise they return `401 {"error":"step_up_required"}` and the console re-runs
Face ID (`/admin/step-up/*`). Connector approval refuses the admin bearer outright.

## Errors

Admin and `/v1` endpoints: `{"error":"<code>","detail":"<optional>"}`.
OAuth endpoints: RFC 6749 shape `{"error":"<code>","error_description":"<optional>"}`.

| Status | Codes |
|---|---|
| 400 | `invalid_request`, `invalid_client_metadata`, `invalid_redirect_uri`, `unsupported_grant_type`, `invalid_grant`, `invalid_target` |
| 401 | `unauthorized`, `invalid_token`, `invalid_client`, `passkey_required`, `step_up_required`, `passkey_rejected`, `recovery_code_rejected` |
| 403 | `unauthorized_client` (service disabled) |
| 404 | `not_found` |
| 409 | `slug_taken`, `resource_taken`, `setup_required` |
| 429 | `too_many_attempts` with `Retry-After` seconds |
| 500 | `server_error` |

## Brute-force limits

Failures, never successes, are counted. 30 failed token exchanges per IP per 10 min; 10 per
service id per 15 min (locks that service's token endpoint); 20 failed passkey or recovery
attempts per IP per 10 min; 20 client registrations per IP per 10 min. API Gateway also caps
raw volume at 50 requests/s.

---

## Discovery and keys

### `GET /health`
`200 {"status":"ok","version":"<git sha>","keys":1}`

### `GET /.well-known/jwks.json`
Public signing keys. Cache by `kid`. Several keys appear during rotation; all are valid.
```json
{"keys":[{"kty":"EC","crv":"P-256","kid":"6be31935-…","use":"sig","alg":"ES256","x":"…","y":"…"}]}
```

### `GET /.well-known/openid-configuration`
### `GET /.well-known/oauth-authorization-server[/…]`
RFC 8414 metadata: `issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`,
`jwks_uri`, `response_types_supported: ["code"]`, `grant_types_supported`,
`code_challenge_methods_supported: ["S256"]`, `token_endpoint_auth_methods_supported`,
`resource_parameter_supported: true`.

---

## Tokens

### `POST /v1/token` (alias `POST /oauth/token`)
`Content-Type: application/x-www-form-urlencoded`. Client credentials go in the form
(`client_id`, `client_secret`) or in HTTP Basic auth.

**Service token** — `grant_type=client_credentials`
```
client_id=svc_…  client_secret=nbk_…
→ 200 {"access_token":"<jwt>","token_type":"Bearer","expires_in":900,"scope":"service"}
```

**Connector code exchange** — `grant_type=authorization_code`
```
client_id=nbc_…  [client_secret=nbcs_…]  code=nbac_…  code_verifier=<43-128 chars>  [redirect_uri=…]
→ 200 {"access_token":"<jwt>","token_type":"Bearer","expires_in":3600,"refresh_token":"nbrt_…","scope":"…"}
```

**Connector refresh** — `grant_type=refresh_token`
```
client_id=nbc_…  [client_secret=nbcs_…]  refresh_token=nbrt_…
→ 200 same shape, with a NEW refresh_token
```
Refresh tokens rotate on every use. Presenting an already-used one revokes the whole family
(`invalid_grant`). After the owner "signs out everywhere", refresh tokens issued earlier are
refused (`invalid_grant`, "reconnect").

### `GET /v1/me`
Service token required. `200 {"service_id":"svc_…","scope":"service","expires_at":<unix>}`.

### Token format
Header `{"alg":"ES256","typ":"at+jwt","kid":"<key id>"}`. Claims:

| Claim | Service token | Connector token |
|---|---|---|
| `iss` | `https://auth.nathanblatter.com` | same |
| `sub` | `svc:<service id>` | `owner` |
| `aud` | `auth` | `<service id>` |
| `scope` | `service` | requested scopes, space-separated |
| `client_id` | — | `nbc_…` |
| `iat`, `exp`, `jti` | yes | yes |

### Verifying a token (what your service does)
1. Fetch JWKS once; pick the key by `kid`; refresh JWKS when you meet an unknown `kid`.
2. Verify the ES256 signature over `header.payload` (raw `r||s`, 64 bytes).
3. Check `exp > now`, `iss`, and `aud == your service id`.
4. Authorize on `scope`.
The Go client does all of this: `client.NewVerifier(issuer, serviceID)` + `client.RequireToken`.

---

## Connector OAuth 2.1 (how Claude connects to your product)

1. Your product serves `GET /.well-known/oauth-protected-resource/<path>` naming this issuer
   (`client.ProtectedResourceMetadata`), and answers unauthenticated requests with
   `WWW-Authenticate: Bearer resource_metadata="…"`.
2. The client registers: **`POST /oauth/register`** (RFC 7591), JSON body
   `redirect_uris` (1–10, https; http only for localhost), `client_name`,
   `token_endpoint_auth_method` (`none` | `client_secret_post` | `client_secret_basic`, default basic),
   `grant_types` ⊆ {`authorization_code`,`refresh_token`}, `response_types` ⊆ {`code`}.
   `201 {"client_id":"nbc_…","client_secret":"nbcs_…"?,"client_id_issued_at":…,"redirect_uris":[…],"token_endpoint_auth_method":"…","grant_types":[…],"response_types":["code"]}`
3. The client opens **`GET /oauth/authorize`** with
   `response_type=code`, `client_id`, `redirect_uri` (must be registered), `state`,
   `scope`, `code_challenge`, `code_challenge_method=S256`, and **`resource`** (required;
   must equal a resource registered on a service). Unknown client or unregistered redirect →
   `400`, no redirect. Other problems → `302` back to `redirect_uri` with `error`.
   Otherwise `302` to the console, where the owner approves with a passkey.
4. The console redirects the browser to `redirect_uri?code=nbac_…&state=…`
   (or `error=access_denied`). Codes live 5 minutes and are single use.
5. Exchange and refresh at `/oauth/token` as above.

---

## Admin API

All under `/admin`. Auth: admin session cookie or admin bearer. **fresh** = step-up required.

### Console and sessions
| Method | Path | Notes |
|---|---|---|
| GET | `/admin` | the console (HTML) |
| GET | `/admin/session` | `{"authenticated":bool,"method":"passkey\|recovery\|token\|","setup_required":bool,"expires_at"?,"fresh"?}` |
| POST | `/admin/login/begin` | `{"challenge_id","options"}` (WebAuthn assertion options); `409 setup_required` when no passkey exists |
| POST | `/admin/login/finish?challenge=` | body: the browser's credential JSON → sets the cookie, `{"authenticated":true,"method":"passkey","expires_at"}` |
| POST | `/admin/logout` | `204`, clears the cookie |
| POST | `/admin/logout-everywhere` | `204`; kills every session and every connector refresh token |
| POST | `/admin/step-up/begin` / `…/finish?challenge=` | re-verify the current passkey session |

### Passkeys and recovery
| Method | Path | Notes |
|---|---|---|
| GET | `/admin/passkeys` | `{"passkeys":[{"id","name","created_at"}]}` |
| POST | `/admin/passkeys/begin` | `{"challenge_id","options"}` (creation options, resident key + UV required) |
| POST | `/admin/passkeys/finish?challenge=&name=` | body: credential JSON → `201 {"id","name","created_at"}` |
| GET | `/admin/recovery-codes` | `{"total","remaining","created_at"?}` |
| POST | `/admin/recovery-codes` | **fresh**. `201 {"codes":[10 × "xxxx-xxxx-xxxx-xxxx"]}`; replaces the old set |
| POST | `/admin/recover` | no auth. `{"code":"…"}` → sets a **recovery** session cookie (can manage passkeys, cannot mint or approve) |

### Services, credentials, resources
| Method | Path | Notes |
|---|---|---|
| POST | `/admin/services` | `{"name":"FinForge","slug":"finforge"}` → `201 service`. Slug: 2–40 chars `[a-z0-9-]`, unique |
| GET | `/admin/services` | `{"services":[service]}` |
| GET | `/admin/services/{id}` | `service` |
| POST | `/admin/services/{id}/resources` | `{"resource":"https://finforge.nathanblatter.com/mcp"}` → `200 service`. Absolute https URL, unique across services |
| POST | `/admin/services/{id}/credentials` | **fresh**. `201 {"credential":"nbk_…", "id","service_id","last4","created_at","revoked":false}` |
| GET | `/admin/services/{id}/credentials` | `{"credentials":[{"id","service_id","last4","created_at","revoked","revoked_at"?}]}` (never the secret or its hash) |
| DELETE | `/admin/services/{id}/credentials/{cred}` | `204`; idempotent. Already-issued 15-minute service tokens finish their lifetime |

`service` = `{"id","slug","name","status":"active|disabled","created_at","resources":[…]}`.

### Connector approvals
| Method | Path | Notes |
|---|---|---|
| GET | `/admin/authorize/{id}` | `{"id","client_name","client_id","scope","resource","service":service,"expires_at"}`; `404` once answered or after 10 min |
| POST | `/admin/authorize/{id}/approve` | **fresh passkey only** (bearer refused). `{"redirect_to":"https://…?code=…&state=…"}` |
| POST | `/admin/authorize/{id}/deny` | `{"redirect_to":"https://…?error=access_denied&state=…"}` |

### Audit log
| Method | Path | Notes |
|---|---|---|
| GET | `/admin/audit?month=YYYY-MM&limit=50&cursor=` | `{"month","events":[{"at","kind","actor","service_id","detail","ip"}],"next"}` newest first; pass `next` back as `cursor` |

Event kinds: `service.create`, `service.resource.add`, `credential.mint`, `credential.revoke`,
`token.issue`, `token.denied`, `passkey.register`, `owner.login`, `owner.login_denied`,
`owner.stepup`, `owner.stepup_denied`, `owner.logout_everywhere`, `recovery.generate`,
`recovery.login`, `recovery.denied`, `oauth.client.register`, `oauth.authorize.request`,
`oauth.approve`, `oauth.deny`, `oauth.token`, `oauth.token.denied`, `oauth.refresh`,
`oauth.refresh.reuse`, `oauth.refresh.denied`.

---

## Quick start for a new product

```sh
AUTH=https://auth.nathanblatter.com
# 1. In the console: create the service, add its resource URL, mint a credential.
# 2. Backend: exchange the credential when you need to call the auth API.
curl -s -X POST $AUTH/v1/token -d grant_type=client_credentials -d client_id=svc_… -d client_secret=nbk_…
# 3. Protect your endpoints with the Go client (verifies connector tokens via JWKS):
#    v := client.NewVerifier(AUTH, "svc_…", client.WithResource("https://you/mcp"))
#    mux.Handle("/mcp", client.RequireToken(v)(h))
```
