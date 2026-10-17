# Squawk

Squawk (renamed from auth-service 2026-10-16; AWS stack/resource names and the flightdeck slug
`auth-service` deliberately keep the old name, see README "A note on names").

VISION (Nathan, 2026-10-15): auth as a service for all of Nathan's products, "my own Okta":
spin up a service, mint a token for it, and have auth out of the box. Rock solid and ready
for when he sells Flightdeck, AI Therapist and Journal to real customers. Also a résumé
project. Prefer clean, generalizable, secure design over Nathan-specific hacks. Features
that don't serve this get killed.

Read `docs/DESIGN.md` before changing anything; `docs/API.md` is the public reference and
must be updated in the same commit as any endpoint change. Decisions marked DECIDED are Nathan's;
don't invent new ones, log proposals in flightdeck (project slug `auth-service`).

## Stack
- Go (stdlib `net/http` routing, no framework), AWS SAM. Lambdas run `provided.al2023` on arm64.
- Layout: `cmd/api` (Lambda + local listener) · `cmd/worker` (SQS consumer) ·
  `internal/core` (business rules) · `internal/httpapi` (HTTP) · `internal/store`
  (Store interface: DynamoDB + in-memory) · `internal/signer` (Signer: KMS + local ECDSA) ·
  `internal/jwt` (ES256 compact JWS, JWKS) · `internal/owner` (owner passkeys + console sessions,
  go-webauthn) · `internal/oauth` (connector + first-party OAuth 2.1) · `internal/users` (end
  users: per-service WebAuthn, Google provider, email codes) · `internal/mailqueue` (SQS outbox)
  · `internal/ratelimit` · `internal/config`.
- `client/` is a separate, stdlib-only Go module (the SDK consumers import). Keep it
  dependency-free; `make check` and CI run its tests too.
- Infra: `infra/template.yaml` (the whole stack) · `infra/bootstrap/github-oidc.yaml`
  (one-time: OIDC provider + deploy role) · `samconfig.toml` (stack `auth-service-prod`, us-east-1).
- Secrets: none in the repo or in GitHub. The admin token's hash lives in SSM
  `/auth-service/prod/admin-token-hash`; signing keys never leave KMS.

## Verify
`make check` = gofmt, go vet, golangci-lint, `go test -race ./...`. CI runs the same plus the
store suite against DynamoDB Local and `sam validate --lint`. The gate is the floor.
`make dev` runs the API on `localhost:4400` with DynamoDB Local (docker compose) and a
throwaway signing key; `.env.example` has the knobs.

## Deploy
Push to `main` → `.github/workflows/deploy.yml`: the check job, then `sam deploy` via the
GitHub OIDC role (`vars.AWS_DEPLOY_ROLE_ARN`), then a smoke test of `/health` and JWKS.
Never hand-deploy the stack. `make deploy` exists for the first bootstrap only.
Custom domain: repo vars `AUTH_DOMAIN_NAME` + `AUTH_CERTIFICATE_ARN`; empty = execute-api URL.

## Gotchas
- Sign in with Google is off until `vars.AUTH_GOOGLE_CLIENT_ID` is set in the repo AND the
  client secret sits in SSM `/auth-service/prod/google-client-secret` (SecureString). The
  Lambda logs and keeps running without it. Redirect URI to register at Google:
  `https://squawk.nathanblatter.com/v1/login/google/callback`.
- Email codes and verification are off until `AUTH_MAIL_QUEUE_URL` is set (the template sets
  it to `MailQueue`). The Lambda only enqueues; email-api's `sqs-bridge` on the Mac mini
  (repo `~/dev/email-api`, compose service `bridge`) drains the queue with the `MailBridgeUser`
  access key and calls email-api's keyed `/send`. If codes stop arriving, check the bridge
  container and the `auth-service-prod-mail-dlq` alarm before suspecting this repo.
- `/admin/*` accepts a passkey session cookie (1h, `internal/owner`) or the interim bearer
  token (break-glass until auth-service-4; also bootstraps the first passkey). Passkeys bind
  to the issuer host, so they only work on squawk.nathanblatter.com or localhost, never on the
  execute-api URL. Locally `AUTH_ADMIN_TOKEN` is used as-is.
- The console is `internal/httpapi/console.html`, embedded, vanilla JS, strict CSP. No build
  step; keep it that way.
- Revoking a credential stops new token exchanges; already-issued 15-minute service tokens
  stay valid until they expire (stateless JWT). Don't "fix" this with a DB lookup per
  request; shorten the TTL if it ever matters.
- Key rotation is a template edit (add key, reorder `AUTH_SIGNING_KEY_IDS`), see DESIGN.md.
- Every mint/revoke/issue/deny writes an audit row; audit failures log loudly but never fail
  the request.
