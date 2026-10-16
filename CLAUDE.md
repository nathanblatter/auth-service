# auth-service

VISION (Nathan, 2026-10-15): auth as a service for all of Nathan's products, "my own Okta":
spin up a service, mint a token for it, and have auth out of the box. Rock solid and ready
for when he sells Flightdeck, AI Therapist and Journal to real customers. Also a résumé
project. Prefer clean, generalizable, secure design over Nathan-specific hacks. Features
that don't serve this get killed.

Read `docs/DESIGN.md` before changing anything. Decisions marked DECIDED are Nathan's;
don't invent new ones, log proposals in flightdeck (project slug `auth-service`).

## Stack
- Go (stdlib `net/http` routing, no framework), AWS SAM. Lambdas run `provided.al2023` on arm64.
- Layout: `cmd/api` (Lambda + local listener) · `cmd/worker` (SQS consumer) ·
  `internal/core` (business rules) · `internal/httpapi` (HTTP) · `internal/store`
  (Store interface: DynamoDB + in-memory) · `internal/signer` (Signer: KMS + local ECDSA) ·
  `internal/jwt` (ES256 compact JWS, JWKS) · `internal/config` (AUTH_* env).
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
- `/admin/*` uses an interim bearer token until the owner passkey (auth-service-2) lands.
  Mint: `openssl rand -base64 32`, store `sha256` hex in the SSM param, keep the plain
  value in 1Password. Locally `AUTH_ADMIN_TOKEN` is used as-is.
- Revoking a credential stops new token exchanges; already-issued 15-minute service tokens
  stay valid until they expire (stateless JWT). Don't "fix" this with a DB lookup per
  request; shorten the TTL if it ever matters.
- Key rotation is a template edit (add key, reorder `AUTH_SIGNING_KEY_IDS`), see DESIGN.md.
- Every mint/revoke/issue/deny writes an audit row; audit failures log loudly but never fail
  the request.
