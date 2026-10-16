# auth-service

Auth as a service for Nathan's products. Headless API at `https://auth.nathanblatter.com`:
products register as **services**, get a credential, and exchange it for short-lived signed
tokens. End-user login (passkeys, Google, Apple) and the OAuth 2.1 flows the Claude
connectors need come next; see `docs/DESIGN.md` for the full picture and what is decided.

## Run locally

```sh
make dev            # DynamoDB Local in Docker + the API on http://localhost:4400
make check          # gofmt, vet, lint, tests (what CI runs)
```

Then, with the dev admin token from `.env`:

```sh
AUTH=http://localhost:4400
TOKEN=dev-admin-token

# register a service
curl -s -X POST $AUTH/admin/services -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"FinForge","slug":"finforge"}'

# mint a credential (the "credential" field is shown exactly once)
curl -s -X POST $AUTH/admin/services/<id>/credentials -H "Authorization: Bearer $TOKEN"

# exchange it for a 15-minute service token
curl -s -X POST $AUTH/v1/token -d grant_type=client_credentials \
  -d client_id=<id> -d client_secret=nbk_...

# use the token
curl -s $AUTH/v1/me -H "Authorization: Bearer <access_token>"
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | liveness, version, key count |
| GET | `/.well-known/jwks.json` | none | public signing keys |
| GET | `/.well-known/openid-configuration` | none | discovery |
| POST | `/v1/token` | client credentials | `grant_type=client_credentials` |
| GET | `/v1/me` | service token | who am I |
| POST | `/admin/services` | admin | register a service |
| GET | `/admin/services[/{id}]` | admin | list / fetch |
| POST | `/admin/services/{id}/credentials` | admin | mint (shown once) |
| GET | `/admin/services/{id}/credentials` | admin | list by last four |
| DELETE | `/admin/services/{id}/credentials/{cred}` | admin | revoke |

## Verifying a token in your service

Fetch `/.well-known/jwks.json`, pick the key by the token's `kid`, verify ES256, then check
`iss`, `aud`, `exp`. A Go client library that does this with caching is planned
(flightdeck `auth-service-12`).

## Deploy

Push to `main`. GitHub Actions runs the checks, then `sam deploy` through an OIDC role.
There are no AWS keys in GitHub. First-time account setup is in `infra/bootstrap/`.
