# auth-service Go client

Standard library only. `go get github.com/nathanblatter/auth-service/client`

## Protect your endpoints

```go
v := client.NewVerifier("https://auth.nathanblatter.com", "<your service id>")

mux.Handle("GET /api/things", client.RequireToken(v)(handler))
mux.Handle("POST /api/things", client.RequireToken(v)(client.RequireScope("write")(handler)))

func handler(w http.ResponseWriter, r *http.Request) {
    claims, _ := client.FromContext(r.Context())
    // claims.Subject, claims.Scopes(), claims.ServiceID()
}
```

The verifier fetches `/.well-known/jwks.json` once, caches it for 10 minutes, and refreshes
when it sees an unknown `kid`, so key rotation needs no restart. During an issuer outage it
keeps serving cached keys.

## Expose an MCP connector (what Claude's phone app needs)

```go
v := client.NewVerifier("https://auth.nathanblatter.com", serviceID,
    client.WithResource("https://finforge.nathanblatter.com/mcp"))

mux.Handle("GET /.well-known/oauth-protected-resource/mcp", client.ProtectedResourceMetadata(v, "FinForge", []string{"read"}))
mux.Handle("/mcp", client.RequireToken(v)(mcpHandler))
```

Register the same resource URL on the service in the admin console. Claude reads the metadata,
registers itself at the auth service, you approve once with your passkey, and tokens flow.

## Call the auth API (or another service) as your service

```go
c := client.NewClient("https://auth.nathanblatter.com", serviceID, os.Getenv("AUTH_CREDENTIAL"))

req, _ := http.NewRequestWithContext(ctx, "GET", "https://auth.nathanblatter.com/v1/me", nil)
if err := c.Authorize(ctx, req); err != nil { ... }
```

Tokens are cached and replaced 30 seconds before they expire. `ErrCredential` means the
credential was revoked or wrong; nothing retries that for you.
