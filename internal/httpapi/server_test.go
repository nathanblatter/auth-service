package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nathanblatter/auth-service/internal/core"
	"github.com/nathanblatter/auth-service/internal/signer"
	"github.com/nathanblatter/auth-service/internal/store"
)

const adminToken = "test-admin-token"

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	s, err := signer.NewLocal("t1")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := signer.NewRing(s)
	if err != nil {
		t.Fatal(err)
	}
	c := core.New(store.NewMemory(), ring, "https://auth.test")
	srv := &Server{Core: c, AdminTokenHash: core.HashSecret(adminToken), Version: "test"}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, method, rawURL, auth, contentType string, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("non-json body (%d): %s", resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, out
}

func TestEndToEnd(t *testing.T) {
	ts := newServer(t)
	admin := "Bearer " + adminToken

	// Public endpoints.
	if code, body := do(t, "GET", ts.URL+"/health", "", "", ""); code != 200 || body["status"] != "ok" {
		t.Fatalf("health: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/.well-known/jwks.json", "", "", ""); code != 200 || len(body["keys"].([]any)) != 1 {
		t.Fatalf("jwks: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/.well-known/openid-configuration", "", "", ""); code != 200 || body["issuer"] != "https://auth.test" {
		t.Fatalf("discovery: %d %v", code, body)
	}

	// Admin gate.
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "", "", ""); code != 401 {
		t.Fatalf("no admin token: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "Bearer wrong", "", ""); code != 401 {
		t.Fatalf("wrong admin token: %d", code)
	}

	// Register a service and mint a credential.
	code, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"FinForge","slug":"finforge"}`)
	if code != 201 {
		t.Fatalf("create service: %d %v", code, svc)
	}
	id := svc["id"].(string)
	if code, body := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Dup","slug":"finforge"}`); code != 409 {
		t.Fatalf("dup slug: %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"X","slug":"ok","extra":1}`); code != 400 {
		t.Fatalf("unknown field: %d %v", code, body)
	}
	code, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	if code != 201 || cred["credential"] == nil {
		t.Fatalf("mint: %d %v", code, cred)
	}
	raw := cred["credential"].(string)
	credID := cred["id"].(string)

	// Listing never includes the raw credential or its hash.
	code, list := do(t, "GET", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	if code != 200 {
		t.Fatalf("list creds: %d", code)
	}
	first := list["credentials"].([]any)[0].(map[string]any)
	if _, leak := first["credential"]; leak {
		t.Fatal("raw credential leaked in list")
	}
	if _, leak := first["hash"]; leak {
		t.Fatal("hash leaked in list")
	}
	if first["last4"] != raw[len(raw)-4:] {
		t.Fatalf("last4 mismatch: %v", first["last4"])
	}

	// Token exchange, form body.
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {raw}}
	code, tok := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	if code != 200 || tok["token_type"] != "Bearer" {
		t.Fatalf("token: %d %v", code, tok)
	}
	access := tok["access_token"].(string)

	// Token exchange, basic auth.
	req, _ := http.NewRequest("POST", ts.URL+"/v1/token", strings.NewReader("grant_type=client_credentials"))
	req.SetBasicAuth(id, raw)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("basic auth token: %v %d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong grant / bad secret.
	if code, body := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", "grant_type=password"); code != 400 || body["error"] != "unsupported_grant_type" {
		t.Fatalf("bad grant: %d %v", code, body)
	}
	form.Set("client_secret", "nbk_bad")
	if code, body := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode()); code != 401 || body["error"] != "invalid_client" {
		t.Fatalf("bad secret: %d %v", code, body)
	}

	// Service token works on /v1/me; admin token does not; garbage does not.
	if code, me := do(t, "GET", ts.URL+"/v1/me", "Bearer "+access, "", ""); code != 200 || me["service_id"] != id {
		t.Fatalf("me: %d %v", code, me)
	}
	if code, _ := do(t, "GET", ts.URL+"/v1/me", admin, "", ""); code != 401 {
		t.Fatalf("admin token on /v1/me: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/v1/me", "Bearer x.y.z", "", ""); code != 401 {
		t.Fatalf("garbage on /v1/me: %d", code)
	}
	// Service token must not open admin.
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "Bearer "+access, "", ""); code != 401 {
		t.Fatalf("service token on admin: %d", code)
	}

	// Revoke, then the credential is dead but the already-issued token is still
	// valid until it expires (documented trade-off of stateless tokens).
	if code, _ := do(t, "DELETE", ts.URL+"/admin/services/"+id+"/credentials/"+credID, admin, "", ""); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	form.Set("client_secret", raw)
	if code, _ := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode()); code != 401 {
		t.Fatalf("revoked credential exchanged: %d", code)
	}
	if code, _ := do(t, "DELETE", ts.URL+"/admin/services/"+id+"/credentials/nope", admin, "", ""); code != 404 {
		t.Fatalf("revoke unknown: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/services/svc_nope", admin, "", ""); code != 404 {
		t.Fatalf("unknown service: %d", code)
	}
}

func TestAdminDisabledWhenNoHash(t *testing.T) {
	s, _ := signer.NewLocal("t1")
	ring, _ := signer.NewRing(s)
	srv := &Server{Core: core.New(store.NewMemory(), ring, "https://auth.test")}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	// Empty hash: even an empty-string token must not match.
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "Bearer ", "", ""); code != 401 {
		t.Fatalf("admin open without hash: %d", code)
	}
}
