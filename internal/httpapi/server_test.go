package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/auth-service/internal/core"
	"github.com/nathanblatter/auth-service/internal/owner"
	"github.com/nathanblatter/auth-service/internal/ratelimit"
	"github.com/nathanblatter/auth-service/internal/signer"
	"github.com/nathanblatter/auth-service/internal/store"
)

const adminToken = "test-admin-token"

func newServer(t *testing.T) *httptest.Server {
	ts, _ := newServerWithStore(t, "https://auth.test")
	return ts
}

func newServerWithStore(t *testing.T, issuer string) (*httptest.Server, *store.Memory) {
	t.Helper()
	s, err := signer.NewLocal("t1")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := signer.NewRing(s)
	if err != nil {
		t.Fatal(err)
	}
	mem := store.NewMemory()
	c := core.New(mem, ring, issuer)
	own, err := owner.New(mem, issuer)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Core: c, Owner: own, Limit: ratelimit.New(mem), AdminTokenHash: core.HashSecret(adminToken), Version: "test"}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, mem
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
	mem := store.NewMemory()
	own, _ := owner.New(mem, "https://auth.test")
	srv := &Server{Core: core.New(mem, ring, "https://auth.test"), Owner: own, Limit: ratelimit.New(mem)}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	// Empty hash: even an empty-string token must not match.
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "Bearer ", "", ""); code != 401 {
		t.Fatalf("admin open without hash: %d", code)
	}
}

// doRaw is do() with full control over headers and the raw response.
func doRaw(t *testing.T, method, rawURL string, headers map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestConsoleAndSessions(t *testing.T) {
	ts, mem := newServerWithStore(t, "https://auth.test")
	ctx := context.Background()

	// The page is served with a strict CSP.
	resp := doRaw(t, "GET", ts.URL+"/admin", nil, "")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("console page: %d %v", resp.StatusCode, resp.Header)
	}
	resp.Body.Close()

	// Fresh install: setup required, login refused until a passkey exists.
	if code, body := do(t, "GET", ts.URL+"/admin/session", "", "", ""); code != 200 || body["setup_required"] != true || body["authenticated"] != false {
		t.Fatalf("session (fresh): %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/login/begin", "", "", ""); code != 409 || body["error"] != "setup_required" {
		t.Fatalf("login/begin without passkeys: %d %v", code, body)
	}
	// Registration begin needs admin auth; the bootstrap token works.
	if code, _ := do(t, "POST", ts.URL+"/admin/passkeys/begin", "", "", ""); code != 401 {
		t.Fatalf("passkeys/begin unauthenticated: %d", code)
	}
	code, begin := do(t, "POST", ts.URL+"/admin/passkeys/begin", "Bearer "+adminToken, "", "")
	if code != 200 || begin["challenge_id"] == "" || begin["options"] == nil {
		t.Fatalf("passkeys/begin: %d %v", code, begin)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/passkeys/finish?challenge="+begin["challenge_id"].(string)+"&name=Phone", "Bearer "+adminToken, "application/json", `{"id":"junk"}`); code != 400 || body["error"] != "passkey_rejected" {
		t.Fatalf("passkeys/finish junk: %d %v", code, body)
	}

	// Simulate a completed passkey login by inserting a session directly.
	now := time.Now()
	tok := "session-token-for-tests"
	if err := mem.PutSession(ctx, store.Session{Hash: core.HashSecret(tok), CreatedAt: now, ExpiresAt: now.Add(owner.SessionTTL)}); err != nil {
		t.Fatal(err)
	}
	cookie := map[string]string{"Cookie": sessionCookie + "=" + tok}

	// Cookie authenticates reads.
	resp = doRaw(t, "GET", ts.URL+"/admin/services", cookie, "")
	if resp.StatusCode != 200 {
		t.Fatalf("cookie read: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "GET", ts.URL+"/admin/session", cookie, "")
	var sess map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	if sess["authenticated"] != true || sess["method"] != "passkey" || sess["expires_at"] == nil {
		t.Fatalf("session (cookie): %v", sess)
	}

	// Cookie on a write needs a same-origin Origin header (CSRF).
	body := `{"name":"Svc","slug":"svc"}`
	resp = doRaw(t, "POST", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=" + tok, "Content-Type": "application/json"}, body)
	if resp.StatusCode != 401 {
		t.Fatalf("cookie write without Origin: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "POST", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=" + tok, "Content-Type": "application/json", "Origin": "https://evil.test"}, body)
	if resp.StatusCode != 401 {
		t.Fatalf("cookie write cross-origin: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "POST", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=" + tok, "Content-Type": "application/json", "Origin": "https://auth.test"}, body)
	if resp.StatusCode != 201 {
		t.Fatalf("cookie write same-origin: %d", resp.StatusCode)
	}
	resp.Body.Close()
	// The audit row names the method.
	last := mem.Audit[len(mem.Audit)-1]
	if last.Kind != "service.create" || last.Actor != "admin:passkey" {
		t.Fatalf("audit actor: %+v", last)
	}

	// Bad cookie is rejected; logout kills the session.
	resp = doRaw(t, "GET", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=nope"}, "")
	if resp.StatusCode != 401 {
		t.Fatalf("bad cookie: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "POST", ts.URL+"/admin/logout", cookie, "")
	if resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "GET", ts.URL+"/admin/services", cookie, "")
	if resp.StatusCode != 401 {
		t.Fatalf("session after logout: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCookieFlags(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	resp := doRaw(t, "POST", ts.URL+"/admin/logout", nil, "")
	resp.Body.Close()
	var c *http.Cookie
	for _, k := range resp.Cookies() {
		if k.Name == sessionCookie {
			c = k
		}
	}
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/admin" {
		t.Fatalf("cookie flags: %+v", c)
	}
}

func TestBruteForceLockout(t *testing.T) {
	ts := newServer(t)
	admin := "Bearer " + adminToken
	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Svc","slug":"svc"}`)
	id := svc["id"].(string)
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	raw := cred["credential"].(string)

	bad := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {"nbk_wrong"}}
	for i := 0; i < ratelimit.TokenClient.Limit; i++ {
		if code, _ := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", bad.Encode()); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	// The service is now locked, even for the right secret.
	good := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {raw}}
	resp := doRaw(t, "POST", ts.URL+"/v1/token", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, good.Encode())
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("locked client: %d retry-after=%q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Another service from the same IP still works until the IP limit (30) is reached.
	_, svc2 := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Two","slug":"two"}`)
	_, cred2 := do(t, "POST", ts.URL+"/admin/services/"+svc2["id"].(string)+"/credentials", admin, "", "")
	good2 := url.Values{"grant_type": {"client_credentials"}, "client_id": {svc2["id"].(string)}, "client_secret": {cred2["credential"].(string)}}
	if code, _ := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", good2.Encode()); code != 200 {
		t.Fatalf("other client from same ip: %d", code)
	}

	// Passkey ceremonies lock per IP after 20 failures.
	for i := 0; i < ratelimit.LoginIP.Limit; i++ {
		_, begin := do(t, "POST", ts.URL+"/admin/passkeys/begin", admin, "", "")
		if code, _ := do(t, "POST", ts.URL+"/admin/passkeys/finish?challenge="+begin["challenge_id"].(string), admin, "application/json", `{"id":"junk"}`); code != 400 {
			t.Fatalf("junk attestation %d: %d", i, code)
		}
	}
	if code, body := do(t, "POST", ts.URL+"/admin/login/begin", "", "", ""); code != 429 || body["error"] != "too_many_attempts" {
		t.Fatalf("login after lockout: %d %v", code, body)
	}
}
