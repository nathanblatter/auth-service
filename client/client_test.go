package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIssuer is a stand-in auth service: it signs tokens with its own keys,
// serves JWKS, and answers /v1/token.
type fakeIssuer struct {
	keys       map[string]*ecdsa.PrivateKey
	published  []string // kids in JWKS
	jwksCalls  atomic.Int32
	tokenCalls atomic.Int32
	srv        *httptest.Server
	now        time.Time
}

func newIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{keys: map[string]*ecdsa.PrivateKey{}, now: time.Unix(1_800_000_000, 0)}
	f.addKey(t, "k1")
	f.published = []string{"k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		f.jwksCalls.Add(1)
		var keys []map[string]string
		for _, kid := range f.published {
			pt, _ := f.keys[kid].PublicKey.Bytes()
			keys = append(keys, map[string]string{"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
				"x": base64.RawURLEncoding.EncodeToString(pt[1:33]), "y": base64.RawURLEncoding.EncodeToString(pt[33:])})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("POST /v1/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)
		_ = r.ParseForm()
		if r.PostForm.Get("client_secret") != "good" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		tok := f.sign(t, "k1", Claims{Issuer: f.srv.URL, Subject: "svc:" + r.PostForm.Get("client_id"), Audience: "auth",
			Scope: "service", IssuedAt: f.now.Unix(), Expires: f.now.Add(15 * time.Minute).Unix()})
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 900})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) addKey(t *testing.T, kid string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.keys[kid] = k
}

func (f *fakeIssuer) sign(t *testing.T, kid string, c Claims) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "at+jwt", "kid": kid})
	body, _ := json.Marshal(c)
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, f.keys[kid], digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIssuer) claims(sub, aud, scope string, ttl time.Duration) Claims {
	return Claims{Issuer: f.srv.URL, Subject: sub, Audience: aud, Scope: scope, IssuedAt: f.now.Unix(), Expires: f.now.Add(ttl).Unix()}
}

func TestVerifier(t *testing.T) {
	f := newIssuer(t)
	v := NewVerifier(f.srv.URL, "svc_me")
	v.now = func() time.Time { return f.now }
	ctx := context.Background()

	tok := f.sign(t, "k1", f.claims("usr:42", "svc_me", "read write", time.Hour))
	c, err := v.Verify(ctx, tok)
	if err != nil || c.Subject != "usr:42" || !c.HasScope("write") || c.HasScope("admin") {
		t.Fatalf("verify: %+v %v", c, err)
	}
	if _, err := v.Verify(ctx, tok); err != nil || f.jwksCalls.Load() != 1 {
		t.Fatalf("jwks must be cached, calls=%d err=%v", f.jwksCalls.Load(), err)
	}

	cases := map[string]struct {
		tok  string
		want error
	}{
		"expired":   {f.sign(t, "k1", f.claims("u", "svc_me", "", -time.Minute)), ErrExpired},
		"audience":  {f.sign(t, "k1", f.claims("u", "svc_other", "", time.Hour)), ErrAudience},
		"issuer":    {f.sign(t, "k1", Claims{Issuer: "https://evil", Subject: "u", Audience: "svc_me", Expires: f.now.Add(time.Hour).Unix()}), ErrIssuer},
		"malformed": {"a.b", ErrMalformed},
		"tampered":  {tok[:len(tok)-2] + "AA", ErrSignature},
	}
	for name, tc := range cases {
		if _, err := v.Verify(ctx, tc.tok); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v want %v", name, err, tc.want)
		}
	}

	// Unknown key not in JWKS: one refresh, then ErrUnknownKey.
	f.addKey(t, "k2")
	if _, err := v.Verify(ctx, f.sign(t, "k2", f.claims("u", "svc_me", "", time.Hour))); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown kid: %v", err)
	}
	// Rotation: publish k2, verifier picks it up on the next unknown kid (rate limit permitting).
	f.published = []string{"k2", "k1"}
	f.now = f.now.Add(2 * time.Minute)
	if _, err := v.Verify(ctx, f.sign(t, "k2", f.claims("u", "svc_me", "", time.Hour))); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	// Old key still works during overlap.
	if _, err := v.Verify(ctx, f.sign(t, "k1", f.claims("u", "svc_me", "", time.Hour))); err != nil {
		t.Fatalf("old key during overlap: %v", err)
	}
}

func TestMiddleware(t *testing.T) {
	f := newIssuer(t)
	v := NewVerifier(f.srv.URL, "svc_me")
	v.now = func() time.Time { return f.now }
	var seen Claims
	h := RequireToken(v)(RequireScope("write")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
		w.WriteHeader(204)
	})))
	call := func(auth string) int {
		req := httptest.NewRequest("GET", "/", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := call(""); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code := call("Bearer junk"); code != 401 {
		t.Fatalf("junk token: %d", code)
	}
	if code := call("Bearer " + f.sign(t, "k1", f.claims("u", "svc_me", "read", time.Hour))); code != 403 {
		t.Fatalf("missing scope: %d", code)
	}
	if code := call("Bearer " + f.sign(t, "k1", f.claims("svc:abc", "svc_me", "read write", time.Hour))); code != 204 {
		t.Fatalf("ok: %d", code)
	}
	if id, ok := seen.ServiceID(); !ok || id != "abc" {
		t.Fatalf("claims in context: %+v", seen)
	}
}

func TestClientCachesTokens(t *testing.T) {
	f := newIssuer(t)
	c := NewClient(f.srv.URL, "svc_me", "good")
	c.now = func() time.Time { return f.now }
	ctx := context.Background()
	t1, err := c.Token(ctx)
	if err != nil || t1 == "" {
		t.Fatal(err)
	}
	t2, _ := c.Token(ctx)
	if t2 != t1 || f.tokenCalls.Load() != 1 {
		t.Fatalf("token not cached: calls=%d", f.tokenCalls.Load())
	}
	// Within 30s of expiry a fresh one is fetched.
	c.now = func() time.Time { return f.now.Add(14*time.Minute + 45*time.Second) }
	if _, err := c.Token(ctx); err != nil || f.tokenCalls.Load() != 2 {
		t.Fatalf("token not refreshed near expiry: calls=%d err=%v", f.tokenCalls.Load(), err)
	}
	req, _ := http.NewRequest("GET", "http://example/", nil)
	if err := c.Authorize(ctx, req); err != nil || req.Header.Get("Authorization") == "" {
		t.Fatalf("authorize: %v", err)
	}

	bad := NewClient(f.srv.URL, "svc_me", "wrong")
	if _, err := bad.Token(ctx); !errors.Is(err, ErrCredential) {
		t.Fatalf("bad credential: %v", err)
	}

	// Round trip: a token from the client verifies with a verifier for "auth".
	v := NewVerifier(f.srv.URL, "auth")
	v.now = func() time.Time { return f.now }
	cl, err := v.Verify(ctx, t1)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := cl.ServiceID(); id != "svc_me" {
		t.Fatalf("round trip claims: %+v", cl)
	}
}

func TestResourceMetadata(t *testing.T) {
	f := newIssuer(t)
	v := NewVerifier(f.srv.URL, "svc_me", WithResource("https://finforge.test/mcp"))
	h := RequireToken(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/mcp", nil))
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") != `Bearer realm="auth", resource_metadata="https://finforge.test/.well-known/oauth-protected-resource/mcp"` {
		t.Fatalf("challenge: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	rec = httptest.NewRecorder()
	ProtectedResourceMetadata(v, "FinForge", []string{"read"}).ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/mcp", nil))
	var md map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &md)
	if md["resource"] != "https://finforge.test/mcp" || md["authorization_servers"].([]any)[0] != f.srv.URL || md["resource_name"] != "FinForge" {
		t.Fatalf("metadata: %v", md)
	}
}
