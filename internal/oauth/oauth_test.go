package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/auth-service/internal/core"
	"github.com/nathanblatter/auth-service/internal/signer"
	"github.com/nathanblatter/auth-service/internal/store"
)

func newServer(t *testing.T) (*Server, *store.Memory, store.Service) {
	t.Helper()
	sg, _ := signer.NewLocal("k1")
	ring, _ := signer.NewRing(sg)
	mem := store.NewMemory()
	c := core.New(mem, ring, "https://auth.test")
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	s := New(c)
	svc, err := c.CreateService(context.Background(), "FinForge", "finforge", core.Actor{ID: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.AddServiceResource(context.Background(), svc.ID, "https://finforge.test/mcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetPermissions(context.Background(), svc.ID, []string{"read", "write"}, map[string][]string{"viewer": {"read"}}, core.Actor{ID: "admin"}); err != nil {
		t.Fatal(err)
	}
	svc, _ = c.GetService(context.Background(), svc.ID)
	return s, mem, svc
}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func oauthErr(t *testing.T, err error, code string) {
	t.Helper()
	var oe *Error
	if !errors.As(err, &oe) || oe.Code != code {
		t.Fatalf("want oauth error %q, got %v", code, err)
	}
}

func TestRegister(t *testing.T) {
	s, _, _ := newServer(t)
	ctx := context.Background()
	c, secret, err := s.Register(ctx, RegisterRequest{RedirectURIs: []string{"https://claude.ai/cb"}, ClientName: "Claude"}, "ip")
	if err != nil || !strings.HasPrefix(c.ID, "nbc_") || !strings.HasPrefix(secret, "nbcs_") || c.AuthMethod != "client_secret_basic" {
		t.Fatalf("register: %+v %q %v", c, secret, err)
	}
	pub, secret, err := s.Register(ctx, RegisterRequest{RedirectURIs: []string{"http://localhost:1234/cb"}, TokenEndpointAuthMethod: "none"}, "ip")
	if err != nil || secret != "" || pub.SecretHash != "" {
		t.Fatalf("public client: %+v %q %v", pub, secret, err)
	}
	_, _, err = s.Register(ctx, RegisterRequest{RedirectURIs: []string{"http://evil.test/cb"}}, "ip")
	oauthErr(t, err, "invalid_redirect_uri")
	_, _, err = s.Register(ctx, RegisterRequest{RedirectURIs: []string{"https://a.test/cb"}, GrantTypes: []string{"password"}}, "ip")
	oauthErr(t, err, "invalid_client_metadata")
	_, _, err = s.Register(ctx, RegisterRequest{}, "ip")
	oauthErr(t, err, "invalid_redirect_uri")
}

func TestFullFlow(t *testing.T) {
	s, mem, svc := newServer(t)
	ctx := context.Background()
	c, secret, _ := s.Register(ctx, RegisterRequest{RedirectURIs: []string{"https://claude.ai/cb"}, ClientName: "Claude"}, "ip")
	verifier, challenge := pkce()

	// Untrusted client/redirect: hard error, no redirect.
	_, err := s.BeginAuthorize(ctx, AuthzParams{ClientID: "nope", RedirectURI: "https://claude.ai/cb"}, "ip")
	oauthErr(t, err, "invalid_request")
	_, err = s.BeginAuthorize(ctx, AuthzParams{ClientID: c.ID, RedirectURI: "https://evil.test/cb"}, "ip")
	oauthErr(t, err, "invalid_request")

	// Trusted client, bad params: bounce back with an error.
	base := AuthzParams{ClientID: c.ID, RedirectURI: "https://claude.ai/cb", ResponseType: "code", State: "xyz", Scope: "read",
		Challenge: challenge, Method: "S256", Resource: "https://finforge.test/mcp"}
	for name, mut := range map[string]func(*AuthzParams){
		"plain pkce":   func(p *AuthzParams) { p.Method = "plain" },
		"no resource":  func(p *AuthzParams) { p.Resource = "" },
		"bad resource": func(p *AuthzParams) { p.Resource = "https://nope.test" },
		"token type":   func(p *AuthzParams) { p.ResponseType = "token" },
	} {
		p := base
		mut(&p)
		out, err := s.BeginAuthorize(ctx, p, "ip")
		if err != nil || out.Err == nil || out.RedirectURI != base.RedirectURI || out.State != "xyz" {
			t.Fatalf("%s: %+v %v", name, out, err)
		}
	}

	// No scope requested means the whole catalog; order follows the catalog.
	all := base
	all.Scope = ""
	outAll, err := s.BeginAuthorize(ctx, all, "ip")
	if err != nil {
		t.Fatal(err)
	}
	if pend, _ := s.Pending(ctx, strings.TrimPrefix(outAll.ApproveURL, "https://auth.test/admin?approve=")); pend.Scope != "read write" {
		t.Fatalf("default grant: %q", pend.Scope)
	}

	// Good request parks and points at the console.
	out, err := s.BeginAuthorize(ctx, base, "ip")
	if err != nil || !strings.HasPrefix(out.ApproveURL, "https://auth.test/admin?approve=") {
		t.Fatalf("begin: %+v %v", out, err)
	}
	id := strings.TrimPrefix(out.ApproveURL, "https://auth.test/admin?approve=")
	pend, err := s.Pending(ctx, id)
	if err != nil || pend.ClientName != "Claude" || pend.Service.ID != svc.ID || pend.Scope != "read" {
		t.Fatalf("pending: %+v %v", pend, err)
	}

	// Deny path.
	denyOut, _ := s.BeginAuthorize(ctx, base, "ip")
	denyID := strings.TrimPrefix(denyOut.ApproveURL, "https://auth.test/admin?approve=")
	loc, err := s.Deny(ctx, denyID, "ip")
	if err != nil || !strings.Contains(loc, "error=access_denied") || !strings.Contains(loc, "state=xyz") {
		t.Fatalf("deny: %s %v", loc, err)
	}
	if _, err := s.Deny(ctx, denyID, "ip"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deny twice: %v", err)
	}

	// Approve → code.
	loc, err = s.Approve(ctx, id, "ip")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if !strings.HasPrefix(code, "nbac_") || u.Query().Get("state") != "xyz" || u.Host != "claude.ai" {
		t.Fatalf("approve redirect: %s", loc)
	}
	if _, err := s.Approve(ctx, id, "ip"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("approve twice: %v", err)
	}

	// Exchange: wrong verifier burns the code.
	_, err = s.Token(ctx, TokenRequest{GrantType: "authorization_code", ClientID: c.ID, ClientSecret: secret, Code: code, CodeVerifier: strings.Repeat("x", 43)}, "ip")
	oauthErr(t, err, "invalid_grant")
	_, err = s.Token(ctx, TokenRequest{GrantType: "authorization_code", ClientID: c.ID, ClientSecret: secret, Code: code, CodeVerifier: verifier}, "ip")
	oauthErr(t, err, "invalid_grant")

	// Fresh approval, correct exchange.
	out, _ = s.BeginAuthorize(ctx, base, "ip")
	loc, _ = s.Approve(ctx, strings.TrimPrefix(out.ApproveURL, "https://auth.test/admin?approve="), "ip")
	u, _ = url.Parse(loc)
	code = u.Query().Get("code")
	_, err = s.Token(ctx, TokenRequest{GrantType: "authorization_code", ClientID: c.ID, ClientSecret: "wrong", Code: code, CodeVerifier: verifier}, "ip")
	oauthErr(t, err, "invalid_client")
	tok, err := s.Token(ctx, TokenRequest{GrantType: "authorization_code", ClientID: c.ID, ClientSecret: secret, Code: code, CodeVerifier: verifier, RedirectURI: "https://claude.ai/cb"}, "ip")
	if err != nil || tok.TokenType != "Bearer" || tok.ExpiresIn != 3600 || !strings.HasPrefix(tok.RefreshToken, "nbrt_") || tok.Scope != "read" {
		t.Fatalf("token: %+v %v", tok, err)
	}
	claims, err := s.Core.VerifyToken(tok.AccessToken, svc.ID)
	if err != nil || claims.Subject != OwnerSubject || claims.ClientID != c.ID || claims.Scope != "read" {
		t.Fatalf("access token claims: %+v %v", claims, err)
	}
	// Not valid for the auth API itself.
	if _, _, err := s.Core.VerifyServiceToken(tok.AccessToken); err == nil {
		t.Fatal("connector token accepted as a service token")
	}

	// Refresh rotates; the old one replays → family revoked.
	tok2, err := s.Token(ctx, TokenRequest{GrantType: "refresh_token", ClientID: c.ID, ClientSecret: secret, RefreshToken: tok.RefreshToken}, "ip")
	if err != nil || tok2.RefreshToken == tok.RefreshToken {
		t.Fatalf("refresh: %+v %v", tok2, err)
	}
	_, err = s.Token(ctx, TokenRequest{GrantType: "refresh_token", ClientID: c.ID, ClientSecret: secret, RefreshToken: tok.RefreshToken}, "ip")
	oauthErr(t, err, "invalid_grant")
	_, err = s.Token(ctx, TokenRequest{GrantType: "refresh_token", ClientID: c.ID, ClientSecret: secret, RefreshToken: tok2.RefreshToken}, "ip")
	oauthErr(t, err, "invalid_grant") // family is gone

	// Another client cannot use a refresh token it does not own.
	other, otherSecret, _ := s.Register(ctx, RegisterRequest{RedirectURIs: []string{"https://claude.ai/cb"}}, "ip")
	out, _ = s.BeginAuthorize(ctx, base, "ip")
	loc, _ = s.Approve(ctx, strings.TrimPrefix(out.ApproveURL, "https://auth.test/admin?approve="), "ip")
	u, _ = url.Parse(loc)
	tok3, err := s.Token(ctx, TokenRequest{GrantType: "authorization_code", ClientID: c.ID, ClientSecret: secret, Code: u.Query().Get("code"), CodeVerifier: verifier}, "ip")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Token(ctx, TokenRequest{GrantType: "refresh_token", ClientID: other.ID, ClientSecret: otherSecret, RefreshToken: tok3.RefreshToken}, "ip")
	oauthErr(t, err, "invalid_grant")

	kinds := map[string]int{}
	for _, e := range mem.Audit {
		kinds[e.Kind]++
	}
	if kinds["oauth.approve"] != 3 || kinds["oauth.deny"] != 1 || kinds["oauth.token"] != 2 || kinds["oauth.refresh"] != 1 || kinds["oauth.refresh.reuse"] != 1 {
		t.Fatalf("audit: %v", kinds)
	}
}

func TestVerifyPKCE(t *testing.T) {
	v, c := pkce()
	if !VerifyPKCE(v, c) || VerifyPKCE("short", c) || VerifyPKCE(v, "") || VerifyPKCE(strings.Repeat("w", 43), c) {
		t.Fatal("pkce")
	}
}

func TestLogoutEverywhereKillsRefresh(t *testing.T) {
	s, mem, _ := newServer(t)
	ctx := context.Background()
	c, secret, _ := s.Register(ctx, RegisterRequest{RedirectURIs: []string{"https://claude.ai/cb"}}, "ip")
	verifier, challenge := pkce()
	p := AuthzParams{ClientID: c.ID, RedirectURI: "https://claude.ai/cb", ResponseType: "code", Challenge: challenge, Method: "S256", Resource: "https://finforge.test/mcp"}
	out, _ := s.BeginAuthorize(ctx, p, "ip")
	loc, _ := s.Approve(ctx, strings.TrimPrefix(out.ApproveURL, "https://auth.test/admin?approve="), "ip")
	u, _ := url.Parse(loc)
	tok, err := s.Token(ctx, TokenRequest{GrantType: "authorization_code", ClientID: c.ID, ClientSecret: secret, Code: u.Query().Get("code"), CodeVerifier: verifier}, "ip")
	if err != nil {
		t.Fatal(err)
	}
	// Owner signs out everywhere one second later.
	base := s.Now()
	s.Now = func() time.Time { return base.Add(time.Second) }
	_ = mem.SetOwnerNotBefore(ctx, s.Now())
	s.Now = func() time.Time { return base.Add(2 * time.Second) }
	_, err = s.Token(ctx, TokenRequest{GrantType: "refresh_token", ClientID: c.ID, ClientSecret: secret, RefreshToken: tok.RefreshToken}, "ip")
	oauthErr(t, err, "invalid_grant")
}
