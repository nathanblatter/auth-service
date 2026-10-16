package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/auth-service/internal/signer"
	"github.com/nathanblatter/auth-service/internal/store"
)

func newCore(t *testing.T) (*Core, *store.Memory) {
	t.Helper()
	s, err := signer.NewLocal("test")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := signer.NewRing(s)
	if err != nil {
		t.Fatal(err)
	}
	mem := store.NewMemory()
	c := New(mem, ring, "https://auth.test")
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	return c, mem
}

func TestServiceLifecycle(t *testing.T) {
	c, mem := newCore(t)
	ctx := context.Background()
	admin := Actor{ID: "admin", IP: "127.0.0.1"}

	if _, err := c.CreateService(ctx, "X", "Bad Slug!", admin); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("bad slug: %v", err)
	}
	if _, err := c.CreateService(ctx, "", "ok", admin); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("bad name: %v", err)
	}
	svc, err := c.CreateService(ctx, "FinForge", "FinForge", admin)
	if err != nil || svc.Slug != "finforge" || !strings.HasPrefix(svc.ID, "svc_") {
		t.Fatalf("create: %+v %v", svc, err)
	}
	if _, err := c.CreateService(ctx, "Again", "finforge", admin); !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("dup slug: %v", err)
	}

	raw, cred, err := c.MintCredential(ctx, svc.ID, admin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "nbk_"+cred.ID+"_") || cred.Hash != HashSecret(raw) || !strings.HasSuffix(raw, cred.Last4) {
		t.Fatalf("credential shape: %s %+v", raw, cred)
	}
	if _, _, err := c.MintCredential(ctx, "svc_missing", admin); !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("mint for missing: %v", err)
	}

	tok, err := c.ExchangeCredential(ctx, svc.ID, raw, "1.2.3.4")
	if err != nil || tok.TokenType != "Bearer" || tok.ExpiresIn != 900 {
		t.Fatalf("exchange: %+v %v", tok, err)
	}
	id, claims, err := c.VerifyServiceToken(tok.AccessToken)
	if err != nil || id != svc.ID || claims.Scope != ScopeService {
		t.Fatalf("verify: %s %+v %v", id, claims, err)
	}

	// Wrong secret, wrong service, garbage: all the same error.
	for name, in := range map[string][2]string{
		"wrong secret":  {svc.ID, raw[:len(raw)-1] + "x"},
		"other service": {"svc_other", raw},
		"garbage":       {svc.ID, "nope"},
		"short":         {svc.ID, "nbk_" + cred.ID + "_short"},
	} {
		if _, err := c.ExchangeCredential(ctx, in[0], in[1], ""); !errors.Is(err, ErrCredentialInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	if err := c.RevokeCredential(ctx, svc.ID, cred.ID, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExchangeCredential(ctx, svc.ID, raw, ""); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("revoked still works: %v", err)
	}
	if err := c.RevokeCredential(ctx, svc.ID, "nope", admin); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("revoke unknown: %v", err)
	}

	// Expired token.
	c.Now = func() time.Time { return time.Date(2026, 10, 15, 13, 0, 0, 0, time.UTC) }
	if _, _, err := c.VerifyServiceToken(tok.AccessToken); err == nil {
		t.Fatal("expired token verified")
	}

	kinds := map[string]int{}
	for _, e := range mem.Audit {
		kinds[e.Kind]++
	}
	if kinds["service.create"] != 1 || kinds["credential.mint"] != 1 || kinds["credential.revoke"] != 1 ||
		kinds["token.issue"] != 1 || kinds["token.denied"] != 5 {
		t.Fatalf("audit trail: %v", kinds)
	}
}

func TestDisabledService(t *testing.T) {
	c, mem := newCore(t)
	ctx := context.Background()
	svc, err := c.CreateService(ctx, "Old", "old", Actor{ID: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := c.MintCredential(ctx, svc.ID, Actor{ID: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	// Flip status directly in the store; there is no admin API for this yet.
	s, _ := mem.GetService(ctx, svc.ID)
	s.Status = "disabled"
	mem2 := store.NewMemory()
	_ = mem2.CreateService(ctx, s)
	creds, _ := mem.ListCredentials(ctx, svc.ID)
	_ = mem2.PutCredential(ctx, creds[0])
	c.Store = mem2
	if _, err := c.ExchangeCredential(ctx, svc.ID, raw, ""); !errors.Is(err, ErrServiceDisabled) {
		t.Fatalf("disabled: %v", err)
	}
}

func TestPermissions(t *testing.T) {
	c, _ := newCore(t)
	ctx := context.Background()
	admin := Actor{ID: "admin"}
	svc, _ := c.CreateService(ctx, "FinForge", "finforge", admin)

	got, err := c.SetPermissions(ctx, svc.ID, []string{"read", " write ", "read"}, map[string][]string{"admin": {"read", "write"}, "viewer": {"read"}}, admin)
	if err != nil || len(got.Scopes) != 2 || len(got.Roles) != 2 || len(got.Roles["admin"]) != 2 {
		t.Fatalf("set: %+v %v", got, err)
	}
	if _, err := c.SetPermissions(ctx, svc.ID, []string{"Bad Scope"}, nil, admin); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("bad scope: %v", err)
	}
	if _, err := c.SetPermissions(ctx, svc.ID, []string{"read"}, map[string][]string{"admin": {"write"}}, admin); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("role outside catalog: %v", err)
	}
	if _, err := c.SetPermissions(ctx, svc.ID, []string{"read"}, map[string][]string{"Admin!": {"read"}}, admin); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("bad role name: %v", err)
	}
	if _, err := c.SetPermissions(ctx, "svc_nope", []string{"read"}, nil, admin); !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("missing service: %v", err)
	}

	cases := []struct {
		req     string
		allowed []string
		want    string
		ok      bool
	}{
		{"", []string{"read", "write"}, "read write", true},
		{"write read", []string{"read", "write"}, "read write", true},
		{"read", []string{"read", "write"}, "read", true},
		{"read admin", []string{"read", "write"}, "", false},
		{"", nil, "", true},
		{"read", nil, "", false},
	}
	for _, tc := range cases {
		got, ok := GrantScope(tc.req, tc.allowed)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("GrantScope(%q, %v) = %q,%v want %q,%v", tc.req, tc.allowed, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSetLogin(t *testing.T) {
	c, _ := newCore(t)
	ctx := context.Background()
	admin := Actor{ID: "admin"}
	svc, _ := c.CreateService(ctx, "FinForge", "finforge", admin)
	_, _ = c.SetPermissions(ctx, svc.ID, []string{"read"}, map[string][]string{"user": {"read"}}, admin)

	got, err := c.SetLogin(ctx, svc.ID, "https://finforge.test/login", "finforge.test", []string{"https://finforge.test/", "https://app.finforge.test"}, []string{"user"}, true, admin)
	if err != nil || got.LoginURL == "" || len(got.Origins) != 2 || got.Origins[0] != "https://finforge.test" || len(got.DefaultRoles) != 1 || !got.OpenSignup {
		t.Fatalf("set login: %+v %v", got, err)
	}
	bad := [][]any{
		{"http://finforge.test/login", "finforge.test", []string{"https://finforge.test"}, []string{}},        // http login url
		{"https://finforge.test/login", "", []string{"https://finforge.test"}, []string{}},                    // no rp id
		{"https://finforge.test/login", "finforge.test", []string{}, []string{}},                              // no origins
		{"https://finforge.test/login", "finforge.test", []string{"https://evil.test"}, []string{}},           // origin not under rp id
		{"https://finforge.test/login", "finforge.test", []string{"https://finforge.test/x"}, []string{}},     // origin with path
		{"https://finforge.test/login", "finforge.test", []string{"https://finforge.test"}, []string{"nope"}}, // unknown role
	}
	for i, b := range bad {
		if _, err := c.SetLogin(ctx, svc.ID, b[0].(string), b[1].(string), b[2].([]string), b[3].([]string), false, admin); !errors.Is(err, ErrInvalidLogin) {
			t.Fatalf("bad case %d: %v", i, err)
		}
	}
	// Back to owner-only; open_signup cannot survive without a user pool.
	got, err = c.SetLogin(ctx, svc.ID, "", "", nil, nil, true, admin)
	if err != nil || got.LoginURL != "" || got.OpenSignup {
		t.Fatalf("clear login: %+v %v", got, err)
	}
}
