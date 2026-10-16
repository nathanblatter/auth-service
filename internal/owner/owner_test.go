package owner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/auth-service/internal/store"
)

func newOwner(t *testing.T) (*Owner, *store.Memory) {
	t.Helper()
	mem := store.NewMemory()
	o, err := New(mem, "https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	o.Now = func() time.Time { return now }
	return o, mem
}

func TestConfigFromIssuer(t *testing.T) {
	o, _ := newOwner(t)
	if o.WA.Config.RPID != "auth.test" || o.WA.Config.RPOrigins[0] != "https://auth.test" {
		t.Fatalf("rp config: %+v", o.WA.Config)
	}
	if _, err := New(store.NewMemory(), "not a url"); err == nil {
		t.Fatal("bad issuer accepted")
	}
	// Local dev: http on localhost with a port.
	l, err := New(store.NewMemory(), "http://localhost:4400")
	if err != nil || l.WA.Config.RPID != "localhost" || l.WA.Config.RPOrigins[0] != "http://localhost:4400" {
		t.Fatalf("localhost config: %v %+v", err, l.WA.Config)
	}
}

func TestRegistrationOptions(t *testing.T) {
	o, _ := newOwner(t)
	ctx := context.Background()
	opts, chID, err := o.BeginRegistration(ctx)
	if err != nil || chID == "" {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(opts)
	var out struct {
		PublicKey struct {
			RP                     struct{ ID string }
			User                   struct{ ID string }
			AuthenticatorSelection struct {
				ResidentKey      string
				UserVerification string
			}
			Challenge string
		}
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.PublicKey.RP.ID != "auth.test" || out.PublicKey.Challenge == "" || out.PublicKey.User.ID == "" ||
		out.PublicKey.AuthenticatorSelection.ResidentKey != "required" || out.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("creation options: %s", raw)
	}
	// A garbage attestation fails the ceremony and burns the challenge.
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"x"}`))
	if _, err := o.FinishRegistration(ctx, chID, "Phone", req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("garbage attestation: %v", err)
	}
	req = httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"x"}`))
	if _, err := o.FinishRegistration(ctx, chID, "Phone", req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("replayed challenge: %v", err)
	}
}

func TestLoginRequiresPasskeys(t *testing.T) {
	o, mem := newOwner(t)
	ctx := context.Background()
	if _, _, err := o.BeginLogin(ctx); !errors.Is(err, ErrNoPasskeys) {
		t.Fatalf("login with no passkeys: %v", err)
	}
	// Seed a syntactically valid credential so BeginLogin proceeds.
	_ = mem.PutPasskey(ctx, store.Passkey{ID: "abc", Name: "Seed", CreatedAt: o.Now(),
		Data: []byte(`{"id":"YWJj","publicKey":"AAAA","attestationType":"none","flags":{},"authenticator":{}}`)})
	opts, chID, err := o.BeginLogin(ctx)
	if err != nil || chID == "" {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(opts)
	if !strings.Contains(string(raw), `"userVerification":"required"`) || !strings.Contains(string(raw), `"rpId":"auth.test"`) {
		t.Fatalf("assertion options: %s", raw)
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"x"}`))
	if _, _, err := o.FinishLogin(ctx, chID, req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("garbage assertion: %v", err)
	}
	if len(mem.Audit) != 1 || mem.Audit[0].Kind != "owner.login_denied" {
		t.Fatalf("denied login not audited: %+v", mem.Audit)
	}
	keys, err := o.ListPasskeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Data != nil {
		t.Fatalf("ListPasskeys must redact data: %+v %v", keys, err)
	}
}

func TestSessions(t *testing.T) {
	o, mem := newOwner(t)
	ctx := context.Background()
	now := o.Now()
	tok := randomToken()
	_ = mem.PutSession(ctx, store.Session{Hash: hash(tok), CreatedAt: now, ExpiresAt: now.Add(SessionTTL)})
	if _, err := o.ValidateSession(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ValidateSession(ctx, "nope"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("unknown session: %v", err)
	}
	if _, err := o.ValidateSession(ctx, ""); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("empty session: %v", err)
	}
	o.Now = func() time.Time { return now.Add(SessionTTL + time.Second) }
	if _, err := o.ValidateSession(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expired session: %v", err)
	}
	o.Now = func() time.Time { return now }
	if err := o.Logout(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ValidateSession(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session survives logout: %v", err)
	}
}
