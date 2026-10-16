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

func TestRecoveryCodes(t *testing.T) {
	o, mem := newOwner(t)
	ctx := context.Background()
	st, err := o.RecoveryStatus(ctx)
	if err != nil || st.Total != 0 {
		t.Fatalf("empty status: %+v %v", st, err)
	}
	codes, err := o.GenerateRecoveryCodes(ctx, "ip")
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("generate: %v %v", codes, err)
	}
	for _, c := range codes {
		if len(c) != 19 || c[4] != '-' || strings.ToLower(c) != c {
			t.Fatalf("code format: %q", c)
		}
	}
	st, _ = o.RecoveryStatus(ctx)
	if st.Total != 10 || st.Remaining != 10 || st.CreatedAt == nil {
		t.Fatalf("status after generate: %+v", st)
	}
	// Typed with different case and spacing still works; once.
	typed := strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))
	tok, _, err := o.RecoverLogin(ctx, typed, "ip")
	if err != nil || tok == "" {
		t.Fatalf("recover: %v", err)
	}
	sess, err := o.ValidateSession(ctx, tok)
	if err != nil || sess.Method != "recovery" {
		t.Fatalf("recovery session: %+v %v", sess, err)
	}
	if _, _, err := o.RecoverLogin(ctx, codes[0], "ip"); !errors.Is(err, ErrRecoveryInvalid) {
		t.Fatalf("code reuse: %v", err)
	}
	if _, _, err := o.RecoverLogin(ctx, "nope", "ip"); !errors.Is(err, ErrRecoveryInvalid) {
		t.Fatalf("garbage code: %v", err)
	}
	st, _ = o.RecoveryStatus(ctx)
	if st.Remaining != 9 {
		t.Fatalf("remaining: %+v", st)
	}
	// A new set invalidates the old one.
	fresh, _ := o.GenerateRecoveryCodes(ctx, "ip")
	if _, _, err := o.RecoverLogin(ctx, codes[1], "ip"); !errors.Is(err, ErrRecoveryInvalid) {
		t.Fatalf("old code after regenerate: %v", err)
	}
	if _, _, err := o.RecoverLogin(ctx, fresh[0], "ip"); err != nil {
		t.Fatalf("fresh code: %v", err)
	}
	kinds := map[string]int{}
	for _, e := range mem.Audit {
		kinds[e.Kind]++
	}
	if kinds["recovery.generate"] != 2 || kinds["recovery.login"] != 2 || kinds["recovery.denied"] != 3 {
		t.Fatalf("audit: %v", kinds)
	}
}

func TestLogoutEverywhere(t *testing.T) {
	o, mem := newOwner(t)
	ctx := context.Background()
	now := o.Now()
	old := randomToken()
	_ = mem.PutSession(ctx, store.Session{Hash: hash(old), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(SessionTTL)})
	if _, err := o.ValidateSession(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := o.LogoutEverywhere(ctx, "ip"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ValidateSession(ctx, old); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("old session survived logout everywhere: %v", err)
	}
	// A session opened afterwards is fine.
	o.Now = func() time.Time { return now.Add(time.Second) }
	fresh, _, err := o.openSession(ctx, "passkey", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ValidateSession(ctx, fresh); err != nil {
		t.Fatalf("new session after logout everywhere: %v", err)
	}
}

func TestFresh(t *testing.T) {
	o, _ := newOwner(t)
	now := o.Now()
	if !o.Fresh(store.Session{Method: "passkey", VerifiedAt: now.Add(-time.Minute)}) {
		t.Fatal("recent passkey assertion should be fresh")
	}
	if o.Fresh(store.Session{Method: "passkey", VerifiedAt: now.Add(-StepUpWindow - time.Second)}) {
		t.Fatal("stale assertion should not be fresh")
	}
	if o.Fresh(store.Session{Method: "recovery", VerifiedAt: now}) {
		t.Fatal("recovery sessions are never fresh")
	}
	if o.Fresh(store.Session{Method: "passkey"}) {
		t.Fatal("never-verified session should not be fresh")
	}
}
