package users

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/auth-service/internal/store"
)

func newUsers(t *testing.T) (*Users, *store.Memory, store.Service) {
	t.Helper()
	mem := store.NewMemory()
	u := New(mem)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	u.Now = func() time.Time { return now }
	ctx := context.Background()
	svc := store.Service{ID: "svc_a", Slug: "finforge", Name: "FinForge", Status: "active", CreatedAt: now}
	if err := mem.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	_ = mem.UpdateServicePermissions(ctx, svc.ID, []string{"read", "write", "admin"}, map[string][]string{"user": {"read"}, "editor": {"read", "write"}, "owner": {"admin", "read", "write"}})
	_ = mem.UpdateServiceLogin(ctx, svc.ID, "https://finforge.test/login", "finforge.test", []string{"https://finforge.test"}, []string{"user"})
	svc, _ = mem.GetService(ctx, svc.ID)
	return u, mem, svc
}

func TestCreateAndManage(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()

	ownerOnly := store.Service{ID: "svc_o", Slug: "o", Name: "O", Status: "active", CreatedAt: u.Now()}
	_ = mem.CreateService(ctx, ownerOnly)
	if _, err := u.Create(ctx, ownerOnly, "a@x.test", "A"); !errors.Is(err, ErrNotUserPool) {
		t.Fatalf("owner-only service: %v", err)
	}
	if _, err := u.Create(ctx, svc, "not an email", "A"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("bad email: %v", err)
	}
	user, err := u.Create(ctx, svc, " Alice@X.test ", "Alice")
	if err != nil || user.Email != "alice@x.test" || user.Method != MethodPasskey || !strings.HasPrefix(user.ID, "usr_") || len(user.Roles) != 1 {
		t.Fatalf("create: %+v %v", user, err)
	}
	if _, err := u.Create(ctx, svc, "alice@x.test", "Again"); !errors.Is(err, ErrIdentityTaken) {
		t.Fatalf("dup email: %v", err)
	}
	if _, err := u.Get(ctx, svc.ID, "nope"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user: %v", err)
	}

	// Allowed scopes follow roles, in catalog order.
	if got := strings.Join(AllowedScopes(svc, user), " "); got != "read" {
		t.Fatalf("default allowed: %q", got)
	}
	roles := []string{"owner", "user"}
	upd, err := u.Update(ctx, svc, user.ID, &roles, nil, nil)
	if err != nil || len(upd.Roles) != 2 {
		t.Fatalf("update roles: %+v %v", upd, err)
	}
	if got := strings.Join(AllowedScopes(svc, upd), " "); got != "read write admin" {
		t.Fatalf("allowed after roles: %q", got)
	}
	bad := []string{"nope"}
	if _, err := u.Update(ctx, svc, user.ID, &bad, nil, nil); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("unknown role: %v", err)
	}
	disabled := "disabled"
	if upd, err := u.Update(ctx, svc, user.ID, nil, &disabled, nil); err != nil || upd.Status != "disabled" {
		t.Fatalf("disable: %+v %v", upd, err)
	}
	if err := u.LogoutEverywhere(ctx, svc.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := u.Get(ctx, svc.ID, user.ID); !got.NotBefore.Equal(u.Now()) {
		t.Fatalf("not-before: %v", got.NotBefore)
	}
	list, next, err := u.List(ctx, svc.ID, 10, "")
	if err != nil || len(list) != 1 || next != "" {
		t.Fatalf("list: %+v %q %v", list, next, err)
	}
}

func TestPasskeyCeremonies(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	user, _ := u.Create(ctx, svc, "p@x.test", "P")

	opts, chID, err := u.BeginRegisterPasskey(ctx, svc, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(opts)
	var out struct {
		PublicKey struct {
			RP   struct{ ID string }
			User struct{ ID, Name string }
		}
	}
	_ = json.Unmarshal(raw, &out)
	if out.PublicKey.RP.ID != "finforge.test" || out.PublicKey.User.Name != "p@x.test" {
		t.Fatalf("creation options bound to the service: %s", raw)
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"junk"}`))
	if _, err := u.FinishRegisterPasskey(ctx, svc, chID, "Phone", req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("junk attestation: %v", err)
	}
	// Service without rp config cannot run ceremonies.
	noRP := svc
	noRP.RPID = ""
	if _, _, err := u.BeginRegisterPasskey(ctx, noRP, user.ID); !errors.Is(err, ErrNoWebAuthn) {
		t.Fatalf("no rp: %v", err)
	}
	// Google users have no passkeys to register.
	_ = mem.CreateUser(ctx, store.User{ID: "usr_g", ServiceID: svc.ID, Method: MethodGoogle, Identity: "google:1", Status: "active", CreatedAt: u.Now()})
	if _, _, err := u.BeginRegisterPasskey(ctx, svc, "usr_g"); !errors.Is(err, ErrWrongMethod) {
		t.Fatalf("google user registering passkey: %v", err)
	}

	// Login ceremony is bound to the authz request and the service.
	lopts, lch, err := u.BeginLoginPasskey(ctx, svc, "authz-1")
	if err != nil || lopts == nil {
		t.Fatal(err)
	}
	other := svc
	other.ID = "svc_other"
	req = httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"junk"}`))
	if _, _, err := u.FinishLoginPasskey(ctx, other, lch, req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("challenge from another service: %v", err)
	}
	lopts, lch, _ = u.BeginLoginPasskey(ctx, svc, "authz-1")
	_ = lopts
	req = httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"junk"}`))
	if _, _, err := u.FinishLoginPasskey(ctx, svc, lch, req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("junk assertion: %v", err)
	}
}

func TestGoogleLoginAndProvider(t *testing.T) {
	u, _, svc := newUsers(t)
	ctx := context.Background()

	if _, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "g@x.test", EmailVerified: false}, "ip"); !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("unverified email: %v", err)
	}
	first, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "G@x.test", EmailVerified: true, Name: "G"}, "ip")
	if err != nil || first.Method != MethodGoogle || first.Email != "g@x.test" || len(first.Roles) != 1 {
		t.Fatalf("first google login: %+v %v", first, err)
	}
	again, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "changed@x.test", EmailVerified: true}, "ip")
	if err != nil || again.ID != first.ID {
		t.Fatalf("second google login must find the same user: %+v %v", again, err)
	}
	// No linking: a passkey account with that email is a different identity.
	pw, err := u.Create(ctx, svc, "g@x.test", "")
	if err != nil || pw.ID == first.ID {
		t.Fatalf("passkey account beside google account: %+v %v", pw, err)
	}
	disabled := "disabled"
	_, _ = u.Update(ctx, svc, first.ID, nil, &disabled, nil)
	if _, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "g@x.test", EmailVerified: true}, "ip"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled google user: %v", err)
	}

	// Provider round trip against a fake Google.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "good" || r.PostForm.Get("client_secret") != "sec" {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at"})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "42", "email": "u@x.test", "email_verified": true, "name": "U"})
	})
	fake := httptest.NewServer(mux)
	defer fake.Close()
	g := NewGoogle("cid", "sec", "https://auth.test/v1/login/google/callback")
	g.AuthURL, g.TokenURL, g.UserinfoURL = fake.URL+"/auth", fake.URL+"/token", fake.URL+"/userinfo"
	if !strings.Contains(g.StartURL("st"), "client_id=cid") || !strings.Contains(g.StartURL("st"), "state=st") {
		t.Fatalf("start url: %s", g.StartURL("st"))
	}
	id, err := g.Exchange(ctx, "good")
	if err != nil || id.Sub != "42" || !id.EmailVerified || id.Name != "U" {
		t.Fatalf("exchange: %+v %v", id, err)
	}
	if _, err := g.Exchange(ctx, "bad"); err == nil {
		t.Fatal("bad code accepted")
	}
	state, err := u.SaveGoogleState(ctx, svc.ID, "authz-9")
	if err != nil {
		t.Fatal(err)
	}
	sid, aid, err := u.LoadGoogleState(ctx, state)
	if err != nil || sid != svc.ID || aid != "authz-9" {
		t.Fatalf("state: %s %s %v", sid, aid, err)
	}
	if _, _, err := u.LoadGoogleState(ctx, state); !errors.Is(err, ErrCeremony) {
		t.Fatalf("state reuse: %v", err)
	}
}

func TestDeleteAndExport(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	user, _ := u.Create(ctx, svc, "d@x.test", "D")
	_ = mem.PutUserPasskey(ctx, store.UserPasskey{ServiceID: svc.ID, UserID: user.ID, ID: "c1", Name: "Phone", CreatedAt: u.Now(), Data: []byte(`{"id":"x"}`)})

	exp, err := u.Export(ctx, svc.ID, user.ID)
	if err != nil || exp.User.ID != user.ID || len(exp.Passkeys) != 1 || exp.Passkeys[0].Name != "Phone" {
		t.Fatalf("export: %+v %v", exp, err)
	}
	// The creation event names the user and is included; no key material leaks.
	found := false
	for _, e := range exp.Audit {
		if e.Kind == "user.create" {
			found = true
		}
	}
	if !found {
		t.Fatalf("export audit missing user.create: %+v", exp.Audit)
	}
	raw, _ := json.Marshal(exp)
	if strings.Contains(string(raw), `"data"`) || strings.Contains(string(raw), `"Data"`) {
		t.Fatal("export leaked passkey data")
	}

	if err := u.Delete(ctx, svc.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Get(ctx, svc.ID, user.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("deleted user: %v", err)
	}
	if _, err := u.Create(ctx, svc, "d@x.test", "D again"); err != nil {
		t.Fatalf("re-register after delete: %v", err)
	}
	if err := u.Delete(ctx, svc.ID, "usr_ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}
