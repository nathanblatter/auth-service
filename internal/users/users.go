// Package users is slice 3: end users of a product. A user belongs to one
// service, has exactly one login method for life (passkey or Google), and
// signs in through the product's own screens; this package owns the
// ceremonies and the account records.
package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nathanblatter/auth-service/internal/store"
)

const (
	MethodPasskey = "passkey"
	MethodGoogle  = "google"

	// ChallengeTTL bounds a WebAuthn ceremony.
	ChallengeTTL = 5 * time.Minute
)

var (
	ErrNotUserPool     = errors.New("users: service has no login_url (owner-only)")
	ErrNoWebAuthn      = errors.New("users: service has no rp_id/origins configured")
	ErrInvalidEmail    = errors.New("users: invalid email")
	ErrInvalidMethod   = errors.New("users: method must be passkey or google")
	ErrIdentityTaken   = errors.New("users: an account with this identity already exists")
	ErrUserNotFound    = errors.New("users: user not found")
	ErrCeremony        = errors.New("users: ceremony failed")
	ErrWrongMethod     = errors.New("users: this account uses a different login method")
	ErrDisabled        = errors.New("users: account disabled")
	ErrEmailUnverified = errors.New("users: provider did not verify the email")
	ErrInvalidRole     = errors.New("users: role is not defined on the service")
)

// Users wires the store with per-service WebAuthn instances.
type Users struct {
	Store store.Store
	Now   func() time.Time
	Log   *slog.Logger

	mu sync.Mutex
	wa map[string]*webauthn.WebAuthn // keyed by service id + config fingerprint
}

// New builds the users component.
func New(st store.Store) *Users {
	return &Users{Store: st, Now: time.Now, Log: slog.Default(), wa: map[string]*webauthn.WebAuthn{}}
}

// webauthnFor returns the RP for a service, built from its rp_id/origins.
func (u *Users) webauthnFor(svc store.Service) (*webauthn.WebAuthn, error) {
	if svc.RPID == "" || len(svc.Origins) == 0 {
		return nil, ErrNoWebAuthn
	}
	key := svc.ID + "|" + svc.RPID + "|" + strings.Join(svc.Origins, ",")
	u.mu.Lock()
	defer u.mu.Unlock()
	if wa, ok := u.wa[key]; ok {
		return wa, nil
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID: svc.RPID, RPDisplayName: svc.Name, RPOrigins: svc.Origins,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("users: webauthn config for %s: %w", svc.Slug, err)
	}
	u.wa[key] = wa
	return wa, nil
}

// ── accounts ───────────────────────────────────────────────────────────────

// Create registers an account. Passkey accounts are keyed on email (lowercased);
// Google accounts are created by the Google flow, not here.
func (u *Users) Create(ctx context.Context, svc store.Service, email, name string) (store.User, error) {
	if svc.LoginURL == "" {
		return store.User{}, ErrNotUserPool
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return store.User{}, err
	}
	user := store.User{
		ID: "usr_" + randomBase32(16), ServiceID: svc.ID, Method: MethodPasskey, Identity: "email:" + email,
		Email: email, Name: strings.TrimSpace(name), Roles: append([]string(nil), svc.DefaultRoles...), Status: "active", CreatedAt: u.Now(),
	}
	if err := u.Store.CreateUser(ctx, user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.User{}, ErrIdentityTaken
		}
		return store.User{}, err
	}
	u.audit(ctx, "user.create", svc.ID, user.ID, "method=passkey", "")
	return user, nil
}

// Get fetches a user of a service.
func (u *Users) Get(ctx context.Context, serviceID, id string) (store.User, error) {
	user, err := u.Store.GetUser(ctx, serviceID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, ErrUserNotFound
	}
	return user, err
}

// List pages a service's users.
func (u *Users) List(ctx context.Context, serviceID string, limit int, cursor string) ([]store.User, string, error) {
	return u.Store.ListUsers(ctx, serviceID, limit, cursor)
}

// Update changes roles, status, name. Roles must exist on the service.
func (u *Users) Update(ctx context.Context, svc store.Service, id string, roles *[]string, status, name *string) (store.User, error) {
	user, err := u.Get(ctx, svc.ID, id)
	if err != nil {
		return store.User{}, err
	}
	if roles != nil {
		for _, r := range *roles {
			if _, ok := svc.Roles[r]; !ok {
				return store.User{}, ErrInvalidRole
			}
		}
		user.Roles = append([]string(nil), *roles...)
	}
	if status != nil {
		if *status != "active" && *status != "disabled" {
			return store.User{}, errors.New("users: status must be active or disabled")
		}
		user.Status = *status
	}
	if name != nil {
		user.Name = strings.TrimSpace(*name)
	}
	if err := u.Store.UpdateUser(ctx, user); err != nil {
		return store.User{}, err
	}
	u.audit(ctx, "user.update", svc.ID, user.ID, fmt.Sprintf("roles=%v status=%s", user.Roles, user.Status), "")
	return user, nil
}

// LogoutEverywhere invalidates the user's refresh tokens (auth-service-11).
func (u *Users) LogoutEverywhere(ctx context.Context, serviceID, id string) error {
	user, err := u.Get(ctx, serviceID, id)
	if err != nil {
		return err
	}
	user.NotBefore = u.Now()
	if err := u.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	u.audit(ctx, "user.logout_everywhere", serviceID, id, "", "")
	return nil
}

// AllowedScopes is the union of the scopes of the user's roles, in catalog order.
func AllowedScopes(svc store.Service, user store.User) []string {
	have := map[string]bool{}
	for _, r := range user.Roles {
		for _, sc := range svc.Roles[r] {
			have[sc] = true
		}
	}
	out := make([]string, 0, len(have))
	for _, sc := range svc.Scopes {
		if have[sc] {
			out = append(out, sc)
		}
	}
	return out
}

// ── passkeys ───────────────────────────────────────────────────────────────

type waUser struct {
	user  store.User
	creds []webauthn.Credential
}

func (w waUser) WebAuthnID() []byte                         { return []byte(w.user.ID) }
func (w waUser) WebAuthnName() string                       { return w.user.Email }
func (w waUser) WebAuthnDisplayName() string                { return nameOr(w.user) }
func (w waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func nameOr(u store.User) string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

func (u *Users) loadWAUser(ctx context.Context, user store.User) (waUser, []store.UserPasskey, error) {
	keys, err := u.Store.ListUserPasskeys(ctx, user.ServiceID, user.ID)
	if err != nil {
		return waUser{}, nil, err
	}
	w := waUser{user: user, creds: make([]webauthn.Credential, 0, len(keys))}
	for _, k := range keys {
		var c webauthn.Credential
		if err := json.Unmarshal(k.Data, &c); err != nil {
			return waUser{}, nil, fmt.Errorf("users: corrupt passkey %s: %w", k.ID, err)
		}
		w.creds = append(w.creds, c)
	}
	return w, keys, nil
}

// BeginRegisterPasskey starts adding a passkey to a passkey-method user.
func (u *Users) BeginRegisterPasskey(ctx context.Context, svc store.Service, userID string) (*protocol.CredentialCreation, string, error) {
	user, err := u.Get(ctx, svc.ID, userID)
	if err != nil {
		return nil, "", err
	}
	if user.Method != MethodPasskey {
		return nil, "", ErrWrongMethod
	}
	wa, err := u.webauthnFor(svc)
	if err != nil {
		return nil, "", err
	}
	w, _, err := u.loadWAUser(ctx, user)
	if err != nil {
		return nil, "", err
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(w.creds))
	for _, c := range w.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, sess, err := wa.BeginRegistration(w,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		return nil, "", err
	}
	id, err := u.saveChallenge(ctx, challengeData{Session: sess, ServiceID: svc.ID, UserID: user.ID})
	return opts, id, err
}

// FinishRegisterPasskey verifies the attestation and stores the credential.
func (u *Users) FinishRegisterPasskey(ctx context.Context, svc store.Service, challengeID, name string, r *http.Request) (store.UserPasskey, error) {
	ch, err := u.loadChallenge(ctx, challengeID)
	if err != nil || ch.ServiceID != svc.ID || ch.UserID == "" {
		return store.UserPasskey{}, ErrCeremony
	}
	user, err := u.Get(ctx, svc.ID, ch.UserID)
	if err != nil {
		return store.UserPasskey{}, err
	}
	wa, err := u.webauthnFor(svc)
	if err != nil {
		return store.UserPasskey{}, err
	}
	w, _, err := u.loadWAUser(ctx, user)
	if err != nil {
		return store.UserPasskey{}, err
	}
	cred, err := wa.FinishRegistration(w, *ch.Session, r)
	if err != nil {
		u.Log.Warn("user passkey registration failed", "service", svc.Slug, "err", err)
		return store.UserPasskey{}, ErrCeremony
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return store.UserPasskey{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	pk := store.UserPasskey{ServiceID: svc.ID, UserID: user.ID, ID: b64(cred.ID), Name: name, CreatedAt: u.Now(), Data: data}
	if err := u.Store.PutUserPasskey(ctx, pk); err != nil {
		return store.UserPasskey{}, err
	}
	u.audit(ctx, "user.passkey.register", svc.ID, user.ID, "pk="+pk.ID, clientIP(r))
	pk.Data = nil
	return pk, nil
}

// BeginLoginPasskey starts a usernameless passkey sign-in for a pending
// authorization (login_challenge). The challenge row remembers the authz id.
func (u *Users) BeginLoginPasskey(ctx context.Context, svc store.Service, authzID string) (*protocol.CredentialAssertion, string, error) {
	wa, err := u.webauthnFor(svc)
	if err != nil {
		return nil, "", err
	}
	opts, sess, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	id, err := u.saveChallenge(ctx, challengeData{Session: sess, ServiceID: svc.ID, AuthzID: authzID})
	return opts, id, err
}

// FinishLoginPasskey verifies the assertion and returns the user plus the
// authz id the ceremony was started for.
func (u *Users) FinishLoginPasskey(ctx context.Context, svc store.Service, challengeID string, r *http.Request) (store.User, string, error) {
	ip := clientIP(r)
	ch, err := u.loadChallenge(ctx, challengeID)
	if err != nil || ch.ServiceID != svc.ID {
		return store.User{}, "", ErrCeremony
	}
	wa, err := u.webauthnFor(svc)
	if err != nil {
		return store.User{}, "", err
	}
	var matched store.User
	var matchedKey store.UserPasskey
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		pk, err := u.Store.GetUserPasskeyByCred(ctx, svc.ID, b64(rawID))
		if err != nil {
			return nil, errors.New("unknown credential")
		}
		if string(userHandle) != pk.UserID {
			return nil, errors.New("user handle mismatch")
		}
		user, err := u.Store.GetUser(ctx, svc.ID, pk.UserID)
		if err != nil {
			return nil, errors.New("unknown user")
		}
		w, _, err := u.loadWAUser(ctx, user)
		if err != nil {
			return nil, err
		}
		matched, matchedKey = user, pk
		return w, nil
	}
	cred, err := wa.FinishDiscoverableLogin(handler, *ch.Session, r)
	if err != nil || cred.Authenticator.CloneWarning {
		u.audit(ctx, "user.login_denied", svc.ID, matched.ID, "passkey", ip)
		return store.User{}, "", ErrCeremony
	}
	if matched.Status != "active" {
		u.audit(ctx, "user.login_denied", svc.ID, matched.ID, "disabled", ip)
		return store.User{}, "", ErrDisabled
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return store.User{}, "", err
	}
	matchedKey.Data = data
	if err := u.Store.UpdateUserPasskey(ctx, matchedKey); err != nil {
		return store.User{}, "", err
	}
	u.audit(ctx, "user.login", svc.ID, matched.ID, "passkey", ip)
	return matched, ch.AuthzID, nil
}

// ── Google ─────────────────────────────────────────────────────────────────

// GoogleIdentity is what the provider tells us about the signed-in person.
type GoogleIdentity struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
}

// LoginGoogle finds or creates the user for a verified Google identity.
func (u *Users) LoginGoogle(ctx context.Context, svc store.Service, g GoogleIdentity, ip string) (store.User, error) {
	if svc.LoginURL == "" {
		return store.User{}, ErrNotUserPool
	}
	if g.Sub == "" || !g.EmailVerified {
		return store.User{}, ErrEmailUnverified
	}
	identity := "google:" + g.Sub
	user, err := u.Store.GetUserByIdentity(ctx, svc.ID, identity)
	switch {
	case errors.Is(err, store.ErrNotFound):
		email, _ := normalizeEmail(g.Email)
		user = store.User{
			ID: "usr_" + randomBase32(16), ServiceID: svc.ID, Method: MethodGoogle, Identity: identity,
			Email: email, Name: strings.TrimSpace(g.Name), Roles: append([]string(nil), svc.DefaultRoles...), Status: "active", CreatedAt: u.Now(),
		}
		if err := u.Store.CreateUser(ctx, user); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return store.User{}, ErrIdentityTaken
			}
			return store.User{}, err
		}
		u.audit(ctx, "user.create", svc.ID, user.ID, "method=google", ip)
	case err != nil:
		return store.User{}, err
	}
	if user.Status != "active" {
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "disabled", ip)
		return store.User{}, ErrDisabled
	}
	u.audit(ctx, "user.login", svc.ID, user.ID, "google", ip)
	return user, nil
}

// ── challenges ─────────────────────────────────────────────────────────────

type challengeData struct {
	Session   *webauthn.SessionData `json:"session,omitempty"`
	ServiceID string                `json:"service_id"`
	UserID    string                `json:"user_id,omitempty"`
	AuthzID   string                `json:"authz_id,omitempty"`
	Nonce     string                `json:"nonce,omitempty"`
}

func (u *Users) saveChallenge(ctx context.Context, c challengeData) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	id := "u" + randomToken()
	return id, u.Store.PutChallenge(ctx, id, data, u.Now().Add(ChallengeTTL))
}

func (u *Users) loadChallenge(ctx context.Context, id string) (challengeData, error) {
	if id == "" {
		return challengeData{}, ErrCeremony
	}
	data, err := u.Store.ConsumeChallenge(ctx, id, u.Now())
	if errors.Is(err, store.ErrNotFound) {
		return challengeData{}, ErrCeremony
	}
	if err != nil {
		return challengeData{}, err
	}
	var c challengeData
	if err := json.Unmarshal(data, &c); err != nil {
		return challengeData{}, ErrCeremony
	}
	return c, nil
}

// SaveGoogleState parks the authz id behind a random state for the Google
// round trip; LoadGoogleState consumes it.
func (u *Users) SaveGoogleState(ctx context.Context, serviceID, authzID string) (string, error) {
	return u.saveChallenge(ctx, challengeData{ServiceID: serviceID, AuthzID: authzID})
}

// LoadGoogleState resolves a state parameter to (service id, authz id).
func (u *Users) LoadGoogleState(ctx context.Context, state string) (serviceID, authzID string, err error) {
	c, err := u.loadChallenge(ctx, state)
	if err != nil {
		return "", "", err
	}
	return c.ServiceID, c.AuthzID, nil
}

// ── helpers ────────────────────────────────────────────────────────────────

func (u *Users) audit(ctx context.Context, kind, serviceID, userID, detail, ip string) {
	actor := "anonymous"
	if userID != "" {
		actor = "usr:" + userID
	}
	e := store.AuditEvent{At: u.Now(), Kind: kind, Actor: actor, ServiceID: serviceID, Detail: detail, IP: ip}
	if err := u.Store.AppendAudit(ctx, e); err != nil {
		u.Log.Error("audit write failed", "kind", kind, "err", err)
	}
}

func normalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", ErrInvalidEmail
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || len(s) > 254 {
		return "", ErrInvalidEmail
	}
	return s, nil
}

// ValidLoginURL accepts absolute https URLs (http for localhost dev).
func ValidLoginURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && u.Hostname() == "localhost")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("users: crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomBase32(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("users: crypto/rand failed: %v", err))
	}
	return strings.ToLower(b32.EncodeToString(buf))[:n]
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// Hash is exported for tests that need the identity key format.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
