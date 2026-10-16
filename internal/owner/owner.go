// Package owner is Nathan's cross-tenant identity: the single account that
// administers the auth service. It authenticates with passkeys (WebAuthn) and
// holds short console sessions. Everything here is single-owner by design;
// per-product users live elsewhere.
package owner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nathanblatter/auth-service/internal/store"
)

const (
	// SessionTTL is how long a console sign-in lasts (Nathan, 2026-10-15: 1 hour).
	SessionTTL = time.Hour
	// ChallengeTTL bounds a WebAuthn ceremony.
	ChallengeTTL = 5 * time.Minute
)

var (
	ErrNoPasskeys      = errors.New("owner: no passkeys registered")
	ErrCeremony        = errors.New("owner: ceremony failed")
	ErrSessionInvalid  = errors.New("owner: session invalid")
	ErrPasskeyNotFound = errors.New("owner: passkey not found")
)

// Owner wires WebAuthn to the store.
type Owner struct {
	Store store.Store
	WA    *webauthn.WebAuthn
	Now   func() time.Time
	Log   *slog.Logger
}

// New configures WebAuthn for the issuer URL: the RP ID is its host and the
// only allowed origin is the issuer itself.
func New(st store.Store, issuer string) (*Owner, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("owner: issuer %q is not a URL", issuer)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: u.Hostname() + " admin",
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("owner: webauthn config: %w", err)
	}
	return &Owner{Store: st, WA: wa, Now: time.Now, Log: slog.Default()}, nil
}

// user adapts the owner to webauthn.User. The handle is a fixed opaque value:
// there is exactly one owner.
type user struct{ creds []webauthn.Credential }

var ownerHandle = func() []byte { h := sha256.Sum256([]byte("auth-service owner")); return h[:] }()

func (user) WebAuthnID() []byte                           { return ownerHandle }
func (user) WebAuthnName() string                         { return "owner" }
func (user) WebAuthnDisplayName() string                  { return "Owner" }
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (o *Owner) loadUser(ctx context.Context) (user, []store.Passkey, error) {
	keys, err := o.Store.ListPasskeys(ctx)
	if err != nil {
		return user{}, nil, err
	}
	u := user{creds: make([]webauthn.Credential, 0, len(keys))}
	for _, k := range keys {
		var c webauthn.Credential
		if err := json.Unmarshal(k.Data, &c); err != nil {
			return user{}, nil, fmt.Errorf("owner: corrupt passkey %s: %w", k.ID, err)
		}
		u.creds = append(u.creds, c)
	}
	return u, keys, nil
}

// HasPasskeys reports whether setup has happened.
func (o *Owner) HasPasskeys(ctx context.Context) (bool, error) {
	keys, err := o.Store.ListPasskeys(ctx)
	return len(keys) > 0, err
}

// ListPasskeys returns the registered passkeys without their key material.
func (o *Owner) ListPasskeys(ctx context.Context) ([]store.Passkey, error) {
	keys, err := o.Store.ListPasskeys(ctx)
	for i := range keys {
		keys[i].Data = nil
	}
	return keys, err
}

// BeginRegistration starts adding a passkey. It returns the browser options and
// the challenge id the client must echo back to FinishRegistration.
func (o *Owner) BeginRegistration(ctx context.Context) (*protocol.CredentialCreation, string, error) {
	u, _, err := o.loadUser(ctx)
	if err != nil {
		return nil, "", err
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, sess, err := o.WA.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		return nil, "", err
	}
	id, err := o.saveChallenge(ctx, sess)
	return opts, id, err
}

// FinishRegistration verifies the attestation and stores the passkey.
func (o *Owner) FinishRegistration(ctx context.Context, challengeID, name string, r *http.Request) (store.Passkey, error) {
	sess, err := o.loadChallenge(ctx, challengeID)
	if err != nil {
		return store.Passkey{}, err
	}
	u, _, err := o.loadUser(ctx)
	if err != nil {
		return store.Passkey{}, err
	}
	cred, err := o.WA.FinishRegistration(u, sess, r)
	if err != nil {
		o.Log.Warn("passkey registration failed", "err", err)
		return store.Passkey{}, ErrCeremony
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return store.Passkey{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	pk := store.Passkey{ID: b64(cred.ID), Name: name, CreatedAt: o.Now(), Data: data}
	if err := o.Store.PutPasskey(ctx, pk); err != nil {
		return store.Passkey{}, err
	}
	o.audit(ctx, "passkey.register", "pk="+pk.ID+" name="+name, clientIP(r))
	pk.Data = nil
	return pk, nil
}

// BeginLogin starts a discoverable (usernameless) passkey sign-in.
func (o *Owner) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	has, err := o.HasPasskeys(ctx)
	if err != nil {
		return nil, "", err
	}
	if !has {
		return nil, "", ErrNoPasskeys
	}
	opts, sess, err := o.WA.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	id, err := o.saveChallenge(ctx, sess)
	return opts, id, err
}

// FinishLogin verifies the assertion and opens a session. The returned token
// is the cookie value; only its hash is stored.
func (o *Owner) FinishLogin(ctx context.Context, challengeID string, r *http.Request) (token string, expires time.Time, err error) {
	ip := clientIP(r)
	sess, err := o.loadChallenge(ctx, challengeID)
	if err != nil {
		return "", time.Time{}, err
	}
	u, keys, err := o.loadUser(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if string(userHandle) != string(ownerHandle) {
			return nil, errors.New("unknown user handle")
		}
		for _, c := range u.creds {
			if string(c.ID) == string(rawID) {
				return u, nil
			}
		}
		return nil, errors.New("unknown credential")
	}
	cred, err := o.WA.FinishDiscoverableLogin(handler, sess, r)
	if err != nil {
		o.audit(ctx, "owner.login_denied", "webauthn: "+err.Error(), ip)
		return "", time.Time{}, ErrCeremony
	}
	if cred.Authenticator.CloneWarning {
		o.audit(ctx, "owner.login_denied", "clone warning on pk="+b64(cred.ID), ip)
		return "", time.Time{}, ErrCeremony
	}
	// Persist the updated sign counter.
	for _, k := range keys {
		if k.ID == b64(cred.ID) {
			data, err := json.Marshal(cred)
			if err != nil {
				return "", time.Time{}, err
			}
			k.Data = data
			if err := o.Store.UpdatePasskey(ctx, k); err != nil {
				return "", time.Time{}, err
			}
		}
	}
	token = randomToken()
	now := o.Now()
	expires = now.Add(SessionTTL)
	if err := o.Store.PutSession(ctx, store.Session{Hash: hash(token), CreatedAt: now, ExpiresAt: expires, IP: ip}); err != nil {
		return "", time.Time{}, err
	}
	o.audit(ctx, "owner.login", "pk="+b64(cred.ID), ip)
	return token, expires, nil
}

// ValidateSession resolves a cookie value to a live session.
func (o *Owner) ValidateSession(ctx context.Context, token string) (store.Session, error) {
	if token == "" {
		return store.Session{}, ErrSessionInvalid
	}
	s, err := o.Store.GetSession(ctx, hash(token), o.Now())
	if errors.Is(err, store.ErrNotFound) {
		return store.Session{}, ErrSessionInvalid
	}
	return s, err
}

// Logout ends a session. Unknown tokens are a no-op.
func (o *Owner) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return o.Store.DeleteSession(ctx, hash(token))
}

func (o *Owner) saveChallenge(ctx context.Context, sess *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	id := randomToken()
	return id, o.Store.PutChallenge(ctx, id, data, o.Now().Add(ChallengeTTL))
}

func (o *Owner) loadChallenge(ctx context.Context, id string) (webauthn.SessionData, error) {
	if id == "" {
		return webauthn.SessionData{}, ErrCeremony
	}
	data, err := o.Store.ConsumeChallenge(ctx, id, o.Now())
	if errors.Is(err, store.ErrNotFound) {
		return webauthn.SessionData{}, ErrCeremony
	}
	if err != nil {
		return webauthn.SessionData{}, err
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(data, &sess); err != nil {
		return webauthn.SessionData{}, ErrCeremony
	}
	return sess, nil
}

func (o *Owner) audit(ctx context.Context, kind, detail, ip string) {
	e := store.AuditEvent{At: o.Now(), Kind: kind, Actor: "owner", Detail: detail, IP: ip}
	if err := o.Store.AppendAudit(ctx, e); err != nil {
		o.Log.Error("audit write failed", "kind", kind, "err", err)
	}
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("owner: crypto/rand failed: %v", err))
	}
	return b64(b[:])
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
