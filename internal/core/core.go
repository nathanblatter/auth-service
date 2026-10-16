// Package core holds the business rules: registering services, minting and
// checking credentials, issuing service tokens. It knows nothing about HTTP
// or AWS beyond the Store and Signer interfaces.
package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nathanblatter/auth-service/internal/jwt"
	"github.com/nathanblatter/auth-service/internal/signer"
	"github.com/nathanblatter/auth-service/internal/store"
)

const (
	// ServiceTokenTTL is the lifetime of a service (machine) token.
	ServiceTokenTTL = 15 * time.Minute
	// AudienceSelf is the audience of tokens meant for the auth API itself.
	AudienceSelf = "auth"
	// ScopeService is the default scope on a service token.
	ScopeService = "service"

	credPrefix = "nbk_"
)

var (
	ErrInvalidSlug       = errors.New("core: slug must be 2-40 chars of a-z, 0-9, '-'")
	ErrInvalidName       = errors.New("core: name must be 1-80 chars")
	ErrSlugTaken         = errors.New("core: slug already in use")
	ErrServiceNotFound   = errors.New("core: service not found")
	ErrCredentialInvalid = errors.New("core: invalid credential")
	ErrServiceDisabled   = errors.New("core: service disabled")
	ErrInvalidResource   = errors.New("core: resource must be an absolute https URL without a fragment")
	ErrResourceTaken     = errors.New("core: resource already registered to a service")
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$`)

// Core wires the store and signing ring with the issuer identity.
type Core struct {
	Store  store.Store
	Ring   *signer.Ring
	Issuer string
	Now    func() time.Time
	Log    *slog.Logger
}

// New returns a Core with sane defaults for Now and Log.
func New(st store.Store, ring *signer.Ring, issuer string) *Core {
	return &Core{Store: st, Ring: ring, Issuer: issuer, Now: time.Now, Log: slog.Default()}
}

// Actor identifies who performed an action, for audit rows.
type Actor struct {
	ID string // "admin", "svc:<id>", "anonymous"
	IP string
}

// CreateService registers a product.
func (c *Core) CreateService(ctx context.Context, name, slug string, by Actor) (store.Service, error) {
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if name == "" || len(name) > 80 {
		return store.Service{}, ErrInvalidName
	}
	if !slugRe.MatchString(slug) {
		return store.Service{}, ErrInvalidSlug
	}
	svc := store.Service{
		ID: "svc_" + randomBase32(16), Slug: slug, Name: name, Status: "active", CreatedAt: c.Now(),
	}
	if err := c.Store.CreateService(ctx, svc); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.Service{}, ErrSlugTaken
		}
		return store.Service{}, err
	}
	c.audit(ctx, "service.create", by, svc.ID, "slug="+slug)
	return svc, nil
}

// ListServices returns every registered service.
func (c *Core) ListServices(ctx context.Context) ([]store.Service, error) {
	return c.Store.ListServices(ctx)
}

// GetService fetches one service.
func (c *Core) GetService(ctx context.Context, id string) (store.Service, error) {
	svc, err := c.Store.GetService(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Service{}, ErrServiceNotFound
	}
	return svc, err
}

// MintCredential creates a credential for a service. The raw value is returned
// exactly once; only its hash is stored.
func (c *Core) MintCredential(ctx context.Context, serviceID string, by Actor) (raw string, cred store.Credential, err error) {
	if _, err := c.GetService(ctx, serviceID); err != nil {
		return "", store.Credential{}, err
	}
	credID := randomBase32(12)
	secret := randomBase64(32)
	raw = credPrefix + credID + "_" + secret
	cred = store.Credential{
		ID: credID, ServiceID: serviceID, Hash: HashSecret(raw), Last4: secret[len(secret)-4:], CreatedAt: c.Now(),
	}
	if err := c.Store.PutCredential(ctx, cred); err != nil {
		return "", store.Credential{}, err
	}
	c.audit(ctx, "credential.mint", by, serviceID, "cred="+credID+" last4="+cred.Last4)
	return raw, cred, nil
}

// ListCredentials lists a service's credentials (hashes included; callers redact).
func (c *Core) ListCredentials(ctx context.Context, serviceID string) ([]store.Credential, error) {
	if _, err := c.GetService(ctx, serviceID); err != nil {
		return nil, err
	}
	return c.Store.ListCredentials(ctx, serviceID)
}

// RevokeCredential disables a credential. Idempotent.
func (c *Core) RevokeCredential(ctx context.Context, serviceID, credID string, by Actor) error {
	err := c.Store.RevokeCredential(ctx, serviceID, credID, c.Now())
	if errors.Is(err, store.ErrNotFound) {
		return ErrCredentialInvalid
	}
	if err != nil {
		return err
	}
	c.audit(ctx, "credential.revoke", by, serviceID, "cred="+credID)
	return nil
}

// Token is an issued access token.
type Token struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Scope       string
}

// ExchangeCredential implements the client_credentials grant: a service
// presents its id and a credential and receives a short-lived service token.
// Every failure path returns ErrCredentialInvalid so callers cannot
// distinguish "no such service" from "wrong secret".
func (c *Core) ExchangeCredential(ctx context.Context, serviceID, rawCredential string, ip string) (Token, error) {
	deny := func(reason string) (Token, error) {
		c.audit(ctx, "token.denied", Actor{ID: "anonymous", IP: ip}, serviceID, reason)
		return Token{}, ErrCredentialInvalid
	}
	credID, ok := parseCredentialID(rawCredential)
	if !ok {
		return deny("malformed credential")
	}
	cred, err := c.Store.GetCredential(ctx, credID)
	if errors.Is(err, store.ErrNotFound) {
		return deny("unknown credential")
	}
	if err != nil {
		return Token{}, err
	}
	// Compare before any other check so timing is identical for all denials.
	match := subtle.ConstantTimeCompare([]byte(cred.Hash), []byte(HashSecret(rawCredential))) == 1
	if !match || cred.ServiceID != serviceID {
		return deny("hash mismatch")
	}
	if cred.Revoked() {
		return deny("revoked credential")
	}
	svc, err := c.Store.GetService(ctx, serviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return deny("service missing")
		}
		return Token{}, err
	}
	if svc.Status != "active" {
		c.audit(ctx, "token.denied", Actor{ID: "svc:" + serviceID, IP: ip}, serviceID, "service disabled")
		return Token{}, ErrServiceDisabled
	}
	now := c.Now()
	claims := jwt.Claims{
		Issuer: c.Issuer, Subject: "svc:" + serviceID, Audience: AudienceSelf, Scope: ScopeService,
		IssuedAt: now.Unix(), Expires: now.Add(ServiceTokenTTL).Unix(),
	}
	tok, err := jwt.Sign(ctx, c.Ring.Active(), claims)
	if err != nil {
		return Token{}, fmt.Errorf("core: sign: %w", err)
	}
	c.audit(ctx, "token.issue", Actor{ID: "svc:" + serviceID, IP: ip}, serviceID, "cred="+credID)
	return Token{AccessToken: tok, TokenType: "Bearer", ExpiresIn: int(ServiceTokenTTL.Seconds()), Scope: ScopeService}, nil
}

// VerifyToken validates a token addressed to an arbitrary audience (a
// service id). Used by tests and by any in-process consumer.
func (c *Core) VerifyToken(token, audience string) (jwt.Claims, error) {
	return jwt.Verify(token, c.Ring.Lookup, c.Now(), c.Issuer, audience)
}

// AddResource registers an RFC 8707 resource identifier for a service so
// connector authorization requests can be mapped to it.
func (c *Core) AddResource(ctx context.Context, serviceID, resource string, by Actor) error {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return ErrInvalidResource
	}
	localDev := u.Scheme == "http" && u.Hostname() == "localhost"
	if u.Scheme != "https" && !localDev {
		return ErrInvalidResource
	}
	err = c.Store.AddServiceResource(ctx, serviceID, resource)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrServiceNotFound
	case errors.Is(err, store.ErrConflict):
		return ErrResourceTaken
	case err != nil:
		return err
	}
	c.audit(ctx, "service.resource.add", by, serviceID, "resource="+resource)
	return nil
}

// VerifyServiceToken validates a bearer token aimed at the auth API and
// returns the service id it belongs to.
func (c *Core) VerifyServiceToken(token string) (serviceID string, claims jwt.Claims, err error) {
	claims, err = jwt.Verify(token, c.Ring.Lookup, c.Now(), c.Issuer, AudienceSelf)
	if err != nil {
		return "", jwt.Claims{}, err
	}
	id, ok := strings.CutPrefix(claims.Subject, "svc:")
	if !ok {
		return "", jwt.Claims{}, jwt.ErrMalformed
	}
	return id, claims, nil
}

// JWKS publishes the ring's public keys.
func (c *Core) JWKS() jwt.JWKS { return jwt.BuildJWKS(c.Ring) }

// HashSecret is the at-rest form of any secret: hex SHA-256.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (c *Core) audit(ctx context.Context, kind string, by Actor, serviceID, detail string) {
	e := store.AuditEvent{At: c.Now(), Kind: kind, Actor: by.ID, ServiceID: serviceID, Detail: detail, IP: by.IP}
	if err := c.Store.AppendAudit(ctx, e); err != nil {
		// Audit failure must not fail the request, but it must be loud.
		c.Log.Error("audit write failed", "kind", kind, "service", serviceID, "err", err)
	}
}

// parseCredentialID pulls the id out of "nbk_<id>_<secret>".
func parseCredentialID(raw string) (string, bool) {
	rest, ok := strings.CutPrefix(raw, credPrefix)
	if !ok {
		return "", false
	}
	id, secret, ok := strings.Cut(rest, "_")
	if !ok || len(id) != 12 || len(secret) < 32 {
		return "", false
	}
	return id, true
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomBase32(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("core: crypto/rand failed: %v", err))
	}
	return strings.ToLower(b32.EncodeToString(buf))[:n]
}

func randomBase64(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("core: crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
