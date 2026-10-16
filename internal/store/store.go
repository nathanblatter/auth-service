// Package store is the persistence boundary. One interface, two
// implementations: DynamoDB for real and an in-memory map for tests and
// `make dev` without Docker.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

// Service is a registered product. It is also the tenant for its users.
type Service struct {
	ID        string
	Slug      string
	Name      string
	Status    string // active | disabled
	CreatedAt time.Time
	// Resources are the RFC 8707 resource identifiers (e.g. an MCP URL) that
	// map an OAuth authorization request to this service.
	Resources []string
}

// Credential is a hashed service credential.
type Credential struct {
	ID        string
	ServiceID string
	Hash      string // hex SHA-256 of the full raw credential
	Last4     string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// Revoked reports whether the credential is no longer usable.
func (c Credential) Revoked() bool { return c.RevokedAt != nil }

// AuditEvent is one security-relevant action.
type AuditEvent struct {
	At        time.Time
	Kind      string // service.create | credential.mint | credential.revoke | token.issue | token.denied
	Actor     string // admin | svc:<id> | anonymous
	ServiceID string
	Detail    string
	IP        string
}

// Passkey is one WebAuthn credential belonging to the owner. Data is the
// JSON-encoded webauthn.Credential; the store treats it as opaque.
type Passkey struct {
	ID        string // base64url credential id
	Name      string
	CreatedAt time.Time
	Data      []byte
}

// Session is an owner console session. Only the SHA-256 of the cookie value
// is stored.
type Session struct {
	Hash      string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	// Method is how the session was opened: "passkey" (default) or "recovery".
	Method string
}

// RecoveryCode is one offline recovery code, stored hashed.
type RecoveryCode struct {
	Hash      string
	CreatedAt time.Time
	UsedAt    *time.Time
}

// OAuthClient is a dynamically registered OAuth client (RFC 7591).
type OAuthClient struct {
	ID           string
	Name         string
	SecretHash   string // empty for public clients
	AuthMethod   string // none | client_secret_post | client_secret_basic
	RedirectURIs []string
	CreatedAt    time.Time
}

// AuthzRequest is a pending authorization awaiting the owner's approval.
type AuthzRequest struct {
	ID          string
	ClientID    string
	RedirectURI string
	State       string
	Scope       string
	Challenge   string // PKCE S256
	Resource    string
	ServiceID   string
	ExpiresAt   time.Time
}

// Code is a one-time authorization code (stored under its hash).
type Code struct {
	ClientID    string
	RedirectURI string
	Challenge   string
	Scope       string
	Subject     string
	ServiceID   string
	ExpiresAt   time.Time
}

// RefreshToken is one member of a rotating family (stored under its hash).
type RefreshToken struct {
	Hash      string
	Family    string
	ClientID  string
	ServiceID string
	Subject   string
	Scope     string
	ExpiresAt time.Time
	Used      bool
}

// Store is everything the core needs from persistence.
type Store interface {
	CreateService(ctx context.Context, s Service) error // ErrConflict when the slug is taken
	GetService(ctx context.Context, id string) (Service, error)
	ListServices(ctx context.Context) ([]Service, error)

	AddServiceResource(ctx context.Context, serviceID, resource string) error // ErrConflict when taken
	GetServiceByResource(ctx context.Context, resource string) (Service, error)

	PutCredential(ctx context.Context, c Credential) error
	GetCredential(ctx context.Context, credID string) (Credential, error)
	ListCredentials(ctx context.Context, serviceID string) ([]Credential, error)
	RevokeCredential(ctx context.Context, serviceID, credID string, at time.Time) error

	AppendAudit(ctx context.Context, e AuditEvent) error

	// Owner passkeys (single owner; see docs/DESIGN.md).
	PutPasskey(ctx context.Context, p Passkey) error // ErrConflict when the id exists
	UpdatePasskey(ctx context.Context, p Passkey) error
	ListPasskeys(ctx context.Context) ([]Passkey, error)

	// WebAuthn ceremony state, keyed by a random id, single use, short lived.
	PutChallenge(ctx context.Context, id string, data []byte, expires time.Time) error
	ConsumeChallenge(ctx context.Context, id string, now time.Time) ([]byte, error) // ErrNotFound when missing or expired

	// Failure counters for brute-force protection. A counter is a key plus a
	// window; failures outside the current window are forgotten.
	FailureCount(ctx context.Context, key string, now time.Time) (int, error)
	RecordFailure(ctx context.Context, key string, now time.Time, window time.Duration) (int, error)

	PutSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, hash string, now time.Time) (Session, error) // ErrNotFound when missing or expired
	DeleteSession(ctx context.Context, hash string) error

	// Recovery codes: ReplaceRecoveryCodes wipes any existing set.
	ReplaceRecoveryCodes(ctx context.Context, hashes []string, created time.Time) error
	ListRecoveryCodes(ctx context.Context) ([]RecoveryCode, error)
	ConsumeRecoveryCode(ctx context.Context, hash string, now time.Time) error // ErrNotFound when missing or used

	// OAuth 2.1 for connectors.
	CreateOAuthClient(ctx context.Context, c OAuthClient) error
	GetOAuthClient(ctx context.Context, id string) (OAuthClient, error)
	PutAuthzRequest(ctx context.Context, a AuthzRequest) error
	GetAuthzRequest(ctx context.Context, id string, now time.Time) (AuthzRequest, error) // ErrNotFound when missing or expired
	DeleteAuthzRequest(ctx context.Context, id string) error
	CreateCode(ctx context.Context, hash string, c Code) error
	ConsumeCode(ctx context.Context, hash string, now time.Time) (Code, error) // single use; ErrNotFound when missing, used or expired
	CreateRefresh(ctx context.Context, t RefreshToken) error
	// ConsumeRefresh marks the token used. reused is true when it had already
	// been used (replay), in which case the token is still returned so the
	// caller can revoke its family.
	ConsumeRefresh(ctx context.Context, hash string, now time.Time) (t RefreshToken, reused bool, err error)
	RevokeRefreshFamily(ctx context.Context, family string) error
}
