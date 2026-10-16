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

// Store is everything the core needs from persistence.
type Store interface {
	CreateService(ctx context.Context, s Service) error // ErrConflict when the slug is taken
	GetService(ctx context.Context, id string) (Service, error)
	ListServices(ctx context.Context) ([]Service, error)

	PutCredential(ctx context.Context, c Credential) error
	GetCredential(ctx context.Context, credID string) (Credential, error)
	ListCredentials(ctx context.Context, serviceID string) ([]Credential, error)
	RevokeCredential(ctx context.Context, serviceID, credID string, at time.Time) error

	AppendAudit(ctx context.Context, e AuditEvent) error
}
