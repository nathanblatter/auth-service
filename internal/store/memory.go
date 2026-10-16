package store

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is a goroutine-safe in-memory Store.
type Memory struct {
	mu       sync.Mutex
	services map[string]Service
	slugs    map[string]string
	creds    map[string]Credential
	Audit    []AuditEvent
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{services: map[string]Service{}, slugs: map[string]string{}, creds: map[string]Credential{}}
}

func (m *Memory) CreateService(_ context.Context, s Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.slugs[s.Slug]; taken {
		return ErrConflict
	}
	if _, taken := m.services[s.ID]; taken {
		return ErrConflict
	}
	m.slugs[s.Slug] = s.ID
	m.services[s.ID] = s
	return nil
}

func (m *Memory) GetService(_ context.Context, id string) (Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.services[id]
	if !ok {
		return Service{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) ListServices(_ context.Context) ([]Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Service, 0, len(m.services))
	for _, s := range m.services {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (m *Memory) PutCredential(_ context.Context, c Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.creds[c.ID]; taken {
		return ErrConflict
	}
	m.creds[c.ID] = c
	return nil
}

func (m *Memory) GetCredential(_ context.Context, credID string) (Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[credID]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) ListCredentials(_ context.Context, serviceID string) ([]Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Credential
	for _, c := range m.creds {
		if c.ServiceID == serviceID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) RevokeCredential(_ context.Context, serviceID, credID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[credID]
	if !ok || c.ServiceID != serviceID {
		return ErrNotFound
	}
	if c.RevokedAt == nil {
		c.RevokedAt = &at
		m.creds[credID] = c
	}
	return nil
}

func (m *Memory) AppendAudit(_ context.Context, e AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Audit = append(m.Audit, e)
	return nil
}
