package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Memory is a goroutine-safe in-memory Store.
type Memory struct {
	mu        sync.Mutex
	services  map[string]Service
	slugs     map[string]string
	creds     map[string]Credential
	passkeys  map[string]Passkey
	chals     map[string]challenge
	sessions  map[string]Session
	fails     map[string]failCounter
	resources map[string]string // resource -> service id
	clients   map[string]OAuthClient
	authz     map[string]AuthzRequest
	codes     map[string]Code
	refresh   map[string]RefreshToken
	recovery  map[string]RecoveryCode
	notBefore time.Time
	Audit     []AuditEvent
}

type failCounter struct {
	count int
	until time.Time
}

type challenge struct {
	data    []byte
	expires time.Time
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{
		services: map[string]Service{}, slugs: map[string]string{}, creds: map[string]Credential{},
		passkeys: map[string]Passkey{}, chals: map[string]challenge{}, sessions: map[string]Session{},
		fails: map[string]failCounter{}, resources: map[string]string{}, clients: map[string]OAuthClient{},
		authz: map[string]AuthzRequest{}, codes: map[string]Code{}, refresh: map[string]RefreshToken{},
		recovery: map[string]RecoveryCode{},
	}
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

func (m *Memory) PutPasskey(_ context.Context, p Passkey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.passkeys[p.ID]; taken {
		return ErrConflict
	}
	m.passkeys[p.ID] = p
	return nil
}

func (m *Memory) UpdatePasskey(_ context.Context, p Passkey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.passkeys[p.ID]; !ok {
		return ErrNotFound
	}
	m.passkeys[p.ID] = p
	return nil
}

func (m *Memory) ListPasskeys(_ context.Context) ([]Passkey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Passkey, 0, len(m.passkeys))
	for _, p := range m.passkeys {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) PutChallenge(_ context.Context, id string, data []byte, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chals[id] = challenge{data: data, expires: expires}
	return nil
}

func (m *Memory) ConsumeChallenge(_ context.Context, id string, now time.Time) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.chals[id]
	delete(m.chals, id)
	if !ok || !now.Before(c.expires) {
		return nil, ErrNotFound
	}
	return c.data, nil
}

func (m *Memory) PutSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.Hash] = s
	return nil
}

func (m *Memory) GetSession(_ context.Context, hash string, now time.Time) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok || !now.Before(s.ExpiresAt) {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) DeleteSession(_ context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hash)
	return nil
}

func (m *Memory) FailureCount(_ context.Context, key string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.fails[key]
	if !ok || !now.Before(c.until) {
		return 0, nil
	}
	return c.count, nil
}

func (m *Memory) RecordFailure(_ context.Context, key string, now time.Time, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.fails[key]
	if !ok || !now.Before(c.until) {
		c = failCounter{count: 0, until: now.Add(window)}
	}
	c.count++
	m.fails[key] = c
	return c.count, nil
}

func (m *Memory) AddServiceResource(_ context.Context, serviceID, resource string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, ok := m.services[serviceID]
	if !ok {
		return ErrNotFound
	}
	if _, taken := m.resources[resource]; taken {
		return ErrConflict
	}
	m.resources[resource] = serviceID
	svc.Resources = append(svc.Resources, resource)
	m.services[serviceID] = svc
	return nil
}

func (m *Memory) GetServiceByResource(_ context.Context, resource string) (Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.resources[resource]
	if !ok {
		return Service{}, ErrNotFound
	}
	return m.services[id], nil
}

func (m *Memory) CreateOAuthClient(_ context.Context, c OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.clients[c.ID]; taken {
		return ErrConflict
	}
	m.clients[c.ID] = c
	return nil
}

func (m *Memory) GetOAuthClient(_ context.Context, id string) (OAuthClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return OAuthClient{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) PutAuthzRequest(_ context.Context, a AuthzRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authz[a.ID] = a
	return nil
}

func (m *Memory) GetAuthzRequest(_ context.Context, id string, now time.Time) (AuthzRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.authz[id]
	if !ok || !now.Before(a.ExpiresAt) {
		return AuthzRequest{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) DeleteAuthzRequest(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.authz, id)
	return nil
}

func (m *Memory) CreateCode(_ context.Context, hash string, c Code) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[hash] = c
	return nil
}

func (m *Memory) ConsumeCode(_ context.Context, hash string, now time.Time) (Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[hash]
	delete(m.codes, hash)
	if !ok || !now.Before(c.ExpiresAt) {
		return Code{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) CreateRefresh(_ context.Context, t RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[t.Hash] = t
	return nil
}

func (m *Memory) ConsumeRefresh(_ context.Context, hash string, now time.Time) (RefreshToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.refresh[hash]
	if !ok || !now.Before(t.ExpiresAt) {
		return RefreshToken{}, false, ErrNotFound
	}
	if t.Used {
		return t, true, nil
	}
	t.Used = true
	m.refresh[hash] = t
	return t, false, nil
}

func (m *Memory) RevokeRefreshFamily(_ context.Context, family string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, t := range m.refresh {
		if t.Family == family {
			delete(m.refresh, h)
		}
	}
	return nil
}

func (m *Memory) ReplaceRecoveryCodes(_ context.Context, hashes []string, created time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recovery = map[string]RecoveryCode{}
	for _, h := range hashes {
		m.recovery[h] = RecoveryCode{Hash: h, CreatedAt: created}
	}
	return nil
}

func (m *Memory) ListRecoveryCodes(_ context.Context) ([]RecoveryCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RecoveryCode, 0, len(m.recovery))
	for _, c := range m.recovery {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out, nil
}

func (m *Memory) ConsumeRecoveryCode(_ context.Context, hash string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.recovery[hash]
	if !ok || c.UsedAt != nil {
		return ErrNotFound
	}
	c.UsedAt = &now
	m.recovery[hash] = c
	return nil
}

func (m *Memory) ListAudit(_ context.Context, month string, limit int, cursor string) ([]AuditEvent, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []AuditEvent
	for _, e := range m.Audit {
		if e.At.UTC().Format("2006-01") == month {
			all = append(all, e)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].At.After(all[j].At) })
	// cursor is an index encoded as a string for the in-memory store.
	start := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "%d", &start); err != nil {
			return nil, "", fmt.Errorf("store: bad cursor %q", cursor)
		}
	}
	if start >= len(all) {
		return []AuditEvent{}, "", nil
	}
	end := min(start+limit, len(all))
	next := ""
	if end < len(all) {
		next = fmt.Sprint(end)
	}
	return all[start:end], next, nil
}

func (m *Memory) GetOwnerNotBefore(_ context.Context) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.notBefore, nil
}

func (m *Memory) SetOwnerNotBefore(_ context.Context, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notBefore = t
	return nil
}

func (m *Memory) TouchSessionVerified(_ context.Context, hash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return ErrNotFound
	}
	s.VerifiedAt = at
	m.sessions[hash] = s
	return nil
}
