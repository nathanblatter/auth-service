// Package signer abstracts the ES256 signing key so the API can sign JWTs with
// a KMS key in production and an in-memory ECDSA key in dev and tests. Private
// key material never leaves the Signer implementation.
package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Signer signs SHA-256 digests with a P-256 key and exposes the public half.
type Signer interface {
	// KeyID is the JWT "kid" for this key.
	KeyID() string
	// Public returns the P-256 public key for JWKS and verification.
	Public() *ecdsa.PublicKey
	// Sign returns the 64-byte raw r||s signature over a 32-byte digest.
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// Ring is an ordered set of signers: the first signs new tokens, all of them
// are published so tokens signed by older keys still verify during rotation.
type Ring struct {
	signers []Signer
	byKID   map[string]Signer
}

// NewRing builds a ring; it needs at least one signer.
func NewRing(signers ...Signer) (*Ring, error) {
	if len(signers) == 0 {
		return nil, errors.New("signer: ring needs at least one key")
	}
	r := &Ring{signers: signers, byKID: make(map[string]Signer, len(signers))}
	for _, s := range signers {
		if _, dup := r.byKID[s.KeyID()]; dup {
			return nil, fmt.Errorf("signer: duplicate kid %q", s.KeyID())
		}
		r.byKID[s.KeyID()] = s
	}
	return r, nil
}

// Active is the signer used for new tokens.
func (r *Ring) Active() Signer { return r.signers[0] }

// Lookup finds the public key for a kid; nil when unknown.
func (r *Ring) Lookup(kid string) *ecdsa.PublicKey {
	if s, ok := r.byKID[kid]; ok {
		return s.Public()
	}
	return nil
}

// All returns every signer in ring order.
func (r *Ring) All() []Signer { return r.signers }

// Local is an in-memory P-256 key for dev and tests.
type Local struct {
	kid string
	key *ecdsa.PrivateKey
}

// NewLocal generates a fresh key with the given kid.
func NewLocal(kid string) (*Local, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Local{kid: kid, key: key}, nil
}

func (l *Local) KeyID() string            { return l.kid }
func (l *Local) Public() *ecdsa.PublicKey { return &l.key.PublicKey }

func (l *Local) Sign(_ context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("signer: digest must be 32 bytes, got %d", len(digest))
	}
	der, err := ecdsa.SignASN1(rand.Reader, l.key, digest)
	if err != nil {
		return nil, err
	}
	return DERToRaw(der)
}

// DERToRaw converts an ASN.1 DER ECDSA signature into the fixed-size r||s
// form JOSE requires for ES256 (32 bytes each).
func DERToRaw(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("signer: bad DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("signer: trailing bytes in DER signature")
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}
