package jwt

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/auth-service/internal/signer"
)

func newRing(t *testing.T, kids ...string) *signer.Ring {
	t.Helper()
	var ss []signer.Signer
	for _, k := range kids {
		s, err := signer.NewLocal(k)
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, s)
	}
	r, err := signer.NewRing(ss...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRoundTrip(t *testing.T) {
	ring := newRing(t, "k1")
	now := time.Unix(1_800_000_000, 0)
	c := Claims{Issuer: "https://auth.test", Subject: "svc:abc", Audience: "auth", Scope: "a b",
		IssuedAt: now.Unix(), Expires: now.Add(15 * time.Minute).Unix()}
	tok, err := Sign(context.Background(), ring.Active(), c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(tok, ring.Lookup, now.Add(time.Minute), "https://auth.test", "auth")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "svc:abc" || got.Scope != "a b" || got.ID == "" {
		t.Fatalf("claims mismatch: %+v", got)
	}
}

func TestRejects(t *testing.T) {
	ring := newRing(t, "k1")
	other := newRing(t, "k1") // same kid, different key: signature must fail
	now := time.Unix(1_800_000_000, 0)
	c := Claims{Issuer: "iss", Subject: "s", Audience: "aud", IssuedAt: now.Unix(), Expires: now.Add(time.Minute).Unix()}
	tok, err := Sign(context.Background(), ring.Active(), c)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		token  string
		lookup func(string) *ecdsa.PublicKey
		now    time.Time
		iss    string
		aud    string
		want   error
	}{
		{"ok", tok, ring.Lookup, now, "iss", "aud", nil},
		{"expired", tok, ring.Lookup, now.Add(2 * time.Minute), "iss", "aud", ErrExpired},
		{"wrong key", tok, other.Lookup, now, "iss", "aud", ErrSignature},
		{"unknown kid", tok, func(string) *ecdsa.PublicKey { return nil }, now, "iss", "aud", ErrUnknownKey},
		{"issuer", tok, ring.Lookup, now, "nope", "aud", ErrIssuer},
		{"audience", tok, ring.Lookup, now, "iss", "nope", ErrAudience},
		{"tampered", tamper(tok), ring.Lookup, now, "iss", "aud", ErrSignature},
		{"garbage", "a.b", ring.Lookup, now, "iss", "aud", ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.token, tc.lookup, tc.now, tc.iss, tc.aud)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestAlgNoneRejected(t *testing.T) {
	ring := newRing(t, "k1")
	hdr := b64([]byte(`{"alg":"none","kid":"k1"}`))
	body := b64([]byte(`{"iss":"iss","sub":"s","aud":"aud","exp":9999999999}`))
	_, err := Verify(hdr+"."+body+".", ring.Lookup, time.Now(), "iss", "aud")
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("alg=none accepted: %v", err)
	}
}

func TestJWKSRotation(t *testing.T) {
	ring := newRing(t, "new", "old")
	ks := BuildJWKS(ring)
	if len(ks.Keys) != 2 || ks.Keys[0].Kid != "new" || ks.Keys[1].Kid != "old" {
		t.Fatalf("jwks order wrong: %+v", ks)
	}
	if ring.Active().KeyID() != "new" {
		t.Fatal("first key must sign")
	}
}

// tamper flips a character in the payload.
func tamper(tok string) string {
	parts := strings.Split(tok, ".")
	p := []byte(parts[1])
	if p[0] == 'A' {
		p[0] = 'B'
	} else {
		p[0] = 'A'
	}
	return parts[0] + "." + string(p) + "." + parts[2]
}
