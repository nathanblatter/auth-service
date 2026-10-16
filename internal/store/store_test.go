package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// conformance runs the same scenario against any Store.
func conformance(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	svc := Service{ID: "svc_a", Slug: "finforge", Name: "FinForge", Status: "active", CreatedAt: now}
	if err := s.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	dup := svc
	dup.ID = "svc_b"
	if err := s.CreateService(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Fatalf("slug reuse: got %v want ErrConflict", err)
	}
	got, err := s.GetService(ctx, "svc_a")
	if err != nil || got.Slug != "finforge" || !got.CreatedAt.Equal(now) {
		t.Fatalf("GetService: %+v %v", got, err)
	}
	if _, err := s.GetService(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing service: %v", err)
	}
	all, err := s.ListServices(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("ListServices: %v %v", all, err)
	}

	c1 := Credential{ID: "c1", ServiceID: "svc_a", Hash: "h1", Last4: "1111", CreatedAt: now}
	c2 := Credential{ID: "c2", ServiceID: "svc_a", Hash: "h2", Last4: "2222", CreatedAt: now.Add(time.Second)}
	for _, c := range []Credential{c1, c2} {
		if err := s.PutCredential(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutCredential(ctx, c1); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup credential: %v", err)
	}
	gc, err := s.GetCredential(ctx, "c2")
	if err != nil || gc.ServiceID != "svc_a" || gc.Hash != "h2" || gc.Revoked() {
		t.Fatalf("GetCredential: %+v %v", gc, err)
	}
	list, err := s.ListCredentials(ctx, "svc_a")
	if err != nil || len(list) != 2 || list[0].ID != "c1" {
		t.Fatalf("ListCredentials: %+v %v", list, err)
	}
	if err := s.RevokeCredential(ctx, "svc_a", "c1", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Revoking twice keeps the first timestamp.
	if err := s.RevokeCredential(ctx, "svc_a", "c1", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	gc, err = s.GetCredential(ctx, "c1")
	if err != nil || !gc.Revoked() || !gc.RevokedAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("revoked: %+v %v", gc, err)
	}
	if err := s.RevokeCredential(ctx, "svc_a", "ghost", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
	if err := s.RevokeCredential(ctx, "svc_other", "c2", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke across service: %v", err)
	}
	if err := s.AppendAudit(ctx, AuditEvent{At: now, Kind: "credential.mint", Actor: "admin", ServiceID: "svc_a"}); err != nil {
		t.Fatal(err)
	}

	// Passkeys.
	pk := Passkey{ID: "cred-1", Name: "iPhone", CreatedAt: now, Data: []byte(`{"id":"x"}`)}
	if err := s.PutPasskey(ctx, pk); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPasskey(ctx, pk); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup passkey: %v", err)
	}
	pk.Data = []byte(`{"id":"x","signCount":2}`)
	if err := s.UpdatePasskey(ctx, pk); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdatePasskey(ctx, Passkey{ID: "ghost", Data: []byte("{}")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing passkey: %v", err)
	}
	pks, err := s.ListPasskeys(ctx)
	if err != nil || len(pks) != 1 || string(pks[0].Data) != `{"id":"x","signCount":2}` || pks[0].Name != "iPhone" {
		t.Fatalf("ListPasskeys: %+v %v", pks, err)
	}

	// Challenges are single use and expire.
	if err := s.PutChallenge(ctx, "ch1", []byte("data"), now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	data, err := s.ConsumeChallenge(ctx, "ch1", now)
	if err != nil || string(data) != "data" {
		t.Fatalf("consume: %s %v", data, err)
	}
	if _, err := s.ConsumeChallenge(ctx, "ch1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume: %v", err)
	}
	if err := s.PutChallenge(ctx, "ch2", []byte("late"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeChallenge(ctx, "ch2", now.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired challenge accepted: %v", err)
	}

	// Sessions expire and can be deleted.
	sess := Session{Hash: "h1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), IP: "1.2.3.4"}
	if err := s.PutSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	gs, err := s.GetSession(ctx, "h1", now.Add(30*time.Minute))
	if err != nil || gs.IP != "1.2.3.4" || !gs.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("GetSession: %+v %v", gs, err)
	}
	if _, err := s.GetSession(ctx, "h1", now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}
	if err := s.DeleteSession(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "h1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session: %v", err)
	}
}

func TestMemory(t *testing.T) { conformance(t, NewMemory()) }

// TestDynamoLocal runs against DynamoDB Local when AUTH_TEST_DYNAMO_ENDPOINT
// is set (docker compose up). It creates a fresh table per run.
func TestDynamoLocal(t *testing.T) {
	ep := os.Getenv("AUTH_TEST_DYNAMO_ENDPOINT")
	if ep == "" {
		t.Skip("AUTH_TEST_DYNAMO_ENDPOINT unset")
	}
	ctx := context.Background()
	client := dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
		BaseEndpoint: aws.String(ep),
	})
	table := "auth-test-" + time.Now().UTC().Format("20060102150405")
	if err := CreateTable(ctx, client, table); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: &table})
	})
	conformance(t, NewDynamo(client, table))
}
