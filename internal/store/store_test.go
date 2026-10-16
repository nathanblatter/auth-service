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
