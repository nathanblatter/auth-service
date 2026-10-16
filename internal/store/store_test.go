package store

import (
	"context"
	"errors"
	"fmt"
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

	// Failure counters: count inside the window, forget after it.
	if n, err := s.FailureCount(ctx, "token:ip:1.1.1.1", now); err != nil || n != 0 {
		t.Fatalf("fresh counter: %d %v", n, err)
	}
	for i := 1; i <= 3; i++ {
		if n, err := s.RecordFailure(ctx, "token:ip:1.1.1.1", now, 10*time.Minute); err != nil || n != i {
			t.Fatalf("record %d: %d %v", i, n, err)
		}
	}
	if n, _ := s.FailureCount(ctx, "token:ip:1.1.1.1", now.Add(9*time.Minute)); n != 3 {
		t.Fatalf("count in window: %d", n)
	}
	if n, _ := s.FailureCount(ctx, "token:ip:1.1.1.1", now.Add(11*time.Minute)); n != 0 {
		t.Fatalf("count after window: %d", n)
	}
	if n, err := s.RecordFailure(ctx, "token:ip:1.1.1.1", now.Add(11*time.Minute), 10*time.Minute); err != nil || n != 1 {
		t.Fatalf("new window restarts at 1: %d %v", n, err)
	}

	// Audit reader: newest first, paginated, per month.
	for i := 0; i < 5; i++ {
		_ = s.AppendAudit(ctx, AuditEvent{At: now.Add(time.Duration(i) * time.Minute), Kind: fmt.Sprintf("k%d", i), Actor: "admin"})
	}
	_ = s.AppendAudit(ctx, AuditEvent{At: now.AddDate(0, -1, 0), Kind: "lastmonth", Actor: "admin"})
	page1, next, err := s.ListAudit(ctx, now.Format("2006-01"), 4, "")
	if err != nil || len(page1) != 4 || next == "" || page1[0].Kind != "k4" || page1[3].Kind != "k1" {
		t.Fatalf("audit page1: %+v next=%q %v", kinds(page1), next, err)
	}
	page2, next2, err := s.ListAudit(ctx, now.Format("2006-01"), 4, next)
	// 2 = k0 plus the credential.mint written earlier in this test; both carry
	// the same timestamp so their relative order is not defined.
	if err != nil || len(page2) != 2 || next2 != "" || (page2[0].Kind != "k0" && page2[1].Kind != "k0") {
		t.Fatalf("audit page2: %+v next=%q %v", kinds(page2), next2, err)
	}
	if lm, _, _ := s.ListAudit(ctx, now.AddDate(0, -1, 0).Format("2006-01"), 10, ""); len(lm) != 1 || lm[0].Kind != "lastmonth" {
		t.Fatalf("audit other month: %+v", kinds(lm))
	}

	// Owner not-before.
	if nb, err := s.GetOwnerNotBefore(ctx); err != nil || !nb.IsZero() {
		t.Fatalf("not-before default: %v %v", nb, err)
	}
	if err := s.SetOwnerNotBefore(ctx, now); err != nil {
		t.Fatal(err)
	}
	if nb, err := s.GetOwnerNotBefore(ctx); err != nil || !nb.Equal(now) {
		t.Fatalf("not-before: %v %v", nb, err)
	}

	// Permissions catalog.
	if err := s.UpdateServicePermissions(ctx, "svc_a", []string{"read", "write"}, map[string][]string{"admin": {"read", "write"}, "user": {"read"}}); err != nil {
		t.Fatal(err)
	}
	if ps, _ := s.GetService(ctx, "svc_a"); len(ps.Scopes) != 2 || len(ps.Roles["admin"]) != 2 || len(ps.Roles["user"]) != 1 {
		t.Fatalf("permissions: %+v", ps)
	}
	if err := s.UpdateServicePermissions(ctx, "svc_a", nil, map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	if ps, _ := s.GetService(ctx, "svc_a"); len(ps.Scopes) != 0 || len(ps.Roles) != 0 {
		t.Fatalf("cleared permissions: %+v", ps)
	}
	if err := s.UpdateServicePermissions(ctx, "svc_missing", []string{"x"}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("permissions on missing service: %v", err)
	}

	// Resources map to services, uniquely.
	if err := s.AddServiceResource(ctx, "svc_a", "https://finforge.test/mcp"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddServiceResource(ctx, "svc_a", "https://finforge.test/mcp"); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup resource: %v", err)
	}
	if err := s.AddServiceResource(ctx, "svc_missing", "https://other.test/mcp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resource on missing service: %v", err)
	}
	if svc, err := s.GetServiceByResource(ctx, "https://finforge.test/mcp"); err != nil || svc.ID != "svc_a" || len(svc.Resources) != 1 {
		t.Fatalf("GetServiceByResource: %+v %v", svc, err)
	}
	if _, err := s.GetServiceByResource(ctx, "https://nope.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown resource: %v", err)
	}

	// OAuth clients.
	cl := OAuthClient{ID: "nbc_1", Name: "Claude", SecretHash: "sh", AuthMethod: "client_secret_basic", RedirectURIs: []string{"https://claude.ai/cb"}, CreatedAt: now}
	if err := s.CreateOAuthClient(ctx, cl); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOAuthClient(ctx, cl); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup client: %v", err)
	}
	if gcl, err := s.GetOAuthClient(ctx, "nbc_1"); err != nil || gcl.Name != "Claude" || len(gcl.RedirectURIs) != 1 || gcl.SecretHash != "sh" {
		t.Fatalf("GetOAuthClient: %+v %v", gcl, err)
	}
	if _, err := s.GetOAuthClient(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown client: %v", err)
	}

	// Authorization requests expire and can be deleted.
	az := AuthzRequest{ID: "az1", ClientID: "nbc_1", RedirectURI: "https://claude.ai/cb", State: "st", Scope: "read", Challenge: "ch",
		Resource: "https://finforge.test/mcp", ServiceID: "svc_a", ExpiresAt: now.Add(10 * time.Minute)}
	if err := s.PutAuthzRequest(ctx, az); err != nil {
		t.Fatal(err)
	}
	if gaz, err := s.GetAuthzRequest(ctx, "az1", now); err != nil || gaz.ServiceID != "svc_a" || gaz.State != "st" {
		t.Fatalf("GetAuthzRequest: %+v %v", gaz, err)
	}
	if _, err := s.GetAuthzRequest(ctx, "az1", now.Add(11*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired authz: %v", err)
	}
	if err := s.DeleteAuthzRequest(ctx, "az1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAuthzRequest(ctx, "az1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted authz: %v", err)
	}

	// Codes are single use.
	code := Code{ClientID: "nbc_1", RedirectURI: "https://claude.ai/cb", Challenge: "ch", Scope: "read", Subject: "owner", ServiceID: "svc_a", ExpiresAt: now.Add(10 * time.Minute)}
	if err := s.CreateCode(ctx, "codehash", code); err != nil {
		t.Fatal(err)
	}
	if gc, err := s.ConsumeCode(ctx, "codehash", now); err != nil || gc.Subject != "owner" || gc.ServiceID != "svc_a" {
		t.Fatalf("ConsumeCode: %+v %v", gc, err)
	}
	if _, err := s.ConsumeCode(ctx, "codehash", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("code reuse: %v", err)
	}
	_ = s.CreateCode(ctx, "late", code)
	if _, err := s.ConsumeCode(ctx, "late", now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired code: %v", err)
	}

	// Refresh tokens: rotate once, detect replay, revoke the family.
	rt := RefreshToken{Hash: "r1", Family: "fam", ClientID: "nbc_1", ServiceID: "svc_a", Subject: "owner", Scope: "read", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	if err := s.CreateRefresh(ctx, rt); err != nil {
		t.Fatal(err)
	}
	got1, reused, err := s.ConsumeRefresh(ctx, "r1", now)
	if err != nil || reused || got1.Family != "fam" || !got1.Used || !got1.IssuedAt.Equal(now) {
		t.Fatalf("first consume: %+v reused=%v %v", got1, reused, err)
	}
	got2, reused, err := s.ConsumeRefresh(ctx, "r1", now)
	if err != nil || !reused || got2.Family != "fam" {
		t.Fatalf("replay must report reused: %+v reused=%v %v", got2, reused, err)
	}
	if _, _, err := s.ConsumeRefresh(ctx, "ghost", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown refresh: %v", err)
	}
	rt2 := rt
	rt2.Hash = "r2"
	_ = s.CreateRefresh(ctx, rt2)
	if _, _, err := s.ConsumeRefresh(ctx, "r2", now.Add(48*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired refresh: %v", err)
	}
	if err := s.RevokeRefreshFamily(ctx, "fam"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ConsumeRefresh(ctx, "r1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("family not revoked: %v", err)
	}

	// Recovery codes: replace wipes, consume is single use.
	if err := s.ReplaceRecoveryCodes(ctx, []string{"rc1", "rc2"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeRecoveryCode(ctx, "rc1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeRecoveryCode(ctx, "rc1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recovery code reuse: %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, "ghost", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown recovery code: %v", err)
	}
	rcs, err := s.ListRecoveryCodes(ctx)
	if err != nil || len(rcs) != 2 {
		t.Fatalf("ListRecoveryCodes: %+v %v", rcs, err)
	}
	used := 0
	for _, c := range rcs {
		if c.UsedAt != nil {
			used++
		}
	}
	if used != 1 {
		t.Fatalf("used count: %d", used)
	}
	if err := s.ReplaceRecoveryCodes(ctx, []string{"rc3"}, now); err != nil {
		t.Fatal(err)
	}
	if rcs, _ := s.ListRecoveryCodes(ctx); len(rcs) != 1 || rcs[0].Hash != "rc3" {
		t.Fatalf("replace did not wipe: %+v", rcs)
	}

	// Sessions expire and can be deleted.
	sess := Session{Hash: "h1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), IP: "1.2.3.4", Method: "recovery"}
	if err := s.PutSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	gs, err := s.GetSession(ctx, "h1", now.Add(30*time.Minute))
	if err != nil || gs.IP != "1.2.3.4" || gs.Method != "recovery" || !gs.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("GetSession: %+v %v", gs, err)
	}
	if err := s.TouchSessionVerified(ctx, "h1", now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if gs, _ := s.GetSession(ctx, "h1", now.Add(30*time.Minute)); !gs.VerifiedAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("verified_at: %v", gs.VerifiedAt)
	}
	if err := s.TouchSessionVerified(ctx, "ghost", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("touch missing session: %v", err)
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

func kinds(es []AuditEvent) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Kind)
	}
	return out
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
