package users

import (
	"context"
	"errors"
	"testing"

	"github.com/nathanblatter/squawk/internal/store"
)

func TestOrgs(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	alice, _ := u.Create(ctx, svc, "alice@x.test", "Alice")
	bob, _ := u.Create(ctx, svc, "bob@x.test", "Bob")

	ownerOnly := store.Service{ID: "svc_o", Slug: "o", Name: "O", Status: "active", CreatedAt: u.Now()}
	_ = mem.CreateService(ctx, ownerOnly)
	if _, err := u.CreateOrg(ctx, ownerOnly, "Practice", alice.ID); !errors.Is(err, ErrNotUserPool) {
		t.Fatalf("owner-only service: %v", err)
	}
	if _, err := u.CreateOrg(ctx, svc, "   ", alice.ID); !errors.Is(err, ErrInvalidOrgName) {
		t.Fatalf("blank name: %v", err)
	}
	if _, err := u.CreateOrg(ctx, svc, "Practice", "usr_ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown creator: %v", err)
	}
	org, err := u.CreateOrg(ctx, svc, "  Sunny Practice ", alice.ID)
	if err != nil || org.Name != "Sunny Practice" || org.Status != "active" || org.ServiceID != svc.ID {
		t.Fatalf("create: %+v %v", org, err)
	}
	// The creator is the first admin.
	if ms, err := u.ListMembers(ctx, svc.ID, org.ID); err != nil || len(ms) != 1 || ms[0].UserID != alice.ID || ms[0].Role != OrgRoleAdmin || ms[0].User.Email != "alice@x.test" {
		t.Fatalf("first admin: %+v %v", ms, err)
	}
	// The last admin cannot be demoted or removed.
	if _, err := u.SetMember(ctx, svc.ID, org.ID, alice.ID, OrgRoleMember); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := u.RemoveMember(ctx, svc.ID, org.ID, alice.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("remove last admin: %v", err)
	}
	if _, err := u.SetMember(ctx, svc.ID, org.ID, bob.ID, "boss"); !errors.Is(err, ErrInvalidOrgRole) {
		t.Fatalf("bad role: %v", err)
	}
	if _, err := u.SetMember(ctx, svc.ID, org.ID, "usr_ghost", OrgRoleMember); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown member: %v", err)
	}
	if _, err := u.SetMember(ctx, svc.ID, "org_ghost", bob.ID, OrgRoleMember); !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("unknown org: %v", err)
	}
	if m, err := u.SetMember(ctx, svc.ID, org.ID, bob.ID, OrgRoleMember); err != nil || m.Role != OrgRoleMember {
		t.Fatalf("add bob: %+v %v", m, err)
	}
	// Promote bob, then alice may step down.
	if m, err := u.SetMember(ctx, svc.ID, org.ID, bob.ID, OrgRoleAdmin); err != nil || m.Role != OrgRoleAdmin {
		t.Fatalf("promote bob: %+v %v", m, err)
	}
	if m, err := u.SetMember(ctx, svc.ID, org.ID, alice.ID, OrgRoleMember); err != nil || m.Role != OrgRoleMember {
		t.Fatalf("demote alice: %+v %v", m, err)
	}
	if err := u.RemoveMember(ctx, svc.ID, org.ID, alice.ID); err != nil {
		t.Fatalf("remove alice: %v", err)
	}
	if err := u.RemoveMember(ctx, svc.ID, org.ID, alice.ID); !errors.Is(err, ErrNotMember) {
		t.Fatalf("remove twice: %v", err)
	}
	if orgs, err := u.UserOrgs(ctx, svc.ID, alice.ID); err != nil || len(orgs) != 0 {
		t.Fatalf("alice orgs: %+v %v", orgs, err)
	}
	if orgs, err := u.UserOrgs(ctx, svc.ID, bob.ID); err != nil || len(orgs) != 1 || orgs[0].ID != org.ID || orgs[0].Role != OrgRoleAdmin || orgs[0].Name != "Sunny Practice" {
		t.Fatalf("bob orgs: %+v %v", orgs, err)
	}
	name, status := "Sunny", "disabled"
	if got, err := u.UpdateOrg(ctx, svc.ID, org.ID, &name, &status); err != nil || got.Name != "Sunny" || got.Status != "disabled" {
		t.Fatalf("update: %+v %v", got, err)
	}
	bad := "gone"
	if _, err := u.UpdateOrg(ctx, svc.ID, org.ID, nil, &bad); err == nil {
		t.Fatal("bad status accepted")
	}
	exp, err := u.Export(ctx, svc.ID, bob.ID)
	if err != nil || len(exp.Orgs) != 1 || exp.Orgs[0].ID != org.ID {
		t.Fatalf("export orgs: %+v %v", exp.Orgs, err)
	}
	// Deleting the only admin leaves the org; deleting the org clears memberships.
	if err := u.Delete(ctx, svc.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if ms, _ := u.ListMembers(ctx, svc.ID, org.ID); len(ms) != 0 {
		t.Fatalf("members after delete: %+v", ms)
	}
	if err := u.DeleteOrg(ctx, svc.ID, org.ID); err != nil {
		t.Fatal(err)
	}
	if err := u.DeleteOrg(ctx, svc.ID, org.ID); !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if list, next, err := u.ListOrgs(ctx, svc.ID, 10, ""); err != nil || len(list) != 0 || next != "" {
		t.Fatalf("list after delete: %+v %q %v", list, next, err)
	}
	kinds := map[string]int{}
	for _, e := range mem.Audit {
		kinds[e.Kind]++
	}
	for _, k := range []string{"org.create", "org.member.set", "org.member.remove", "org.update", "org.delete"} {
		if kinds[k] == 0 {
			t.Fatalf("missing audit %s: %v", k, kinds)
		}
	}
}
