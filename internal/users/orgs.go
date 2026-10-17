package users

import (
	"context"
	"errors"
	"strings"

	"github.com/nathanblatter/squawk/internal/store"
)

// Teams and organisations (auth-service-15). DECIDED (Nathan, 2026-10-17):
// an org lives inside one service, like its users; any user may create one
// through the app and becomes its first admin; members are added directly by
// user id (emailed invites later); a user holds 0..n memberships with an
// org role (admin | member) layered on their service roles; the app asks for
// an org context at login and the token carries org + org_role.
//
// Authority: these calls run under the product's service token, so the
// product decides who may call them (normally: an org admin, checked against
// the org_role in the caller's token). Squawk keeps the records consistent:
// one admin always remains.

const (
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"

	// OrgNameMax bounds an org name.
	OrgNameMax = 80
)

var (
	ErrOrgNotFound    = errors.New("users: org not found")
	ErrInvalidOrgName = errors.New("users: org name must be 1-80 characters")
	ErrInvalidOrgRole = errors.New("users: org role must be admin or member")
	ErrLastAdmin      = errors.New("users: an org must keep at least one admin")
	ErrNotMember      = errors.New("users: not a member of this org")
	ErrOrgDisabled    = errors.New("users: org disabled")
)

func validOrgRole(r string) bool { return r == OrgRoleAdmin || r == OrgRoleMember }

func normalizeOrgName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > OrgNameMax {
		return "", ErrInvalidOrgName
	}
	return name, nil
}

// CreateOrg makes an org under the service with creator as its first admin.
func (u *Users) CreateOrg(ctx context.Context, svc store.Service, name, creatorID string) (store.Org, error) {
	if svc.LoginURL == "" {
		return store.Org{}, ErrNotUserPool
	}
	name, err := normalizeOrgName(name)
	if err != nil {
		return store.Org{}, err
	}
	if _, err := u.Get(ctx, svc.ID, creatorID); err != nil {
		return store.Org{}, err
	}
	org := store.Org{ID: "org_" + randomBase32(16), ServiceID: svc.ID, Name: name, Status: "active", CreatedAt: u.Now()}
	if err := u.Store.CreateOrg(ctx, org); err != nil {
		return store.Org{}, err
	}
	if err := u.Store.PutOrgMember(ctx, store.OrgMember{ServiceID: svc.ID, OrgID: org.ID, UserID: creatorID, Role: OrgRoleAdmin, CreatedAt: org.CreatedAt}); err != nil {
		return store.Org{}, err
	}
	u.audit(ctx, "org.create", svc.ID, creatorID, "org="+org.ID+" name="+name, "")
	return org, nil
}

// GetOrg fetches an org of a service.
func (u *Users) GetOrg(ctx context.Context, serviceID, id string) (store.Org, error) {
	org, err := u.Store.GetOrg(ctx, serviceID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Org{}, ErrOrgNotFound
	}
	return org, err
}

// ListOrgs pages a service's orgs, oldest first.
func (u *Users) ListOrgs(ctx context.Context, serviceID string, limit int, cursor string) ([]store.Org, string, error) {
	return u.Store.ListOrgs(ctx, serviceID, limit, cursor)
}

// UpdateOrg changes the name and/or status.
func (u *Users) UpdateOrg(ctx context.Context, serviceID, id string, name, status *string) (store.Org, error) {
	org, err := u.GetOrg(ctx, serviceID, id)
	if err != nil {
		return store.Org{}, err
	}
	if name != nil {
		if org.Name, err = normalizeOrgName(*name); err != nil {
			return store.Org{}, err
		}
	}
	if status != nil {
		if *status != "active" && *status != "disabled" {
			return store.Org{}, errors.New("users: status must be active or disabled")
		}
		org.Status = *status
	}
	if err := u.Store.UpdateOrg(ctx, org); err != nil {
		return store.Org{}, err
	}
	u.audit(ctx, "org.update", serviceID, "", "org="+org.ID+" name="+org.Name+" status="+org.Status, "")
	return org, nil
}

// DeleteOrg removes the org and every membership. Tokens already carrying
// the org run out within the hour; refreshes drop the org context.
func (u *Users) DeleteOrg(ctx context.Context, serviceID, id string) error {
	if _, err := u.GetOrg(ctx, serviceID, id); err != nil {
		return err
	}
	if err := u.Store.DeleteOrg(ctx, serviceID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrOrgNotFound
		}
		return err
	}
	u.audit(ctx, "org.delete", serviceID, "", "org="+id, "")
	return nil
}

// SetMember adds a user to an org or changes their role. Demoting the last
// admin is refused.
func (u *Users) SetMember(ctx context.Context, serviceID, orgID, userID, role string) (store.OrgMember, error) {
	if !validOrgRole(role) {
		return store.OrgMember{}, ErrInvalidOrgRole
	}
	if _, err := u.GetOrg(ctx, serviceID, orgID); err != nil {
		return store.OrgMember{}, err
	}
	if _, err := u.Get(ctx, serviceID, userID); err != nil {
		return store.OrgMember{}, err
	}
	if role == OrgRoleMember {
		if err := u.ensureAnotherAdmin(ctx, serviceID, orgID, userID); err != nil {
			return store.OrgMember{}, err
		}
	}
	m := store.OrgMember{ServiceID: serviceID, OrgID: orgID, UserID: userID, Role: role, CreatedAt: u.Now()}
	if err := u.Store.PutOrgMember(ctx, m); err != nil {
		return store.OrgMember{}, err
	}
	m, err := u.Store.GetOrgMember(ctx, serviceID, orgID, userID)
	if err != nil {
		return store.OrgMember{}, err
	}
	u.audit(ctx, "org.member.set", serviceID, userID, "org="+orgID+" role="+role, "")
	return m, nil
}

// RemoveMember takes a user out of an org. Removing the last admin is refused;
// delete the org instead.
func (u *Users) RemoveMember(ctx context.Context, serviceID, orgID, userID string) error {
	if _, err := u.GetOrg(ctx, serviceID, orgID); err != nil {
		return err
	}
	if err := u.ensureAnotherAdmin(ctx, serviceID, orgID, userID); err != nil {
		return err
	}
	if err := u.Store.DeleteOrgMember(ctx, serviceID, orgID, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotMember
		}
		return err
	}
	u.audit(ctx, "org.member.remove", serviceID, userID, "org="+orgID, "")
	return nil
}

// ensureAnotherAdmin refuses when userID is currently the only admin.
func (u *Users) ensureAnotherAdmin(ctx context.Context, serviceID, orgID, userID string) error {
	cur, err := u.Store.GetOrgMember(ctx, serviceID, orgID, userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && cur.Role != OrgRoleAdmin) {
		return nil // not an admin today, nothing to protect
	}
	if err != nil {
		return err
	}
	members, err := u.Store.ListOrgMembers(ctx, serviceID, orgID)
	if err != nil {
		return err
	}
	for _, m := range members {
		if m.Role == OrgRoleAdmin && m.UserID != userID {
			return nil
		}
	}
	return ErrLastAdmin
}

// Member is a membership joined with the user's account.
type Member struct {
	store.OrgMember
	User store.User
}

// ListMembers returns an org's members with their accounts (a deleted user
// leaves no row, so every membership resolves).
func (u *Users) ListMembers(ctx context.Context, serviceID, orgID string) ([]Member, error) {
	if _, err := u.GetOrg(ctx, serviceID, orgID); err != nil {
		return nil, err
	}
	ms, err := u.Store.ListOrgMembers(ctx, serviceID, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(ms))
	for _, m := range ms {
		user, err := u.Store.GetUser(ctx, serviceID, m.UserID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Member{OrgMember: m, User: user})
	}
	return out, nil
}

// Membership is an org joined with the user's role in it.
type Membership struct {
	store.Org
	Role string
}

// UserOrgs lists the orgs a user belongs to, with their role in each.
func (u *Users) UserOrgs(ctx context.Context, serviceID, userID string) ([]Membership, error) {
	if _, err := u.Get(ctx, serviceID, userID); err != nil {
		return nil, err
	}
	return u.memberships(ctx, serviceID, userID)
}

func (u *Users) memberships(ctx context.Context, serviceID, userID string) ([]Membership, error) {
	ms, err := u.Store.ListUserOrgs(ctx, serviceID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Membership, 0, len(ms))
	for _, m := range ms {
		org, err := u.Store.GetOrg(ctx, serviceID, m.OrgID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Membership{Org: org, Role: m.Role})
	}
	return out, nil
}
