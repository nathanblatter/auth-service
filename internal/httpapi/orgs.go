package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nathanblatter/squawk/internal/store"
	"github.com/nathanblatter/squawk/internal/users"
)

// Teams and organisations (auth-service-15), driven by the product's backend
// with its service token. The product decides who may call these (normally
// an org admin, judged by the org_role in the caller's token); Squawk keeps
// the records consistent and puts the org context into tokens.

func (s *Server) orgRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/orgs", s.requireService(s.createOrg))
	mux.HandleFunc("GET /v1/orgs", s.requireService(s.listOrgs))
	mux.HandleFunc("GET /v1/orgs/{id}", s.requireService(s.getOrg))
	mux.HandleFunc("PATCH /v1/orgs/{id}", s.requireService(s.updateOrg))
	mux.HandleFunc("DELETE /v1/orgs/{id}", s.requireService(s.deleteOrg))
	mux.HandleFunc("GET /v1/orgs/{id}/members", s.requireService(s.listOrgMembers))
	mux.HandleFunc("PUT /v1/orgs/{id}/members/{user}", s.requireService(s.setOrgMember))
	mux.HandleFunc("DELETE /v1/orgs/{id}/members/{user}", s.requireService(s.removeOrgMember))
	mux.HandleFunc("GET /v1/users/{id}/orgs", s.requireService(s.userOrgs))
	mux.HandleFunc("GET /admin/services/{id}/orgs", s.requireAdmin(s.adminListOrgs))
	mux.HandleFunc("GET /admin/services/{id}/orgs/{org}/members", s.requireAdmin(s.adminListOrgMembers))
}

func orgJSON(o store.Org) map[string]any {
	return map[string]any{"id": o.ID, "service_id": o.ServiceID, "name": o.Name, "status": o.Status, "created_at": o.CreatedAt.UTC().Format(time.RFC3339)}
}

func memberJSON(m users.Member) map[string]any {
	return map[string]any{"user_id": m.UserID, "role": m.Role, "joined_at": m.CreatedAt.UTC().Format(time.RFC3339),
		"email": m.User.Email, "name": m.User.Name, "status": m.User.Status}
}

func membershipJSON(m users.Membership) map[string]any {
	out := orgJSON(m.Org)
	out["role"] = m.Role
	return out
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Name        string `json:"name"`
		AdminUserID string `json:"admin_user_id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	org, err := s.Users.CreateOrg(r.Context(), svc, in.Name, in.AdminUserID)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 201, orgJSON(org))
}

func pageLimit(r *http.Request) int {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	return limit
}

func (s *Server) writeOrgList(w http.ResponseWriter, r *http.Request, serviceID string) {
	list, next, err := s.Users.ListOrgs(r.Context(), serviceID, pageLimit(r), r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, o := range list {
		out = append(out, orgJSON(o))
	}
	writeJSON(w, 200, map[string]any{"orgs": out, "next": next})
}

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	s.writeOrgList(w, r, svc.ID)
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	org, err := s.Users.GetOrg(r.Context(), svc.ID, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, orgJSON(org))
}

func (s *Server) updateOrg(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Name   *string `json:"name"`
		Status *string `json:"status"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	org, err := s.Users.UpdateOrg(r.Context(), svc.ID, r.PathValue("id"), in.Name, in.Status)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, orgJSON(org))
}

func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.DeleteOrg(r.Context(), svc.ID, r.PathValue("id"))) {
		return
	}
	w.WriteHeader(204)
}

func (s *Server) writeMembers(w http.ResponseWriter, r *http.Request, serviceID, orgID string) {
	members, err := s.Users.ListMembers(r.Context(), serviceID, orgID)
	if s.userFail(w, err) {
		return
	}
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		out = append(out, memberJSON(m))
	}
	writeJSON(w, 200, map[string]any{"members": out})
}

func (s *Server) listOrgMembers(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	s.writeMembers(w, r, svc.ID, r.PathValue("id"))
}

func (s *Server) setOrgMember(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	m, err := s.Users.SetMember(r.Context(), svc.ID, r.PathValue("id"), r.PathValue("user"), in.Role)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"org_id": m.OrgID, "user_id": m.UserID, "role": m.Role, "joined_at": m.CreatedAt.UTC().Format(time.RFC3339)})
}

func (s *Server) removeOrgMember(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.RemoveMember(r.Context(), svc.ID, r.PathValue("id"), r.PathValue("user"))) {
		return
	}
	w.WriteHeader(204)
}

func (s *Server) userOrgs(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	list, err := s.Users.UserOrgs(r.Context(), svc.ID, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, m := range list {
		out = append(out, membershipJSON(m))
	}
	writeJSON(w, 200, map[string]any{"orgs": out})
}

func (s *Server) adminListOrgs(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	s.writeOrgList(w, r, svc.ID)
}

func (s *Server) adminListOrgMembers(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	s.writeMembers(w, r, svc.ID, r.PathValue("org"))
}
