package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nathanblatter/auth-service/internal/core"
	"github.com/nathanblatter/auth-service/internal/oauth"
	"github.com/nathanblatter/auth-service/internal/ratelimit"
	"github.com/nathanblatter/auth-service/internal/store"
	"github.com/nathanblatter/auth-service/internal/users"
)

// Slice 3: end-user accounts and login, driven by a product's backend with
// its service token. The product owns the screens; these endpoints own the
// ceremonies and the records.

func (s *Server) userRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/users", s.requireService(s.createUser))
	mux.HandleFunc("GET /v1/users", s.requireService(s.listUsers))
	mux.HandleFunc("GET /v1/users/{id}", s.requireService(s.getUser))
	mux.HandleFunc("PATCH /v1/users/{id}", s.requireService(s.updateUser))
	mux.HandleFunc("POST /v1/users/{id}/logout-everywhere", s.requireService(s.userLogoutEverywhere))
	mux.HandleFunc("DELETE /v1/users/{id}", s.requireService(s.deleteUser))
	mux.HandleFunc("GET /v1/users/{id}/export", s.requireService(s.exportUser))
	mux.HandleFunc("GET /v1/users/{id}/passkeys", s.requireService(s.listUserPasskeys))
	mux.HandleFunc("POST /v1/users/{id}/passkeys/begin", s.requireService(s.userPasskeyBegin))
	mux.HandleFunc("POST /v1/users/{id}/passkeys/finish", s.requireService(s.userPasskeyFinish))
	mux.HandleFunc("POST /v1/login/passkey/begin", s.requireService(s.loginPasskeyBegin))
	mux.HandleFunc("POST /v1/login/passkey/finish", s.requireService(s.loginPasskeyFinish))
	mux.HandleFunc("GET /v1/login/google/start", s.googleStart)
	mux.HandleFunc("GET /v1/login/google/callback", s.googleCallback)
	mux.HandleFunc("PUT /admin/services/{id}/login", s.requireAdmin(s.setLogin))
	mux.HandleFunc("POST /admin/services/{id}/users", s.requireAdmin(s.adminCreateUser))
	mux.HandleFunc("GET /admin/services/{id}/users", s.requireAdmin(s.adminListUsers))
}

// callerService loads the service behind the request's service token.
func (s *Server) callerService(w http.ResponseWriter, r *http.Request) (store.Service, bool) {
	id, _ := serviceFrom(r)
	svc, err := s.Core.GetService(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return store.Service{}, false
	}
	return svc, true
}

// userFail maps users-package errors to responses; returns true when it wrote.
func (s *Server) userFail(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, users.ErrUserNotFound):
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	case errors.Is(err, users.ErrIdentityTaken):
		writeJSON(w, 409, map[string]string{"error": "identity_taken"})
	case errors.Is(err, users.ErrNotUserPool), errors.Is(err, users.ErrNoWebAuthn):
		writeJSON(w, 409, map[string]string{"error": "service_not_configured", "detail": err.Error()})
	case errors.Is(err, users.ErrInvalidEmail), errors.Is(err, users.ErrInvalidRole), errors.Is(err, users.ErrWrongMethod), errors.Is(err, users.ErrInvalidMethod):
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": err.Error()})
	case errors.Is(err, users.ErrSignupClosed):
		writeJSON(w, 403, map[string]string{"error": "signup_closed", "detail": "this service does not accept sign-ups; the owner creates accounts"})
	case errors.Is(err, users.ErrDisabled):
		writeJSON(w, 403, map[string]string{"error": "account_disabled"})
	case errors.Is(err, users.ErrEmailUnverified):
		writeJSON(w, 403, map[string]string{"error": "email_unverified"})
	default:
		s.fail(w, err)
	}
	return true
}

func userJSON(u store.User) map[string]any {
	roles := u.Roles
	if roles == nil {
		roles = []string{}
	}
	out := map[string]any{"id": u.ID, "service_id": u.ServiceID, "method": u.Method, "email": u.Email, "name": u.Name,
		"roles": roles, "status": u.Status, "created_at": u.CreatedAt.UTC().Format(time.RFC3339)}
	return out
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct{ Email, Name string }
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Users.Create(r.Context(), svc, in.Email, in.Name)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 201, userJSON(u))
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	list, next, err := s.Users.List(r.Context(), svc.ID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, userJSON(u))
	}
	writeJSON(w, 200, map[string]any{"users": out, "next": next})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	u, err := s.Users.Get(r.Context(), svc.ID, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, userJSON(u))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Roles  *[]string
		Status *string
		Name   *string
	}
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Users.Update(r.Context(), svc, r.PathValue("id"), in.Roles, in.Status, in.Name)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, userJSON(u))
}

func (s *Server) userLogoutEverywhere(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.LogoutEverywhere(r.Context(), svc.ID, r.PathValue("id"))) {
		return
	}
	w.WriteHeader(204)
}

// deleteUser is permanent (auth-service-13). The product is responsible for
// its own confirmation / step-up before calling it.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.Delete(r.Context(), svc.ID, r.PathValue("id"))) {
		return
	}
	w.WriteHeader(204)
}

func (s *Server) exportUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	exp, err := s.Users.Export(r.Context(), svc.ID, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+exp.User.ID+`-export.json"`)
	writeJSON(w, 200, exp)
}

func (s *Server) listUserPasskeys(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if _, err := s.Users.Get(r.Context(), svc.ID, r.PathValue("id")); s.userFail(w, err) {
		return
	}
	keys, err := s.Users.Store.ListUserPasskeys(r.Context(), svc.ID, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"id": k.ID, "name": k.Name, "created_at": k.CreatedAt.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, 200, map[string]any{"passkeys": out})
}

func (s *Server) userPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	opts, chID, err := s.Users.BeginRegisterPasskey(r.Context(), svc, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "options": opts})
}

func (s *Server) userPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	q := r.URL.Query()
	pk, err := s.Users.FinishRegisterPasskey(r.Context(), svc, q.Get("challenge"), q.Get("name"), r)
	if errors.Is(err, users.ErrCeremony) {
		writeJSON(w, 400, map[string]string{"error": "passkey_rejected"})
		return
	}
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 201, map[string]any{"id": pk.ID, "name": pk.Name, "user_id": pk.UserID, "created_at": pk.CreatedAt.UTC().Format(time.RFC3339)})
}

// pendingFor validates a login_challenge against the calling service.
func (s *Server) pendingFor(w http.ResponseWriter, r *http.Request, svc store.Service, authzID string) bool {
	p, err := s.OAuth.Pending(r.Context(), authzID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && p.Service.ID != svc.ID) {
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "login_challenge is unknown, expired, or belongs to another service"})
		return false
	}
	if err != nil {
		s.fail(w, err)
		return false
	}
	return true
}

func (s *Server) loginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		LoginChallenge string `json:"login_challenge"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !s.pendingFor(w, r, svc, in.LoginChallenge) {
		return
	}
	opts, chID, err := s.Users.BeginLoginPasskey(r.Context(), svc, in.LoginChallenge)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "options": opts})
}

func (s *Server) loginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	user, authzID, err := s.Users.FinishLoginPasskey(r.Context(), svc, r.URL.Query().Get("challenge"), r)
	if errors.Is(err, users.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
		writeJSON(w, 401, map[string]string{"error": "passkey_rejected"})
		return
	}
	if s.userFail(w, err) {
		return
	}
	loc, err := s.OAuth.CompleteForUser(r.Context(), authzID, user, users.AllowedScopes(svc, user), clientIP(r))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "login_challenge expired; start over"})
		return
	}
	if s.oauthFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"redirect_to": loc, "user": userJSON(user)})
}

// googleStart is hit by the browser from the product's login page.
func (s *Server) googleStart(w http.ResponseWriter, r *http.Request) {
	if !s.Google.Enabled() {
		writeJSON(w, 404, map[string]string{"error": "google_disabled"})
		return
	}
	authzID := r.URL.Query().Get("login_challenge")
	p, err := s.OAuth.Pending(r.Context(), authzID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && p.Service.LoginURL == "") {
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "login_challenge is unknown or expired"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	state, err := s.Users.SaveGoogleState(r.Context(), p.Service.ID, authzID)
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, s.Google.StartURL(state), http.StatusFound) //nolint:gosec // destination is Google's configured auth endpoint, not user input
}

// googleCallback completes the authorization for the Google identity.
func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	if !s.Google.Enabled() {
		writeJSON(w, 404, map[string]string{"error": "google_disabled"})
		return
	}
	q := r.URL.Query()
	serviceID, authzID, err := s.Users.LoadGoogleState(r.Context(), q.Get("state"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": "state is unknown or expired; start the sign-in again"})
		return
	}
	svc, err := s.Core.GetService(r.Context(), serviceID)
	if err != nil {
		s.fail(w, err)
		return
	}
	backToLogin := func(reason string) {
		loc, _ := oauth.RedirectWith(svc.LoginURL, url.Values{"login_challenge": {authzID}, "error": {reason}})
		http.Redirect(w, r, loc, http.StatusFound)
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		backToLogin("google_" + strings.TrimSpace(q.Get("error")))
		return
	}
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	identity, err := s.Google.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
		s.Log.Warn("google exchange failed", "err", err)
		backToLogin("google_exchange_failed")
		return
	}
	user, err := s.Users.LoginGoogle(r.Context(), svc, identity, clientIP(r))
	switch {
	case errors.Is(err, users.ErrDisabled):
		backToLogin("account_disabled")
		return
	case errors.Is(err, users.ErrEmailUnverified):
		backToLogin("email_unverified")
		return
	case errors.Is(err, users.ErrSignupClosed):
		backToLogin("signup_closed")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	loc, err := s.OAuth.CompleteForUser(r.Context(), authzID, user, users.AllowedScopes(svc, user), clientIP(r))
	if errors.Is(err, store.ErrNotFound) {
		backToLogin("expired")
		return
	}
	if s.oauthFail(w, err) {
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func (s *Server) setLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		LoginURL     string   `json:"login_url"`
		RPID         string   `json:"rp_id"`
		Origins      []string `json:"origins"`
		DefaultRoles []string `json:"default_roles"`
		OpenSignup   bool     `json:"open_signup"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	svc, err := s.Core.SetLogin(r.Context(), r.PathValue("id"), in.LoginURL, in.RPID, in.Origins, in.DefaultRoles, in.OpenSignup, s.actor(r))
	switch {
	case errors.Is(err, core.ErrInvalidLogin):
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": err.Error()})
	case errors.Is(err, core.ErrServiceNotFound):
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	case err != nil:
		s.fail(w, err)
	default:
		writeJSON(w, 200, serviceJSON(svc))
	}
}

// adminService loads the service named in the path for the owner's user routes.
func (s *Server) adminService(w http.ResponseWriter, r *http.Request) (store.Service, bool) {
	svc, err := s.Core.GetService(r.Context(), r.PathValue("id"))
	if errors.Is(err, core.ErrServiceNotFound) {
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return store.Service{}, false
	}
	if err != nil {
		s.fail(w, err)
		return store.Service{}, false
	}
	return svc, true
}

// adminCreateUser provisions an account from the console, open pool or not.
func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	var in struct{ Email, Name, Method string }
	if !readJSON(w, r, &in) {
		return
	}
	if in.Method == "" {
		in.Method = users.MethodPasskey
	}
	u, err := s.Users.Provision(r.Context(), svc, in.Method, in.Email, in.Name)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 201, userJSON(u))
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	list, next, err := s.Users.List(r.Context(), svc.ID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, userJSON(u))
	}
	writeJSON(w, 200, map[string]any{"users": out, "next": next})
}
