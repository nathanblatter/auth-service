// Package httpapi exposes the core over HTTP. The same handler runs inside
// Lambda (behind API Gateway) and locally with net/http.
package httpapi

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nathanblatter/auth-service/internal/core"
	"github.com/nathanblatter/auth-service/internal/jwt"
	"github.com/nathanblatter/auth-service/internal/owner"
	"github.com/nathanblatter/auth-service/internal/store"
)

//go:embed console.html
var consoleHTML []byte

// sessionCookie carries the owner console session.
const sessionCookie = "auth_admin_session"

// Server holds the dependencies of the HTTP layer.
type Server struct {
	Core *core.Core
	// Owner handles passkey sign-in and console sessions. Required.
	Owner *owner.Owner
	// AdminTokenHash is the hex SHA-256 of the interim admin bearer token
	// (break-glass until auth-service-4). Empty disables bearer admin auth.
	AdminTokenHash string
	Log            *slog.Logger
	Version        string
}

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("POST /v1/token", s.token)
	mux.HandleFunc("GET /v1/me", s.requireService(s.me))

	// Owner console: the page, passkey ceremonies, sessions.
	mux.HandleFunc("GET /admin", s.console)
	mux.HandleFunc("GET /admin/{$}", s.console)
	mux.HandleFunc("GET /admin/session", s.session)
	mux.HandleFunc("POST /admin/login/begin", s.loginBegin)
	mux.HandleFunc("POST /admin/login/finish", s.loginFinish)
	mux.HandleFunc("POST /admin/logout", s.logout)
	mux.HandleFunc("GET /admin/passkeys", s.requireAdmin(s.listPasskeys))
	mux.HandleFunc("POST /admin/passkeys/begin", s.requireAdmin(s.passkeyBegin))
	mux.HandleFunc("POST /admin/passkeys/finish", s.requireAdmin(s.passkeyFinish))

	mux.HandleFunc("POST /admin/services", s.requireAdmin(s.createService))
	mux.HandleFunc("GET /admin/services", s.requireAdmin(s.listServices))
	mux.HandleFunc("GET /admin/services/{id}", s.requireAdmin(s.getService))
	mux.HandleFunc("POST /admin/services/{id}/credentials", s.requireAdmin(s.mintCredential))
	mux.HandleFunc("GET /admin/services/{id}/credentials", s.requireAdmin(s.listCredentials))
	mux.HandleFunc("DELETE /admin/services/{id}/credentials/{cred}", s.requireAdmin(s.revokeCredential))
	return s.withCommon(mux)
}

// withCommon sets security headers and logs each request.
func (s *Server) withCommon(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rw.status,
			"ms", time.Since(start).Milliseconds(), "ip", clientIP(r))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

// ── public ─────────────────────────────────────────────────────────────────

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "version": s.Version, "keys": len(s.Core.Ring.All())})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, 200, s.Core.JWKS())
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := s.Core.Issuer
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, 200, map[string]any{
		"issuer":                                iss,
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"token_endpoint":                        iss + "/v1/token",
		"grant_types_supported":                 []string{"client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

// token implements the OAuth 2.0 token endpoint for client_credentials.
// Errors follow RFC 6749 §5.2.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "body must be application/x-www-form-urlencoded")
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		oauthError(w, 400, "unsupported_grant_type", "only client_credentials is supported")
		return
	}
	clientID, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, secret = u, p
	}
	if clientID == "" || secret == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth"`)
		oauthError(w, 401, "invalid_client", "client_id and client_secret required")
		return
	}
	tok, err := s.Core.ExchangeCredential(r.Context(), clientID, secret, clientIP(r))
	switch {
	case errors.Is(err, core.ErrCredentialInvalid):
		oauthError(w, 401, "invalid_client", "")
	case errors.Is(err, core.ErrServiceDisabled):
		oauthError(w, 403, "unauthorized_client", "service is disabled")
	case err != nil:
		s.Log.Error("token exchange", "err", err)
		oauthError(w, 500, "server_error", "")
	default:
		writeJSON(w, 200, map[string]any{
			"access_token": tok.AccessToken, "token_type": tok.TokenType,
			"expires_in": tok.ExpiresIn, "scope": tok.Scope,
		})
	}
}

type serviceCtxKey struct{}

// requireService authenticates a service token and stores the claims.
func (s *Server) requireService(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="auth"`)
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		id, claims, err := s.Core.VerifyServiceToken(raw)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="auth", error="invalid_token"`)
			writeJSON(w, 401, map[string]string{"error": "invalid_token"})
			return
		}
		ctx := withService(r.Context(), id, claims)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id, claims := serviceFrom(r)
	writeJSON(w, 200, map[string]any{"service_id": id, "scope": claims.Scope, "expires_at": claims.Expires})
}

// ── admin ──────────────────────────────────────────────────────────────────

// adminMethod reports how the request is authenticated for /admin: "passkey"
// (session cookie), "token" (interim bearer), or "" for neither. Cookie auth
// on a state-changing request additionally requires a same-origin Origin
// header, which closes CSRF without a token dance.
func (s *Server) adminMethod(r *http.Request) string {
	if raw, ok := bearer(r); ok && s.AdminTokenHash != "" &&
		subtle.ConstantTimeCompare([]byte(core.HashSecret(raw)), []byte(s.AdminTokenHash)) == 1 {
		return "token"
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if _, err := s.Owner.ValidateSession(r.Context(), c.Value); err == nil {
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.sameOrigin(r) {
				return ""
			}
			return "passkey"
		}
	}
	return ""
}

func (s *Server) sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	want, err := url.Parse(s.Core.Issuer)
	if err != nil {
		return false
	}
	got, err := url.Parse(o)
	if err != nil {
		return false
	}
	return strings.EqualFold(got.Scheme, want.Scheme) && strings.EqualFold(got.Host, want.Host)
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminMethod(r) == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) actor(r *http.Request) core.Actor {
	return core.Actor{ID: "admin:" + s.adminMethod(r), IP: clientIP(r)}
}

// ── owner console ──────────────────────────────────────────────────────────

func (s *Server) console(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	w.WriteHeader(200)
	_, _ = w.Write(consoleHTML)
}

// session tells the page where it stands: signed in or not, and whether the
// very first passkey still has to be registered.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	has, err := s.Owner.HasPasskeys(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"authenticated": false, "method": "", "setup_required": !has}
	if m := s.adminMethod(r); m != "" {
		out["authenticated"] = true
		out["method"] = m
		if c, err := r.Cookie(sessionCookie); err == nil && m == "passkey" {
			if sess, err := s.Owner.ValidateSession(r.Context(), c.Value); err == nil {
				out["expires_at"] = sess.ExpiresAt.UTC().Format(time.RFC3339)
			}
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	opts, chID, err := s.Owner.BeginLogin(r.Context())
	if errors.Is(err, owner.ErrNoPasskeys) {
		writeJSON(w, 409, map[string]string{"error": "setup_required"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "options": opts})
}

func (s *Server) loginFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	tok, exp, err := s.Owner.FinishLogin(r.Context(), r.URL.Query().Get("challenge"), r)
	if errors.Is(err, owner.ErrCeremony) {
		writeJSON(w, 401, map[string]string{"error": "passkey_rejected"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.SetCookie(w, s.cookie(tok, exp))
	writeJSON(w, 200, map[string]any{"authenticated": true, "method": "passkey", "expires_at": exp.UTC().Format(time.RFC3339)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.Owner.Logout(r.Context(), c.Value); err != nil {
			s.fail(w, err)
			return
		}
	}
	http.SetCookie(w, s.cookie("", time.Unix(0, 0)))
	w.WriteHeader(204)
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Owner.ListPasskeys(r.Context())
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

func (s *Server) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	opts, chID, err := s.Owner.BeginRegistration(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "options": opts})
}

func (s *Server) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	q := r.URL.Query()
	pk, err := s.Owner.FinishRegistration(r.Context(), q.Get("challenge"), q.Get("name"), r)
	if errors.Is(err, owner.ErrCeremony) {
		writeJSON(w, 400, map[string]string{"error": "passkey_rejected"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": pk.ID, "name": pk.Name, "created_at": pk.CreatedAt.UTC().Format(time.RFC3339)})
}

// cookie builds the session cookie. Secure is dropped only for an http issuer
// (local dev on localhost).
func (s *Server) cookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is computed: true for every https issuer, false only for http://localhost dev.
		Name: sessionCookie, Value: value, Path: "/admin", Expires: expires,
		HttpOnly: true, Secure: strings.HasPrefix(s.Core.Issuer, "https://"), SameSite: http.SameSiteStrictMode,
	}
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Slug string }
	if !readJSON(w, r, &in) {
		return
	}
	svc, err := s.Core.CreateService(r.Context(), in.Name, in.Slug, s.actor(r))
	switch {
	case errors.Is(err, core.ErrInvalidName), errors.Is(err, core.ErrInvalidSlug):
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": err.Error()})
	case errors.Is(err, core.ErrSlugTaken):
		writeJSON(w, 409, map[string]string{"error": "slug_taken"})
	case err != nil:
		s.fail(w, err)
	default:
		writeJSON(w, 201, serviceJSON(svc))
	}
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	svcs, err := s.Core.ListServices(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(svcs))
	for _, svc := range svcs {
		out = append(out, serviceJSON(svc))
	}
	writeJSON(w, 200, map[string]any{"services": out})
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request) {
	svc, err := s.Core.GetService(r.Context(), r.PathValue("id"))
	if s.notFoundOrFail(w, err) {
		return
	}
	writeJSON(w, 200, serviceJSON(svc))
}

func (s *Server) mintCredential(w http.ResponseWriter, r *http.Request) {
	raw, cred, err := s.Core.MintCredential(r.Context(), r.PathValue("id"), s.actor(r))
	if s.notFoundOrFail(w, err) {
		return
	}
	out := credentialJSON(cred)
	out["credential"] = raw // the only time the raw value is ever returned
	writeJSON(w, 201, out)
}

func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.Core.ListCredentials(r.Context(), r.PathValue("id"))
	if s.notFoundOrFail(w, err) {
		return
	}
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		out = append(out, credentialJSON(c))
	}
	writeJSON(w, 200, map[string]any{"credentials": out})
}

func (s *Server) revokeCredential(w http.ResponseWriter, r *http.Request) {
	err := s.Core.RevokeCredential(r.Context(), r.PathValue("id"), r.PathValue("cred"), s.actor(r))
	if errors.Is(err, core.ErrCredentialInvalid) {
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(204)
}

// ── helpers ────────────────────────────────────────────────────────────────

func (s *Server) notFoundOrFail(w http.ResponseWriter, err error) bool {
	if errors.Is(err, core.ErrServiceNotFound) {
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return true
	}
	if err != nil {
		s.fail(w, err)
		return true
	}
	return false
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log.Error("request failed", "err", err)
	writeJSON(w, 500, map[string]string{"error": "server_error"})
}

func serviceJSON(svc store.Service) map[string]any {
	return map[string]any{"id": svc.ID, "slug": svc.Slug, "name": svc.Name, "status": svc.Status,
		"created_at": svc.CreatedAt.UTC().Format(time.RFC3339)}
}

func credentialJSON(c store.Credential) map[string]any {
	out := map[string]any{"id": c.ID, "service_id": c.ServiceID, "last4": c.Last4,
		"created_at": c.CreatedAt.UTC().Format(time.RFC3339), "revoked": c.Revoked()}
	if c.RevokedAt != nil {
		out["revoked_at"] = c.RevokedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	tok = strings.TrimSpace(tok)
	return tok, ok && tok != ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": "bad json: " + err.Error()})
		return false
	}
	return true
}

// clientIP prefers the first X-Forwarded-For hop (API Gateway sets it from the
// real source), then RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type serviceInfo struct {
	id     string
	claims jwt.Claims
}

func withService(ctx context.Context, id string, c jwt.Claims) context.Context {
	return context.WithValue(ctx, serviceCtxKey{}, serviceInfo{id: id, claims: c})
}

func serviceFrom(r *http.Request) (string, jwt.Claims) {
	info, _ := r.Context().Value(serviceCtxKey{}).(serviceInfo)
	return info.id, info.claims
}
