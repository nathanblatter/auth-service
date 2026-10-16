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
	"strconv"
	"strings"
	"time"

	"github.com/nathanblatter/auth-service/internal/core"
	"github.com/nathanblatter/auth-service/internal/jwt"
	"github.com/nathanblatter/auth-service/internal/oauth"
	"github.com/nathanblatter/auth-service/internal/owner"
	"github.com/nathanblatter/auth-service/internal/ratelimit"
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
	// Limit counts failures for brute-force protection. Required.
	Limit *ratelimit.Limiter
	// OAuth is the connector authorization server. Required.
	OAuth *oauth.Server
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

	// OAuth 2.1 for connectors (RFC 8414 metadata, RFC 7591 DCR, code + PKCE).
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.oauthMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/{rest...}", s.oauthMetadata)
	mux.HandleFunc("POST /oauth/register", s.oauthRegister)
	mux.HandleFunc("GET /oauth/authorize", s.oauthAuthorize)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("GET /admin/authorize/{id}", s.requireAdmin(s.pendingApproval))
	mux.HandleFunc("POST /admin/authorize/{id}/approve", s.requireFresh(false, s.approve))
	mux.HandleFunc("POST /admin/authorize/{id}/deny", s.requireAdmin(s.deny))

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
	mux.HandleFunc("GET /admin/recovery-codes", s.requireAdmin(s.recoveryStatus))
	mux.HandleFunc("POST /admin/recovery-codes", s.requireFresh(true, s.recoveryGenerate))
	mux.HandleFunc("POST /admin/recover", s.recoverLogin)
	mux.HandleFunc("POST /admin/logout-everywhere", s.requireAdmin(s.logoutEverywhere))
	mux.HandleFunc("POST /admin/step-up/begin", s.requireAdmin(s.stepUpBegin))
	mux.HandleFunc("POST /admin/step-up/finish", s.requireAdmin(s.stepUpFinish))
	mux.HandleFunc("GET /admin/audit", s.requireAdmin(s.audit))

	mux.HandleFunc("POST /admin/services", s.requireAdmin(s.createService))
	mux.HandleFunc("GET /admin/services", s.requireAdmin(s.listServices))
	mux.HandleFunc("GET /admin/services/{id}", s.requireAdmin(s.getService))
	mux.HandleFunc("POST /admin/services/{id}/credentials", s.requireFresh(true, s.mintCredential))
	mux.HandleFunc("GET /admin/services/{id}/credentials", s.requireAdmin(s.listCredentials))
	mux.HandleFunc("DELETE /admin/services/{id}/credentials/{cred}", s.requireAdmin(s.revokeCredential))
	mux.HandleFunc("POST /admin/services/{id}/resources", s.requireAdmin(s.addResource))
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
		"authorization_endpoint":                iss + "/oauth/authorize",
		"registration_endpoint":                 iss + "/oauth/register",
		"grant_types_supported":                 []string{"client_credentials", "authorization_code", "refresh_token"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

// token is the OAuth token endpoint. client_credentials is handled by the
// core (service credentials); authorization_code and refresh_token by the
// connector OAuth server. Errors follow RFC 6749 §5.2.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "body must be application/x-www-form-urlencoded")
		return
	}
	clientID, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, secret = u, p
	}
	switch g := r.PostForm.Get("grant_type"); g {
	case "client_credentials":
	case "authorization_code", "refresh_token":
		s.oauthToken(w, r, oauth.TokenRequest{
			GrantType: g, ClientID: clientID, ClientSecret: secret, Code: r.PostForm.Get("code"),
			CodeVerifier: r.PostForm.Get("code_verifier"), RedirectURI: r.PostForm.Get("redirect_uri"), RefreshToken: r.PostForm.Get("refresh_token"),
		})
		return
	default:
		oauthError(w, 400, "unsupported_grant_type", "grant_type must be client_credentials, authorization_code or refresh_token")
		return
	}
	if clientID == "" || secret == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth"`)
		oauthError(w, 401, "invalid_client", "client_id and client_secret required")
		return
	}
	ip := clientIP(r)
	ipKey, clientKey := "token:ip:"+ip, "token:client:"+clientID
	if !s.Limit.Allow(r.Context(), ratelimit.TokenIP, ipKey) {
		tooMany(w, ratelimit.TokenIP)
		return
	}
	if !s.Limit.Allow(r.Context(), ratelimit.TokenClient, clientKey) {
		tooMany(w, ratelimit.TokenClient)
		return
	}
	tok, err := s.Core.ExchangeCredential(r.Context(), clientID, secret, ip)
	switch {
	case errors.Is(err, core.ErrCredentialInvalid):
		s.Limit.Fail(r.Context(), ratelimit.TokenIP, ipKey)
		s.Limit.Fail(r.Context(), ratelimit.TokenClient, clientKey)
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
		if sess, err := s.Owner.ValidateSession(r.Context(), c.Value); err == nil {
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.sameOrigin(r) {
				return ""
			}
			if sess.Method == "" {
				return "passkey"
			}
			return sess.Method // passkey | recovery
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
		if c, err := r.Cookie(sessionCookie); err == nil && m != "token" {
			if sess, err := s.Owner.ValidateSession(r.Context(), c.Value); err == nil {
				out["expires_at"] = sess.ExpiresAt.UTC().Format(time.RFC3339)
				out["fresh"] = s.Owner.Fresh(sess)
			}
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, "login:ip:"+clientIP(r)) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
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
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	tok, exp, err := s.Owner.FinishLogin(r.Context(), r.URL.Query().Get("challenge"), r)
	if errors.Is(err, owner.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
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
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	pk, err := s.Owner.FinishRegistration(r.Context(), q.Get("challenge"), q.Get("name"), r)
	if errors.Is(err, owner.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
		writeJSON(w, 400, map[string]string{"error": "passkey_rejected"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": pk.ID, "name": pk.Name, "created_at": pk.CreatedAt.UTC().Format(time.RFC3339)})
}

// ── recovery (auth-service-4) ──────────────────────────────────────────────

func (s *Server) recoveryStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Owner.RecoveryStatus(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"total": st.Total, "remaining": st.Remaining}
	if st.CreatedAt != nil {
		out["created_at"] = st.CreatedAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, 200, out)
}

// recoveryGenerate replaces the code set. The plain codes are in this
// response and nowhere else.
func (s *Server) recoveryGenerate(w http.ResponseWriter, r *http.Request) {
	codes, err := s.Owner.GenerateRecoveryCodes(r.Context(), clientIP(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"codes": codes})
}

// recoverLogin opens a recovery session from a code. Public, rate limited.
func (s *Server) recoverLogin(w http.ResponseWriter, r *http.Request) {
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	var in struct{ Code string }
	if !readJSON(w, r, &in) {
		return
	}
	tok, exp, err := s.Owner.RecoverLogin(r.Context(), in.Code, clientIP(r))
	if errors.Is(err, owner.ErrRecoveryInvalid) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
		writeJSON(w, 401, map[string]string{"error": "recovery_code_rejected"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.SetCookie(w, s.cookie(tok, exp))
	writeJSON(w, 200, map[string]any{"authenticated": true, "method": "recovery", "expires_at": exp.UTC().Format(time.RFC3339)})
}

// logoutEverywhere (auth-service-11) kills every console session and every
// connector refresh token the owner holds, including the caller's.
func (s *Server) logoutEverywhere(w http.ResponseWriter, r *http.Request) {
	if err := s.Owner.LogoutEverywhere(r.Context(), clientIP(r)); err != nil {
		s.fail(w, err)
		return
	}
	http.SetCookie(w, s.cookie("", time.Unix(0, 0)))
	w.WriteHeader(204)
}

// audit (auth-service-7) pages through one month of events, newest first.
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	month := q.Get("month")
	if month == "" {
		month = s.Core.Now().UTC().Format("2006-01")
	}
	if _, err := time.Parse("2006-01", month); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": "month must be YYYY-MM"})
		return
	}
	limit := 50
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	events, next, err := s.Core.Store.ListAudit(r.Context(), month, limit, q.Get("cursor"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{"at": e.At.UTC().Format(time.RFC3339Nano), "kind": e.Kind, "actor": e.Actor,
			"service_id": e.ServiceID, "detail": e.Detail, "ip": e.IP})
	}
	writeJSON(w, 200, map[string]any{"month": month, "events": out, "next": next})
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

// ── OAuth for connectors ───────────────────────────────────────────────────

func (s *Server) oauthMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, 200, s.OAuth.Metadata())
}

func (s *Server) oauthRegister(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	// Registrations are cheap to spam; count every one against the IP.
	key := "oauth:register:ip:" + ip
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, key) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	s.Limit.Fail(r.Context(), ratelimit.LoginIP, key)
	var req oauth.RegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		oauthError(w, 400, "invalid_client_metadata", "body must be JSON")
		return
	}
	c, secret, err := s.OAuth.Register(r.Context(), req, ip)
	if s.oauthFail(w, err) {
		return
	}
	resp := map[string]any{
		"client_id": c.ID, "client_id_issued_at": c.CreatedAt.Unix(), "client_name": c.Name,
		"redirect_uris": c.RedirectURIs, "token_endpoint_auth_method": c.AuthMethod,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
	}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, 201, resp)
}

func (s *Server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	out, err := s.OAuth.BeginAuthorize(r.Context(), oauth.ParseAuthz(r.URL.Query()), clientIP(r))
	if s.oauthFail(w, err) {
		return
	}
	if out.Err != nil {
		loc, err := oauth.RedirectWith(out.RedirectURI, url.Values{"error": {out.Err.Code}, "error_description": {out.Err.Description}, "state": {out.State}})
		if err != nil {
			oauthError(w, 400, "invalid_request", "bad redirect_uri")
			return
		}
		http.Redirect(w, r, loc, http.StatusFound)
		return
	}
	http.Redirect(w, r, out.ApproveURL, http.StatusFound)
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request, req oauth.TokenRequest) {
	ip := clientIP(r)
	ipKey := "token:ip:" + ip
	if !s.Limit.Allow(r.Context(), ratelimit.TokenIP, ipKey) {
		tooMany(w, ratelimit.TokenIP)
		return
	}
	tok, err := s.OAuth.Token(r.Context(), req, ip)
	var oe *oauth.Error
	if errors.As(err, &oe) && (oe.Code == "invalid_client" || oe.Code == "invalid_grant") {
		s.Limit.Fail(r.Context(), ratelimit.TokenIP, ipKey)
	}
	if s.oauthFail(w, err) {
		return
	}
	writeJSON(w, 200, tok)
}

// requireFresh guards sensitive actions (auth-service-17): a passkey session
// whose last assertion is within StepUpWindow. A stale passkey session gets
// 401 step_up_required and the console re-runs Face ID. allowToken lets the
// break-glass bearer through (minting, recovery codes: needed for bootstrap);
// connector approval never accepts it (Nathan: approval is the passkey).
func (s *Server) requireFresh(allowToken bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch s.adminMethod(r) {
		case "token":
			if allowToken {
				next(w, r)
				return
			}
			writeJSON(w, 401, map[string]string{"error": "passkey_required"})
			return
		case "passkey":
			if c, err := r.Cookie(sessionCookie); err == nil {
				if sess, err := s.Owner.ValidateSession(r.Context(), c.Value); err == nil && s.Owner.Fresh(sess) {
					next(w, r)
					return
				}
			}
			writeJSON(w, 401, map[string]string{"error": "step_up_required"})
		case "recovery":
			writeJSON(w, 401, map[string]string{"error": "passkey_required", "detail": "register a passkey and sign in with it"})
		default:
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		}
	}
}

func (s *Server) stepUpBegin(w http.ResponseWriter, r *http.Request) {
	if s.adminMethod(r) != "passkey" {
		writeJSON(w, 400, map[string]string{"error": "passkey_required"})
		return
	}
	opts, chID, err := s.Owner.BeginStepUp(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "options": opts})
}

func (s *Server) stepUpFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	c, err := r.Cookie(sessionCookie)
	if err != nil || s.adminMethod(r) != "passkey" {
		writeJSON(w, 400, map[string]string{"error": "passkey_required"})
		return
	}
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	err = s.Owner.FinishStepUp(r.Context(), r.URL.Query().Get("challenge"), c.Value, r)
	if errors.Is(err, owner.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
		writeJSON(w, 401, map[string]string{"error": "passkey_rejected"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"verified": true})
}

func (s *Server) pendingApproval(w http.ResponseWriter, r *http.Request) {
	p, err := s.OAuth.Pending(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "this request expired or was already answered"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": p.ID, "client_name": p.ClientName, "client_id": p.ClientID, "scope": p.Scope, "resource": p.Resource,
		"service": serviceJSON(p.Service), "expires_at": p.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	loc, err := s.OAuth.Approve(r.Context(), r.PathValue("id"), clientIP(r))
	s.approvalResult(w, loc, err)
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request) {
	loc, err := s.OAuth.Deny(r.Context(), r.PathValue("id"), clientIP(r))
	s.approvalResult(w, loc, err)
}

func (s *Server) approvalResult(w http.ResponseWriter, loc string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "this request expired or was already answered"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"redirect_to": loc})
}

func (s *Server) addResource(w http.ResponseWriter, r *http.Request) {
	var in struct{ Resource string }
	if !readJSON(w, r, &in) {
		return
	}
	err := s.Core.AddResource(r.Context(), r.PathValue("id"), strings.TrimSpace(in.Resource), s.actor(r))
	switch {
	case errors.Is(err, core.ErrInvalidResource):
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": err.Error()})
	case errors.Is(err, core.ErrResourceTaken):
		writeJSON(w, 409, map[string]string{"error": "resource_taken"})
	case errors.Is(err, core.ErrServiceNotFound):
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	case err != nil:
		s.fail(w, err)
	default:
		svc, err := s.Core.GetService(r.Context(), r.PathValue("id"))
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, 200, serviceJSON(svc))
	}
}

// oauthFail writes an *oauth.Error or a 500; returns true when it wrote.
func (s *Server) oauthFail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var oe *oauth.Error
	if errors.As(err, &oe) {
		if oe.Code == "invalid_client" {
			w.Header().Set("WWW-Authenticate", `Basic realm="auth"`)
		}
		oauthError(w, oe.Status, oe.Code, oe.Description)
		return true
	}
	s.Log.Error("oauth", "err", err)
	oauthError(w, 500, "server_error", "")
	return true
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
	res := svc.Resources
	if res == nil {
		res = []string{}
	}
	return map[string]any{"id": svc.ID, "slug": svc.Slug, "name": svc.Name, "status": svc.Status,
		"created_at": svc.CreatedAt.UTC().Format(time.RFC3339), "resources": res}
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

// tooMany answers a brute-force lockout. Same body shape for OAuth and JSON
// callers; Retry-After is the policy window.
func tooMany(w http.ResponseWriter, p ratelimit.Policy) {
	w.Header().Set("Retry-After", strconv.Itoa(p.RetryAfter()))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_attempts",
		"error_description": "too many failed attempts; try again later"})
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
