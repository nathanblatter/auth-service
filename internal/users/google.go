package users

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Google is the Sign in with Google provider: standard OAuth 2.0 code flow
// against Google's endpoints, identity read from the OpenID userinfo
// endpoint over TLS (so no ID-token signature code is needed here).
type Google struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string // https://squawk.nathanblatter.com/v1/login/google/callback
	// Endpoints are overridable for tests.
	AuthURL     string
	TokenURL    string
	UserinfoURL string
	HTTP        *http.Client
}

// NewGoogle configures the provider with Google's production endpoints.
func NewGoogle(clientID, clientSecret, redirectURL string) *Google {
	return &Google{ //nolint:gosec // the "token" URL is Google's endpoint address, not a credential
		ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserinfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
		HTTP:        &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether credentials are configured.
func (g *Google) Enabled() bool { return g != nil && g.ClientID != "" && g.ClientSecret != "" }

// StartURL is where to send the browser.
func (g *Google) StartURL(state string) string {
	q := url.Values{
		"client_id": {g.ClientID}, "redirect_uri": {g.RedirectURL}, "response_type": {"code"},
		"scope": {"openid email profile"}, "state": {state}, "prompt": {"select_account"},
	}
	return g.AuthURL + "?" + q.Encode()
}

// Exchange turns the callback code into a verified identity.
func (g *Google) Exchange(ctx context.Context, code string) (GoogleIdentity, error) {
	form := url.Values{
		"code": {code}, "client_id": {g.ClientID}, "client_secret": {g.ClientSecret},
		"redirect_uri": {g.RedirectURL}, "grant_type": {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return GoogleIdentity{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return GoogleIdentity{}, fmt.Errorf("google token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return GoogleIdentity{}, fmt.Errorf("google token: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return GoogleIdentity{}, errors.New("google token: malformed response")
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, g.UserinfoURL, nil)
	if err != nil {
		return GoogleIdentity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp2, err := g.HTTP.Do(req)
	if err != nil {
		return GoogleIdentity{}, fmt.Errorf("google userinfo: %w", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return GoogleIdentity{}, fmt.Errorf("google userinfo: status %d", resp2.StatusCode)
	}
	var info struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp2.Body, 64<<10)).Decode(&info); err != nil {
		return GoogleIdentity{}, errors.New("google userinfo: malformed response")
	}
	return GoogleIdentity{Sub: info.Sub, Email: info.Email, EmailVerified: info.EmailVerified, Name: info.Name}, nil
}
