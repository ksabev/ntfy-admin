package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NtfyClient talks to ntfy. Admin calls go over the admin unix socket when one
// is configured (full powers: roles, admin users), else over HTTP with the
// logged-in admin's short-lived session token (ntfy refuses role changes and
// changes to admin users there).
type NtfyClient struct {
	base   string
	http   *http.Client
	socket *http.Client // nil without NTFY_ADMIN_SOCKET
}

// Paths ntfy serves on the admin socket (server_admin.go: adminSocketPaths).
var socketPaths = map[string]bool{
	"/v1/version": true, "/v1/users": true, "/v1/users/access": true,
	"/v1/users/tokens": true, "/v1/users/password/reset": true, "/v1/tiers": true,
}

func newNtfyClient(sc ServerConfig) *NtfyClient {
	c := &NtfyClient{
		base: strings.TrimRight(sc.URL, "/"),
		http: &http.Client{Timeout: 20 * time.Second},
	}
	if sc.Socket != "" {
		path := sc.Socket
		c.socket = &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", path)
				},
			},
		}
	}
	return c
}

// NtfyError is an error response from ntfy ({"code":40301,"http":403,"error":"..."}).
type NtfyError struct {
	Status  int    `json:"http"`
	Code    int    `json:"code"`
	Message string `json:"error"`
}

func (e *NtfyError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("ntfy: %s (%d)", e.Message, e.Code)
	}
	return "ntfy: " + e.Message
}

func isStatus(err error, status int) bool {
	var ne *NtfyError
	return errors.As(err, &ne) && ne.Status == status
}

// auth carries how a single request authenticates against ntfy.
type auth struct {
	basicUser, basicPass string
	token                string
	clientIP             string // forwarded so ntfy's rate limiting sees the real client
}

func (a auth) apply(r *http.Request) {
	switch {
	case a.token != "":
		r.Header.Set("Authorization", "Bearer "+a.token)
	case a.basicUser != "":
		r.SetBasicAuth(a.basicUser, a.basicPass)
	}
	if a.clientIP != "" {
		r.Header.Set("X-Forwarded-For", a.clientIP)
	}
}

func (c *NtfyClient) do(ctx context.Context, a auth, method, path string, query url.Values, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	client, base := c.http, c.base
	if c.socket != nil && socketPaths[path] {
		client, base = c.socket, "http://ntfy-admin-socket"
	}
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "ntfy-admin/"+version)
	if client == c.http {
		a.apply(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		ne := &NtfyError{Status: resp.StatusCode}
		if json.Unmarshal(data, ne) != nil || ne.Message == "" {
			ne.Message = strings.TrimSpace(string(data))
			if ne.Message == "" {
				ne.Message = http.StatusText(resp.StatusCode)
			}
		}
		ne.Status = resp.StatusCode
		return ne
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// --- account (login) ---------------------------------------------------------

type ntfyAccount struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (c *NtfyClient) account(ctx context.Context, a auth) (*ntfyAccount, error) {
	var acc ntfyAccount
	if err := c.do(ctx, a, http.MethodGet, "/v1/account", nil, nil, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}

func (c *NtfyClient) createSessionToken(ctx context.Context, a auth, label string, expires time.Time) (string, error) {
	exp := expires.Unix()
	var out struct {
		Token string `json:"token"`
	}
	err := c.do(ctx, a, http.MethodPost, "/v1/account/token", nil,
		map[string]any{"label": label, "expires": exp}, &out)
	if err == nil && out.Token == "" {
		err = errors.New("ntfy returned no token")
	}
	return out.Token, err
}

func (c *NtfyClient) deleteSessionToken(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base+"/v1/account/token", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// --- server info -----------------------------------------------------------------

func (c *NtfyClient) healthy(ctx context.Context) bool {
	var h struct {
		Healthy bool `json:"healthy"`
	}
	return c.do(ctx, auth{}, http.MethodGet, "/v1/health", nil, nil, &h) == nil && h.Healthy
}

type ntfyVersion struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func (c *NtfyClient) version(ctx context.Context, a auth) (*ntfyVersion, error) {
	var v ntfyVersion
	return &v, c.do(ctx, a, http.MethodGet, "/v1/version", nil, nil, &v)
}

// --- users / access ------------------------------------------------------------

type ntfyGrant struct {
	Topic       string `json:"topic"`
	Permission  string `json:"permission"`
	Provisioned bool   `json:"provisioned,omitempty"`
}

type ntfyUser struct {
	Username      string       `json:"username"`
	Role          string       `json:"role"`
	Tier          string       `json:"tier,omitempty"`
	TierName      string       `json:"tier_name,omitempty"`
	Provisioned   bool         `json:"provisioned,omitempty"`
	DefaultAccess string       `json:"default_access,omitempty"`
	Grants        []*ntfyGrant `json:"grants,omitempty"`
}

func (c *NtfyClient) users(ctx context.Context, a auth) ([]*ntfyUser, error) {
	var us []*ntfyUser
	return us, c.do(ctx, a, http.MethodGet, "/v1/users", nil, nil, &us)
}

type userWrite struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Tier     string `json:"tier,omitempty"`
	Role     string `json:"role,omitempty"`
}

func (c *NtfyClient) addUser(ctx context.Context, a auth, w userWrite) error {
	return c.do(ctx, a, http.MethodPost, "/v1/users", nil, w, nil)
}

func (c *NtfyClient) updateUser(ctx context.Context, a auth, w userWrite) error {
	return c.do(ctx, a, http.MethodPut, "/v1/users", nil, w, nil)
}

func (c *NtfyClient) deleteUser(ctx context.Context, a auth, username string) error {
	return c.do(ctx, a, http.MethodDelete, "/v1/users", nil, map[string]string{"username": username}, nil)
}

func (c *NtfyClient) allowAccess(ctx context.Context, a auth, username, topic, perm string) error {
	return c.do(ctx, a, http.MethodPut, "/v1/users/access", nil,
		map[string]string{"username": username, "topic": topic, "permission": perm}, nil)
}

func (c *NtfyClient) resetAccess(ctx context.Context, a auth, username, topic string) error {
	return c.do(ctx, a, http.MethodDelete, "/v1/users/access", nil,
		map[string]string{"username": username, "topic": topic}, nil)
}

func (c *NtfyClient) passwordResetLink(ctx context.Context, a auth, username string) (string, error) {
	var out struct {
		Link string `json:"link"`
	}
	err := c.do(ctx, a, http.MethodPost, "/v1/users/password/reset", nil,
		map[string]any{"username": username, "send_email": false}, &out)
	return out.Link, err
}

// --- tokens ------------------------------------------------------------------------

type ntfyToken struct {
	Username    string `json:"username"`
	Token       string `json:"token"`
	Label       string `json:"label,omitempty"`
	Expires     int64  `json:"expires"`
	LastAccess  int64  `json:"last_access,omitempty"`
	LastOrigin  string `json:"last_origin,omitempty"`
	Provisioned bool   `json:"provisioned,omitempty"`
}

func (c *NtfyClient) tokens(ctx context.Context, a auth, username string) ([]*ntfyToken, error) {
	var ts []*ntfyToken
	q := url.Values{}
	if username != "" {
		q.Set("username", username)
	}
	return ts, c.do(ctx, a, http.MethodGet, "/v1/users/tokens", q, nil, &ts)
}

func (c *NtfyClient) addToken(ctx context.Context, a auth, username, label string, expires int64) (*ntfyToken, error) {
	var t ntfyToken
	return &t, c.do(ctx, a, http.MethodPost, "/v1/users/tokens", nil,
		map[string]any{"username": username, "label": label, "expires": expires}, &t)
}

func (c *NtfyClient) deleteToken(ctx context.Context, a auth, username, token string) error {
	return c.do(ctx, a, http.MethodDelete, "/v1/users/tokens", nil,
		map[string]string{"username": username, "token": token}, nil)
}

func (c *NtfyClient) tiers(ctx context.Context, a auth) ([]map[string]any, error) {
	var ts []map[string]any
	return ts, c.do(ctx, a, http.MethodGet, "/v1/tiers", nil, nil, &ts)
}

// --- publishing ----------------------------------------------------------------------

type publishReq struct {
	Topic    string   `json:"topic"`
	Message  string   `json:"message"`
	Title    string   `json:"title,omitempty"`
	Priority int      `json:"priority,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

func (c *NtfyClient) publish(ctx context.Context, a auth, p publishReq) error {
	// JSON publishing goes to the root URL with the topic in the body
	return c.do(ctx, a, http.MethodPost, "/", nil, p, nil)
}
