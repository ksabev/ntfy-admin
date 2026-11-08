package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"gopkg.in/yaml.v3"
)

//go:embed web
var webFS embed.FS

const cookieName = "ntfy_admin"

var (
	reUsername = regexp.MustCompile(`^[-_.+@a-zA-Z0-9]{1,128}$`) // ntfy: user.AllowedUsername
	reTopic    = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)     // ntfy: user.AllowedTopic
	rePattern  = regexp.MustCompile(`^[-_*A-Za-z0-9]{1,64}$`)    // ntfy: user.AllowedTopicPattern
	perms      = map[string]string{
		"read-write": "read-write", "rw": "read-write",
		"read-only": "read-only", "ro": "read-only",
		"write-only": "write-only", "wo": "write-only",
		"deny": "deny-all", "deny-all": "deny-all", "none": "deny-all",
	}
)

type App struct {
	cfg      *Config
	ntfy     *NtfyClient
	sessions *sessionStore
	limiter  *loginLimiter
	topics   *topicStore

	mu        sync.Mutex
	tokensAPI *bool // nil = not probed yet; ntfy < 2.36 has no admin token API
}

func newApp(cfg *Config) (*App, error) {
	return &App{
		cfg:      cfg,
		ntfy:     newNtfyClient(cfg),
		sessions: newSessionStore(),
		limiter:  newLoginLimiter(),
		topics:   newTopicStore(cfg.DataDir),
	}, nil
}

// --- plumbing ------------------------------------------------------------------------

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func bad(format string, a ...any) error {
	return &apiError{http.StatusBadRequest, fmt.Sprintf(format, a...)}
}

type handler func(w http.ResponseWriter, r *http.Request, s *session) error

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	var ne *NtfyError
	switch {
	case errors.As(err, &ae):
		writeJSON(w, ae.status, map[string]string{"error": ae.msg})
	case errors.As(err, &ne):
		status := ne.Status
		if status < 400 || status >= 600 {
			status = http.StatusBadGateway
		}
		msg := ne.Message
		if status == http.StatusUnauthorized { // our ntfy session token died (revoked/expired): log in again
			msg = "ntfy session expired, please log in again"
		}
		writeJSON(w, status, map[string]any{"error": msg, "ntfy_code": ne.Code})
	default:
		slog.Error("request failed", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return bad("invalid JSON: %v", err)
	}
	return nil
}

func (a *App) clientIP(r *http.Request) string {
	if a.cfg.BehindProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *App) secureCookie(r *http.Request) bool {
	switch a.cfg.CookieSecure {
	case "true":
		return true
	case "false":
		return false
	}
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *App) auth(s *session) auth {
	return auth{token: s.Token, clientIP: s.ClientIP}
}

// authed wraps an API handler: valid session cookie, plus a CSRF header on
// anything that changes state (SameSite=Strict already blocks most of it).
func (a *App) authed(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var s *session
		if err == nil {
			s = a.sessions.get(c.Value)
		}
		if s == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if t := r.Header.Get("X-CSRF-Token"); t == "" || subtle.ConstantTimeCompare([]byte(t), []byte(s.CSRF)) != 1 {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or bad CSRF token"})
				return
			}
		}
		if err := h(w, r, s); err != nil {
			writeErr(w, err)
		}
	}
}

func (a *App) audit(r *http.Request, s *session, action string, attrs ...any) {
	slog.Info("audit", append([]any{"admin", s.Username, "ip", s.ClientIP, "action", action}, attrs...)...)
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	p := a.cfg.BasePath

	static, _ := fs.Sub(webFS, "web")
	files := http.StripPrefix(p+"/", http.FileServer(http.FS(static)))
	mux.Handle("GET "+p+"/", files)
	if p != "" {
		mux.Handle("GET "+p, http.RedirectHandler(p+"/", http.StatusMovedPermanently))
	}
	mux.HandleFunc("GET "+p+"/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version})
	})

	mux.HandleFunc("POST "+p+"/api/login", a.handleLogin)
	mux.HandleFunc("POST "+p+"/api/logout", a.authed(a.handleLogout))
	mux.HandleFunc("GET "+p+"/api/me", a.authed(a.handleMe))
	mux.HandleFunc("GET "+p+"/api/state", a.authed(a.handleState))

	mux.HandleFunc("POST "+p+"/api/users", a.authed(a.handleUserCreate))
	mux.HandleFunc("PATCH "+p+"/api/users/{name}", a.authed(a.handleUserUpdate))
	mux.HandleFunc("DELETE "+p+"/api/users/{name}", a.authed(a.handleUserDelete))
	mux.HandleFunc("POST "+p+"/api/users/{name}/reset-link", a.authed(a.handleResetLink))

	mux.HandleFunc("PUT "+p+"/api/access", a.authed(a.handleAccessSet))
	mux.HandleFunc("POST "+p+"/api/access/delete", a.authed(a.handleAccessDelete))

	mux.HandleFunc("POST "+p+"/api/tokens", a.authed(a.handleTokenCreate))
	mux.HandleFunc("POST "+p+"/api/tokens/reveal", a.authed(a.handleTokenReveal))
	mux.HandleFunc("POST "+p+"/api/tokens/delete", a.authed(a.handleTokenDelete))

	mux.HandleFunc("PUT "+p+"/api/topics/{name}", a.authed(a.handleTopicSet))
	mux.HandleFunc("DELETE "+p+"/api/topics/{name}", a.authed(a.handleTopicDelete))
	mux.HandleFunc("POST "+p+"/api/publish", a.authed(a.handlePublish))

	mux.HandleFunc("GET "+p+"/api/qr", a.authed(a.handleQR))
	mux.HandleFunc("GET "+p+"/api/export", a.authed(a.handleExport))

	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.Contains(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// --- login -----------------------------------------------------------------------------

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if !a.limiter.allowed(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed logins, try again in a few minutes"})
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	cred := auth{basicUser: in.Username, basicPass: in.Password, clientIP: ip}
	ctx := r.Context()
	acc, err := a.ntfy.account(ctx, cred)
	if err != nil || acc.Username != in.Username || in.Username == "" {
		a.limiter.fail(ip)
		slog.Warn("login failed", "user", in.Username, "ip", ip, "err", err)
		if err != nil && !isStatus(err, http.StatusUnauthorized) && !isStatus(err, http.StatusForbidden) {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "wrong username or password"})
		return
	}
	if acc.Role != "admin" {
		a.limiter.fail(ip)
		slog.Warn("login refused: not an admin", "user", in.Username, "ip", ip)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this ntfy account is not an admin"})
		return
	}
	token, err := a.ntfy.createSessionToken(ctx, cred, "ntfy-admin session", time.Now().Add(a.cfg.SessionTTL))
	if err != nil {
		writeErr(w, err)
		return
	}
	a.limiter.reset(ip)
	s := a.sessions.create(acc.Username, acc.Role, token, ip, a.cfg.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.ID, Path: a.cfg.BasePath + "/",
		HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteStrictMode,
		Expires: s.ExpiresAt,
	})
	slog.Info("audit", "admin", s.Username, "ip", ip, "action", "login")
	writeJSON(w, http.StatusOK, a.me(ctx, s))
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request, s *session) error {
	a.sessions.remove(s.ID)
	_ = a.ntfy.deleteSessionToken(r.Context(), s.Token)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: a.cfg.BasePath + "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteStrictMode})
	a.audit(r, s, "logout")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

type caps struct {
	Socket bool `json:"socket"` // admin socket: roles, admin users, all tokens at once
	Tokens bool `json:"tokens"` // ntfy >= 2.36 admin token API
}

func (a *App) caps(ctx context.Context, s *session) caps {
	c := caps{Socket: a.ntfy.socket != nil}
	a.mu.Lock()
	known := a.tokensAPI
	a.mu.Unlock()
	if known != nil {
		c.Tokens = *known
		return c
	}
	// Probe: asking for our own (admin) tokens is 403 over HTTP, 200 over the
	// socket — either way the endpoint exists. Older ntfy answers 404.
	_, err := a.ntfy.tokens(ctx, a.auth(s), s.Username)
	ok := err == nil || !isStatus(err, http.StatusNotFound)
	var ne *NtfyError
	if err != nil && !errors.As(err, &ne) {
		return c // ntfy unreachable: do not cache a guess
	}
	a.mu.Lock()
	a.tokensAPI = &ok
	a.mu.Unlock()
	c.Tokens = ok
	return c
}

func (a *App) me(ctx context.Context, s *session) map[string]any {
	return map[string]any{
		"username":   s.Username,
		"csrf":       s.CSRF,
		"expires_at": s.ExpiresAt.Unix(),
		"caps":       a.caps(ctx, s),
		"version":    version,
	}
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request, s *session) error {
	writeJSON(w, http.StatusOK, a.me(r.Context(), s))
	return nil
}

// --- state ----------------------------------------------------------------------------

type tokenView struct {
	ID          string `json:"id"`     // sha256 prefix: the browser never gets token values unless revealed
	Prefix      string `json:"prefix"` // "tk_ab12…"
	Label       string `json:"label,omitempty"`
	Expires     int64  `json:"expires"`
	LastAccess  int64  `json:"last_access,omitempty"`
	LastOrigin  string `json:"last_origin,omitempty"`
	Provisioned bool   `json:"provisioned,omitempty"`
}

type userView struct {
	*ntfyUser
	Tokens        []*tokenView `json:"tokens"`
	TokensVisible bool         `json:"tokens_visible"` // false: admin user over HTTP, ntfy hides them
	Grants        []*ntfyGrant `json:"grants"`
}

type topicView struct {
	Name    string `json:"name"`
	Display string `json:"display,omitempty"`
	About   string `json:"about,omitempty"`
	Noted   bool   `json:"noted"`   // has panel notes
	Granted bool   `json:"granted"` // appears literally in some ACL entry
}

func tokenID(tk string) string {
	h := sha256.Sum256([]byte(tk))
	return hex.EncodeToString(h[:8])
}

func viewToken(t *ntfyToken) *tokenView {
	prefix := t.Token
	if len(prefix) > 7 {
		prefix = prefix[:7] + "…"
	}
	return &tokenView{ID: tokenID(t.Token), Prefix: prefix, Label: t.Label, Expires: t.Expires,
		LastAccess: t.LastAccess, LastOrigin: t.LastOrigin, Provisioned: t.Provisioned}
}

func (a *App) userTokens(ctx context.Context, s *session, users []*ntfyUser, c caps) (map[string][]*ntfyToken, map[string]bool) {
	out, visible := map[string][]*ntfyToken{}, map[string]bool{}
	if !c.Tokens {
		return out, visible
	}
	if c.Socket {
		all, err := a.ntfy.tokens(ctx, a.auth(s), "")
		if err == nil {
			for _, t := range all {
				out[t.Username] = append(out[t.Username], t)
			}
			for _, u := range users {
				visible[u.Username] = true
			}
			return out, visible
		}
		slog.Warn("listing all tokens over the socket failed, falling back to per user", "err", err)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, u := range users {
		if u.Username == "*" || (u.Role == "admin" && !c.Socket) {
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ts, err := a.ntfy.tokens(ctx, a.auth(s), name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				slog.Warn("listing tokens failed", "user", name, "err", err)
				return
			}
			out[name], visible[name] = ts, true
		}(u.Username)
	}
	wg.Wait()
	return out, visible
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request, s *session) error {
	ctx := r.Context()
	c := a.caps(ctx, s)
	users, err := a.ntfy.users(ctx, a.auth(s))
	if err != nil {
		return err
	}
	tokens, visible := a.userTokens(ctx, s, users, c)

	var views []*userView
	var everyone *userView
	topicSet := map[string]*topicView{}
	for _, u := range users {
		v := &userView{ntfyUser: u, Grants: u.Grants, Tokens: []*tokenView{}, TokensVisible: visible[u.Username]}
		if v.Grants == nil {
			v.Grants = []*ntfyGrant{}
		}
		for _, t := range tokens[u.Username] {
			v.Tokens = append(v.Tokens, viewToken(t))
		}
		sort.Slice(v.Tokens, func(i, j int) bool { return v.Tokens[i].Label < v.Tokens[j].Label })
		for _, g := range u.Grants {
			if reTopic.MatchString(g.Topic) {
				topicSet[g.Topic] = &topicView{Name: g.Topic, Granted: true}
			}
		}
		if u.Username == "*" {
			everyone = v
			continue
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Username < views[j].Username })
	for name, n := range a.topics.all() {
		t := topicSet[name]
		if t == nil {
			t = &topicView{Name: name}
			topicSet[name] = t
		}
		t.Display, t.About, t.Noted = n.Display, n.About, true
	}
	topicList := make([]*topicView, 0, len(topicSet))
	for _, t := range topicSet {
		topicList = append(topicList, t)
	}
	sort.Slice(topicList, func(i, j int) bool { return topicList[i].Name < topicList[j].Name })

	server := map[string]any{"healthy": a.ntfy.healthy(ctx), "url": a.cfg.NtfyURL}
	if v, err := a.ntfy.version(ctx, a.auth(s)); err == nil {
		server["version"] = v.Version
	}
	// ntfy's /v1/config deliberately reports an empty base_url, so the public
	// URL (what phones use) has to come from our own config
	server["public_url"], server["public_url_set"] = a.cfg.PublicURL, a.cfg.PublicURL != ""
	if a.cfg.PublicURL == "" {
		server["public_url"] = a.cfg.NtfyURL
	}
	defaultAccess := ""
	if everyone != nil {
		defaultAccess = everyone.DefaultAccess
	}
	server["default_access"] = defaultAccess

	tiers, _ := a.ntfy.tiers(ctx, a.auth(s)) // optional; empty on servers without tiers
	writeJSON(w, http.StatusOK, map[string]any{
		"server":         server,
		"caps":           c,
		"users":          views,
		"everyone":       everyone,
		"topics":         topicList,
		"tiers":          tiers,
		"notes_writable": a.topics.writable,
	})
	return nil
}

// --- users -------------------------------------------------------------------------------

const pwAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generatePassword(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(pwAlphabet)))
	for i := range b {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = pwAlphabet[k.Int64()]
	}
	return string(b)
}

type userIn struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Generate bool   `json:"generate"`
	Role     string `json:"role"`
	Tier     string `json:"tier"`
}

func (in *userIn) password() (string, error) {
	if in.Generate {
		return generatePassword(20), nil
	}
	if in.Password == "" {
		return "", nil
	}
	if len(in.Password) < 8 {
		return "", bad("password: at least 8 characters")
	}
	if len(in.Password) > 128 {
		return "", bad("password: at most 128 characters")
	}
	return in.Password, nil
}

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request, s *session) error {
	var in userIn
	if err := decode(r, &in); err != nil {
		return err
	}
	if !reUsername.MatchString(in.Username) {
		return bad("username: letters, digits and - _ . + @ only")
	}
	pw, err := in.password()
	if err != nil {
		return err
	}
	if pw == "" {
		return bad("password: set one or generate one")
	}
	if in.Role != "" && in.Role != "user" && in.Role != "admin" {
		return bad("role: user or admin")
	}
	if in.Role == "admin" && a.ntfy.socket == nil {
		return bad("creating admins needs the admin socket (NTFY_ADMIN_SOCKET)")
	}
	ctx := r.Context()
	if err := a.ntfy.addUser(ctx, a.auth(s), userWrite{Username: in.Username, Password: pw, Tier: in.Tier}); err != nil {
		return err
	}
	if in.Role == "admin" {
		if err := a.ntfy.updateUser(ctx, a.auth(s), userWrite{Username: in.Username, Role: "admin"}); err != nil {
			return fmt.Errorf("user created, but making it admin failed: %w", err)
		}
	}
	a.audit(r, s, "user.create", "user", in.Username, "role", in.Role)
	out := map[string]any{"ok": true}
	if in.Generate {
		out["password"] = pw
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (a *App) handleUserUpdate(w http.ResponseWriter, r *http.Request, s *session) error {
	name := r.PathValue("name")
	var in userIn
	if err := decode(r, &in); err != nil {
		return err
	}
	pw, err := in.password()
	if err != nil {
		return err
	}
	if in.Role != "" && in.Role != "user" && in.Role != "admin" {
		return bad("role: user or admin")
	}
	if in.Role != "" && a.ntfy.socket == nil {
		return bad("changing roles needs the admin socket (NTFY_ADMIN_SOCKET)")
	}
	if in.Role == "user" && name == s.Username {
		return bad("you cannot demote yourself")
	}
	if pw == "" && in.Role == "" && in.Tier == "" {
		return bad("nothing to change")
	}
	if err := a.ntfy.updateUser(r.Context(), a.auth(s), userWrite{Username: name, Password: pw, Role: in.Role, Tier: in.Tier}); err != nil {
		return err
	}
	a.audit(r, s, "user.update", "user", name, "password", pw != "", "role", in.Role, "tier", in.Tier)
	out := map[string]any{"ok": true}
	if in.Generate {
		out["password"] = pw
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (a *App) handleUserDelete(w http.ResponseWriter, r *http.Request, s *session) error {
	name := r.PathValue("name")
	if name == s.Username {
		return bad("you cannot delete yourself")
	}
	if err := a.ntfy.deleteUser(r.Context(), a.auth(s), name); err != nil {
		return err
	}
	a.audit(r, s, "user.delete", "user", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handleResetLink(w http.ResponseWriter, r *http.Request, s *session) error {
	name := r.PathValue("name")
	link, err := a.ntfy.passwordResetLink(r.Context(), a.auth(s), name)
	if err != nil {
		return err
	}
	a.audit(r, s, "user.reset_link", "user", name)
	writeJSON(w, http.StatusOK, map[string]string{"link": link})
	return nil
}

// --- access ------------------------------------------------------------------------------

type accessIn struct {
	Username   string `json:"username"`
	Topic      string `json:"topic"`
	Permission string `json:"permission"`
}

func (in *accessIn) validate(needPerm bool) error {
	if in.Username != "*" && !reUsername.MatchString(in.Username) {
		return bad("username invalid")
	}
	if !rePattern.MatchString(in.Topic) {
		return bad("topic: letters, digits, - _ and * wildcards, max 64")
	}
	if needPerm {
		p, ok := perms[in.Permission]
		if !ok {
			return bad("permission: read-write | read-only | write-only | deny-all")
		}
		in.Permission = p
	}
	return nil
}

func (a *App) handleAccessSet(w http.ResponseWriter, r *http.Request, s *session) error {
	var in accessIn
	if err := decode(r, &in); err != nil {
		return err
	}
	if err := in.validate(true); err != nil {
		return err
	}
	if err := a.ntfy.allowAccess(r.Context(), a.auth(s), in.Username, in.Topic, in.Permission); err != nil {
		return err
	}
	a.audit(r, s, "access.set", "user", in.Username, "topic", in.Topic, "perm", in.Permission)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handleAccessDelete(w http.ResponseWriter, r *http.Request, s *session) error {
	var in accessIn
	if err := decode(r, &in); err != nil {
		return err
	}
	if err := in.validate(false); err != nil {
		return err
	}
	if err := a.ntfy.resetAccess(r.Context(), a.auth(s), in.Username, in.Topic); err != nil {
		return err
	}
	a.audit(r, s, "access.delete", "user", in.Username, "topic", in.Topic)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// --- tokens ---------------------------------------------------------------------------------

func (a *App) findToken(ctx context.Context, s *session, username, id string) (*ntfyToken, error) {
	ts, err := a.ntfy.tokens(ctx, a.auth(s), username)
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		if tokenID(t.Token) == id {
			return t, nil
		}
	}
	return nil, &apiError{http.StatusNotFound, "token not found (already deleted?)"}
}

func (a *App) handleTokenCreate(w http.ResponseWriter, r *http.Request, s *session) error {
	var in struct {
		Username string `json:"username"`
		Label    string `json:"label"`
		Expires  int64  `json:"expires"` // unix seconds, 0 = never
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	in.Label = strings.TrimSpace(in.Label)
	if !reUsername.MatchString(in.Username) {
		return bad("username invalid")
	}
	if in.Label == "" || len(in.Label) > 64 || strings.ContainsAny(in.Label, "\r\n") {
		return bad("label: 1-64 characters, one line — name it after the device or service using it")
	}
	if in.Expires != 0 && in.Expires <= time.Now().Unix() {
		return bad("expiry must be in the future")
	}
	t, err := a.ntfy.addToken(r.Context(), a.auth(s), in.Username, in.Label, in.Expires)
	if err != nil {
		return err
	}
	a.audit(r, s, "token.create", "user", in.Username, "label", in.Label)
	writeJSON(w, http.StatusOK, map[string]any{"token": t.Token, "view": viewToken(t)})
	return nil
}

type tokenRef struct {
	Username string `json:"username"`
	ID       string `json:"id"`
}

func (a *App) handleTokenReveal(w http.ResponseWriter, r *http.Request, s *session) error {
	var in tokenRef
	if err := decode(r, &in); err != nil {
		return err
	}
	t, err := a.findToken(r.Context(), s, in.Username, in.ID)
	if err != nil {
		return err
	}
	a.audit(r, s, "token.reveal", "user", in.Username, "label", t.Label)
	writeJSON(w, http.StatusOK, map[string]string{"token": t.Token})
	return nil
}

func (a *App) handleTokenDelete(w http.ResponseWriter, r *http.Request, s *session) error {
	var in tokenRef
	if err := decode(r, &in); err != nil {
		return err
	}
	ctx := r.Context()
	t, err := a.findToken(ctx, s, in.Username, in.ID)
	if err != nil {
		return err
	}
	if err := a.ntfy.deleteToken(ctx, a.auth(s), in.Username, t.Token); err != nil {
		return err
	}
	a.audit(r, s, "token.delete", "user", in.Username, "label", t.Label)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// --- topics / publish ----------------------------------------------------------------------

func (a *App) handleTopicSet(w http.ResponseWriter, r *http.Request, s *session) error {
	name := r.PathValue("name")
	if !reTopic.MatchString(name) {
		return bad("topic: letters, digits, - and _, max 64")
	}
	var n topicNote
	if err := decode(r, &n); err != nil {
		return err
	}
	n.Display, n.About = strings.TrimSpace(n.Display), strings.TrimSpace(n.About)
	if len(n.Display) > 100 || len(n.About) > 300 || strings.ContainsAny(n.Display+n.About, "\r\n") {
		return bad("display: max 100, about: max 300 characters, one line each")
	}
	if err := a.topics.set(name, n); err != nil {
		return &apiError{http.StatusConflict, err.Error()}
	}
	a.audit(r, s, "topic.note", "topic", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handleTopicDelete(w http.ResponseWriter, r *http.Request, s *session) error {
	name := r.PathValue("name")
	if err := a.topics.remove(name); err != nil {
		return &apiError{http.StatusConflict, err.Error()}
	}
	a.audit(r, s, "topic.forget", "topic", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handlePublish(w http.ResponseWriter, r *http.Request, s *session) error {
	var in publishReq
	if err := decode(r, &in); err != nil {
		return err
	}
	if !reTopic.MatchString(in.Topic) {
		return bad("topic invalid")
	}
	if strings.TrimSpace(in.Message) == "" {
		in.Message = "Test from ntfy-admin"
	}
	if in.Priority < 0 || in.Priority > 5 {
		return bad("priority: 1-5")
	}
	if err := a.ntfy.publish(r.Context(), a.auth(s), in); err != nil {
		return err
	}
	a.audit(r, s, "publish", "topic", in.Topic)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// --- QR / export ------------------------------------------------------------------------------

func (a *App) handleQR(w http.ResponseWriter, r *http.Request, s *session) error {
	data := r.URL.Query().Get("data")
	if len(data) > 512 || !(strings.HasPrefix(data, "ntfy://") || strings.HasPrefix(data, "https://") || strings.HasPrefix(data, "http://")) {
		return bad("qr: only ntfy:// or http(s) links, max 512 chars")
	}
	png, err := qrcode.Encode(data, qrcode.Medium, 320)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, err = w.Write(png)
	return err
}

type exportUser struct {
	Role   string            `yaml:"role,omitempty"`
	Tier   string            `yaml:"tier,omitempty"`
	Access map[string]string `yaml:"access,omitempty"`
	Tokens []string          `yaml:"tokens,omitempty"`
	Note   string            `yaml:"note,omitempty"`
}

// handleExport dumps who-can-what as YAML, for docs or git. No hashes, no token values.
func (a *App) handleExport(w http.ResponseWriter, r *http.Request, s *session) error {
	ctx := r.Context()
	c := a.caps(ctx, s)
	users, err := a.ntfy.users(ctx, a.auth(s))
	if err != nil {
		return err
	}
	tokens, visible := a.userTokens(ctx, s, users, c)
	doc := struct {
		Exported      string                `yaml:"exported"`
		Server        string                `yaml:"server"`
		DefaultAccess string                `yaml:"default_access,omitempty"`
		Users         map[string]exportUser `yaml:"users"`
		Topics        map[string]topicNote  `yaml:"topics,omitempty"`
	}{
		Exported: time.Now().UTC().Format(time.RFC3339),
		Server:   a.cfg.PublicURL,
		Users:    map[string]exportUser{},
		Topics:   a.topics.all(),
	}
	if doc.Server == "" {
		doc.Server = a.cfg.NtfyURL
	}
	for _, u := range users {
		eu := exportUser{Tier: u.Tier, Access: map[string]string{}}
		if u.Role != "user" && u.Role != "anonymous" {
			eu.Role = u.Role
		}
		for _, g := range u.Grants {
			eu.Access[g.Topic] = g.Permission
		}
		for _, t := range tokens[u.Username] {
			eu.Tokens = append(eu.Tokens, t.Label)
		}
		sort.Strings(eu.Tokens)
		if u.Username != "*" && !visible[u.Username] && c.Tokens {
			eu.Note = "tokens not visible over HTTP (admin user)"
		}
		if u.Provisioned {
			eu.Note = strings.TrimPrefix(eu.Note+"; provisioned in server.yml", "; ")
		}
		if u.Username == "*" {
			doc.DefaultAccess = u.DefaultAccess
			if len(eu.Access) == 0 {
				continue
			}
		}
		doc.Users[u.Username] = eu
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	a.audit(r, s, "export")
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="ntfy-access.yml"`)
	_, err = w.Write(append([]byte("# ntfy access export (ntfy-admin) — no passwords, no token values\n"), out...))
	return err
}
