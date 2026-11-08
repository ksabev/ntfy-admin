package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

const cookieName = "ntfy_admin"

type App struct {
	cfg      *Config
	servers  *registry
	sessions *sessionStore
	limiter  *loginLimiter
}

func newApp(cfg *Config) (*App, error) {
	return &App{
		cfg:      cfg,
		servers:  newRegistry(cfg),
		sessions: newSessionStore(),
		limiter:  newLoginLimiter(),
	}, nil
}

// --- plumbing --------------------------------------------------------------------------

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func bad(format string, a ...any) error {
	return &apiError{http.StatusBadRequest, fmt.Sprintf(format, a...)}
}

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
		msg, code := ne.Message, ""
		if status == http.StatusUnauthorized { // our ntfy session token died: log in to that server again
			msg, code = "ntfy session expired, please log in again", "server_login"
		}
		writeJSON(w, status, map[string]any{"error": msg, "ntfy_code": ne.Code, "code": code})
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

func (a *App) cookie(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	return a.sessions.get(c.Value)
}

func (a *App) setCookie(w http.ResponseWriter, r *http.Request, s *session) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.ID, Path: a.cfg.BasePath + "/",
		HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteStrictMode, Expires: s.ExpiresAt,
	})
}

func (a *App) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: a.cfg.BasePath + "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteStrictMode})
}

func csrfOK(r *http.Request, s *session) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	t := r.Header.Get("X-CSRF-Token")
	return t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(s.CSRF)) == 1
}

func audit(s *session, server, action string, attrs ...any) {
	slog.Info("audit", append([]any{"ip", s.ClientIP, "server", server, "action", action}, attrs...)...)
}

// sessioned: valid cookie, logged in to at least one server, CSRF on changes.
func (a *App) sessioned(h func(w http.ResponseWriter, r *http.Request, s *session) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := a.cookie(r)
		if s == nil || !s.anyLogin() {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in", "code": "login"})
			return
		}
		if !csrfOK(r, s) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or bad CSRF token"})
			return
		}
		if err := h(w, r, s); err != nil {
			writeErr(w, err)
		}
	}
}

// call is one request scoped to one server the browser is logged in to.
type call struct {
	s     *session
	srv   *Server
	login *login
}

func (c *call) auth() auth { return auth{token: c.login.Token, clientIP: c.s.ClientIP} }

func (c *call) audit(action string, attrs ...any) {
	audit(c.s, c.srv.ID, action, append([]any{"admin", c.login.Username}, attrs...)...)
}

// scoped: like sessioned, plus a login to the server named in {sid}.
func (a *App) scoped(h func(w http.ResponseWriter, r *http.Request, c *call) error) http.HandlerFunc {
	return a.sessioned(func(w http.ResponseWriter, r *http.Request, s *session) error {
		srv := a.servers.get(r.PathValue("sid"))
		if srv == nil {
			return &apiError{http.StatusNotFound, "no such server"}
		}
		l := s.login(srv.ID)
		if l == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in to " + srv.Name, "code": "server_login"})
			return nil
		}
		return h(w, r, &call{s: s, srv: srv, login: l})
	})
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	p := a.cfg.BasePath

	static, _ := fs.Sub(webFS, "web")
	mux.Handle("GET "+p+"/", http.StripPrefix(p+"/", http.FileServer(http.FS(static))))
	if p != "" {
		mux.Handle("GET "+p, http.RedirectHandler(p+"/", http.StatusMovedPermanently))
	}
	mux.HandleFunc("GET "+p+"/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version})
	})

	// panel-level
	mux.HandleFunc("GET "+p+"/api/servers", a.handleServers)
	mux.HandleFunc("POST "+p+"/api/setup", a.handleSetup)
	mux.HandleFunc("GET "+p+"/api/me", a.sessioned(a.handleMe))
	mux.HandleFunc("POST "+p+"/api/logout", a.sessioned(a.handleLogoutAll))
	mux.HandleFunc("POST "+p+"/api/servers", a.sessioned(a.handleServerAdd))
	mux.HandleFunc("PUT "+p+"/api/servers/{id}", a.sessioned(a.handleServerUpdate))
	mux.HandleFunc("DELETE "+p+"/api/servers/{id}", a.sessioned(a.handleServerDelete))
	mux.HandleFunc("GET "+p+"/api/qr", a.sessioned(a.handleQR))

	// per server
	s := p + "/api/s/{sid}"
	mux.HandleFunc("POST "+s+"/login", a.handleLogin)
	mux.HandleFunc("POST "+s+"/logout", a.scoped(a.handleLogout))
	mux.HandleFunc("GET "+s+"/state", a.scoped(a.handleState))
	mux.HandleFunc("POST "+s+"/users", a.scoped(a.handleUserCreate))
	mux.HandleFunc("PATCH "+s+"/users/{name}", a.scoped(a.handleUserUpdate))
	mux.HandleFunc("DELETE "+s+"/users/{name}", a.scoped(a.handleUserDelete))
	mux.HandleFunc("POST "+s+"/users/{name}/reset-link", a.scoped(a.handleResetLink))
	mux.HandleFunc("PUT "+s+"/access", a.scoped(a.handleAccessSet))
	mux.HandleFunc("POST "+s+"/access/delete", a.scoped(a.handleAccessDelete))
	mux.HandleFunc("POST "+s+"/tokens", a.scoped(a.handleTokenCreate))
	mux.HandleFunc("POST "+s+"/tokens/reveal", a.scoped(a.handleTokenReveal))
	mux.HandleFunc("POST "+s+"/tokens/delete", a.scoped(a.handleTokenDelete))
	mux.HandleFunc("PUT "+s+"/topics/{name}", a.scoped(a.handleTopicSet))
	mux.HandleFunc("DELETE "+s+"/topics/{name}", a.scoped(a.handleTopicDelete))
	mux.HandleFunc("POST "+s+"/publish", a.scoped(a.handlePublish))
	mux.HandleFunc("GET "+s+"/export", a.scoped(a.handleExport))

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

// --- login --------------------------------------------------------------------------------

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// verifyAdmin checks the credentials against ntfy and swaps them for a session token.
func (a *App) verifyAdmin(ctx context.Context, client *NtfyClient, in credentials, ip string) (*login, error) {
	if !a.limiter.allowed(ip) {
		return nil, &apiError{http.StatusTooManyRequests, "too many failed logins, try again in a few minutes"}
	}
	cred := auth{basicUser: in.Username, basicPass: in.Password, clientIP: ip}
	acc, err := client.account(ctx, cred)
	if err != nil || in.Username == "" || acc.Username != in.Username {
		a.limiter.fail(ip)
		slog.Warn("login failed", "user", in.Username, "ip", ip, "err", err)
		if err != nil && !isStatus(err, http.StatusUnauthorized) && !isStatus(err, http.StatusForbidden) {
			return nil, err
		}
		return nil, &apiError{http.StatusUnauthorized, "wrong username or password"}
	}
	if acc.Role != "admin" {
		a.limiter.fail(ip)
		slog.Warn("login refused: not an admin", "user", in.Username, "ip", ip)
		return nil, &apiError{http.StatusForbidden, "this ntfy account is not an admin"}
	}
	token, err := client.createSessionToken(ctx, cred, "ntfy-admin session", time.Now().Add(a.cfg.SessionTTL))
	if err != nil {
		return nil, err
	}
	a.limiter.reset(ip)
	return &login{Username: acc.Username, Token: token}, nil
}

// attach adds a login to the browser's session, creating the session if needed.
func (a *App) attach(w http.ResponseWriter, r *http.Request, srv *Server, l *login) *session {
	s := a.cookie(r)
	if s == nil {
		s = a.sessions.create(a.clientIP(r), a.cfg.SessionTTL)
		a.setCookie(w, r, s)
	}
	if old := s.setLogin(srv.ID, l); old != nil {
		_ = srv.client.deleteSessionToken(r.Context(), old.Token)
	}
	audit(s, srv.ID, "login", "admin", l.Username)
	return s
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	srv := a.servers.get(r.PathValue("sid"))
	if srv == nil {
		writeErr(w, &apiError{http.StatusNotFound, "no such server"})
		return
	}
	var in credentials
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	l, err := a.verifyAdmin(r.Context(), srv.client, in, a.clientIP(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	s := a.attach(w, r, srv, l)
	writeJSON(w, http.StatusOK, a.me(s))
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request, c *call) error {
	c.s.setLogin(c.srv.ID, nil)
	_ = c.srv.client.deleteSessionToken(r.Context(), c.login.Token)
	c.audit("logout")
	if !c.s.anyLogin() {
		a.sessions.remove(c.s.ID)
		a.clearCookie(w, r)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handleLogoutAll(w http.ResponseWriter, r *http.Request, s *session) error {
	for sid, l := range s.loginsCopy() {
		if srv := a.servers.get(sid); srv != nil {
			_ = srv.client.deleteSessionToken(r.Context(), l.Token)
		}
	}
	a.sessions.remove(s.ID)
	a.clearCookie(w, r)
	audit(s, "", "logout_all")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) me(s *session) map[string]any {
	logins := map[string]string{}
	for sid, l := range s.loginsCopy() {
		logins[sid] = l.Username
	}
	return map[string]any{"csrf": s.CSRF, "logins": logins, "super": a.cfg.Super, "version": version}
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request, s *session) error {
	writeJSON(w, http.StatusOK, a.me(s))
	return nil
}

// --- servers ------------------------------------------------------------------------------

type serverView struct {
	ServerConfig
	Healthy  *bool  `json:"healthy,omitempty"`
	LoggedIn string `json:"logged_in,omitempty"`
	Socket   bool   `json:"uses_socket"`
}

// handleServers: public part (names, for the login screen) without a session;
// full config and health with one.
func (a *App) handleServers(w http.ResponseWriter, r *http.Request) {
	s := a.cookie(r)
	authed := s != nil && s.anyLogin()
	list := a.servers.list()
	out := make([]any, len(list))
	var wg sync.WaitGroup
	for i, srv := range list {
		if !authed {
			out[i] = map[string]string{"id": srv.ID, "name": srv.Name}
			continue
		}
		v := &serverView{ServerConfig: srv.ServerConfig, Socket: srv.usesSocket()}
		if !a.cfg.Super {
			v.ServerConfig.Socket = "" // not a concern of the regular panel
		}
		if l := s.login(srv.ID); l != nil {
			v.LoggedIn = l.Username
		}
		out[i] = v
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			ok := srv.client.healthy(ctx)
			v.Healthy = &ok
		}()
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":      out,
		"setup_needed": len(list) == 0,
		"super":        a.cfg.Super,
		"editable":     a.servers.editable() == nil,
		"locked":       a.servers.locked,
		"version":      version,
	})
}

type serverIn struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	PublicURL string `json:"public_url"`
	Socket    string `json:"socket"`
	SkipCheck bool   `json:"skip_check"`
}

func (in serverIn) config() ServerConfig {
	return ServerConfig{Name: in.Name, URL: in.URL, PublicURL: in.PublicURL, Socket: in.Socket}
}

// handleSetup adds the very first server. No session exists yet, so it is only
// allowed while there are no servers, and only with working admin credentials.
func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		serverIn
		credentials
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	if !a.servers.empty() {
		writeErr(w, &apiError{http.StatusConflict, "already set up: log in and add servers from the Servers tab"})
		return
	}
	if err := a.servers.editable(); err != nil {
		writeErr(w, err)
		return
	}
	sc := in.serverIn.config()
	if !a.cfg.Super {
		sc.Socket = ""
	}
	if err := a.servers.validate(r.Context(), &sc, false); err != nil {
		writeErr(w, err)
		return
	}
	l, err := a.verifyAdmin(r.Context(), newNtfyClient(sc), in.credentials, a.clientIP(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	if !a.servers.empty() { // lost a race with another setup
		writeErr(w, &apiError{http.StatusConflict, "already set up"})
		return
	}
	srv, err := a.servers.add(sc)
	if err != nil {
		writeErr(w, err)
		return
	}
	s := a.attach(w, r, srv, l)
	audit(s, srv.ID, "server.setup", "url", sc.URL)
	writeJSON(w, http.StatusOK, map[string]any{"me": a.me(s), "server": srv.ID})
}

func (a *App) handleServerAdd(w http.ResponseWriter, r *http.Request, s *session) error {
	if err := a.servers.editable(); err != nil {
		return err
	}
	var in serverIn
	if err := decode(r, &in); err != nil {
		return err
	}
	sc := in.config()
	if !a.cfg.Super {
		sc.Socket = ""
	}
	if err := a.servers.validate(r.Context(), &sc, in.SkipCheck); err != nil {
		return err
	}
	srv, err := a.servers.add(sc)
	if err != nil {
		return err
	}
	audit(s, srv.ID, "server.add", "url", sc.URL)
	writeJSON(w, http.StatusOK, map[string]string{"id": srv.ID})
	return nil
}

func (a *App) handleServerUpdate(w http.ResponseWriter, r *http.Request, s *session) error {
	if err := a.servers.editable(); err != nil {
		return err
	}
	old := a.servers.get(r.PathValue("id"))
	if old == nil {
		return &apiError{http.StatusNotFound, "no such server"}
	}
	var in serverIn
	if err := decode(r, &in); err != nil {
		return err
	}
	sc := in.config()
	if !a.cfg.Super {
		sc.Socket = old.ServerConfig.Socket // the regular panel never sees or changes it
	}
	if err := a.servers.validate(r.Context(), &sc, in.SkipCheck); err != nil {
		return err
	}
	if sc.URL != old.URL || sc.Socket != old.ServerConfig.Socket {
		// re-pointed: nobody's ntfy token belongs to the new target
		a.sessions.dropServer(r.Context(), old)
	}
	if _, err := a.servers.update(old.ID, sc); err != nil {
		return err
	}
	audit(s, old.ID, "server.update", "url", sc.URL, "public_url", sc.PublicURL)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handleServerDelete(w http.ResponseWriter, r *http.Request, s *session) error {
	if err := a.servers.editable(); err != nil {
		return err
	}
	srv := a.servers.get(r.PathValue("id"))
	if srv == nil {
		return &apiError{http.StatusNotFound, "no such server"}
	}
	a.sessions.dropServer(r.Context(), srv)
	if err := a.servers.remove(srv.ID); err != nil {
		return err
	}
	audit(s, srv.ID, "server.remove")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}
