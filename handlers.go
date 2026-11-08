package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"gopkg.in/yaml.v3"
)

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

// --- capabilities ------------------------------------------------------------------------

type caps struct {
	Socket bool `json:"socket"` // admin socket: roles, admin users, all tokens at once
	Tokens bool `json:"tokens"` // ntfy >= 2.36 admin token API
}

func (c *call) caps(ctx context.Context) caps {
	srv := c.srv
	out := caps{Socket: srv.usesSocket()}
	srv.mu.Lock()
	known := srv.tokensAPI
	srv.mu.Unlock()
	if known != nil {
		out.Tokens = *known
		return out
	}
	// Probe: asking for our own (admin) tokens is 403 over HTTP, 200 over the
	// socket; either way the endpoint exists. Older ntfy answers 404.
	_, err := srv.client.tokens(ctx, c.auth(), c.login.Username)
	var ne *NtfyError
	if err != nil && !errors.As(err, &ne) {
		return out // ntfy unreachable: do not cache a guess
	}
	ok := err == nil || !isStatus(err, http.StatusNotFound)
	srv.mu.Lock()
	srv.tokensAPI = &ok
	srv.mu.Unlock()
	out.Tokens = ok
	return out
}

// --- state ----------------------------------------------------------------------------------

type tokenView struct {
	ID          string `json:"id"`     // sha256 prefix: the browser gets token values only when revealed
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
	Noted   bool   `json:"noted"`
	Granted bool   `json:"granted"`
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

func (c *call) userTokens(ctx context.Context, users []*ntfyUser, cp caps) (map[string][]*ntfyToken, map[string]bool) {
	out, visible := map[string][]*ntfyToken{}, map[string]bool{}
	if !cp.Tokens {
		return out, visible
	}
	if cp.Socket {
		all, err := c.srv.client.tokens(ctx, c.auth(), "")
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
		if u.Username == "*" || (u.Role == "admin" && !cp.Socket) {
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ts, err := c.srv.client.tokens(ctx, c.auth(), name)
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

func (a *App) handleState(w http.ResponseWriter, r *http.Request, c *call) error {
	ctx := r.Context()
	cp := c.caps(ctx)
	users, err := c.srv.client.users(ctx, c.auth())
	if err != nil {
		return err
	}
	tokens, visible := c.userTokens(ctx, users, cp)

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
	for name, n := range c.srv.notes.all() {
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

	server := map[string]any{
		"id": c.srv.ID, "name": c.srv.Name, "healthy": c.srv.client.healthy(ctx), "url": c.srv.URL,
		// ntfy's /v1/config always reports an empty base_url: the public URL is our own setting
		"public_url": c.srv.publicURL(), "public_url_set": c.srv.PublicURL != "",
	}
	if v, err := c.srv.client.version(ctx, c.auth()); err == nil {
		server["version"] = v.Version
	}
	if everyone != nil {
		server["default_access"] = everyone.DefaultAccess
	}
	tiers, _ := c.srv.client.tiers(ctx, c.auth()) // optional
	writeJSON(w, http.StatusOK, map[string]any{
		"server":         server,
		"caps":           cp,
		"me":             c.login.Username,
		"users":          views,
		"everyone":       everyone,
		"topics":         topicList,
		"tiers":          tiers,
		"notes_writable": c.srv.notes.writable,
	})
	return nil
}

// --- users ------------------------------------------------------------------------------------

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

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request, c *call) error {
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
	if in.Role == "admin" && !c.srv.usesSocket() {
		return bad("creating admins needs super admin mode (admin socket)")
	}
	ctx := r.Context()
	if err := c.srv.client.addUser(ctx, c.auth(), userWrite{Username: in.Username, Password: pw, Tier: in.Tier}); err != nil {
		return err
	}
	if in.Role == "admin" {
		if err := c.srv.client.updateUser(ctx, c.auth(), userWrite{Username: in.Username, Role: "admin"}); err != nil {
			return fmt.Errorf("user created, but making it admin failed: %w", err)
		}
	}
	c.audit("user.create", "user", in.Username, "role", in.Role)
	out := map[string]any{"ok": true}
	if in.Generate {
		out["password"] = pw
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (a *App) handleUserUpdate(w http.ResponseWriter, r *http.Request, c *call) error {
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
	if in.Role != "" && !c.srv.usesSocket() {
		return bad("changing roles needs super admin mode (admin socket)")
	}
	if in.Role == "user" && name == c.login.Username {
		return bad("you cannot demote yourself")
	}
	if pw == "" && in.Role == "" && in.Tier == "" {
		return bad("nothing to change")
	}
	if err := c.srv.client.updateUser(r.Context(), c.auth(), userWrite{Username: name, Password: pw, Role: in.Role, Tier: in.Tier}); err != nil {
		return err
	}
	c.audit("user.update", "user", name, "password", pw != "", "role", in.Role, "tier", in.Tier)
	out := map[string]any{"ok": true}
	if in.Generate {
		out["password"] = pw
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (a *App) handleUserDelete(w http.ResponseWriter, r *http.Request, c *call) error {
	name := r.PathValue("name")
	if name == c.login.Username {
		return bad("you cannot delete yourself")
	}
	if err := c.srv.client.deleteUser(r.Context(), c.auth(), name); err != nil {
		return err
	}
	c.audit("user.delete", "user", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handleResetLink(w http.ResponseWriter, r *http.Request, c *call) error {
	name := r.PathValue("name")
	link, err := c.srv.client.passwordResetLink(r.Context(), c.auth(), name)
	if err != nil {
		return err
	}
	c.audit("user.reset_link", "user", name)
	writeJSON(w, http.StatusOK, map[string]string{"link": link})
	return nil
}

// --- access -------------------------------------------------------------------------------------

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

func (a *App) handleAccessSet(w http.ResponseWriter, r *http.Request, c *call) error {
	var in accessIn
	if err := decode(r, &in); err != nil {
		return err
	}
	if err := in.validate(true); err != nil {
		return err
	}
	if err := c.srv.client.allowAccess(r.Context(), c.auth(), in.Username, in.Topic, in.Permission); err != nil {
		return err
	}
	c.audit("access.set", "user", in.Username, "topic", in.Topic, "perm", in.Permission)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handleAccessDelete(w http.ResponseWriter, r *http.Request, c *call) error {
	var in accessIn
	if err := decode(r, &in); err != nil {
		return err
	}
	if err := in.validate(false); err != nil {
		return err
	}
	if err := c.srv.client.resetAccess(r.Context(), c.auth(), in.Username, in.Topic); err != nil {
		return err
	}
	c.audit("access.delete", "user", in.Username, "topic", in.Topic)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// --- tokens ---------------------------------------------------------------------------------------

func (c *call) findToken(ctx context.Context, username, id string) (*ntfyToken, error) {
	ts, err := c.srv.client.tokens(ctx, c.auth(), username)
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

func (a *App) handleTokenCreate(w http.ResponseWriter, r *http.Request, c *call) error {
	var in struct {
		Username string `json:"username"`
		Label    string `json:"label"`
		Expires  int64  `json:"expires"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	in.Label = strings.TrimSpace(in.Label)
	if !reUsername.MatchString(in.Username) {
		return bad("username invalid")
	}
	if in.Label == "" || len(in.Label) > 64 || strings.ContainsAny(in.Label, "\r\n") {
		return bad("label: 1-64 characters, one line; name it after the device or service using it")
	}
	if in.Expires != 0 && in.Expires <= time.Now().Unix() {
		return bad("expiry must be in the future")
	}
	t, err := c.srv.client.addToken(r.Context(), c.auth(), in.Username, in.Label, in.Expires)
	if err != nil {
		return err
	}
	c.audit("token.create", "user", in.Username, "label", in.Label)
	writeJSON(w, http.StatusOK, map[string]any{"token": t.Token, "view": viewToken(t)})
	return nil
}

type tokenRef struct {
	Username string `json:"username"`
	ID       string `json:"id"`
}

func (a *App) handleTokenReveal(w http.ResponseWriter, r *http.Request, c *call) error {
	var in tokenRef
	if err := decode(r, &in); err != nil {
		return err
	}
	t, err := c.findToken(r.Context(), in.Username, in.ID)
	if err != nil {
		return err
	}
	c.audit("token.reveal", "user", in.Username, "label", t.Label)
	writeJSON(w, http.StatusOK, map[string]string{"token": t.Token})
	return nil
}

func (a *App) handleTokenDelete(w http.ResponseWriter, r *http.Request, c *call) error {
	var in tokenRef
	if err := decode(r, &in); err != nil {
		return err
	}
	ctx := r.Context()
	t, err := c.findToken(ctx, in.Username, in.ID)
	if err != nil {
		return err
	}
	if err := c.srv.client.deleteToken(ctx, c.auth(), in.Username, t.Token); err != nil {
		return err
	}
	c.audit("token.delete", "user", in.Username, "label", t.Label)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// --- topics / publish ---------------------------------------------------------------------------

func (a *App) handleTopicSet(w http.ResponseWriter, r *http.Request, c *call) error {
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
	if err := c.srv.notes.set(name, n); err != nil {
		return &apiError{http.StatusConflict, err.Error()}
	}
	c.audit("topic.note", "topic", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handleTopicDelete(w http.ResponseWriter, r *http.Request, c *call) error {
	name := r.PathValue("name")
	if err := c.srv.notes.remove(name); err != nil {
		return &apiError{http.StatusConflict, err.Error()}
	}
	c.audit("topic.forget", "topic", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (a *App) handlePublish(w http.ResponseWriter, r *http.Request, c *call) error {
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
	if err := c.srv.client.publish(r.Context(), c.auth(), in); err != nil {
		return err
	}
	c.audit("publish", "topic", in.Topic)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// --- QR / export --------------------------------------------------------------------------------

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
func (a *App) handleExport(w http.ResponseWriter, r *http.Request, c *call) error {
	ctx := r.Context()
	cp := c.caps(ctx)
	users, err := c.srv.client.users(ctx, c.auth())
	if err != nil {
		return err
	}
	tokens, visible := c.userTokens(ctx, users, cp)
	doc := struct {
		Exported      string                `yaml:"exported"`
		Server        string                `yaml:"server"`
		DefaultAccess string                `yaml:"default_access,omitempty"`
		Users         map[string]exportUser `yaml:"users"`
		Topics        map[string]topicNote  `yaml:"topics,omitempty"`
	}{
		Exported: time.Now().UTC().Format(time.RFC3339),
		Server:   c.srv.publicURL(),
		Users:    map[string]exportUser{},
		Topics:   c.srv.notes.all(),
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
		if u.Username != "*" && !visible[u.Username] && cp.Tokens {
			eu.Note = "tokens not visible outside super admin mode (admin user)"
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
	c.audit("export")
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ntfy-access-%s.yml"`, c.srv.ID))
	_, err = w.Write(append([]byte("# ntfy access export (ntfy-admin): no passwords, no token values\n"), out...))
	return err
}
