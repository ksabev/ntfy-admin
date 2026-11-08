package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ServerConfig is one ntfy server the panel manages. No secrets in here.
type ServerConfig struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`                  // how the panel reaches ntfy (internal)
	PublicURL string `json:"public_url,omitempty"` // how phones reach ntfy (QR codes, examples)
	Socket    string `json:"socket,omitempty"`     // ntfy admin socket path inside this container
}

// Server is a configured server plus its client and probed capabilities.
type Server struct {
	ServerConfig
	client *NtfyClient
	notes  *topicStore

	mu        sync.Mutex
	tokensAPI *bool // nil = not probed yet; ntfy < 2.36 has no admin token API
}

type registry struct {
	mu       sync.RWMutex
	dir      string
	path     string
	servers  map[string]*Server
	writable bool
	locked   bool
	super    bool      // only super mode talks to admin sockets
	mtime    time.Time // servers.json as last loaded; another panel instance may change it
}

var reServerID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func newRegistry(cfg *Config) *registry {
	r := &registry{dir: cfg.DataDir, path: filepath.Join(cfg.DataDir, "servers.json"),
		servers: map[string]*Server{}, locked: cfg.LockServers, super: cfg.Super}
	r.writable = probeWritable(cfg.DataDir)

	list, err := r.readFile()
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		if cfg.Seed.URL != "" { // first start: seed from the environment
			s := cfg.Seed
			if s.Name == "" {
				s.Name = hostOf(firstNonEmpty(s.PublicURL, s.URL))
			}
			s.ID = slugify(s.Name)
			list = []ServerConfig{s}
			slog.Info("seeded first server from environment", "name", s.Name, "url", s.URL)
		}
	default:
		slog.Error("cannot read servers.json; starting with no servers", "err", err)
	}
	for _, sc := range list {
		r.servers[sc.ID] = r.build(sc)
	}
	if errors.Is(err, fs.ErrNotExist) && len(list) > 0 && r.writable {
		if err := r.saveLocked(); err != nil {
			slog.Warn("cannot save seeded servers.json", "err", err)
		}
	}
	if !r.writable {
		slog.Warn("data dir not writable: servers and topic notes are read-only", "dir", cfg.DataDir)
	}
	return r
}

func (r *registry) readFile() ([]ServerConfig, error) {
	st, err := os.Stat(r.path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, err
	}
	var list []ServerConfig
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	r.mtime = st.ModTime()
	return list, nil
}

// refresh picks up changes another panel instance (admin <-> super) made to servers.json.
func (r *registry) refresh() {
	st, err := os.Stat(r.path)
	r.mu.RLock()
	same := err != nil || st.ModTime().Equal(r.mtime)
	r.mu.RUnlock()
	if same {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	list, err := r.readFile()
	if err != nil {
		slog.Warn("cannot reload servers.json", "err", err)
		return
	}
	next := map[string]*Server{}
	for _, sc := range list {
		if old := r.servers[sc.ID]; old != nil && old.ServerConfig == sc {
			next[sc.ID] = old // keep probed capabilities
		} else {
			next[sc.ID] = r.build(sc)
		}
	}
	r.servers = next
	slog.Info("reloaded servers.json", "servers", len(next))
}

func (r *registry) build(sc ServerConfig) *Server {
	cc := sc
	if !r.super {
		cc.Socket = "" // regular admin mode never touches the admin socket
	}
	return &Server{ServerConfig: sc, client: newNtfyClient(cc),
		notes: newTopicStore(filepath.Join(r.dir, "notes", sc.ID+".json"), r.writable)}
}

func (r *registry) get(id string) *Server {
	r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.servers[id]
}

func (r *registry) list() []*Server {
	r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Server, 0, len(r.servers))
	for _, s := range r.servers {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (r *registry) empty() bool {
	r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.servers) == 0
}

func (r *registry) editable() error {
	if r.locked {
		return &apiError{409, "the server list is locked (NTFY_ADMIN_LOCK_SERVERS)"}
	}
	if !r.writable {
		return &apiError{409, "data dir is not writable (mount a volume at NTFY_ADMIN_DATA_DIR)"}
	}
	return nil
}

// validate normalizes and checks a server config; it also checks the server answers.
func (r *registry) validate(ctx context.Context, sc *ServerConfig, skipCheck bool) error {
	sc.Name = strings.TrimSpace(sc.Name)
	sc.URL = strings.TrimRight(strings.TrimSpace(sc.URL), "/")
	sc.PublicURL = strings.TrimRight(strings.TrimSpace(sc.PublicURL), "/")
	sc.Socket = strings.TrimSpace(sc.Socket)
	if sc.URL == "" {
		return bad("URL is required (how this panel reaches ntfy, e.g. http://ntfy:80)")
	}
	if err := checkURL("URL", sc.URL); err != nil {
		return bad("%v", err)
	}
	if err := checkURL("public URL", sc.PublicURL); err != nil {
		return bad("%v", err)
	}
	if sc.Name == "" {
		sc.Name = hostOf(firstNonEmpty(sc.PublicURL, sc.URL))
	}
	if len(sc.Name) > 60 || strings.ContainsAny(sc.Name, "\r\n") {
		return bad("name: max 60 characters, one line")
	}
	if sc.Socket != "" && r.super {
		if !filepath.IsAbs(sc.Socket) || filepath.Clean(sc.Socket) != sc.Socket {
			return bad("socket: absolute path, e.g. /run/ntfy/admin.sock")
		}
		if st, err := os.Stat(sc.Socket); err != nil || st.Mode().Type() != fs.ModeSocket {
			return bad("socket %s: not found in this container (mount ntfy's socket directory)", sc.Socket)
		}
		conn, err := net.DialTimeout("unix", sc.Socket, 2*time.Second)
		if err != nil {
			return bad("socket %s: cannot connect: %v", sc.Socket, err)
		}
		conn.Close()
	}
	if !skipCheck {
		c := newNtfyClient(*sc)
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if !c.healthy(ctx) {
			return bad("no healthy ntfy at %s (check the URL, or skip the check)", sc.URL)
		}
	}
	return nil
}

func (r *registry) add(sc ServerConfig) (*Server, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	base := slugify(sc.Name)
	sc.ID = base
	for i := 2; r.servers[sc.ID] != nil; i++ {
		sc.ID = fmt.Sprintf("%s-%d", base, i)
	}
	s := r.build(sc)
	r.servers[sc.ID] = s
	if err := r.saveLocked(); err != nil {
		delete(r.servers, sc.ID)
		return nil, err
	}
	return s, nil
}

func (r *registry) update(id string, sc ServerConfig) (*Server, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.servers[id]
	if old == nil {
		return nil, &apiError{404, "no such server"}
	}
	sc.ID = id
	s := r.build(sc)
	r.servers[id] = s
	if err := r.saveLocked(); err != nil {
		r.servers[id] = old
		return nil, err
	}
	return s, nil
}

func (r *registry) remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.servers[id]
	if old == nil {
		return &apiError{404, "no such server"}
	}
	delete(r.servers, id)
	if err := r.saveLocked(); err != nil {
		r.servers[id] = old
		return err
	}
	return nil
}

func (r *registry) saveLocked() error {
	list := make([]ServerConfig, 0, len(r.servers))
	for _, s := range r.servers {
		list = append(list, s.ServerConfig)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, r.path); err != nil {
		return err
	}
	if st, err := os.Stat(r.path); err == nil {
		r.mtime = st.ModTime()
	}
	return nil
}

// --- helpers ----------------------------------------------------------------------------

func probeWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false
	}
	probe := filepath.Join(dir, ".write-test")
	f, err := os.Create(probe)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(probe)
	return true
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return raw
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

var reNonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(name string) string {
	s := strings.Trim(reNonSlug.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > 24 {
		s = strings.Trim(s[:24], "-")
	}
	if s == "" {
		s = "server"
	}
	return s
}

// usesSocket: this panel instance talks to this server over its admin socket.
func (s *Server) usesSocket() bool { return s.client.socket != nil }

// publicURL is what phones should use; falls back to the internal URL.
func (s *Server) publicURL() string {
	return firstNonEmpty(s.PublicURL, s.URL)
}
