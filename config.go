package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config comes from the environment. The NTFY_ADMIN_NTFY_URL / _PUBLIC_URL /
// _SOCKET / _SERVER_NAME variables only seed the first server on first start;
// after that, servers are managed in the UI (DATA_DIR/servers.json), unless
// NTFY_ADMIN_LOCK_SERVERS=true.
type Config struct {
	Listen       string        // NTFY_ADMIN_LISTEN, default :8080
	DataDir      string        // NTFY_ADMIN_DATA_DIR: servers.json + topic notes (no secrets)
	SessionTTL   time.Duration // NTFY_ADMIN_SESSION_TTL, default 12h
	CookieSecure string        // NTFY_ADMIN_COOKIE_SECURE: auto | true | false
	BasePath     string        // NTFY_ADMIN_BASE_PATH: serve under a sub-path behind a proxy, e.g. /admin
	BehindProxy  bool          // NTFY_ADMIN_BEHIND_PROXY: trust X-Forwarded-For for the client IP
	LockServers  bool          // NTFY_ADMIN_LOCK_SERVERS: server list is read-only in the UI
	Super        bool          // NTFY_ADMIN_SUPER: super admin mode: use admin sockets (roles, admin users); red UI

	Seed ServerConfig // first server, from NTFY_ADMIN_NTFY_URL etc.
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func checkURL(name, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s: want an http(s) URL, got %q", name, raw)
	}
	return nil
}

func loadConfig() (*Config, error) {
	c := &Config{
		Listen:       env("NTFY_ADMIN_LISTEN", ":8080"),
		DataDir:      env("NTFY_ADMIN_DATA_DIR", "/data"),
		CookieSecure: strings.ToLower(env("NTFY_ADMIN_COOKIE_SECURE", "auto")),
		BasePath:     strings.TrimRight(env("NTFY_ADMIN_BASE_PATH", ""), "/"),
		BehindProxy:  env("NTFY_ADMIN_BEHIND_PROXY", "false") == "true",
		LockServers:  env("NTFY_ADMIN_LOCK_SERVERS", "false") == "true",
		Super:        env("NTFY_ADMIN_SUPER", "false") == "true",
		Seed: ServerConfig{
			Name:      env("NTFY_ADMIN_SERVER_NAME", ""),
			URL:       strings.TrimRight(env("NTFY_ADMIN_NTFY_URL", ""), "/"),
			PublicURL: strings.TrimRight(env("NTFY_ADMIN_PUBLIC_URL", ""), "/"),
			Socket:    env("NTFY_ADMIN_SOCKET", ""),
		},
	}
	ttl, err := time.ParseDuration(env("NTFY_ADMIN_SESSION_TTL", "12h"))
	if err != nil || ttl < 5*time.Minute {
		return nil, fmt.Errorf("NTFY_ADMIN_SESSION_TTL: want a duration >= 5m, e.g. 12h")
	}
	c.SessionTTL = ttl
	if err := checkURL("NTFY_ADMIN_NTFY_URL", c.Seed.URL); err != nil {
		return nil, err
	}
	if err := checkURL("NTFY_ADMIN_PUBLIC_URL", c.Seed.PublicURL); err != nil {
		return nil, err
	}
	switch c.CookieSecure {
	case "auto", "true", "false":
	default:
		return nil, fmt.Errorf("NTFY_ADMIN_COOKIE_SECURE: auto | true | false")
	}
	if c.BasePath != "" && !strings.HasPrefix(c.BasePath, "/") {
		c.BasePath = "/" + c.BasePath
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return nil, fmt.Errorf("NTFY_ADMIN_LISTEN: want host:port or :port, got %q", c.Listen)
	}
	return c, nil
}
