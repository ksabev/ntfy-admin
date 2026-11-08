package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config comes from the environment only (container friendly).
type Config struct {
	Listen       string        // NTFY_ADMIN_LISTEN, default :8080
	NtfyURL      string        // NTFY_ADMIN_NTFY_URL: how this container reaches ntfy, e.g. http://ntfy:80
	PublicURL    string        // NTFY_ADMIN_PUBLIC_URL: how phones reach ntfy (QR codes, examples); default: ntfy's base-url
	AdminSocket  string        // NTFY_ADMIN_SOCKET: optional path to ntfy's admin unix socket (full admin powers)
	DataDir      string        // NTFY_ADMIN_DATA_DIR: topic notes (display names, descriptions)
	SessionTTL   time.Duration // NTFY_ADMIN_SESSION_TTL, default 12h
	CookieSecure string        // NTFY_ADMIN_COOKIE_SECURE: auto | true | false
	BasePath     string        // NTFY_ADMIN_BASE_PATH: serve under a sub-path behind a proxy, e.g. /admin
	BehindProxy  bool          // NTFY_ADMIN_BEHIND_PROXY: trust X-Forwarded-For for the client IP
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func loadConfig() (*Config, error) {
	c := &Config{
		Listen:       env("NTFY_ADMIN_LISTEN", ":8080"),
		NtfyURL:      strings.TrimRight(env("NTFY_ADMIN_NTFY_URL", "http://ntfy:80"), "/"),
		PublicURL:    strings.TrimRight(env("NTFY_ADMIN_PUBLIC_URL", ""), "/"),
		AdminSocket:  env("NTFY_ADMIN_SOCKET", ""),
		DataDir:      env("NTFY_ADMIN_DATA_DIR", "/data"),
		CookieSecure: strings.ToLower(env("NTFY_ADMIN_COOKIE_SECURE", "auto")),
		BasePath:     strings.TrimRight(env("NTFY_ADMIN_BASE_PATH", ""), "/"),
		BehindProxy:  env("NTFY_ADMIN_BEHIND_PROXY", "false") == "true",
	}
	ttl, err := time.ParseDuration(env("NTFY_ADMIN_SESSION_TTL", "12h"))
	if err != nil || ttl < 5*time.Minute {
		return nil, fmt.Errorf("NTFY_ADMIN_SESSION_TTL: want a duration >= 5m, e.g. 12h")
	}
	c.SessionTTL = ttl
	for name, raw := range map[string]string{"NTFY_ADMIN_NTFY_URL": c.NtfyURL, "NTFY_ADMIN_PUBLIC_URL": c.PublicURL} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%s: want an http(s) URL, got %q", name, raw)
		}
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
