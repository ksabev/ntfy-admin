// ntfy-admin — a small web admin panel for self-hosted ntfy servers.
//
// It is a thin, stateless UI over ntfy's own admin API: users, access control
// lists, access tokens and onboarding. It keeps no user database and no copy of
// any secret; you log in with an ntfy admin account.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "dev" // set by -ldflags at build time

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(2)
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(cfg))
	}

	app, err := newApp(cfg)
	if err != nil {
		slog.Error("startup", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		app.sessions.closeAll(shutdown, app.servers) // revoke our short-lived ntfy session tokens
		_ = srv.Shutdown(shutdown)
	}()

	slog.Info("ntfy-admin listening", "version", version, "listen", cfg.Listen,
		"servers", len(app.servers.list()), "data", cfg.DataDir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
}

// healthcheck lets a distroless image check itself: `ntfy-admin healthcheck`.
func healthcheck(cfg *Config) int {
	addr := cfg.Listen
	if len(addr) > 0 && addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + cfg.BasePath + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
