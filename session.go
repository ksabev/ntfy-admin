package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// session is one logged-in admin. We never keep the admin's password: at login
// we trade it for a short-lived ntfy token (labelled "ntfy-admin session"),
// which is revoked again at logout or shutdown and expires on its own anyway.
type session struct {
	ID        string
	CSRF      string
	Username  string
	Role      string
	Token     string // ntfy bearer token of this admin
	ClientIP  string
	ExpiresAt time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionStore() *sessionStore {
	s := &sessionStore{sessions: map[string]*session{}}
	go s.janitor()
	return s
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessionStore) create(username, role, token, ip string, ttl time.Duration) *session {
	sess := &session{
		ID:        randomString(32),
		CSRF:      randomString(24),
		Username:  username,
		Role:      role,
		Token:     token,
		ClientIP:  ip,
		ExpiresAt: time.Now().Add(ttl),
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

func (s *sessionStore) get(id string) *session {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sess := range s.sessions {
		// constant-time compare; the map is tiny (a handful of admins)
		if subtle.ConstantTimeCompare([]byte(k), []byte(id)) == 1 {
			if time.Now().After(sess.ExpiresAt) {
				delete(s.sessions, k)
				return nil
			}
			return sess
		}
	}
	return nil
}

func (s *sessionStore) remove(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	delete(s.sessions, id)
	return sess
}

func (s *sessionStore) closeAll(ctx context.Context, c *NtfyClient) {
	s.mu.Lock()
	all := s.sessions
	s.sessions = map[string]*session{}
	s.mu.Unlock()
	for _, sess := range all {
		_ = c.deleteSessionToken(ctx, sess.Token)
	}
}

func (s *sessionStore) janitor() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		s.mu.Lock()
		for k, sess := range s.sessions {
			if now.After(sess.ExpiresAt) {
				delete(s.sessions, k) // its ntfy token expires on its own
			}
		}
		s.mu.Unlock()
	}
}

// loginLimiter slows down password guessing through the panel: at most
// `max` failed logins per client IP per window.
type loginLimiter struct {
	mu     sync.Mutex
	fails  map[string][]time.Time
	max    int
	window time.Duration
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{fails: map[string][]time.Time{}, max: 8, window: 10 * time.Minute}
}

func (l *loginLimiter) prune(ip string, now time.Time) []time.Time {
	keep := l.fails[ip][:0]
	for _, t := range l.fails[ip] {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, ip)
	} else {
		l.fails[ip] = keep
	}
	return keep
}

func (l *loginLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(ip, time.Now())) < l.max
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[ip] = append(l.prune(ip, time.Now()), time.Now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}
