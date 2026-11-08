package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// login is one admin logged in to one ntfy server. We never keep the password:
// at login it is traded for a short-lived ntfy token (label "ntfy-admin session"),
// revoked again at logout or shutdown, and expiring on its own anyway.
type login struct {
	Username string
	Token    string
}

// session is one browser. It can be logged in to several servers at once.
type session struct {
	ID        string
	CSRF      string
	ClientIP  string
	ExpiresAt time.Time

	mu     sync.Mutex
	logins map[string]*login // by server ID
}

func (s *session) login(serverID string) *login {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins[serverID]
}

func (s *session) setLogin(serverID string, l *login) (old *login) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old = s.logins[serverID]
	if l == nil {
		delete(s.logins, serverID)
	} else {
		s.logins[serverID] = l
	}
	return old
}

func (s *session) loginsCopy() map[string]*login {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*login, len(s.logins))
	for k, v := range s.logins {
		out[k] = v
	}
	return out
}

func (s *session) anyLogin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.logins) > 0
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
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (st *sessionStore) create(ip string, ttl time.Duration) *session {
	s := &session{ID: randomString(32), CSRF: randomString(24), ClientIP: ip,
		ExpiresAt: time.Now().Add(ttl), logins: map[string]*login{}}
	st.mu.Lock()
	st.sessions[s.ID] = s
	st.mu.Unlock()
	return s
}

func (st *sessionStore) get(id string) *session {
	if id == "" {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, s := range st.sessions {
		if subtle.ConstantTimeCompare([]byte(k), []byte(id)) == 1 {
			if time.Now().After(s.ExpiresAt) {
				delete(st.sessions, k)
				return nil
			}
			return s
		}
	}
	return nil
}

func (st *sessionStore) remove(id string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.sessions, id)
}

func (st *sessionStore) all() []*session {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*session, 0, len(st.sessions))
	for _, s := range st.sessions {
		out = append(out, s)
	}
	return out
}

// dropServer logs every session out of one server (removed or re-pointed), revoking tokens.
func (st *sessionStore) dropServer(ctx context.Context, srv *Server) {
	for _, s := range st.all() {
		if l := s.setLogin(srv.ID, nil); l != nil && srv != nil {
			_ = srv.client.deleteSessionToken(ctx, l.Token)
		}
	}
}

func (st *sessionStore) closeAll(ctx context.Context, reg *registry) {
	for _, s := range st.all() {
		for sid, l := range s.loginsCopy() {
			if srv := reg.get(sid); srv != nil {
				_ = srv.client.deleteSessionToken(ctx, l.Token)
			}
		}
	}
	st.mu.Lock()
	st.sessions = map[string]*session{}
	st.mu.Unlock()
}

func (st *sessionStore) janitor() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		st.mu.Lock()
		for k, s := range st.sessions {
			if now.After(s.ExpiresAt) {
				delete(st.sessions, k) // its ntfy tokens expire on their own
			}
		}
		st.mu.Unlock()
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
