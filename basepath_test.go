package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestBasePathWithAndWithoutPrefix(t *testing.T) {
	h := (&App{cfg: &Config{BasePath: "/ntfy-admin"}}).routes()
	for _, path := range []string{
		"/ntfy-admin/", "/ntfy-admin/app.js", "/ntfy-admin/healthz", // proxy keeps the prefix
		"/", "/app.js", "/healthz", // proxy strips it
	} {
		if w := get(h, path); w.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", path, w.Code)
		}
	}
	if w := get(h, "/ntfy-admin"); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/ntfy-admin/" {
		t.Errorf("GET /ntfy-admin: status %d, Location %q", w.Code, w.Header().Get("Location"))
	}
	if w := get(h, "/nope"); w.Code != http.StatusNotFound {
		t.Errorf("GET /nope: status %d, want 404", w.Code)
	}
}

func TestBasePathIndex(t *testing.T) {
	h := (&App{cfg: &Config{BasePath: "/ntfy-admin"}}).routes()
	for _, path := range []string{"/", "/ntfy-admin/"} {
		w := get(h, path)
		if !strings.Contains(w.Body.String(), `<base href="/ntfy-admin/">`) {
			t.Errorf("GET %s: no <base> tag", path)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s: Content-Type %q", path, ct)
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "base-uri 'self'") {
			t.Errorf("GET %s: CSP does not allow the <base> tag: %s", path, csp)
		}
	}
}

func TestNoBasePath(t *testing.T) {
	h := (&App{cfg: &Config{}}).routes()
	w := get(h, "/")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "<base") {
		t.Errorf("GET /: status %d, or an unexpected <base> tag", w.Code)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "base-uri 'none'") {
		t.Errorf("CSP should stay strict without a base path: %s", csp)
	}
}

func TestBasePathKeepsEscapedSegments(t *testing.T) {
	var got string
	h := withBasePath("/admin", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
	}))
	get(h, "/api/s/home/users/a%2Fb")
	if want := "/admin/api/s/home/users/a%2Fb"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
