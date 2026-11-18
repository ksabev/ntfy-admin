package main

import (
	"html"
	"net/http"
	"strings"
)

// withBasePath lets the panel work behind both kinds of proxy when NTFY_ADMIN_BASE_PATH
// is set: those that forward the sub-path (nginx `proxy_pass http://host:port;`) and those
// that strip it (Apache `ProxyPass /admin http://host:port`). Routes are registered with
// the prefix, so a request that arrives without it gets it added back.
func withBasePath(prefix string, next http.Handler) http.Handler {
	if prefix == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u := *r.URL
		u.Path = prefix + path
		if u.RawPath != "" {
			u.RawPath = prefix + u.RawPath
		}
		r2 := *r
		r2.URL = &u
		next.ServeHTTP(w, &r2)
	})
}

// indexWithBase pins relative URLs to the sub-path. A proxy that strips the prefix can
// serve the page at /admin (no trailing slash) without the panel being able to tell, and
// the browser would then look for /app.js and /api/... at the root of the site.
func indexWithBase(index []byte, prefix string) []byte {
	tag := `<head>` + "\n" + `  <base href="` + html.EscapeString(prefix) + `/">`
	return []byte(strings.Replace(string(index), "<head>", tag, 1))
}
