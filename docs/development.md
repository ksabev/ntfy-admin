# Development

## Layout

```
main.go        startup, graceful shutdown (revokes session tokens), `healthcheck` subcommand
config.go      environment variables
servers.go     server registry: servers.json, seeding, validation, reload on change
session.go     browser sessions (logins to several servers), login rate limiter
ntfy.go        ntfy client: admin API over HTTP or the admin unix socket
app.go         routing, auth middleware, login/setup, server management
handlers.go    per-server handlers: state, users, access, tokens, topics, publish, QR, export
topics.go      topic notes per server (DATA_DIR/notes/<id>.json)
web/           the UI: index.html, app.js, style.css (embedded into the binary)
test/          docker compose test bed + end-to-end tests
scripts/       deprovision.py (migration helper)
```

Dependencies: [`skip2/go-qrcode`](https://github.com/skip2/go-qrcode) and
`gopkg.in/yaml.v3`. The UI uses no libraries.

## How it talks to ntfy

| ntfy endpoint | Used for |
|---|---|
| `GET /v1/account` (Basic auth) | login: is this account an admin? |
| `POST/DELETE /v1/account/token` | the panel's own session token |
| `GET/POST/PUT/DELETE /v1/users` | list, add, update (password, role, tier), delete users |
| `PUT/DELETE /v1/users/access` | grant and reset access rules |
| `GET/POST/DELETE /v1/users/tokens` | users' tokens (ntfy 2.36+) |
| `POST /v1/users/password/reset` | reset links |
| `GET /v1/tiers`, `GET /v1/version`, `GET /v1/health` | tiers, version, health |
| `POST /` (JSON) | test messages |

In super mode, requests to the admin paths go over the admin socket when the server
has one. ntfy allows more there: roles, admin users, and all tokens in one call.
Everything else goes over HTTP with the session token.

Token capability is probed once per server: `GET /v1/users/tokens` answers 404 on ntfy
older than 2.36.

## The panel's HTTP API

All JSON. Changes need the `X-CSRF-Token` header from `/api/me` or the login response.
Server-scoped routes need a login to that server; otherwise they answer
`401 {"code":"server_login"}`.

| Route | |
|---|---|
| `GET /healthz` | health, version |
| `GET /api/servers` | without a session: names and IDs only, `setup_needed`, `super`; with one: URLs, health, who you are logged in as |
| `POST /api/setup` | first server + admin login, only while there are no servers |
| `GET /api/me` · `POST /api/logout` | session info · log out of all servers |
| `POST /api/servers` · `PUT/DELETE /api/servers/{id}` | manage servers |
| `GET /api/qr?data=…` | QR code PNG (`ntfy://`, `http(s)://` only) |
| `POST /api/s/{sid}/login` · `/logout` | per-server login (creates the session cookie if needed) |
| `GET /api/s/{sid}/state` | everything the UI shows: server, capabilities, users with rules and tokens (no values), anonymous rules, topics, tiers |
| `POST /api/s/{sid}/users` · `PATCH/DELETE …/users/{name}` | `{username, password \| generate, role, tier}` |
| `POST /api/s/{sid}/users/{name}/reset-link` | reset link |
| `PUT /api/s/{sid}/access` · `POST …/access/delete` | `{username, topic, permission}`; `*` is the anonymous user |
| `POST /api/s/{sid}/tokens` · `…/tokens/reveal` · `…/tokens/delete` | create `{username, label, expires}`; reveal and delete by `{username, id}` |
| `PUT/DELETE /api/s/{sid}/topics/{name}` | topic notes `{display, about}` |
| `POST /api/s/{sid}/publish` | `{topic, message, title, priority}` |
| `GET /api/s/{sid}/export` | YAML |

Token IDs are the first 8 bytes of the token's SHA-256, so the browser never has to
hold a token value it did not ask to see.

## Tests

The end-to-end suite runs against a real ntfy, with a regular and a super panel:

```sh
docker compose -f test/compose.yml up -d --build
docker compose -f test/compose.yml exec ntfy sh -c 'NTFY_PASSWORD=adminpass123 ntfy user add --role=admin admin'
test/e2e.sh          # needs curl and jq
```

The suite covers login, CSRF, server management, user/rule/token lifecycles checked
against ntfy itself, the refusals ntfy makes over HTTP, and logout. Run it before
every change.

| Port | |
|---|---|
| 18080 | ntfy |
| 18081 | regular panel |
| 18082 | super panel |

To reach the test bed from other machines:
`BIND=0.0.0.0 TEST_HOST=<this host> docker compose -f test/compose.yml up -d`.
Clean up with `docker compose -f test/compose.yml down -v`.

## CI and releases

`.github/workflows/ci.yml` runs on every push and pull request: gofmt, go vet, build,
a JS syntax check, and the full end-to-end suite against a real ntfy. A push to `main`
publishes `ghcr.io/ksabev/ntfy-admin:edge`. A `v*` tag publishes the release tags
(`0.2.2`, `0.2`, `latest`) for amd64, arm64 and armv7, then creates the GitHub Release
with that version's section of `CHANGELOG.md` as its notes
(`scripts/release-notes.sh 0.2.2` prints it). A tag without a changelog section fails
the release job.

To make a release: add a `## X.Y.Z (date)` section to `CHANGELOG.md`, push `main`, then tag and push the tag **on
its own**. If the branch and the tag go in one push, GitHub can skip the tag event and
no release image gets built:

```sh
git push github main
git tag -a v0.2.2 -m "…"
git push github v0.2.2
```

## Building

```sh
go vet ./... && go build .                           # needs Go 1.24
docker build --build-arg VERSION=0.2.0 -t ntfy-admin:0.2.0 .
```

No Go installed? `docker run --rm -v "$PWD":/src -w /src golang:1.24-alpine go build .`

## Conventions

- Keep the UI dependency-free: plain JS, DOM built with `h()` and `textContent`, no
  `innerHTML` with data, no inline scripts or styles (the CSP forbids them).
- The panel stores no secrets. A feature that needs one is probably the wrong feature.
- Mirror ntfy's rules instead of inventing new ones: name validation and permission
  resolution follow ntfy's source.
- `gofmt` and `go vet` clean. Update `test/e2e.sh` along with the API.
