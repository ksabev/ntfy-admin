# ntfy-admin

A small web admin panel for self-hosted [ntfy](https://ntfy.sh) servers.

ntfy can manage users, access rules and tokens, but the server's own web app
only lets you manage *your own* account. Everything else needs the CLI inside the
container. ntfy-admin is the missing admin page:

- **Users:** create, delete, change or generate passwords, password reset links, roles, tiers
- **Access rules:** per user and for anonymous visitors, with `*` wildcards
- **Access matrix:** effective permission for every user × topic, resolved the
  same way ntfy resolves it (own most specific rule → anonymous rules → server default)
- **Access tokens:** one per device or service, with label and expiry, last used
  time and IP, revoke with one click. Values are hidden until you click *Show*.
- **Onboarding:** a printable card with the server, username, a fresh password
  and a QR code per topic the user can read (opens the ntfy app, already subscribed)
- **Topics:** who can read and who can publish, optional display names, *send a test message*
- **Export:** who-can-what as YAML, for docs or git. No passwords, no token values.

It is a thin layer over **ntfy's own admin API**. It has no user database and stores
no secrets: you log in with an ntfy admin account. No Docker socket, and no access
to ntfy's files. It works with SQLite or PostgreSQL ntfy, in Docker or with systemd.

Single static Go binary with a plain HTML/JS UI (no build step). The image is
about 10 MB, distroless, and runs as non-root.

## Requirements

- ntfy **2.36 or newer** for everything (token management, admin socket).
  Older servers still get users and access rules; the token tab turns itself off.
- Auth enabled in ntfy (`auth-file` or `database-url`), and at least one **admin** user.

## Quick start (docker compose)

```yaml
services:
  ntfy:
    image: binwiederhier/ntfy:v2.37.2
    command: ["serve"]
    environment:
      NTFY_BASE_URL: https://ntfy.example.com
      NTFY_AUTH_FILE: /var/lib/ntfy/user.db
      NTFY_AUTH_DEFAULT_ACCESS: deny-all
      NTFY_BEHIND_PROXY: "true"
      # the admin socket gives the panel full powers (roles, admin users)
      NTFY_EXPERIMENTAL_LISTEN_ADMIN_UNIX: /run/ntfy/admin.sock
    volumes:
      - ./ntfy/lib:/var/lib/ntfy
      - ntfy-run:/run/ntfy
    ports: ["8082:80"]

  ntfy-admin:
    image: ntfy-admin:latest            # build: docker build -t ntfy-admin .
    environment:
      NTFY_ADMIN_NTFY_URL: http://ntfy:80                    # how the panel reaches ntfy
      NTFY_ADMIN_PUBLIC_URL: https://ntfy.example.com        # how phones reach ntfy (QR codes)
      NTFY_ADMIN_SOCKET: /run/ntfy/admin.sock
    group_add: ["0"]                    # ntfy runs as root: its socket is root:root 0660
    volumes:
      - ntfy-run:/run/ntfy
      - ./ntfy-admin:/data              # topic notes only
    ports: ["127.0.0.1:8083:8080"]      # keep it off the internet, see Security
    depends_on: [ntfy]

volumes:
  ntfy-run:
```

Create the first admin once, then log in at http://localhost:8083:

```sh
docker compose exec ntfy ntfy user add --role=admin yourname
```

## Two ways to talk to ntfy

| | Admin socket (recommended) | HTTP only |
|---|---|---|
| Setup | share `/run/ntfy` between the two containers | nothing extra |
| Users, access rules, tokens, reset links | yes | yes |
| Change roles, create or edit **admin** users | yes | no: ntfy refuses this over HTTP |
| Tokens of admin users | yes | hidden |

ntfy's admin socket is still marked *experimental* (since 2.36). Without
`NTFY_ADMIN_SOCKET`, the panel uses the HTTP admin API and turns off what ntfy
does not allow there.

The socket is the authorization: anything that can open it is an admin. Share it
only with this container. If ntfy runs as a non-root user, run the panel with the
same `user:` or group instead of `group_add: ["0"]`.

## Configuration

All settings are environment variables:

| Variable | Default | |
|---|---|---|
| `NTFY_ADMIN_NTFY_URL` | `http://ntfy:80` | How the panel reaches ntfy (internal URL) |
| `NTFY_ADMIN_PUBLIC_URL` | (none) | How phones reach ntfy. Used for QR codes and examples. ntfy does not expose its `base-url` over the API, so set this. |
| `NTFY_ADMIN_SOCKET` | (none) | Path to ntfy's admin socket (`experimental-listen-admin-unix`) |
| `NTFY_ADMIN_LISTEN` | `:8080` | Listen address |
| `NTFY_ADMIN_DATA_DIR` | `/data` | Topic notes (`topics.json`). No secrets. |
| `NTFY_ADMIN_SESSION_TTL` | `12h` | Login lifetime |
| `NTFY_ADMIN_BASE_PATH` | (none) | Serve under a sub-path, e.g. `/admin` |
| `NTFY_ADMIN_BEHIND_PROXY` | `false` | Trust `X-Forwarded-For` for the client IP (rate limiting, audit log) |
| `NTFY_ADMIN_COOKIE_SECURE` | `auto` | `auto` sets `Secure` when the request came over HTTPS (or `X-Forwarded-Proto: https`) |

## Users that come from the config file

Users, rules and tokens defined in ntfy's `server.yml` (`auth-users`,
`auth-access`, `auth-tokens`) are **provisioned**: ntfy rebuilds them on every start
and refuses API changes to them. The panel shows them with a *provisioned* badge,
read-only. Pick one source of truth per user: the config file or this panel.

## Security

- **Login.** Only ntfy accounts with the `admin` role can log in. Your password is
  checked by ntfy and then forgotten: the panel swaps it for a short-lived ntfy
  token (label `ntfy-admin session`, expires with the session, revoked at logout).
- **Sessions.** Kept in memory: a restart logs everyone out. The cookie is
  `HttpOnly` and `SameSite=Strict`. Every change also needs a per-session CSRF
  header. Failed logins are rate limited per IP.
- **Token values.** They never appear in lists. *Show* fetches one on demand, and
  that action is audit-logged.
- **Audit log.** Every change is logged to stdout (`action=… admin=… ip=…`), and ntfy
  logs it too.
- **Exposure.** The panel can create admins and read every token. Keep it on your
  LAN or VPN, or put SSO (Authelia, Authentik, oauth2-proxy) in front of it. Don't
  publish it on the internet like ntfy itself.
- **Hardening.** Strict CSP (no inline script or style), distroless non-root image.

## Development

```sh
docker compose -f test/compose.yml up -d --build    # ntfy 2.37 + panel in socket and HTTP mode
docker compose -f test/compose.yml exec ntfy sh -c 'NTFY_PASSWORD=adminpass123 ntfy user add --role=admin admin'
test/e2e.sh                                         # end-to-end tests against the real server (curl + jq)
```

Socket panel: http://127.0.0.1:18081 · HTTP-only panel: http://127.0.0.1:18082 ·
ntfy: http://127.0.0.1:18080

No Go on the host? Build with `docker build -t ntfy-admin .`.

## License

Apache-2.0. Not affiliated with the ntfy project.
