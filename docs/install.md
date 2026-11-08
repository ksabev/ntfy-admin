# Installation

## Requirements

- **ntfy 2.36 or newer.** That release added the admin token API and the admin socket.
  With older ntfy (back to 2.5), users and access rules work, and the token section
  says it is not available.
- **Auth enabled in ntfy:** `auth-file` (SQLite) or `database-url` (PostgreSQL).
  `auth-default-access: deny-all` is recommended but not required.
- **At least one ntfy admin account.** The admin API cannot create the first one:
  ```sh
  docker compose exec ntfy ntfy user add --role=admin admin
  ```

## Get the image

Images for linux/amd64, linux/arm64 and linux/arm/v7 are built by GitHub Actions:

| Tag | |
|---|---|
| `ghcr.io/ksabev/ntfy-admin:latest` | latest release |
| `ghcr.io/ksabev/ntfy-admin:0.2` / `:0.2.1` | a release line / an exact release |
| `ghcr.io/ksabev/ntfy-admin:edge` | current `main` |

Pin an exact version in production. To build it yourself:

```sh
docker build --build-arg VERSION=0.2.1 -t ntfy-admin:0.2.1 .    # version shows in the UI and /healthz
```

To copy a self-built image to a host without a registry:

```sh
docker save ntfy-admin:0.2.0 | gzip | ssh myhost 'gunzip | docker load'
```

## Regular and super panel

Run the image twice:

| | `ntfy-admin` | `ntfy-admin-super` |
|---|---|---|
| Purpose | everyday work | the rare role or admin-user change |
| Talks to ntfy | HTTP admin API | admin socket, where one is configured |
| `NTFY_ADMIN_SUPER` | `false` | `true` |
| Users, rules, tokens, reset links, onboarding | yes | yes |
| Make someone admin, change or delete admin users | no (ntfy refuses this over HTTP) | yes |
| Admin users' tokens | hidden | visible |
| Looks | calm | red and striped, on purpose |

The super panel is optional. Without it you still manage everything except roles,
and you make admins from the CLI.

Both panels can share `/data`. A server added in one appears in the other: each
watches `servers.json` for changes.

[docker-compose.example.yml](../docker-compose.example.yml) sets up ntfy and both panels.

### The admin socket

ntfy 2.36+ can serve its admin API on a unix socket
(`experimental-listen-admin-unix`, still marked experimental). **Opening the socket
is the authorization**: there is no password. Mount it only into the super panel.

ntfy creates the socket with mode `0660` in a directory with mode `0750`, owned by
the user ntfy runs as. The official ntfy image runs as root, so the socket is
`root:root`. Give the super panel group 0 without making it root:

- compose v2+ / `docker compose`: `group_add: ["0"]`
- old `docker-compose` 1.x with a `version: "3"` file (no `group_add` there): `user: "65532:0"`

If ntfy runs as another user (for example `user: 1000:1000`), give the super panel
that group instead.

The panel checks the socket when you save a server in super mode. If the panel
can't open it, you get an error before anything is saved.

## Data directory

`/data` holds `servers.json` (server names and URLs) and `notes/<server>.json` (topic
display names and descriptions). Nothing secret. The image runs as uid 65532:

```sh
mkdir -p ntfy-admin && sudo chown 65532:65532 ntfy-admin
```

The image declares `/data` as a volume, so without a mount Docker creates an
anonymous one. That works, but you lose the server list when the container is
recreated. If `/data` is not writable, the server list and notes are read-only and
the UI says so.

## Configuration

Everything is set through environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `NTFY_ADMIN_SUPER` | `false` | Super admin mode |
| `NTFY_ADMIN_SERVER_NAME` | host of the URL | Seed: name of the first server |
| `NTFY_ADMIN_NTFY_URL` | (none) | Seed: URL the panel uses to reach ntfy, e.g. `http://ntfy:80` |
| `NTFY_ADMIN_PUBLIC_URL` | (none) | Seed: URL phones use, e.g. `https://ntfy.example.com` |
| `NTFY_ADMIN_SOCKET` | (none) | Seed: admin socket path (used in super mode only) |
| `NTFY_ADMIN_LOCK_SERVERS` | `false` | The server list cannot be changed from the UI |
| `NTFY_ADMIN_LISTEN` | `:8080` | Listen address |
| `NTFY_ADMIN_DATA_DIR` | `/data` | Data directory |
| `NTFY_ADMIN_SESSION_TTL` | `12h` | How long a login lasts (minimum `5m`) |
| `NTFY_ADMIN_BASE_PATH` | (none) | Serve under a sub-path, e.g. `/admin` |
| `NTFY_ADMIN_BEHIND_PROXY` | `false` | Take the client IP from `X-Forwarded-For` |
| `NTFY_ADMIN_COOKIE_SECURE` | `auto` | `auto`: `Secure` cookie when the request came over HTTPS (or `X-Forwarded-Proto: https`) |

**Seed variables** apply only while `servers.json` does not exist. On the first start
they become the first server, and from then on the UI owns the list. To keep the list
under config management instead, write `servers.json` yourself and set
`NTFY_ADMIN_LOCK_SERVERS=true`:

```json
[
  {"id": "home", "name": "Home", "url": "http://ntfy:80", "public_url": "https://ntfy.example.com", "socket": "/run/ntfy/admin.sock"}
]
```

**The public URL matters.** QR codes, onboarding cards and `curl` examples are built
from it. ntfy does not report its own `base-url` over the API, so the panel cannot
find it out. Without a public URL, the panel falls back to the internal URL and shows
a warning.

## Reverse proxy

Any proxy works. Set `NTFY_ADMIN_BEHIND_PROXY=true` so rate limiting and the audit log
see the real client IP.

**Caddy**, reachable from private networks only:

```caddy
ntfy-admin.example.com {
    @outside not remote_ip private_ranges
    respond @outside "LAN only" 403
    reverse_proxy ntfy-admin:8080
}
```

**nginx**, under a sub-path (`NTFY_ADMIN_BASE_PATH=/admin`):

```nginx
location /admin/ {
    allow 10.0.0.0/8; allow 172.16.0.0/12; allow 192.168.0.0/16; deny all;
    proxy_pass http://ntfy-admin:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Keep the super panel off the proxy if you can: reach it on a LAN address or through
an SSH tunnel (`ssh -L 8084:localhost:8084 myhost`).

## Without Docker

The binary has no runtime dependencies:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.2.0" -o ntfy-admin .
```

Example systemd unit for a host where ntfy runs from the Debian package (user and
group `ntfy`, socket in `/run/ntfy`). This setup is not covered by the test suite.

```ini
[Unit]
Description=ntfy-admin (super)
After=ntfy.service

[Service]
ExecStart=/usr/local/bin/ntfy-admin
Environment=NTFY_ADMIN_SUPER=true
Environment=NTFY_ADMIN_LISTEN=127.0.0.1:8084
Environment=NTFY_ADMIN_DATA_DIR=/var/lib/ntfy-admin
Environment=NTFY_ADMIN_NTFY_URL=http://127.0.0.1:80
Environment=NTFY_ADMIN_PUBLIC_URL=https://ntfy.example.com
Environment=NTFY_ADMIN_SOCKET=/run/ntfy/admin.sock
DynamicUser=yes
SupplementaryGroups=ntfy
StateDirectory=ntfy-admin
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

## Health

- `GET /healthz` returns `{"ok":true,"version":"…"}` and does not need a login.
- In the image: `ntfy-admin healthcheck` (exit code 0 or 1). The Dockerfile sets
  `HEALTHCHECK` with it.

## Upgrading

The panel is stateless apart from `/data`. Build or pull the new image and recreate
the container. Logins are kept in memory, so everyone logs in again.
