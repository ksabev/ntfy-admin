# Changelog

## 0.2.1 (2026-11-08)

- Published images on `ghcr.io/ksabev/ntfy-admin` for amd64, arm64 and armv7, built
  by GitHub Actions. CI runs the end-to-end suite against a real ntfy on every push.
- Documentation points to the published image.

## 0.2.0 (2026-11-08)

- **Many servers:** add, edit and remove ntfy servers in the UI (`/data/servers.json`).
  Environment variables now only seed the first server; `NTFY_ADMIN_LOCK_SERVERS`
  freezes the list.
- **Setup screen** on first start without servers. A server is saved only after a
  working admin login.
- One browser session can be logged in to several servers.
- **Super admin mode** (`NTFY_ADMIN_SUPER=true`): only this mode uses admin sockets
  (roles, admin users). Red, striped UI. Regular and super panels can share `/data`.
- Topic notes are stored per server.
- `scripts/deprovision.py` and a guide for migrating away from `auth-users`.
- Documentation in `docs/`.

## 0.1.0 (2026-11-08)

- First version: users, access rules, access matrix, tokens (ntfy 2.36+), onboarding
  cards with QR codes, topic notes, test messages and YAML export.
- Works over ntfy's HTTP admin API or its admin socket.
- Login with an ntfy admin account, swapped for a short-lived ntfy token.
