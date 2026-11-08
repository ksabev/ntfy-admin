#!/usr/bin/env bash
# End-to-end test against test/compose.yml (real ntfy). Needs curl + jq.
set -uo pipefail
NTFY=http://127.0.0.1:18080
ADMIN_PW=${ADMIN_PW:-adminpass123}
pass=0; fail=0
ok(){ echo "  ok   $*"; pass=$((pass+1)); }
ko(){ echo "  FAIL $*"; fail=$((fail+1)); }
check(){ local name="$1" want="$2" got="$3"; [ "$got" = "$want" ] && ok "$name" || ko "$name (want '$want', got '$got')"; }

SID=${SID:-test}
run_panel(){ # $1 = base url, $2 = mode (socket|http)
  local P="$1" mode="$2" J; J=$(mktemp); local C; C=$(mktemp)
  echo "== $mode panel $P"
  req(){ # method path [json] -> body in $J, echoes status; "s/..." paths are server-scoped
    local m="$1" p="$2" d="${3:-}"
    case "$p" in servers*|setup|me|logout|qr*) ;; *) p="s/$SID/$p" ;; esac
    local args=(-s -o "$J" -w '%{http_code}' -b "$C" -c "$C" -X "$m" "$P/api/$p" -H "X-CSRF-Token: ${CSRF:-}")
    [ -n "$d" ] && args+=(-H 'Content-Type: application/json' -d "$d")
    curl "${args[@]}"
  }
  CSRF=""
  check "unauthenticated state → 401" 401 "$(req GET state)"
  check "public server list" "$SID|false" "$(req GET servers >/dev/null; jq -r '"\(.servers[0].id)|\(.servers[0]|has("url"))"' "$J")"
  check "super flag" "$([ "$mode" = socket ] && echo true || echo false)" "$(jq -r .super "$J")"
  check "setup refused once configured" 409 "$(req POST setup '{"url":"http://ntfy:80","username":"admin","password":"x"}')"
  check "unknown server login → 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $P/api/s/nope/login -d '{}')"
  check "wrong password → 401" 401 "$(req POST login '{"username":"admin","password":"nope"}')"
  check "login" 200 "$(req POST login "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}")"
  CSRF=$(jq -r .csrf "$J")
  check "me.logins" admin "$(jq -r ".logins.$SID" "$J")"
  req GET state >/dev/null
  check "caps.socket" "$([ "$mode" = socket ] && echo true || echo false)" "$(jq -r .caps.socket "$J")"
  check "caps.tokens" true "$(jq -r .caps.tokens "$J")"
  check "public url from server config" "true" "$(jq -r .server.public_url_set "$J")"
  check "full server list when logged in" "http://ntfy:80" "$(req GET servers >/dev/null; jq -r .servers[0].url "$J")"
  check "add 2nd server (skip check)" 200 "$(req POST servers '{"name":"Other box","url":"http://10.255.255.1:80","public_url":"https://ntfy.other.example","skip_check":true}')"
  local OID; OID=$(jq -r .id "$J")
  check "2nd server id" "other-box" "$OID"
  check "add unreachable server without skip → 400" 400 "$(req POST servers '{"name":"Dead","url":"http://10.255.255.1:80"}')"
  check "not logged in to 2nd → 401 server_login" "401|server_login" "$(curl -s -o "$J" -w '%{http_code}' -b "$C" $P/api/s/$OID/state)|$(jq -r .code "$J")"
  check "edit 2nd server public url" 200 "$(req PUT servers/$OID '{"name":"Other box","url":"http://10.255.255.1:80","public_url":"https://ntfy2.other.example","skip_check":true}')"
  check "remove 2nd server" 200 "$(req DELETE servers/$OID)"
  local saved=$CSRF; CSRF=bogus
  check "mutation without valid CSRF → 403" 403 "$(req POST users '{"username":"x","generate":true}')"
  CSRF=$saved

  local U="e2e-$mode"
  check "create user (generated pw)" 200 "$(req POST users "{\"username\":\"$U\",\"generate\":true}")"
  local PW; PW=$(jq -r .password "$J")
  check "generated pw length" 20 "${#PW}"
  check "duplicate user → 409" 409 "$(req POST users "{\"username\":\"$U\",\"generate\":true}")"
  check "bad username → 400" 400 "$(req POST users '{"username":"bad name","generate":true}')"
  check "short password → 400" 400 "$(req POST users '{"username":"shorty","password":"abc"}')"
  check "grant house-* ro" 200 "$(req PUT access "{\"username\":\"$U\",\"topic\":\"house-*\",\"permission\":\"ro\"}")"
  check "grant house-status rw" 200 "$(req PUT access "{\"username\":\"$U\",\"topic\":\"house-status\",\"permission\":\"read-write\"}")"
  check "bad pattern → 400" 400 "$(req PUT access "{\"username\":\"$U\",\"topic\":\"a/b\",\"permission\":\"ro\"}")"
  check "new user can log in to ntfy" 200 "$(curl -s -o /dev/null -w '%{http_code}' -u "$U:$PW" $NTFY/v1/account)"
  check "user can publish house-status (rw)" 200 "$(curl -s -o /dev/null -w '%{http_code}' -u "$U:$PW" -d hi $NTFY/house-status)"
  check "user cannot publish house-info (ro via pattern)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "$U:$PW" -d hi $NTFY/house-info)"
  check "non-admin cannot log in to panel" 403 "$(curl -s -o /dev/null -w '%{http_code}' -X POST $P/api/s/$SID/login -d "{\"username\":\"$U\",\"password\":\"$PW\"}")"

  check "create token" 200 "$(req POST tokens "{\"username\":\"$U\",\"label\":\"garden esp32\",\"expires\":0}")"
  local TK; TK=$(jq -r .token "$J"); local TID; TID=$(jq -r .view.id "$J")
  [[ "$TK" == tk_* ]] && ok "token format" || ko "token format ($TK)"
  check "token publishes" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TK" -d hi $NTFY/house-status)"
  check "state" 200 "$(req GET state)"
  check "state lists token w/o value" "garden esp32|false" "$(jq -r --arg u "$U" '.users[]|select(.username==$u)|.tokens[0]|"\(.label)|\(has("token"))"' "$J")"
  check "state: grants" 2 "$(jq -r --arg u "$U" '.users[]|select(.username==$u)|.grants|length' "$J")"
  check "state: topics include house-status" true "$(jq -r '[.topics[].name]|index("house-status")!=null' "$J")"
  check "reveal token" "$TK" "$( req POST tokens/reveal "{\"username\":\"$U\",\"id\":\"$TID\"}" >/dev/null; jq -r .token "$J")"
  check "revoke token" 200 "$(req POST tokens/delete "{\"username\":\"$U\",\"id\":\"$TID\"}")"
  check "revoked token rejected" 401 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TK" -d hi $NTFY/house-status)"

  check "change password (set)" 200 "$(req PATCH users/$U '{"password":"newpassword1"}')"
  check "new password works" 200 "$(curl -s -o /dev/null -w '%{http_code}' -u "$U:newpassword1" $NTFY/v1/account)"
  check "reset link" 200 "$(req POST users/$U/reset-link '{}')"
  [[ "$(jq -r .link "$J")" == http*reset* ]] && ok "reset link url" || ko "reset link url ($(cat "$J"))"
  check "remove rule" 200 "$(req POST access/delete "{\"username\":\"$U\",\"topic\":\"house-status\"}")"
  check "anonymous rule" 200 "$(req PUT access '{"username":"*","topic":"public-news","permission":"ro"}')"
  check "anonymous can read public-news" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$NTFY/public-news/json?poll=1")"
  check "remove anonymous rule" 200 "$(req POST access/delete '{"username":"*","topic":"public-news"}')"
  check "publish as admin" 200 "$(req POST publish '{"topic":"house-status","message":"panel test","priority":3}')"
  check "qr png" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b "$C" "$P/api/qr?data=ntfy%3A%2F%2Fexample.com%2Fhouse-status")"
  check "qr rejects junk" 400 "$(curl -s -o /dev/null -w '%{http_code}' -b "$C" "$P/api/qr?data=javascript:alert(1)")"
  check "qr needs login" 401 "$(curl -s -o /dev/null -w '%{http_code}' "$P/api/qr?data=ntfy%3A%2F%2Fexample.com%2Fx")"
  check "export" 200 "$(req GET export)"
  grep -q "tk_" "$J" && ko "export leaks token values" || ok "export has no token values"

  if [ "$mode" = socket ]; then
    check "topic note" 200 "$(req PUT topics/house-status '{"display":"Къща — критично","about":"alerts"}')"
    check "make admin (socket)" 200 "$(req PATCH users/$U '{"role":"admin"}')"
    check "make user again" 200 "$(req PATCH users/$U '{"role":"user"}')"
    check "create admin directly" 200 "$(req POST users '{"username":"admin2","generate":true,"role":"admin"}')"
    check "admin tokens visible via socket" 200 "$(req POST tokens '{"username":"admin2","label":"x","expires":0}')"
    check "delete admin (socket)" 200 "$(req DELETE users/admin2)"
  else
    check "role change refused w/o socket" 400 "$(req PATCH users/$U '{"role":"admin"}')"
    check "topic note (shared /data)" 200 "$(req PUT topics/house-info '{"display":"Къща — инфо"}')"
    check "admin password change refused by ntfy over HTTP" 403 "$(req PATCH users/admin '{"generate":true}')"
  fi
  check "cannot delete self" 400 "$(req DELETE users/admin)"
  check "delete user" 200 "$(req DELETE users/$U)"
  check "deleted user gone from ntfy" 401 "$(curl -s -o /dev/null -w '%{http_code}' -u "$U:newpassword1" $NTFY/v1/account)"
  check "logout" 200 "$(req POST logout '{}')"
  check "after logout → 401" 401 "$(req GET state)"
  rm -f "$J" "$C"
}

run_panel http://127.0.0.1:18081 http
run_panel http://127.0.0.1:18082 socket
echo "== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
