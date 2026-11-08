"use strict";
// ntfy-admin UI — vanilla JS, no build step. All DOM is built with textContent
// (never innerHTML with data), and the CSP forbids inline script/style.

const $ = (sel, root = document) => root.querySelector(sel);
const PERMS = ["read-write", "read-only", "write-only", "deny-all"];
const PERM_SHORT = { "read-write": "rw", "read-only": "ro", "write-only": "wo", "deny-all": "deny", admin: "admin" };
const PERM_LABEL = {
  "read-write": "read-write", "read-only": "read-only", "write-only": "write-only", "deny-all": "deny", admin: "admin",
};

let me = null;      // {username, csrf, caps, version}
let state = null;   // /api/state
let openUsers = new Set();
let activeTab = "users";

// --- tiny DOM helper -----------------------------------------------------------
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show" + (err ? " err" : "");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.className = "toast"), err ? 6000 : 2500);
}

// --- API ---------------------------------------------------------------------------
async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (method !== "GET" && me) opts.headers["X-CSRF-Token"] = me.csrf;
  const res = await fetch("api/" + path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* empty */ }
  if (res.status === 401 && path !== "login") {
    showLogin("Session expired — please log in again.");
    throw new Error("not logged in");
  }
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}

// Run a mutation, toast the outcome, reload state.
async function act(fn, okMsg) {
  try {
    const out = await fn();
    if (okMsg) toast(okMsg);
    await refresh();
    return out;
  } catch (e) {
    if (e.message !== "not logged in") toast(e.message, true);
    throw e;
  }
}

// --- permission logic (mirrors ntfy user/access_cache.go) -------------------------------
// Stored patterns: '*' becomes '%' (1 char), '_' becomes '\_' (2 chars).
const storedLen = (p) => p.length + (p.match(/_/g) || []).length;
const patternRe = (p) => new RegExp("^" + p.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\-]/g, "\\$&")).join(".*") + "$");
const canWrite = (perm) => perm === "read-write" || perm === "write-only";
const canRead = (perm) => perm === "read-write" || perm === "read-only";

function bestGrant(grants, topic) {
  let best = null;
  for (const g of grants || []) {
    if (!patternRe(g.topic).test(topic)) continue;
    if (!best) { best = g; continue; }
    const a = storedLen(g.topic), b = storedLen(best.topic);
    if (a > b || (a === b && canWrite(g.permission) && !canWrite(best.permission))) best = g;
  }
  return best;
}

function effective(user, topic) {
  if (user && user.role === "admin") return { perm: "admin", source: "admin role" };
  const own = user ? bestGrant(user.grants, topic) : null;
  if (own) return { perm: own.permission, source: "rule " + own.topic, rule: own };
  const anon = bestGrant(state.everyone ? state.everyone.grants : [], topic);
  if (anon) return { perm: anon.permission, source: "anonymous rule " + anon.topic, rule: anon };
  const def = state.server.default_access || "read-write";
  return { perm: def, source: "server default" };
}

const topicNames = () => state.topics.map((t) => t.name);
const readableTopics = (u) => state.topics.filter((t) => {
  const p = effective(u, t.name).perm;
  return p === "admin" || canRead(p);
});
const writableTopics = (u) => state.topics.filter((t) => {
  const p = effective(u, t.name).perm;
  return p === "admin" || canWrite(p);
});

// --- formatting ------------------------------------------------------------------------
function ago(unix) {
  if (!unix) return "never";
  const s = Math.round(Date.now() / 1000 - unix);
  if (s < 0) return "in " + dur(-s);
  if (s < 60) return "just now";
  return dur(s) + " ago";
}
function dur(s) {
  if (s < 3600) return Math.round(s / 60) + " min";
  if (s < 86400) return Math.round(s / 3600) + " h";
  if (s < 86400 * 60) return Math.round(s / 86400) + " d";
  return Math.round(s / 86400 / 30) + " mo";
}
const fmtDate = (unix) => (unix ? new Date(unix * 1000).toLocaleString() : "");
const permChip = (perm, extra = "") => h("span", { class: "chip p-" + perm + (extra ? " " + extra : "") }, PERM_LABEL[perm] || perm);

function publicHost() {
  try { return new URL(state.server.public_url).host; } catch { return state.server.public_url; }
}
function deepLink(topic) {
  const meta = state.topics.find((t) => t.name === topic) || {};
  const q = meta.display ? "?display=" + encodeURIComponent(meta.display) : "";
  return "ntfy://" + publicHost() + "/" + topic + q;
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied");
  } catch {
    // no clipboard API outside secure contexts (plain-http LAN): select it instead
    const ta = h("textarea", { class: "offscreen" });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand("copy");
    ta.remove();
    toast(ok ? "Copied" : "Copy failed — select the text manually", !ok);
  }
}
const secretBox = (value) => h("div", { class: "secret" }, h("code", {}, value),
  h("button", { type: "button", class: "btn small", onclick: () => copy(value) }, "Copy"));

// --- dialog ------------------------------------------------------------------------------
// openDialog({title, body: [nodes], submit: "Save", danger, onSubmit(formData) -> truthy keeps open})
function openDialog({ title, body = [], submit, danger = false, cancel = "Cancel", onSubmit }) {
  const dlg = $("#dialog");
  const form = $("#dialog-form");
  form.replaceChildren(
    h("h2", {}, title),
    ...body.filter((n) => n !== null && n !== undefined && n !== false),
    h("div", { class: "dialog-actions" },
      h("button", { type: "button", class: "btn ghost", onclick: () => dlg.close() }, submit ? cancel : "Close"),
      submit ? h("button", { type: "submit", class: "btn " + (danger ? "danger" : "primary") }, submit) : null,
    ),
  );
  form.onsubmit = async (ev) => {
    if (!onSubmit) return;
    ev.preventDefault();
    const btn = form.querySelector("button[type=submit]");
    btn.disabled = true;
    try {
      const keep = await onSubmit(new FormData(form));
      if (!keep) dlg.close();
    } catch { /* toast already shown */ } finally { btn.disabled = false; }
  };
  dlg.showModal();
  const first = form.querySelector("input:not([type=hidden]):not([readonly]), select, textarea");
  if (first) first.focus();
}

function confirmDialog(title, text, submit, fn) {
  openDialog({ title, body: [h("p", {}, text)], submit, danger: true, onSubmit: fn });
}

// --- login / bootstrap --------------------------------------------------------------------
function showLogin(msg = "") {
  me = null;
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#login-error").textContent = msg;
  if ($("#dialog").open) $("#dialog").close();
}

$("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  $("#login-error").textContent = "";
  try {
    me = await api("POST", "login", { username: f.get("username"), password: f.get("password") });
    ev.target.reset();
    await start();
  } catch (e) {
    $("#login-error").textContent = e.message;
  }
});

$("#logout").addEventListener("click", async () => {
  try { await api("POST", "logout", {}); } catch { /* ignore */ }
  showLogin();
});

document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));
function selectTab(name) {
  activeTab = name;
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tabpanel").forEach((p) => p.classList.toggle("hidden", p.id !== "tab-" + name));
  try { localStorage.setItem("ntfy-admin-tab", name); } catch { /* private mode */ }
}

$("#user-filter").addEventListener("input", renderUsers);
$("#add-user").addEventListener("click", newUserDialog);
$("#add-topic").addEventListener("click", () => topicDialog(null));

async function start() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#whoami").textContent = me.username;
  let tab = "users";
  try { tab = localStorage.getItem("ntfy-admin-tab") || tab; } catch { /* ignore */ }
  selectTab(tab);
  await refresh();
}

async function refresh() {
  state = await api("GET", "state");
  render();
}

(async function boot() {
  try {
    me = await api("GET", "me");
    await start();
  } catch {
    showLogin();
  }
})();

// --- render ------------------------------------------------------------------------------
function render() {
  renderServer();
  renderUsers();
  renderTopics();
  renderMatrix();
  renderEveryone();
}

function renderServer() {
  const s = state.server;
  $("#server-info").replaceChildren(
    h("span", { class: "dot " + (s.healthy ? "ok" : "bad"), title: s.healthy ? "healthy" : "unhealthy" }),
    h("a", { href: s.public_url, target: "_blank", rel: "noopener" }, publicHost()),
    s.version ? h("span", {}, "ntfy " + s.version) : null,
    state.caps.socket
      ? h("span", { class: "badge socket", title: "Admin socket: roles and admin users can be managed" }, "admin socket")
      : h("span", { class: "badge", title: "HTTP admin API: roles and admin users are read-only" }, "http api"),
  );
  const notes = [];
  if (!state.caps.tokens) notes.push("This ntfy server has no admin token API (needs ntfy 2.36+): token management is off.");
  if (!s.public_url_set) notes.push("NTFY_ADMIN_PUBLIC_URL is not set: QR codes and examples point to " + s.public_url + ", which phones probably cannot reach.");
  if (!state.notes_writable) notes.push("Data dir is not writable: topic notes are read-only. Mount a volume at /data.");
  const b = $("#banner");
  b.textContent = notes.join(" ");
  b.classList.toggle("hidden", notes.length === 0);
}

function userBadges(u) {
  return [
    u.role === "admin" ? h("span", { class: "badge admin" }, "admin") : null,
    u.tier ? h("span", { class: "badge", title: "tier" }, u.tier_name || u.tier) : null,
    u.provisioned ? h("span", { class: "badge prov", title: "Defined in server.yml (auth-users); ntfy refuses changes via the API" }, "provisioned") : null,
  ];
}

function renderUsers() {
  const q = $("#user-filter").value.trim().toLowerCase();
  const list = state.users.filter((u) => !q || u.username.toLowerCase().includes(q)
    || u.grants.some((g) => g.topic.toLowerCase().includes(q)) || u.tokens.some((t) => (t.label || "").toLowerCase().includes(q)));
  const root = $("#users");
  if (!list.length) {
    root.replaceChildren(h("p", { class: "empty" }, state.users.length ? "No users match." : "No users yet."));
    return;
  }
  root.replaceChildren(...list.map((u) => {
    const card = h("div", { class: "card user" + (openUsers.has(u.username) ? " open" : "") });
    const chips = u.role === "admin" ? [permChip("admin")]
      : u.grants.slice(0, 6).map((g) => h("span", { class: "chip p-" + g.permission, title: g.permission }, g.topic + " · " + PERM_SHORT[g.permission]));
    if (u.role !== "admin" && u.grants.length > 6) chips.push(h("span", { class: "badge" }, "+" + (u.grants.length - 6)));
    if (u.tokens.length) chips.push(h("span", { class: "badge", title: "access tokens" }, "🔑 " + u.tokens.length));
    const head = h("div", {
      class: "user-head", role: "button", tabindex: "0", "aria-expanded": String(openUsers.has(u.username)),
      onclick: () => toggleUser(u.username, card),
      onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleUser(u.username, card); } },
    }, h("span", { class: "chev" }, "▸"), h("span", { class: "user-name" }, u.username), ...userBadges(u),
      h("div", { class: "user-chips" }, chips));
    card.append(head, h("div", { class: "user-body" }, openUsers.has(u.username) ? userBody(u) : null));
    return card;
  }));
}

function toggleUser(name, card) {
  if (openUsers.has(name)) openUsers.delete(name); else openUsers.add(name);
  const u = state.users.find((x) => x.username === name);
  card.classList.toggle("open");
  const body = card.querySelector(".user-body");
  body.replaceChildren(openUsers.has(name) && u ? userBody(u) : "");
}

function userBody(u) {
  const isSelf = u.username === me.username;
  const roleLocked = u.role === "admin" && !state.caps.socket;
  return h("div", { class: "cols" },
    h("div", {}, h("h3", {}, "Access"), accessEditor(u)),
    h("div", {},
      h("h3", {}, "Access tokens"), tokenSection(u),
      h("h3", {}, "Account"),
      roleLocked ? h("p", { class: "note" }, "ntfy only lets the admin socket change admin users. Configure NTFY_ADMIN_SOCKET to manage them here.") : null,
      h("div", { class: "row-btns" },
        h("button", { class: "btn small", disabled: u.provisioned || roleLocked, onclick: () => passwordDialog(u) }, "Change password"),
        h("button", { class: "btn small", disabled: u.provisioned || roleLocked, onclick: () => resetLink(u) }, "Reset link"),
        h("button", { class: "btn small", onclick: () => onboardingDialog(u, null) }, "Onboarding QR"),
        state.caps.socket && !isSelf ? h("button", {
          class: "btn small", disabled: u.provisioned,
          onclick: () => roleDialog(u),
        }, u.role === "admin" ? "Make regular user" : "Make admin") : null,
        h("button", {
          class: "btn small danger", disabled: isSelf || u.provisioned || roleLocked,
          title: isSelf ? "You cannot delete yourself" : "",
          onclick: () => confirmDialog("Delete " + u.username + "?",
            "The user, their access rules and tokens are removed. Devices using them stop working immediately.", "Delete user",
            () => act(() => api("DELETE", "users/" + encodeURIComponent(u.username)), "Deleted " + u.username)),
        }, "Delete"),
      ),
      u.provisioned ? h("p", { class: "note" }, "Provisioned via server.yml (auth-users): edit it there; ntfy refuses API changes.") : null,
    ),
  );
}

// --- access editor (users and anonymous) ----------------------------------------------------
function permSelect(name, value, disabled) {
  return h("select", { name, disabled, "aria-label": "permission" },
    PERMS.map((p) => h("option", { value: p, selected: p === value }, PERM_LABEL[p])));
}

function topicDatalist() {
  const id = "topics-dl";
  let dl = document.getElementById(id);
  if (!dl) { dl = h("datalist", { id }); document.body.append(dl); }
  dl.replaceChildren(...topicNames().map((t) => h("option", { value: t })));
  return id;
}

function accessEditor(u) {
  if (u.role === "admin") {
    return h("p", { class: "note" }, "Admins can read and write every topic; ntfy ignores access rules for them.");
  }
  const rows = u.grants.slice().sort((a, b) => a.topic.localeCompare(b.topic)).map((g) => {
    const sel = permSelect("perm", g.permission, g.provisioned);
    sel.addEventListener("change", () => act(() => api("PUT", "access",
      { username: u.username, topic: g.topic, permission: sel.value }), "Updated " + g.topic));
    return h("tr", {},
      h("td", { class: "mono" }, g.topic, g.provisioned ? h("span", { class: "badge prov", title: "from server.yml" }, " prov") : null),
      h("td", {}, sel),
      h("td", { class: "actions" }, h("button", {
        class: "btn small icon danger", title: "Remove rule", disabled: g.provisioned,
        onclick: () => act(() => api("POST", "access/delete", { username: u.username, topic: g.topic }), "Removed " + g.topic),
      }, "✕")));
  });
  const topic = h("input", { placeholder: "topic or pattern, e.g. house-*", list: topicDatalist(), "aria-label": "topic" });
  const perm = permSelect("perm", "read-only");
  const add = async () => {
    const t = topic.value.trim();
    if (!t) return topic.focus();
    await act(() => api("PUT", "access", { username: u.username, topic: t, permission: perm.value }), "Granted " + t);
  };
  topic.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });
  return h("div", {},
    rows.length ? h("table", {}, h("tbody", {}, rows)) : h("p", { class: "empty" }, u.username === "*"
      ? "No anonymous rules." : "No rules: falls back to anonymous rules, then the server default (" + (state.server.default_access || "?") + ")."),
    h("div", { class: "addrow" }, topic, perm, h("button", { class: "btn small", onclick: add }, "Add")),
    h("p", { class: "note" }, "* is a wildcard. The longest matching rule wins; at equal length, write beats read."),
  );
}

// --- tokens ---------------------------------------------------------------------------------
function tokenSection(u) {
  if (!state.caps.tokens) return h("p", { class: "note" }, "Needs ntfy 2.36+ (admin token API).");
  if (!u.tokens_visible) {
    return h("p", { class: "note" }, u.role === "admin"
      ? "ntfy shows admin users' tokens only over the admin socket."
      : "Could not list tokens.");
  }
  const rows = u.tokens.map((t) => h("tr", {},
    h("td", {}, h("div", {}, t.label || h("span", { class: "muted" }, "(no label)"),
      t.label === "ntfy-admin session" ? [" ", h("span", { class: "badge", title: "Created when someone logged in to this panel; expires on its own" }, "panel login")] : null),
      h("div", { class: "mono muted" }, t.prefix)),
    h("td", { class: "muted", title: t.last_origin ? "from " + t.last_origin + " · " + fmtDate(t.last_access) : "" },
      "used " + ago(t.last_access), t.expires ? h("div", {}, "expires " + ago(t.expires)) : null),
    h("td", { class: "actions" },
      h("button", { class: "btn small", title: "Show and copy the token", onclick: () => revealToken(u, t) }, "Show"),
      " ",
      h("button", {
        class: "btn small icon danger", title: "Revoke", disabled: t.provisioned,
        onclick: () => confirmDialog("Revoke token “" + (t.label || t.prefix) + "”?",
          "Whatever uses this token loses access immediately.", "Revoke",
          () => act(() => api("POST", "tokens/delete", { username: u.username, id: t.id }), "Revoked")),
      }, "✕"))));
  return h("div", {},
    rows.length ? h("table", {}, h("tbody", {}, rows)) : h("p", { class: "empty" }, "No tokens."),
    h("div", { class: "row-btns" }, h("button", { class: "btn small", onclick: () => tokenDialog(u) }, "+ New token")),
  );
}

function tokenDialog(u) {
  openDialog({
    title: "New token for " + u.username,
    body: [
      h("label", {}, "Label", h("input", { name: "label", required: true, maxlength: 64, placeholder: "e.g. alertmanager bridge, garden ESP32" })),
      h("label", {}, "Expires", h("select", { name: "expires" },
        h("option", { value: "0" }, "never"), h("option", { value: "30" }, "in 30 days"),
        h("option", { value: "90" }, "in 90 days"), h("option", { value: "365" }, "in 1 year"))),
      h("p", { class: "note" }, "One token per device or service: you can then revoke one without touching the others."),
    ],
    submit: "Create token",
    onSubmit: async (f) => {
      const days = Number(f.get("expires"));
      const expires = days ? Math.floor(Date.now() / 1000) + days * 86400 : 0;
      const out = await act(() => api("POST", "tokens", { username: u.username, label: f.get("label"), expires }));
      showToken(u, out.token, f.get("label"), true);
      return true;
    },
  });
}

async function revealToken(u, t) {
  try {
    const out = await api("POST", "tokens/reveal", { username: u.username, id: t.id });
    showToken(u, out.token, t.label, false);
  } catch (e) { toast(e.message, true); }
}

function showToken(u, token, label, fresh) {
  const topic = (writableTopics(u)[0] || {}).name || "<topic>";
  const base = state.server.public_url;
  openDialog({
    title: (fresh ? "Token created" : "Token") + (label ? " — " + label : ""),
    body: [
      secretBox(token),
      fresh ? h("p", { class: "note" }, "You can show it again later from this panel; treat it like a password.") : null,
      h("h3", {}, "Publish with it"),
      h("pre", { class: "snippet" }, `curl -H "Authorization: Bearer ${token}" \\\n     -d "Hello from ${u.username}" \\\n     ${base}/${topic}`),
      h("button", { type: "button", class: "btn small", onclick: () => copy(`curl -H "Authorization: Bearer ${token}" -d "Hello from ${u.username}" ${base}/${topic}`) }, "Copy curl"),
    ],
  });
}

// --- users: create / password / role ------------------------------------------------------
function pwFields() {
  const custom = h("input", { name: "password", type: "password", minlength: 8, maxlength: 128, autocomplete: "new-password", placeholder: "at least 8 characters", disabled: true });
  const gen = h("input", { type: "radio", name: "mode", value: "generate", checked: true });
  const set = h("input", { type: "radio", name: "mode", value: "set" });
  const sync = () => { custom.disabled = !set.checked; custom.required = set.checked; if (set.checked) custom.focus(); };
  gen.addEventListener("change", sync);
  set.addEventListener("change", sync);
  return [
    h("div", { class: "radio-row" },
      h("label", { class: "inline" }, gen, "Generate a strong password"),
      h("label", { class: "inline" }, set, "Set it myself")),
    custom,
  ];
}
const pwPayload = (f) => (f.get("mode") === "set" ? { password: f.get("password") } : { generate: true });

function newUserDialog() {
  const tiers = state.tiers || [];
  openDialog({
    title: "New user",
    body: [
      h("label", {}, "Username", h("input", { name: "username", required: true, pattern: "[-_.+@a-zA-Z0-9]{1,128}", autocomplete: "off", placeholder: "e.g. maria or garden-esp32" })),
      h("label", {}, "Password"), ...pwFields(),
      state.caps.socket ? h("label", {}, "Role", h("select", { name: "role" },
        h("option", { value: "user" }, "user"), h("option", { value: "admin" }, "admin — full access, can use this panel"))) : null,
      tiers.length ? h("label", {}, "Tier", h("select", { name: "tier" }, h("option", { value: "" }, "(none)"),
        tiers.map((t) => h("option", { value: t.code }, t.name || t.code)))) : null,
      h("label", {}, "Give access to (optional)", h("input", { name: "topic", list: topicDatalist(), placeholder: "topic or pattern" })),
      h("label", {}, "", permSelect("perm", "read-only")),
      h("p", { class: "note" }, "Machines (scripts, ESP boards, alert bridges) usually get a write-only rule and a token instead of using the password."),
    ],
    submit: "Create user",
    onSubmit: async (f) => {
      const username = f.get("username").trim();
      const body = { username, ...pwPayload(f) };
      if (f.get("role")) body.role = f.get("role");
      if (f.get("tier")) body.tier = f.get("tier");
      let out;
      try {
        out = await api("POST", "users", body);
        const topic = (f.get("topic") || "").trim();
        if (topic && body.role !== "admin") await api("PUT", "access", { username, topic, permission: f.get("perm") });
        toast("Created " + username);
      } catch (e) {
        toast(e.message, true);
        await refresh();
        return true;
      }
      openUsers.add(username);
      await refresh();
      const u = state.users.find((x) => x.username === username);
      onboardingDialog(u || { username, grants: [], role: body.role || "user" }, out.password || f.get("password"));
      return true;
    },
  });
}

function passwordDialog(u) {
  openDialog({
    title: "Change password — " + u.username,
    body: [...pwFields(), h("p", { class: "note" }, "Phones logged in with the old password will need the new one.")],
    submit: "Change password",
    onSubmit: async (f) => {
      const out = await act(() => api("PATCH", "users/" + encodeURIComponent(u.username), pwPayload(f)), "Password changed");
      onboardingDialog(u, out.password || f.get("password"));
      return true;
    },
  });
}

async function resetLink(u) {
  try {
    const out = await api("POST", "users/" + encodeURIComponent(u.username) + "/reset-link", {});
    openDialog({
      title: "Password reset link — " + u.username,
      body: [
        h("p", {}, "Send this to " + u.username + "; they pick a new password themselves. Valid for a limited time."),
        secretBox(out.link),
        h("div", { class: "qr-grid" }, h("div", { class: "qr" }, h("img", { src: "api/qr?data=" + encodeURIComponent(out.link), alt: "QR code of the reset link" }))),
      ],
    });
  } catch (e) { toast(e.message, true); }
}

function roleDialog(u) {
  const to = u.role === "admin" ? "user" : "admin";
  confirmDialog(to === "admin" ? "Make " + u.username + " an admin?" : "Make " + u.username + " a regular user?",
    to === "admin"
      ? "Admins can read and write every topic and log in to this panel. Their access rules stop mattering."
      : "They lose access to everything not covered by access rules, and can no longer use this panel.",
    to === "admin" ? "Make admin" : "Make regular user",
    () => act(() => api("PATCH", "users/" + encodeURIComponent(u.username), { role: to }), u.username + " is now " + to));
}

// --- onboarding -------------------------------------------------------------------------------
function onboardingDialog(u, password) {
  const topics = readableTopics(u);
  openDialog({
    title: "Onboarding — " + u.username,
    body: [
      h("table", {}, h("tbody", {},
        h("tr", {}, h("th", {}, "Server"), h("td", { class: "mono" }, state.server.public_url)),
        h("tr", {}, h("th", {}, "Username"), h("td", { class: "mono" }, u.username)),
      )),
      password ? h("div", {}, h("div", { class: "warn" }, "Password — shown only now:"), secretBox(password)) : null,
      h("ol", {},
        h("li", {}, "ntfy app → Settings → Manage users → Add user: server, username and password above."),
        h("li", {}, "Scan a QR code to subscribe to that topic."),
      ),
      topics.length
        ? h("div", { class: "qr-grid" }, topics.map((t) => h("div", { class: "qr" },
          h("img", { src: "api/qr?data=" + encodeURIComponent(deepLink(t.name)), alt: "QR code for " + t.name, loading: "lazy" }),
          h("div", { class: "t" }, t.display || t.name),
          h("div", { class: "mono muted" }, t.name),
          t.about ? h("div", { class: "note" }, t.about) : null)))
        : h("p", { class: "empty" }, "No readable topics known yet. Grant read access to a topic, or add a topic note."),
      h("div", { class: "row-btns" }, h("button", { type: "button", class: "btn small", onclick: () => window.print() }, "Print")),
    ],
  });
}

// --- topics ---------------------------------------------------------------------------------------
function renderTopics() {
  const users = state.users;
  const rows = state.topics.map((t) => {
    const readers = [], writers = [];
    for (const u of users) {
      const p = effective(u, t.name).perm;
      if (p === "admin") continue;
      if (canRead(p)) readers.push(u.username);
      if (canWrite(p)) writers.push(u.username);
    }
    const anon = effective(null, t.name).perm;
    const who = (list, anonOk) => h("div", { class: "who" },
      anonOk ? h("span", { class: "badge", title: "anonymous" }, "everyone") : null,
      list.map((n) => h("span", { class: "chip p-read-only" }, n)),
      !list.length && !anonOk ? h("span", { class: "muted" }, "—") : null);
    return h("tr", {},
      h("td", {}, t.name),
      h("td", {}, t.display ? h("div", {}, t.display) : null, t.about ? h("div", { class: "note" }, t.about) : null,
        !t.display && !t.about ? h("span", { class: "muted" }, "—") : null),
      h("td", {}, who(readers, canRead(anon))),
      h("td", {}, who(writers, canWrite(anon))),
      h("td", { class: "actions" },
        h("button", { class: "btn small", onclick: () => publishDialog(t.name) }, "Test"), " ",
        h("button", { class: "btn small", disabled: !state.notes_writable, onclick: () => topicDialog(t) }, "Note"), " ",
        t.noted ? h("button", {
          class: "btn small icon danger", title: "Forget the note (access rules stay)", disabled: !state.notes_writable,
          onclick: () => act(() => api("DELETE", "topics/" + encodeURIComponent(t.name)), "Note removed"),
        }, "✕") : null));
  });
  $("#topics").replaceChildren(rows.length
    ? h("div", { class: "card" }, h("table", { class: "topics-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Topic"), h("th", {}, "Note"), h("th", {}, "Can read"), h("th", {}, "Can publish"), h("th", {}))),
      h("tbody", {}, rows)))
    : h("p", { class: "empty" }, "No topics yet."));
  $("#add-topic").disabled = !state.notes_writable;
}

function topicDialog(t) {
  openDialog({
    title: t ? "Topic note — " + t.name : "New topic note",
    body: [
      h("label", {}, "Topic", h("input", { name: "name", required: true, pattern: "[-_A-Za-z0-9]{1,64}", value: t ? t.name : "", readonly: !!t })),
      h("label", {}, "Display name (shown in the phone app)", h("input", { name: "display", maxlength: 100, value: t ? t.display || "" : "" })),
      h("label", {}, "About", h("input", { name: "about", maxlength: 300, value: t ? t.about || "" : "", placeholder: "what lands here, how loud it is" })),
      h("p", { class: "note" }, "Notes live in this panel only (no secrets). Access is still set per user."),
    ],
    submit: "Save",
    onSubmit: (f) => act(() => api("PUT", "topics/" + encodeURIComponent(f.get("name").trim()),
      { display: f.get("display"), about: f.get("about") }), "Saved"),
  });
}

function publishDialog(topic) {
  openDialog({
    title: "Send a test message",
    body: [
      h("label", {}, "Topic", h("input", { name: "topic", value: topic, readonly: true })),
      h("label", {}, "Title", h("input", { name: "title", placeholder: "optional" })),
      h("label", {}, "Message", h("textarea", { name: "message", rows: 3 }, "Test from ntfy-admin")),
      h("label", {}, "Priority", h("select", { name: "priority" },
        [["3", "default"], ["1", "min"], ["2", "low"], ["4", "high"], ["5", "max (urgent)"]].map(([v, l]) => h("option", { value: v }, l)))),
      h("p", { class: "note" }, "Sent as you (" + me.username + ")."),
    ],
    submit: "Send",
    onSubmit: async (f) => {
      try {
        await api("POST", "publish", { topic, title: f.get("title"), message: f.get("message"), priority: Number(f.get("priority")) });
        toast("Sent to " + topic);
      } catch (e) { toast(e.message, true); return true; }
    },
  });
}

// --- matrix ----------------------------------------------------------------------------------------
function renderMatrix() {
  const topics = topicNames();
  if (!topics.length || !state.users.length) {
    $("#matrix").replaceChildren(h("p", { class: "empty" }, "Nothing to show yet."));
    return;
  }
  const head = h("tr", {}, h("th", {}, ""), topics.map((t) => h("th", {}, t)));
  const rows = [null, ...state.users].map((u) => {
    const name = u ? u.username : "(anonymous)";
    return h("tr", {}, h("th", {}, name, ...(u ? userBadges(u).filter(Boolean).flatMap((b) => [" ", b]) : [])),
      topics.map((t) => {
        const eff = effective(u, t);
        const exact = u ? (u.grants || []).find((g) => g.topic === t)
          : ((state.everyone && state.everyone.grants) || []).find((g) => g.topic === t);
        const cell = h("td", { class: "p-" + eff.perm + (exact ? " exact" : "") },
          h("button", {
            title: `${name} → ${t}: ${eff.perm} (${eff.source})`,
            disabled: eff.perm === "admin",
            onclick: () => cellDialog(u ? u.username : "*", name, t, exact),
          }, PERM_SHORT[eff.perm] || eff.perm));
        return cell;
      }));
  });
  $("#matrix").replaceChildren(
    h("table", { class: "matrix" }, h("thead", {}, head), h("tbody", {}, rows)),
  );
  const legend = h("div", { class: "legend" }, PERMS.map((p) => permChip(p)), permChip("admin"),
    h("span", { class: "muted" }, "outlined = exact rule for that topic"));
  $("#matrix").before(legend);
  // keep a single legend
  const legends = document.querySelectorAll("#tab-matrix .legend");
  legends.forEach((l, i) => { if (i < legends.length - 1) l.remove(); });
}

function cellDialog(username, display, topic, exact) {
  openDialog({
    title: display + " → " + topic,
    body: [
      h("label", {}, "Exact rule for this topic", permSelect("perm", exact ? exact.permission : "read-only", exact && exact.provisioned)),
      exact ? null : h("p", { class: "note" }, "Currently resolved by: " + effective(username === "*" ? null : state.users.find((u) => u.username === username), topic).source),
      exact ? h("button", {
        type: "button", class: "btn small danger", disabled: exact.provisioned,
        onclick: async () => { $("#dialog").close(); await act(() => api("POST", "access/delete", { username, topic }), "Rule removed"); },
      }, "Remove exact rule") : null,
    ],
    submit: "Save rule",
    onSubmit: (f) => act(() => api("PUT", "access", { username, topic, permission: f.get("perm") }), "Saved"),
  });
}

// --- anonymous ---------------------------------------------------------------------------------------
function renderEveryone() {
  const e = state.everyone || { username: "*", grants: [], role: "anonymous" };
  const def = state.server.default_access || "?";
  $("#everyone").replaceChildren(h("div", { class: "card user open" },
    h("div", { class: "user-head" }, h("span", { class: "user-name" }, "Anonymous (not logged in)")),
    h("div", { class: "user-body" },
      h("p", {}, "Server default for anything without a rule: ", permChip(def in PERM_SHORT ? def : "deny-all"), " ",
        h("span", { class: "muted" }, "(auth-default-access in server.yml; not changeable via the API)")),
      def === "read-write" ? h("p", { class: "warn" }, "Anyone who can reach the server can read and publish to topics without rules.") : null,
      h("h3", {}, "Anonymous rules"),
      accessEditor({ ...e, username: "*", role: "anonymous" }),
      h("p", { class: "note" }, "Logged-in users fall back to these rules when none of their own match."),
    )));
}
