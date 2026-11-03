"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const test = require("node:test");
const { createApp, isGateway } = require("../src/app");
const { openDatabase } = require("../src/database");
const { decryptText, hashPassword, sha256 } = require("../src/security");

function removeTempDirectory(directory) {
  try {
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  } catch (error) {
    if (process.platform !== "win32" || error.code !== "EPERM") throw error;
    setTimeout(() => {
      fs.rm(directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }, () => {});
    }, 100);
  }
}

// Các test mã hóa key cần một secret xác định. Đặt trước khi openDatabase/createApp
// chạy vì encryptText đọc mặc định từ process.env.
const KEY_SECRET = "test-key-encryption-secret-value";
process.env.KEY_ENCRYPTION_SECRET = KEY_SECRET;

async function fixture(options = {}) {
  let current = Date.parse("2026-07-30T00:00:00.000Z");
  const db = openDatabase(options.filename);
  const server = http.createServer(createApp({ db, adminPasswordHash: hashPassword("very-long-admin-password"), clock: () => current, ...options }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  async function request(path, options = {}) {
    const response = await fetch(`${base}${path}`, options);
    const type = response.headers.get("content-type") || "";
    return { response, body: type.includes("json") ? await response.json() : await response.text() };
  }
  async function login() {
    const result = await request("/admin/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: "very-long-admin-password" }), redirect: "manual" });
    return result.response.headers.getSetCookie()[0].split(";", 1)[0];
  }
  async function csrf(cookie) {
    const page = await request("/admin", { headers: { cookie } });
    return page.body.match(/name="csrf" value="([^"]+)"/)?.[1];
  }
  async function createAccount(plan = "Pro", days = 30) {
    const cookie = await login();
    const token = await csrf(cookie);
    const result = await request("/admin/accounts", { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, plan, days: String(days), note: "matrix" }) });
    const key = result.body.match(/Key mới \(chỉ hiển thị lần này\): ([A-Za-z0-9_-]+)/)?.[1];
    return { cookie, key, accountId: Number(db.prepare("SELECT id FROM accounts ORDER BY id DESC LIMIT 1").get().id) };
  }
  return { db, request, login, createAccount, advance(ms) { current += ms; }, close: async () => { await new Promise((resolve) => server.close(resolve)); db.close(); } };
}

function uid(letter) { return letter.repeat(64); }
async function csrfFor(app, cookie) {
  const page = await app.request("/admin", { headers: { cookie } });
  return page.body.match(/name="csrf" value="([^"]+)"/)?.[1];
}

function panelJson(obj, { success = true, status = 200 } = {}) {
  return new Response(JSON.stringify({ success, obj }), { status, headers: { "content-type": "application/json" } });
}

function vlessInbound(overrides = {}) {
  return {
    id: 7,
    protocol: "vless",
    remark: "Primary VPN",
    port: 443,
    enable: true,
    settings: JSON.stringify({ clients: [{ email: "existing@example.com", enable: true, limitIp: 2, totalGB: 1073741824, expiryTime: 0, id: "must-not-leak" }] }),
    clientStats: [{ email: "existing@example.com", up: 10, down: 20 }],
    ...overrides,
  };
}

const GPM_LICENSE_UUID = "11111111-1111-4111-8111-111111111111";
const GPM_SUB_UUID = "22222222-2222-4222-8222-222222222222";

function gpmResponse(data, { status = 200, cookie = "" } = {}) {
  const headers = { "content-type": "application/json" };
  if (cookie) headers["set-cookie"] = `${cookie}; Path=/; HttpOnly`;
  return new Response(JSON.stringify({ data }), { status, headers });
}

async function protonAdmin(app) {
  const cookie = await app.login();
  return { cookie, csrf: await csrfFor(app, cookie) };
}

async function createProtonAccount(app, admin, overrides = {}) {
  const result = await app.request("/admin/proton/accounts", { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ name: "Proton Main", email: "proton@example.test", cookie: "AUTH=test-secret-cookie", uid: "manager-session", password: "secret-password", appVersion: "web-vpn@1.0", ...overrides }) });
  assert.equal(result.response.status, 201);
  return result.body.account;
}

test("matrix: tạo key chỉ trả plaintext một lần và database chỉ lưu hash", async () => {
  const app = await fixture();
  try {
    const created = await app.createAccount("Business", 45);
    assert.match(created.key, /^292sv-ZP-/);
    const keyRow = app.db.prepare("SELECT * FROM account_keys").get();
    assert.equal(keyRow.key_hash, sha256(created.key));
    assert.equal(JSON.stringify(keyRow).includes(created.key), false);
    const page = await app.request("/admin", { headers: { cookie: created.cookie } });
    assert.equal(page.body.includes(created.key), false);
  } finally { await app.close(); }
});

test("292vpn: key chuyên nghiệp tách product và chỉ kích hoạt qua API VPN", async () => {
  const hysteria2Url = "hysteria2://password@example.test:8443?insecure=1";
  const hysteria2UrlSg = "hysteria2://password@sg.example.test:8443?insecure=1&mport=20000-50000&hop_interval=30s";
  const app = await fixture({ hysteria2Url, hysteria2UrlSg });
  try {
    const cookie = await app.login();
    const token = await csrfFor(app, cookie);
    const created = await app.request("/admin/accounts", {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: token, product: "292vpn", name: "VPN Customer", plan: "VPN 30", days: "30", note: "Hanoi" }),
    });
    const key = created.body.match(/Key mới \(chỉ hiển thị lần này\): ([A-Za-z0-9_-]+)/)?.[1];
    assert.match(key, /^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){3}$/);
    assert.equal(app.db.prepare("SELECT product FROM accounts ORDER BY id DESC LIMIT 1").get().product, "292vpn");

    const wrongProduct = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    assert.equal(wrongProduct.response.status, 403);
    const activated = await app.request("/api/vpn/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    assert.equal(activated.response.status, 200);
    assert.equal(activated.body.account.status, "active");
    const headers = { authorization: `Bearer ${activated.body.token}` };
    const nodes = await app.request("/api/vpn/nodes", { headers });
    assert.deepEqual(nodes.body.nodes.map((node) => node.id), ["vn-hanoi-1", "vn-hanoi-2"]);
    const hysteria = await app.request("/api/vpn/configs/issue", { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify({ node_id: "vn-hanoi-2" }) });
    assert.equal(hysteria.response.status, 200);
    assert.equal(hysteria.body.config_url, hysteria2Url);
  } finally { await app.close(); }
});

test("292vpn: hơn 10 máy sẽ pending 10 phút, còn UID cũ vẫn tái kích hoạt đúng slot", async () => {
  const app = await fixture();
  try {
    const cookie = await app.login();
    const csrf = await csrfFor(app, cookie);
    const created = await app.request("/admin/accounts", {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf, product: "292vpn", name: "Multi device", plan: "VPN 30", days: "30" }),
    });
    const key = created.body.match(/Key mới \(chỉ hiển thị lần này\): ([A-Z2-9-]+)/)?.[1];
    const deviceUids = Array.from({ length: 12 }, (_, index) => (index + 1).toString(16).padStart(64, "0"));
    const activate = (value) => app.request("/api/vpn/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: value }) });

    for (const [index, value] of deviceUids.slice(0, 10).entries()) {
      const result = await activate(value);
      assert.equal(result.response.status, 200);
      assert.equal(result.body.device.status, "active");
      assert.equal(result.body.device.activeSlots, index + 1);
    }

    const pending = await activate(deviceUids[10]);
    assert.equal(pending.response.status, 200);
    assert.equal(pending.body.device.status, "pending");
    assert.equal(pending.body.device.activeSlots, 10);
    assert.ok(pending.body.device.pendingUntil);

    const heartbeat = await app.request("/api/vpn/heartbeat", { method: "POST", headers: { authorization: `Bearer ${pending.body.token}`, "content-type": "application/json" }, body: JSON.stringify({ sequence: 1 }) });
    assert.equal(heartbeat.response.status, 200);
    assert.equal(heartbeat.body.blocked, true);
    assert.equal(heartbeat.body.device.status, "pending");

    const reused = await activate(deviceUids[0]);
    assert.equal(reused.response.status, 200);
    assert.equal(reused.body.device.status, "active");
    assert.equal(reused.body.device.activeSlots, 10);

    app.advance(10 * 60 * 1000 + 1);
    const afterExpiry = await activate(deviceUids[11]);
    assert.equal(afterExpiry.response.status, 200);
    assert.equal(afterExpiry.body.device.status, "pending");
    assert.equal(app.db.prepare("SELECT released_at FROM devices WHERE uid=?").get(deviceUids[10]).released_at !== null, true);
  } finally { await app.close(); }
});

test("292vpn: WireGuard cấp config riêng, idempotent và chỉ lưu bản mã hóa", async () => {
  const configText = "[Interface]\nPrivateKey = test-private-key\nAddress = 10.29.0.10/32\n\n[Peer]\nPublicKey = test-public-key\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:443\n";
  const calls = [];
  const app = await fixture({
    wireGuardProvisioner: {
      configured: true,
      async provision(allocationId) { calls.push(allocationId); return configText; },
    },
  });
  try {
    const cookie = await app.login();
    const token = await csrfFor(app, cookie);
    const created = await app.request("/admin/accounts", {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: token, product: "292vpn", name: "WireGuard Customer", plan: "VPN 30", days: "30", note: "Hanoi 3" }),
    });
    const key = created.body.match(/Key mới \(chỉ hiển thị lần này\): ([A-Z2-9-]+)/)?.[1];
    const activated = await app.request("/api/vpn/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    const headers = { authorization: `Bearer ${activated.body.token}` };
    const nodes = await app.request("/api/vpn/nodes", { headers });
    assert.equal(nodes.body.nodes.at(-1).id, "vn-hanoi-3");
    const options = { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify({ node_id: "vn-hanoi-3" }) };
    const first = await app.request("/api/vpn/configs/issue", options);
    const second = await app.request("/api/vpn/configs/issue", options);
    assert.equal(first.response.status, 200);
    assert.equal(first.body.protocol, "wireguard");
    assert.equal(first.body.config_url, "");
    assert.equal(first.body.config_text, configText);
    assert.equal(second.body.config_text, configText);
    assert.equal(calls.length, 1);
    const stored = app.db.prepare("SELECT config_url FROM vpn_allocations WHERE node_id='vn-hanoi-3'").get().config_url;
    assert.match(stored, /^gcm:/);
    assert.equal(stored.includes("test-private-key"), false);
  } finally { await app.close(); }
});

test("292vpn: node WireGuard vẫn hiện khi metadata có nhưng provisioner tạm thiếu secret", async () => {
  const app = await fixture({
    wireGuardProvisioner: { configured: false, catalogConfigured: true },
    wireGuardProvisionerHcm: { configured: false, catalogConfigured: true },
  });
  try {
    const cookie = await app.login();
    const csrf = await csrfFor(app, cookie);
    const createdResponse = await app.request("/admin/accounts", {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf, product: "292vpn", name: "VPN Customer", plan: "VPN 30", days: "30" }),
    });
    const created = { key: createdResponse.body.match(/Key mới \(chỉ hiển thị lần này\): ([A-Z2-9-]+)/)?.[1] };
    const activated = await app.request("/api/vpn/activate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key: created.key, uid: uid("a") }),
    });
    const nodes = await app.request("/api/vpn/nodes", {
      headers: { authorization: `Bearer ${activated.body.token}` },
    });
    assert.deepEqual(nodes.body.nodes.map((node) => node.id), ["vn-hanoi-1", "vn-hanoi-3", "vn-hcm-1"]);
  } finally { await app.close(); }
});

test("proton: admin auth/CSRF, safe projection và database mã hóa credential", async () => {
  const app = await fixture({ fetchImpl: async () => new Response(JSON.stringify({ sessions: [] }), { headers: { "content-type": "application/json" } }) });
  try {
    const denied = await app.request("/admin/proton/accounts", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "x", cookie: "secret", uid: "uid-1" }) });
    assert.equal(denied.response.status, 401);
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const listed = await app.request("/admin/proton/accounts", { headers: { cookie: admin.cookie } });
    assert.equal(listed.response.status, 200); assert.equal(JSON.stringify(listed.body).includes("AUTH=test-secret-cookie"), false); assert.equal(JSON.stringify(listed.body).includes("secret-password"), false);
    const stored = app.db.prepare("SELECT cookie_encrypted,password_encrypted FROM proton_accounts WHERE id=?").get(account.id);
    assert.match(stored.cookie_encrypted, /^gcm:/); assert.match(stored.password_encrypted, /^gcm:/); assert.equal(app.db.prepare("PRAGMA foreign_key_check").all().length, 0);
  } finally { await app.close(); }
});

test("proton: session mock, assignment validation/current guard, export/import", async () => {
  const calls = [];
  const sessions = [{ UID: "manager-session", LocalizedClientName: "Windows VPN" }, { UID: "rented-session", ClientID: "Android VPN", CreateTime: 1785369600 }, { UID: "mail-session", LocalizedClientName: "Web Mail" }];
  const app = await fixture({ fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(JSON.stringify({ Sessions: sessions }), { headers: { "content-type": "application/json" } }); } });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    let result = await app.request(`/admin/proton/accounts/${account.id}/sessions`, { headers: { cookie: admin.cookie } });
    assert.equal(result.body.sessions.length, 2); assert.equal(result.body.stats.manager, 1); assert.equal(result.body.stats.unassigned, 1); assert.equal(result.body.stats.total, 2); assert.equal(result.body.sessions[1].device, "Android VPN"); assert.ok(result.body.sessions[1].createdAt);
    assert.equal(calls[0].url, "https://account.protonvpn.com/api/auth/v4/sessions"); assert.equal(calls[0].options.headers.accept, "application/vnd.protonmail.v1+json"); assert.equal(calls[0].options.headers["accept-language"], "en_US"); assert.equal(calls[0].options.headers["x-pm-locale"], "en_US"); assert.equal(calls[0].options.headers["x-pm-appversion"], "web-vpn@1.0");
    result = await app.request("/admin/proton/rentals/rented-session", { method: "PUT", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ accountId: account.id, customer: "Nguyen", phone: "0909", note: "test", duration: 2, unit: "days" }) });
    assert.equal(result.response.status, 200);
    const current = await app.request("/admin/proton/rentals/manager-session", { method: "PUT", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ accountId: account.id, customer: "bad", duration: 1, unit: "days" }) });
    assert.equal(current.response.status, 409);
    const exported = await app.request("/admin/proton/export.json", { headers: { cookie: admin.cookie } }); assert.equal(exported.body.rentals.length, 1); assert.equal(JSON.stringify(exported.body).includes("AUTH="), false);
    const imported = await app.request("/admin/proton/import", { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ rentals: [{ sessionUid: "rented-session", accountId: account.id, customer: "overwrite?", expiresAt: "2030-01-01T00:00:00Z" }] }) });
    assert.equal(imported.body.skipped, 1);
  } finally { await app.close(); }
});

test("proton: revoke chỉ xóa rental sau Proton success và cleanup dry-run/revoke", async () => {
  const calls = [];
  const app = await fixture({ fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(JSON.stringify({ Sessions: [{ UID: "manager-session", LocalizedClientName: "Windows VPN" }, { UID: "expired-session", LocalizedClientName: "Android VPN" }] }), { headers: { "content-type": "application/json" } }); } });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const assign = (sessionUid, expiresAt) => app.request(`/admin/proton/rentals/${sessionUid}`, { method: "PUT", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ accountId: account.id, customer: "Customer", expiresAt }) });
    await assign("expired-session", "2020-01-01T00:00:00Z");
    let result = await app.request(`/admin/proton/accounts/${account.id}/cleanup`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ dryRun: true }) });
    assert.deepEqual(result.body, { scanned: 2, eligible: 1, revoked: 0, failed: 0, skippedCurrent: 1 });
    result = await app.request(`/admin/proton/accounts/${account.id}/sessions/expired-session/revoke`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: "{}" });
    assert.equal(result.response.status, 200); assert.equal(app.db.prepare("SELECT * FROM proton_rentals WHERE session_uid=?").get("expired-session"), undefined); assert.ok(calls.some((call) => call.options.method === "DELETE" && call.url === "https://account.protonvpn.com/api/auth/v4/sessions/expired-session"));
    result = await app.request(`/admin/proton/accounts/${account.id}/sessions/manager-session/revoke`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: "{}" }); assert.equal(result.response.status, 409);
  } finally { await app.close(); }
});

test("proton: allowlist giữ session mới 5 phút và thu hồi session không có rental sau đó", async () => {
  const calls = [];
  const app = await fixture({
    proton: { sessionGraceMs: 300000, autoRevoke: false },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return options.method === "DELETE"
        ? new Response("", { status: 200 })
        : new Response(JSON.stringify({ Sessions: [
          { UID: "manager-session", LocalizedClientName: "Windows VPN" },
          { UID: "old-unassigned", LocalizedClientName: "Android VPN", CreateTime: 1785369240 },
          { UID: "new-unassigned", LocalizedClientName: "Android VPN", CreateTime: 1785369900 },
        ] }), { headers: { "content-type": "application/json" } });
    },
  });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    let result = await app.request(`/admin/proton/accounts/${account.id}/cleanup`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ dryRun: true }) });
    assert.equal(result.response.status, 200);
    assert.equal(result.body.eligible, 1);
    assert.equal(result.body.revoked, 0);
    result = await app.request(`/admin/proton/accounts/${account.id}/cleanup`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({}) });
    assert.equal(result.response.status, 200);
    assert.equal(result.body.eligible, 1);
    assert.equal(result.body.revoked, 1);
    assert.deepEqual(calls.filter((call) => call.options.method === "DELETE").map((call) => call.url), ["https://account.protonvpn.com/api/auth/v4/sessions/old-unassigned"]);
  } finally { await app.close(); }
});

test("proton: xóa người dùng thu hồi session rồi xóa rental và block history", async () => {
  const calls = [];
  const app = await fixture({
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response(options.method === "DELETE" ? "" : JSON.stringify({ Sessions: [{ UID: "manager-session", LocalizedClientName: "Windows VPN" }, { UID: "rented-session", LocalizedClientName: "Android VPN" }] }), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    app.db.prepare("INSERT INTO proton_rentals(session_uid,account_id,customer,phone,note,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").run("rented-session", account.id, "Customer", "0909", "note", "2030-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z");
    app.db.prepare("INSERT INTO proton_uid_blocks(account_id,session_uid,blocked_at,updated_at) VALUES(?,?,?,?)").run(account.id, "rented-session", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z");
    const result = await app.request(`/admin/proton/accounts/${account.id}/sessions/rented-session/delete-user`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: "{}" });
    assert.equal(result.response.status, 200);
    assert.equal(app.db.prepare("SELECT * FROM proton_rentals WHERE session_uid=?").get("rented-session"), undefined);
    assert.equal(app.db.prepare("SELECT * FROM proton_uid_blocks WHERE account_id=? AND session_uid=?").get(account.id, "rented-session"), undefined);
    assert.equal(calls.filter((call) => call.options.method === "DELETE").length, 1);
  } finally { await app.close(); }
});

test("proton: lưu trữ trả rental đã thu hồi và UID đang khóa", async () => {
  const app = await fixture({ fetchImpl: async () => new Response(JSON.stringify({ Sessions: [] }), { headers: { "content-type": "application/json" } }) });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const insertRental = app.db.prepare("INSERT INTO proton_rentals(session_uid,account_id,customer,phone,note,expires_at,created_at,updated_at,archived_at) VALUES(?,?,?,?,?,?,?,?,?)");
    insertRental.run("archived-session", account.id, "Old customer", "0909", "", "2026-01-01T00:00:00.000Z", "2025-12-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "2026-01-01T00:05:00.000Z");
    insertRental.run("live-session", account.id, "Live customer", "", "", "2030-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", null);
    const insertBlock = app.db.prepare("INSERT INTO proton_uid_blocks(account_id,session_uid,blocked_at,unblocked_at,updated_at) VALUES(?,?,?,?,?)");
    insertBlock.run(account.id, "blocked-session", "2026-01-02T00:00:00.000Z", null, "2026-01-02T00:00:00.000Z");
    insertBlock.run(account.id, "unblocked-session", "2026-01-02T00:00:00.000Z", "2026-01-03T00:00:00.000Z", "2026-01-03T00:00:00.000Z");
    assert.equal((await app.request("/admin/proton/archive")).response.status, 401);
    const result = await app.request("/admin/proton/archive", { headers: { cookie: admin.cookie } });
    assert.equal(result.response.status, 200);
    assert.deepEqual(result.body.rentals.map((rental) => rental.sessionUid), ["archived-session"]);
    assert.equal(result.body.rentals[0].archivedAt, "2026-01-01T00:05:00.000Z");
    assert.deepEqual(result.body.blocks.map((block) => block.sessionUid), ["blocked-session"]);
    assert.equal(result.body.blocks[0].accountId, account.id);
  } finally { await app.close(); }
});

test("proton: khôi phục rental đã thu hồi sang session mới hoặc chính UID cũ", async () => {
  const app = await fixture({ fetchImpl: async () => new Response(JSON.stringify({ Sessions: [{ UID: "manager-session", LocalizedClientName: "Windows VPN" }, { UID: "new-session", LocalizedClientName: "Android VPN" }, { UID: "same-session", LocalizedClientName: "iOS VPN" }, { UID: "taken-session", LocalizedClientName: "Mac VPN" }, { UID: "blocked-session", LocalizedClientName: "Linux VPN" }] }), { headers: { "content-type": "application/json" } }) });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const headers = { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" };
    const insertRental = app.db.prepare("INSERT INTO proton_rentals(session_uid,account_id,customer,phone,note,expires_at,created_at,updated_at,archived_at) VALUES(?,?,?,?,?,?,?,?,?)");
    insertRental.run("old-session", account.id, "Old customer", "0909", "VIP", "2026-01-01T00:00:00.000Z", "2025-12-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "2026-01-01T00:05:00.000Z");
    insertRental.run("same-session", account.id, "Same customer", "", "", "2026-01-01T00:00:00.000Z", "2025-12-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "2026-01-01T00:05:00.000Z");
    insertRental.run("taken-session", account.id, "Other", "", "", "2030-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", null);
    app.db.prepare("INSERT INTO proton_uid_blocks(account_id,session_uid,blocked_at,unblocked_at,updated_at) VALUES(?,?,?,?,?)").run(account.id, "blocked-session", "2026-01-01T00:00:00.000Z", null, "2026-01-01T00:00:00.000Z");
    const restore = (uid, body) => app.request(`/admin/proton/rentals/${uid}/restore`, { method: "POST", headers, body: JSON.stringify(body) });
    assert.equal((await restore("taken-session", { duration: 30 })).response.status, 404);
    assert.equal((await restore("old-session", { targetSessionUid: "taken-session", duration: 30 })).response.status, 409);
    assert.equal((await restore("old-session", { targetSessionUid: "manager-session", duration: 30 })).response.status, 409);
    assert.equal((await restore("old-session", { targetSessionUid: "blocked-session", duration: 30 })).response.status, 409);
    assert.equal((await restore("old-session", { targetSessionUid: "missing-session", duration: 30 })).response.status, 400);
    const moved = await restore("old-session", { targetSessionUid: "new-session", duration: 30 });
    assert.equal(moved.response.status, 200);
    const row = app.db.prepare("SELECT * FROM proton_rentals WHERE session_uid=?").get("new-session");
    assert.equal(row.customer, "Old customer"); assert.equal(row.phone, "0909"); assert.equal(row.note, "VIP"); assert.equal(row.archived_at, null);
    assert.notEqual(row.expires_at, "2026-01-01T00:00:00.000Z");
    assert.equal(app.db.prepare("SELECT 1 FROM proton_rentals WHERE session_uid=?").get("old-session"), undefined);
    const same = await restore("same-session", { expiresAt: "2031-01-01T00:00:00.000Z" });
    assert.equal(same.response.status, 200);
    const sameRow = app.db.prepare("SELECT * FROM proton_rentals WHERE session_uid=?").get("same-session");
    assert.equal(sameRow.archived_at, null); assert.equal(sameRow.expires_at, "2031-01-01T00:00:00.000Z"); assert.equal(sameRow.customer, "Same customer");
    assert.equal((await restore("same-session", { duration: 30 })).response.status, 404);
  } finally { await app.close(); }
});

test("proton: revoke chấp nhận success body rỗng và không GET sessions trước DELETE", async () => {
  const calls = [];
  const app = await fixture({ fetchImpl: async (url, options) => {
    calls.push({ url, options });
    if (options.method === "DELETE") return new Response("", { status: 200 });
    return new Response(JSON.stringify({ Sessions: [] }), { headers: { "content-type": "application/json" } });
  } });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    app.db.prepare("INSERT INTO proton_rentals(session_uid,account_id,customer,phone,note,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").run("rented-session", account.id, "Customer", "", "", "2020-01-01T00:00:00.000Z", "2020-01-01T00:00:00.000Z", "2020-01-01T00:00:00.000Z");
    const result = await app.request(`/admin/proton/accounts/${account.id}/sessions/rented-session/revoke`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: "{}" });
    assert.equal(result.response.status, 200);
    assert.deepEqual(calls.map((call) => call.options.method), ["DELETE"]);
    assert.equal(app.db.prepare("SELECT * FROM proton_rentals WHERE session_uid=?").get("rented-session"), undefined);
  } finally { await app.close(); }
});

test("proton: revoke 422 chỉ thành công idempotent khi session đã biến mất", async () => {
  for (const stillExists of [false, true]) {
    const calls = [];
    const app = await fixture({ fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (options.method === "DELETE") return new Response(JSON.stringify({ Error: "Session does not exist" }), { status: 422, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ Sessions: stillExists ? [{ UID: "rented-session", LocalizedClientName: "Android VPN" }] : [] }), { headers: { "content-type": "application/json" } });
    } });
    try {
      const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
      app.db.prepare("INSERT INTO proton_rentals(session_uid,account_id,customer,phone,note,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").run("rented-session", account.id, "Customer", "", "", "2020-01-01T00:00:00.000Z", "2020-01-01T00:00:00.000Z", "2020-01-01T00:00:00.000Z");
      const result = await app.request(`/admin/proton/accounts/${account.id}/sessions/rented-session/revoke`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: "{}" });
      assert.equal(result.response.status, stillExists ? 422 : 200);
      assert.equal(Boolean(app.db.prepare("SELECT * FROM proton_rentals WHERE session_uid=?").get("rented-session")), stillExists);
      assert.deepEqual(calls.map((call) => call.options.method), ["DELETE", "GET"]);
    } finally { await app.close(); }
  }
});

test("proton: helper renew cập nhật credential và retry request 401", async () => {
  const calls = [];
  const helper = path.join(__dirname, "fixtures", "proton-refresh-helper.js");
  const app = await fixture({
    proton: { refreshCommand: process.execPath, refreshArgs: [helper] },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (options.headers.cookie === "AUTH=test-secret-cookie") return new Response(JSON.stringify({ Error: "expired" }), { status: 401, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ Sessions: [{ UID: "manager-session", LocalizedClientName: "Windows VPN" }] }), { headers: { "content-type": "application/json" } });
    },
  });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const result = await app.request(`/admin/proton/accounts/${account.id}/sessions`, { headers: { cookie: admin.cookie } });
    assert.equal(result.response.status, 200);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].options.headers.cookie, "AUTH-manager-session=renewed-cookie");
    const stored = app.db.prepare("SELECT cookie_encrypted,app_version FROM proton_accounts WHERE id=?").get(account.id);
    assert.equal(decryptText(stored.cookie_encrypted), "AUTH-manager-session=renewed-cookie");
    assert.equal(stored.app_version, "web-vpn@renewed");
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM audit WHERE event='proton_credentials_refreshed'").get().count, 1);
  } finally { await app.close(); }
});

test("proton: helper renew chấp nhận dòng chẩn đoán trước JSON kết quả", async () => {
  const helper = path.join(__dirname, "fixtures", "proton-refresh-helper.js");
  const app = await fixture({
    proton: { refreshCommand: process.execPath, refreshArgs: [helper, "--diagnostic-prefix"] },
    fetchImpl: async (url, options) => options.headers.cookie === "AUTH=test-secret-cookie"
      ? new Response(JSON.stringify({ Error: "expired" }), { status: 401, headers: { "content-type": "application/json" } })
      : new Response(JSON.stringify({ Sessions: [] }), { headers: { "content-type": "application/json" } }),
  });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const result = await app.request(`/admin/proton/accounts/${account.id}/sessions`, { headers: { cookie: admin.cookie } });
    assert.equal(result.response.status, 200);
  } finally { await app.close(); }
});

test("proton: helper renew dùng email riêng và retry request 422 đúng một lần", async () => {
  const calls = [];
  const helper = path.join(__dirname, "fixtures", "proton-refresh-helper.js");
  const app = await fixture({
    proton: { refreshCommand: process.execPath, refreshArgs: [helper] },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (options.headers.cookie === "AUTH=test-secret-cookie") return new Response(JSON.stringify({ Error: "expired" }), { status: 422, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ Sessions: [{ UID: "manager-session", LocalizedClientName: "Windows VPN" }] }), { headers: { "content-type": "application/json" } });
    },
  });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const result = await app.request(`/admin/proton/accounts/${account.id}/sessions`, { headers: { cookie: admin.cookie } });
    assert.equal(result.response.status, 200);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].options.headers.cookie, "AUTH-manager-session=renewed-cookie");
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM audit WHERE event='proton_credentials_refreshed'").get().count, 1);
  } finally { await app.close(); }
});

test("proton: 422 Code 5003 tự cập nhật app version từ version.json mà không gọi helper", async () => {
  const calls = [];
  const helper = path.join(__dirname, "fixtures", "proton-refresh-helper.js");
  const app = await fixture({
    proton: { refreshCommand: process.execPath, refreshArgs: [helper] },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/assets/version.json")) return new Response(JSON.stringify({ version: "5.0.419.0" }), { headers: { "content-type": "application/json" } });
      if (options.headers["x-pm-appversion"] === "web-vpn@1.0") return new Response(JSON.stringify({ Code: 5003, Error: "This web page is out of date" }), { status: 422, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ Sessions: [{ UID: "manager-session", LocalizedClientName: "Windows VPN" }] }), { headers: { "content-type": "application/json" } });
    },
  });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const result = await app.request(`/admin/proton/accounts/${account.id}/sessions`, { headers: { cookie: admin.cookie } });
    assert.equal(result.response.status, 200);
    assert.equal(calls.length, 3);
    assert.equal(calls[2].options.headers["x-pm-appversion"], "web-vpn-settings@5.0.419.0");
    assert.equal(app.db.prepare("SELECT app_version FROM proton_accounts WHERE id=?").get(account.id).app_version, "web-vpn-settings@5.0.419.0");
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM audit WHERE event='proton_credentials_refreshed'").get().count, 0);
  } finally { await app.close(); }
});

test("proton: retry helper bao phủ 403 và không lặp khi request thứ hai vẫn lỗi", async () => {
  const helper = path.join(__dirname, "fixtures", "proton-refresh-helper.js");
  for (const secondStatus of [200, 403]) {
    const calls = [];
    const app = await fixture({
      proton: { refreshCommand: process.execPath, refreshArgs: [helper] },
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        const status = calls.length === 1 ? 403 : secondStatus;
        return new Response(JSON.stringify(status === 200 ? { Sessions: [] } : { Error: "expired" }), { status, headers: { "content-type": "application/json" } });
      },
    });
    try {
      const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
      const result = await app.request(`/admin/proton/accounts/${account.id}/sessions`, { headers: { cookie: admin.cookie } });
      assert.equal(result.response.status, secondStatus === 200 ? 200 : 502);
      assert.equal(calls.length, 2);
      assert.equal(app.db.prepare("SELECT COUNT(*) count FROM audit WHERE event='proton_credentials_refreshed'").get().count, 1);
    } finally { await app.close(); }
  }
});

test("proton: cookie fallback chỉ áp dụng khi AUTH UID khớp account", async () => {
  for (const matches of [true, false]) {
    const calls = [];
    const fallback = `AUTH-${matches ? "manager-session" : "another-manager"}=fallback-cookie`;
    const app = await fixture({
      proton: { cookie: fallback },
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        if (options.headers.cookie === "AUTH=test-secret-cookie") return new Response(JSON.stringify({ Error: "expired" }), { status: 401, headers: { "content-type": "application/json" } });
        return new Response(JSON.stringify({ Sessions: [] }), { headers: { "content-type": "application/json" } });
      },
    });
    try {
      const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin, { password: "" });
      const result = await app.request(`/admin/proton/accounts/${account.id}/sessions`, { headers: { cookie: admin.cookie } });
      assert.equal(result.response.status, matches ? 200 : 503);
      assert.equal(calls.length, matches ? 2 : 1);
      if (matches) assert.equal(calls[1].options.headers.cookie, fallback);
    } finally { await app.close(); }
  }
});

test("proton: account cũ thiếu email vẫn dùng cookie nhưng renew yêu cầu bổ sung email", async () => {
  const helper = path.join(__dirname, "fixtures", "proton-refresh-helper.js");
  const app = await fixture({
    proton: { refreshCommand: process.execPath, refreshArgs: [helper] },
    fetchImpl: async () => new Response(JSON.stringify({ Error: "expired" }), { status: 401, headers: { "content-type": "application/json" } }),
  });
  try {
    const timestamp = "2026-07-30T00:00:00.000Z";
    const { encryptText } = require("../src/security");
    const result = app.db.prepare("INSERT INTO proton_accounts(name,email,cookie_encrypted,uid,password_encrypted,app_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
      .run("Legacy Proton", "", encryptText("AUTH=legacy-cookie"), "legacy-manager", encryptText("legacy-password"), "web-vpn@1.0", timestamp, timestamp);
    const admin = await protonAdmin(app);
    const sessions = await app.request(`/admin/proton/accounts/${Number(result.lastInsertRowid)}/sessions`, { headers: { cookie: admin.cookie } });
    assert.equal(sessions.response.status, 503);
    assert.equal(sessions.body.error, "Proton account chưa lưu email để tự động renew cookie.");
    assert.equal(JSON.stringify(sessions.body).includes("legacy-password"), false);
  } finally { await app.close(); }
});

test("proton: worker tiếp tục account sau khi một account lỗi", async () => {
  let workerRun;
  const requestedCookies = [];
  const app = await fixture({
    proton: { autoRevoke: true, autoRevokeIntervalMs: 10000 },
    setIntervalImpl(callback) { workerRun = callback; return { unref() {} }; },
    fetchImpl: async (url, options) => {
      requestedCookies.push(options.headers.cookie);
      if (options.headers.cookie === "AUTH=broken") return new Response(JSON.stringify({ Error: "upstream failed" }), { status: 500, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ Sessions: [] }), { headers: { "content-type": "application/json" } });
    },
  });
  try {
    const admin = await protonAdmin(app);
    const broken = await createProtonAccount(app, admin, { name: "Broken", email: "broken@example.test", cookie: "AUTH=broken", uid: "broken-manager" });
    await createProtonAccount(app, admin, { name: "Healthy", email: "healthy@example.test", cookie: "AUTH=healthy", uid: "healthy-manager" });
    assert.equal(typeof workerRun, "function");
    await workerRun();
    assert.deepEqual(requestedCookies, ["AUTH=broken", "AUTH=healthy"]);
    const overview = await app.request("/admin/proton/overview", { headers: { cookie: admin.cookie } });
    assert.match(overview.body.worker.lastError, new RegExp(`Account ${broken.id} \\(Broken\\)`));
    assert.ok(overview.body.worker.lastRunAt);
  } finally { await app.close(); }
});

test("migration: thêm email Proton không làm mất account cũ", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zpm-proton-migration-"));
  const filename = path.join(directory, "accounts.sqlite");
  const legacy = new DatabaseSync(filename);
  legacy.exec("CREATE TABLE proton_accounts (id INTEGER PRIMARY KEY,name TEXT NOT NULL,cookie_encrypted TEXT NOT NULL,uid TEXT NOT NULL UNIQUE,password_encrypted TEXT NOT NULL DEFAULT '',app_version TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL)");
  legacy.prepare("INSERT INTO proton_accounts(id,name,cookie_encrypted,uid,password_encrypted,app_version,created_at,updated_at) VALUES(1,'Legacy','encrypted','legacy-uid','','','2026-01-01','2026-01-01')").run();
  legacy.close();
  const db = openDatabase(filename);
  try {
    const row = db.prepare("SELECT id,name,email,uid FROM proton_accounts WHERE id=1").get();
    assert.deepEqual({ ...row }, { id: 1, name: "Legacy", email: "", uid: "legacy-uid" });
    assert.equal(db.prepare("PRAGMA foreign_key_check").all().length, 0);
  } finally { db.close(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test("compose: chạy Node trực tiếp, nạp server.env raw và không ghi đè rỗng", () => {
  const compose = fs.readFileSync(path.join(__dirname, "..", "compose.yaml"), "utf8");
  assert.match(compose, /^\s+entrypoint: \["node"\]$/m);
  assert.match(compose, /^\s+command: \["src\/server\.js"\]$/m);
  assert.match(compose, /^\s+env_file:\s*$/m);
  assert.match(compose, /^\s+- path: server\.env\s*$/m);
  assert.match(compose, /^\s+format: raw\s*$/m);
  for (const key of ["292VPN_PANEL_API_URL", "292VPN_PANEL_USERNAME", "292VPN_PANEL_PASSWORD", "292VPN_HYSTERIA2_URL", "VPN_WIREGUARD_HOST_SG", "VPN_WIREGUARD_HOST_HK"]) {
    assert.doesNotMatch(compose, new RegExp(`^\\s+${key}:`, "m"));
  }
});

test("wireguard: SG/HK dùng chung identity/known-hosts với các node khác", () => {
  const server = fs.readFileSync(path.join(__dirname, "..", "src", "server.js"), "utf8");
  const sg = server.slice(server.indexOf("const wireGuardProvisionerSg"), server.indexOf("const wireGuardProvisionerHk"));
  const hk = server.slice(server.indexOf("const wireGuardProvisionerHk"), server.indexOf("// Node biến mất"));
  for (const block of [sg, hk]) {
    assert.match(block, /process\.env\.VPN_WIREGUARD_IDENTITY_FILE \|\| process\.env\["292VPN_WIREGUARD_IDENTITY_FILE"\]/);
    assert.match(block, /process\.env\.VPN_WIREGUARD_KNOWN_HOSTS_FILE \|\| process\.env\["292VPN_WIREGUARD_KNOWN_HOSTS_FILE"\]/);
  }
});

test("proton: server chấp nhận refresh args bị Docker env-file bỏ dấu nháy", () => {
  const server = fs.readFileSync(path.join(__dirname, "..", "src", "server.js"), "utf8");
  assert.match(server, /raw\.match\(\/\^\\\[\(\.\*\)\\\]\$\/s\)/);
  assert.match(server, /split\(","\).*filter\(Boolean\)/s);
});

test("vless: username/password env được ưu tiên, không gửi kèm token tĩnh cũ", async () => {
  const calls = [];
  const app = await fixture({
    xui: { baseUrl: "https://panel.example", token: "stale-token", username: "admin", password: "panel-password" },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/csrf-token")) return new Response(JSON.stringify({ success: true, obj: "csrf-panel" }), { headers: { "content-type": "application/json", "set-cookie": "session=bootstrap; Path=/" } });
      if (url.endsWith("/login")) {
        assert.equal(options.headers["content-type"], "application/x-www-form-urlencoded");
        assert.equal(options.headers["x-csrf-token"], "csrf-panel");
        assert.equal(options.headers.cookie, "session=bootstrap");
        assert.equal(options.body.toString(), "username=admin&password=panel-password&twoFactorCode=");
        return new Response(JSON.stringify({ success: true }), { headers: { "content-type": "application/json", "set-cookie": "session=xui-session; Path=/; HttpOnly" } });
      }
      return panelJson([]);
    },
  });
  try {
    const cookie = await app.login();
    const result = await app.request("/admin/vless", { headers: { cookie } });
    assert.equal(result.response.status, 200);
    assert.equal(calls[0].url, "https://panel.example/csrf-token");
    assert.equal(calls[1].url, "https://panel.example/login");
    assert.equal(calls[2].options.headers.cookie, "session=xui-session");
    assert.equal(calls[2].options.headers.authorization, undefined);
  } finally { await app.close(); }
});

test("vless: username/password vẫn được ưu tiên khi token cũ còn cấu hình", async () => {
  const calls = [];
  const app = await fixture({
    xui: { baseUrl: "https://panel.example", token: "stale-token", username: "admin", password: "panel-password" },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/csrf-token")) return new Response(JSON.stringify({ success: true, obj: "csrf-panel" }), { headers: { "set-cookie": "session=bootstrap; Path=/" } });
      if (url.endsWith("/login")) return new Response(JSON.stringify({ success: true }), { headers: { "set-cookie": "session=xui-session; Path=/" } });
      return panelJson([]);
    },
  });
  try {
    const cookie = await app.login();
    const result = await app.request("/admin/vless", { headers: { cookie } });
    assert.equal(result.response.status, 200);
    assert.equal(calls[0].url, "https://panel.example/csrf-token");
    assert.equal(calls[1].url, "https://panel.example/login");
    assert.equal(calls[2].options.headers.cookie, "session=xui-session");
    assert.equal(calls[2].options.headers.authorization, undefined);
  } finally { await app.close(); }
});

test("proton helper production có flow headless VPS và localStorage fallback", () => {
  const helper = fs.readFileSync(path.join(__dirname, "..", "scripts", "refresh-proton.py"), "utf8");
  assert.match(helper, /--headless=new/);
  assert.match(helper, /Service\("\/usr\/bin\/chromedriver"/);
  assert.match(helper, /Page\.addScriptToEvaluateOnNewDocument/);
  assert.match(helper, /os\.environ\["HOME"\] = profile_dir/);
  assert.match(helper, /startswith\("AUTH-"\)/);
  assert.match(helper, /key\.startswith\("ps-"\)/);
  assert.match(helper, /session\.get\("AccessToken"\)/);
  assert.match(helper, /range\(2\)/);
  const dockerfile = fs.readFileSync(path.join(__dirname, "..", "Dockerfile"), "utf8");
  assert.match(dockerfile, /chromium chromium-driver python3 python3-selenium/);
  const compose = fs.readFileSync(path.join(__dirname, "..", "compose.yaml"), "utf8");
  assert.match(compose, /\/tmp:size=768m,mode=1777/);
});

test("gpm: login, refresh sau 401 và không fallback login khi refresh gặp 500", async () => {
  const calls = [];
  let businessCalls = 0;
  const app = await fixture({
    gpm: { email: "gpm@example.test", password: "gpm-password" },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/auth/login")) return gpmResponse({ accessToken: "access-1", user: { email: "gpm@example.test" } }, { status: 201, cookie: "refreshToken_account=refresh-1" });
      if (url.endsWith("/auth/refresh")) return gpmResponse({ accessToken: "access-2", user: { email: "gpm@example.test" } });
      if (url.endsWith("/auth/me")) {
        businessCalls += 1;
        if (businessCalls === 1) return gpmResponse({ message: "expired" }, { status: 401 });
        return gpmResponse({ fullName: "GPM Admin", email: "gpm@example.test", role: { name: "OWNER" }, isActive: true, isEmailVerified: true });
      }
      throw new Error(`unexpected GPM URL ${url}`);
    },
  });
  try {
    const admin = await protonAdmin(app);
    const first = await app.request("/admin/gpm/account", { headers: { cookie: admin.cookie } });
    assert.equal(first.response.status, 200);
    assert.equal(first.body.account.email, "gpm@example.test");
    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), ["/api/v1/auth/login", "/api/v1/auth/me", "/api/v1/auth/refresh", "/api/v1/auth/me"]);
    assert.equal(calls[0].options.headers.origin, "https://account.gpmsoftwares.com");
    assert.deepEqual(JSON.parse(calls[0].options.body), { email: "gpm@example.test", password: "gpm-password" });
    assert.equal(calls[3].options.headers.authorization, "Bearer access-2");
    assert.equal(JSON.stringify(first.body).includes("refresh-1"), false);
    assert.equal(JSON.stringify(first.body).includes("access-2"), false);

    const refresh500 = await fixture({
      gpm: { email: "gpm@example.test", password: "gpm-password" },
      fetchImpl: async (url) => url.endsWith("/auth/login")
        ? gpmResponse({ accessToken: "access-1" }, { status: 201, cookie: "refreshToken_account=refresh-1" })
        : url.endsWith("/auth/refresh") ? gpmResponse({ error: "upstream" }, { status: 500 })
          : gpmResponse({ message: "expired" }, { status: 401 }),
    });
    try {
      const refreshAdmin = await protonAdmin(refresh500);
      const result = await refresh500.request("/admin/gpm/account", { headers: { cookie: refreshAdmin.cookie } });
      assert.equal(result.response.status, 502);
    } finally { await refresh500.close(); }
  } finally { await app.close(); }
});

test("gpm: projections, CSRF, mutation contracts và reveal không lộ key", async () => {
  const calls = [];
  const fullLicense = "GPM-LICENSE-SECRET-DO-NOT-LEAK";
  const fullSubLicense = "GPM-SUB-SECRET-DO-NOT-LEAK";
  const detail = {
    uuid: GPM_LICENSE_UUID,
    license: fullLicense,
    product: { name: "GPM Login" },
    productPackage: { name: "Lifetime" },
    type: "LIFETIME",
    status: "ACTIVE",
    limitDevices: 5,
    usedDevices: 1,
    expiresAt: "2030-01-01T00:00:00Z",
    devices: [{ uuid: "device-1", os: "Windows", machineName: "DESKTOP-1" }],
    subLicenses: [{ uuid: GPM_SUB_UUID, subLicense: fullSubLicense, os: "Windows", machineName: "SUB-1" }],
  };
  const app = await fixture({
    gpm: { email: "gpm@example.test", password: "gpm-password" },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/auth/login")) return gpmResponse({ accessToken: "access-1" }, { status: 201, cookie: "refreshToken_account=refresh-1" });
      if (url.endsWith("/auth/me")) return gpmResponse({ fullName: "GPM Admin", email: "gpm@example.test", role: { name: "OWNER" }, isActive: true, isEmailVerified: true, _count: { ownedLicenses: 1 } });
      if (url.endsWith(`/licenses/${GPM_LICENSE_UUID}/reset-devices`)) return gpmResponse({ ok: true });
      if (url.endsWith(`/licenses/${GPM_LICENSE_UUID}/sub-licenses`)) return gpmResponse({ subLicenses: [{ uuid: GPM_SUB_UUID, subLicense: fullSubLicense }] });
      if (url.endsWith(`/licenses/${GPM_LICENSE_UUID}/sub-licenses/all`)) return gpmResponse({ ok: true });
      if (url.endsWith(`/licenses/${GPM_LICENSE_UUID}`)) return gpmResponse(detail);
      if (url.endsWith("/licenses")) return gpmResponse({ data: [detail], meta: { total: 1 } });
      throw new Error(`unexpected GPM URL ${url}`);
    },
  });
  try {
    const admin = await protonAdmin(app);
    const listed = await app.request("/admin/gpm/licenses", { headers: { cookie: admin.cookie } });
    assert.equal(listed.response.status, 200);
    assert.equal(listed.body.licenses[0].licenseMasked, "GPM-...LEAK");
    assert.equal(JSON.stringify(listed.body).includes(fullLicense), false);
    assert.equal(JSON.stringify(listed.body).includes(fullSubLicense), false);
    const detailListed = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}`, { headers: { cookie: admin.cookie } });
    assert.equal(Object.prototype.hasOwnProperty.call(detailListed.body.license, "devices"), false);

    const noCsrf = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/reset-devices`, { method: "POST", headers: { cookie: admin.cookie, "content-type": "application/json" }, body: "{}" });
    assert.equal(noCsrf.response.status, 403);
    const reset = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/reset-devices`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ csrf: admin.csrf, note: "support request" }) });
    assert.equal(reset.response.status, 200);
    assert.deepEqual(JSON.parse(calls.find((call) => call.url.endsWith("/reset-devices")).options.body), { note: "support request" });

    const created = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/sub-licenses`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ csrf: admin.csrf, quantity: 2 }) });
    assert.equal(created.response.status, 201);
    assert.equal(JSON.stringify(created.body).includes(fullSubLicense), false);
    assert.deepEqual(JSON.parse(calls.find((call) => call.url.endsWith("/sub-licenses") && call.options.method === "POST").options.body), { quantity: 2 });

    const deleted = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/sub-licenses/all`, { method: "DELETE", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ csrf: admin.csrf }) });
    assert.equal(deleted.response.status, 200);
    assert.equal(calls.some((call) => call.url.endsWith(`/sub-licenses/all`) && call.options.method === "DELETE"), true);

    const parentReveal = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/reveal`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ csrf: admin.csrf }) });
    assert.equal(parentReveal.body.key, fullLicense);
    const subReveal = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/sub-licenses/${GPM_SUB_UUID}/reveal`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ csrf: admin.csrf }) });
    assert.equal(subReveal.body.key, fullSubLicense);
    const audits = app.db.prepare("SELECT detail FROM audit WHERE event LIKE 'admin_gpm_%'").all();
    assert.equal(JSON.stringify(audits).includes(fullLicense), false);
    assert.equal(JSON.stringify(audits).includes(fullSubLicense), false);
  } finally { await app.close(); }
});

test("gpm: migration schedule idempotent và không có cột lưu full key", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gpm-terms-"));
  const filename = path.join(directory, "accounts.sqlite");
  try {
    for (let restart = 0; restart < 2; restart += 1) {
      const db = openDatabase(filename);
      const columns = db.prepare("PRAGMA table_info(gpm_sub_license_terms)").all().map((column) => column.name);
      assert.deepEqual(columns, ["sub_license_uuid", "license_uuid", "starts_at", "expires_at", "term_days", "auto_exchange", "last_exchange_at", "last_error", "created_at", "updated_at", "display_name"]);
      assert.equal(db.prepare("SELECT COUNT(*) count FROM pragma_index_list('gpm_sub_license_terms') WHERE name IN ('idx_gpm_terms_expiry','idx_gpm_terms_auto_expiry')").get().count, 2);
      assert.throws(() => db.prepare("INSERT INTO gpm_sub_license_terms VALUES(?,?,?,?,?,?,?,?,?,?,?)").run(GPM_SUB_UUID, GPM_LICENSE_UUID, null, null, 0, 1, null, null, "now", "now", ""), /CHECK constraint/);
      db.close();
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("gpm: schedule, extend và status projection dùng term local an toàn", async () => {
  const secret = "GPM-SUB-SCHEDULE-SECRET";
  const detail = { uuid: GPM_LICENSE_UUID, license: "PARENT-SECRET", subLicenses: [{ uuid: GPM_SUB_UUID, subLicense: secret, lastDevicesResetAt: "" }] };
  const app = await fixture({
    gpm: { email: "gpm@example.test", password: "gpm-password", autoExchange: false },
    fetchImpl: async (url) => url.endsWith("/auth/login") ? gpmResponse({ accessToken: "access" }) : gpmResponse(detail),
  });
  try {
    const admin = await protonAdmin(app);
    const unscheduled = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}`, { headers: { cookie: admin.cookie } });
    assert.equal(unscheduled.body.license.subLicenses[0].schedule.status, "unscheduled");
    assert.equal(unscheduled.body.license.subLicenses[0].canExchange, true);

    const scheduled = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/sub-licenses/${GPM_SUB_UUID}/schedule`, { method: "PUT", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ name: "Laptop công ty", startsAt: "2026-07-30T00:00:00.000Z", termDays: 2, autoExchange: true }) });
    assert.equal(scheduled.response.status, 200);
    assert.equal(scheduled.body.license.subLicenses[0].schedule.status, "expiring");
    assert.equal(scheduled.body.license.subLicenses[0].schedule.termDays, 2);
    assert.equal(scheduled.body.license.subLicenses[0].schedule.name, "Laptop công ty");
    assert.equal(scheduled.body.license.subLicenses[0].name, "Laptop công ty");
    assert.equal(app.db.prepare("SELECT display_name FROM gpm_sub_license_terms WHERE sub_license_uuid=?").get(GPM_SUB_UUID).display_name, "Laptop công ty");

    const extended = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/sub-licenses/${GPM_SUB_UUID}/extend`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ days: 5 }) });
    assert.equal(extended.response.status, 200);
    assert.equal(extended.body.license.subLicenses[0].schedule.status, "scheduled");
    assert.equal(extended.body.license.subLicenses[0].schedule.termDays, 7);
    assert.equal(extended.body.license.subLicenses[0].schedule.expiresAt, "2026-08-06T00:00:00.000Z");
    assert.equal(JSON.stringify(app.db.prepare("SELECT * FROM gpm_sub_license_terms").all()).includes(secret), false);
    assert.equal(JSON.stringify(app.db.prepare("SELECT detail FROM audit WHERE event LIKE 'admin_gpm_%'").all()).includes(secret), false);
  } finally { await app.close(); }
});

test("gpm: từ chối schedule khi license gốc đã hết hạn hoặc bị tắt", async () => {
  const detailExpired = { uuid: GPM_LICENSE_UUID, license: "PARENT-SECRET", status: "expired", expiresAt: "2020-01-01T00:00:00.000Z", subLicenses: [{ uuid: GPM_SUB_UUID, subLicense: "SUB-SECRET", lastDevicesResetAt: "" }] };
  const app = await fixture({
    gpm: { email: "gpm@example.test", password: "gpm-password", autoExchange: false },
    fetchImpl: async (url) => url.endsWith("/auth/login") ? gpmResponse({ accessToken: "access" }) : gpmResponse(detailExpired),
  });
  try {
    const admin = await protonAdmin(app);
    const scheduled = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/sub-licenses/${GPM_SUB_UUID}/schedule`, { method: "PUT", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify({ name: "Sub", startsAt: "2026-07-30T00:00:00.000Z", termDays: 2, autoExchange: true }) });
    assert.equal(scheduled.response.status, 409);
    assert.match(scheduled.body.error, /License gốc đã hết hạn hoặc bị tắt/);
  } finally { await app.close(); }
});

test("gpm: manual exchange dùng exact path/body, refetch và chặn cooldown local", async () => {
  const calls = [];
  let resetAt = "";
  const detail = () => ({ uuid: GPM_LICENSE_UUID, license: "PARENT-SECRET", subLicenses: [{ uuid: GPM_SUB_UUID, subLicense: "SUB-SECRET", lastDevicesResetAt: resetAt }] });
  const app = await fixture({
    gpm: { email: "gpm@example.test", password: "gpm-password", autoExchange: false },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/auth/login")) return gpmResponse({ accessToken: "access" });
      if (url.endsWith(`/licenses/sub-licenses/${GPM_SUB_UUID}/exchange`)) return gpmResponse({ ignoredSecret: "UPSTREAM-SECRET" });
      return gpmResponse(detail());
    },
  });
  try {
    const admin = await protonAdmin(app);
    app.db.prepare("INSERT INTO gpm_sub_license_terms VALUES(?,?,?,?,?,?,?,?,?,?,?)").run(GPM_SUB_UUID, GPM_LICENSE_UUID, "2026-07-20T00:00:00.000Z", "2026-07-29T00:00:00.000Z", 9, 1, null, "old", "2026-07-20T00:00:00.000Z", "2026-07-20T00:00:00.000Z", "Tên cũ");
    const exchanged = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/sub-licenses/${GPM_SUB_UUID}/exchange`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: "{}" });
    assert.equal(exchanged.response.status, 200);
    const mutation = calls.find((call) => call.url.endsWith(`/licenses/sub-licenses/${GPM_SUB_UUID}/exchange`));
    assert.equal(new URL(mutation.url).pathname, `/api/v1/licenses/sub-licenses/${GPM_SUB_UUID}/exchange`);
    assert.equal(mutation.options.method, "POST");
    assert.deepEqual(JSON.parse(mutation.options.body), {});
    assert.equal(calls.filter((call) => call.url.endsWith(`/licenses/${GPM_LICENSE_UUID}`)).length, 2);
    assert.equal(exchanged.body.license.subLicenses[0].schedule.expiresAt, "2026-08-08T00:00:00.000Z");
    assert.equal(exchanged.body.license.subLicenses[0].schedule.lastError, null);
    assert.equal(JSON.stringify(exchanged.body).includes("UPSTREAM-SECRET"), false);

    resetAt = "2026-07-29T00:00:00.000Z";
    const before = calls.length;
    const cooldown = await app.request(`/admin/gpm/licenses/${GPM_LICENSE_UUID}/sub-licenses/${GPM_SUB_UUID}/exchange`, { method: "POST", headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: "{}" });
    assert.equal(cooldown.response.status, 409);
    assert.equal(cooldown.body.error.includes("2026-08-01T00:00:00.000Z"), true);
    assert.equal(calls.slice(before).some((call) => call.url.endsWith(`/licenses/sub-licenses/${GPM_SUB_UUID}/exchange`)), false);
  } finally { await app.close(); }
});

test("gpm: worker single-flight auto exchange và bắt đầu chu kỳ term mới", async () => {
  const calls = [];
  const detail = { uuid: GPM_LICENSE_UUID, license: "WORKER-PARENT-SECRET", subLicenses: [{ uuid: GPM_SUB_UUID, subLicense: "WORKER-SUB-SECRET", lastDevicesResetAt: "2026-07-20T00:00:00.000Z" }] };
  const app = await fixture({
    gpm: { email: "gpm@example.test", password: "gpm-password", autoExchange: true, autoExchangeIntervalMs: 10 },
    fetchImpl: async (url, options) => { calls.push({ url, options }); return url.endsWith("/auth/login") ? gpmResponse({ accessToken: "access" }) : url.endsWith("/exchange") ? gpmResponse({ secret: "IGNORED" }) : gpmResponse(detail); },
  });
  try {
    app.db.prepare("INSERT INTO gpm_sub_license_terms VALUES(?,?,?,?,?,?,?,?,?,?,?)").run(GPM_SUB_UUID, GPM_LICENSE_UUID, "2026-07-28T00:00:00.000Z", "2026-07-29T00:00:00.000Z", 3, 1, null, null, "2026-07-28T00:00:00.000Z", "2026-07-28T00:00:00.000Z", "Worker term");
    await new Promise((resolve) => setTimeout(resolve, 80));
    const row = app.db.prepare("SELECT * FROM gpm_sub_license_terms WHERE sub_license_uuid=?").get(GPM_SUB_UUID);
    assert.equal(row.starts_at, "2026-07-30T00:00:00.000Z");
    assert.equal(row.expires_at, "2026-08-02T00:00:00.000Z");
    assert.equal(row.last_error, null);
    assert.equal(calls.filter((call) => call.url.endsWith("/exchange")).length, 1);
    const admin = await protonAdmin(app);
    const worker = await app.request("/admin/gpm/worker", { headers: { cookie: admin.cookie } });
    assert.equal(worker.body.worker.enabled, true);
    assert.equal(worker.body.worker.running, false);
    assert.equal(worker.body.worker.exchanged, 1);
    assert.equal(worker.body.worker.failed, 0);
    const audits = app.db.prepare("SELECT detail FROM audit WHERE event LIKE 'gpm_auto_exchange%'").all();
    assert.equal(JSON.stringify(audits).includes("WORKER-SUB-SECRET"), false);
    assert.equal(JSON.stringify(worker.body).includes("WORKER-PARENT-SECRET"), false);
  } finally { await app.close(); }
});

test("matrix: kích hoạt key mới bind UID và trả lease/token không lộ key", async () => {
  const app = await fixture();
  try {
    const { key } = await app.createAccount();
    const result = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    assert.equal(result.response.status, 200);
    assert.equal(result.body.account.uid, uid("a"));
    assert.equal(result.body.leaseSeconds, 300);
    assert.equal(result.body.graceSeconds, 86400);
    assert.ok(result.body.token.length >= 40);
    assert.equal(JSON.stringify(result.body).includes(key), false);
    assert.equal(app.db.prepare("SELECT token_hash FROM sessions").get().token_hash, sha256(result.body.token));
  } finally { await app.close(); }
});

test("regression: qua ngày mới không block heartbeat khi key vẫn còn hạn", async () => {
  const app = await fixture();
  try {
    const { key, accountId } = await app.createAccount();
    app.db.prepare("UPDATE accounts SET expires_at=? WHERE id=?").run("2026-08-05T01:00:00.000Z", accountId);
    const activation = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    assert.equal(activation.response.status, 200);

    // Fixture starts at 07:00 GMT+7. Advancing 18 hours crosses midnight in
    // Vietnam while remaining several days before the exact expiry timestamp.
    app.advance(18 * 3600000);
    const heartbeat = await app.request("/api/v1/heartbeat", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${activation.body.token}` }, body: JSON.stringify({ sequence: 1 }) });
    assert.equal(heartbeat.response.status, 200);
    assert.equal(heartbeat.body.blocked, false);
    assert.equal(heartbeat.body.account.status, "active");
    assert.equal(heartbeat.body.account.expiresAt, "2026-08-05T01:00:00.000Z");
    assert.equal(app.db.prepare("SELECT revoked_at FROM sessions WHERE token_hash=?").get(sha256(activation.body.token)).revoked_at, null);
  } finally { await app.close(); }
});

test("matrix: key đã bind từ chối UID khác, giữ binding và audit không chứa key", async () => {
  const app = await fixture();
  try {
    const { key } = await app.createAccount();
    await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    const denied = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("b") }) });
    assert.equal(denied.response.status, 403);
    assert.equal(app.db.prepare("SELECT uid FROM devices").get().uid, uid("a"));
    const audit = app.db.prepare("SELECT * FROM audit WHERE event='activation_wrong_device'").get();
    assert.ok(audit);
    assert.equal(JSON.stringify(audit).includes(key), false);
  } finally { await app.close(); }
});

test("matrix: command được retry đến khi agent ACK rồi mới revoke session", async () => {
  const app = await fixture();
  try {
    const { key, cookie, accountId } = await app.createAccount();
    const activation = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    const page = await app.request("/admin", { headers: { cookie } });
    const csrf = page.body.match(/name="csrf" value="([^"]+)"/)?.[1];
    await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, action: "force_logout" }), redirect: "manual" });
    assert.equal(app.db.prepare("SELECT delivered_at FROM commands").get().delivered_at, null);
    const heartbeat = await app.request("/api/v1/heartbeat", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${activation.body.token}` }, body: JSON.stringify({ sequence: 1 }) });
    assert.equal(heartbeat.body.command.type, "force_logout");
    assert.equal(heartbeat.body.blocked, true);
    assert.ok(app.db.prepare("SELECT delivered_at FROM commands").get().delivered_at);
    assert.equal(app.db.prepare("SELECT revoked_at FROM sessions").get().revoked_at, null);
    const retry = await app.request("/api/v1/heartbeat", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${activation.body.token}` }, body: JSON.stringify({ sequence: 2 }) });
    assert.equal(retry.body.command.id, heartbeat.body.command.id);
    const ack = await app.request("/api/v1/commands/ack", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${activation.body.token}` }, body: JSON.stringify({ commandId: heartbeat.body.command.id, generation: heartbeat.body.command.generation }) });
    assert.equal(ack.response.status, 200);
    assert.ok(app.db.prepare("SELECT acked_at FROM commands").get().acked_at);
    assert.ok(app.db.prepare("SELECT revoked_at FROM sessions").get().revoked_at);
    const afterAck = await app.request("/api/v1/heartbeat", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${activation.body.token}` }, body: JSON.stringify({ sequence: 3 }) });
    assert.equal(afterAck.response.status, 401);
  } finally { await app.close(); }
});

test("matrix: unlock supersedes pending lock so stale command cannot reach a new session", async () => {
  const app = await fixture();
  try {
    const { key, cookie, accountId } = await app.createAccount();
    const activation = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    let token = await csrfFor(app, cookie);
    await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, action: "lock" }), redirect: "manual" });
    token = await csrfFor(app, cookie);
    await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, action: "unlock" }), redirect: "manual" });
    assert.ok(app.db.prepare("SELECT acked_at FROM commands").get().acked_at);
    const stale = await app.request("/api/v1/heartbeat", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${activation.body.token}` }, body: JSON.stringify({ sequence: 1 }) });
    assert.equal(stale.response.status, 401);
    const reactivation = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    const heartbeat = await app.request("/api/v1/heartbeat", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${reactivation.body.token}` }, body: JSON.stringify({ sequence: 1 }) });
    assert.equal(heartbeat.body.command, null);
    assert.equal(heartbeat.body.blocked, false);
  } finally { await app.close(); }
});

test("matrix: heartbeat cập nhật gia hạn/mở khóa nhưng không tạo session mới", async () => {
  const app = await fixture();
  try {
    const { key, cookie, accountId } = await app.createAccount();
    const activation = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    const originalExpiry = activation.body.account.expiresAt;
    let page = await app.request("/admin", { headers: { cookie } });
    let csrf = page.body.match(/name="csrf" value="([^"]+)"/)?.[1];
    await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, action: "extend" }), redirect: "manual" });
    page = await app.request("/admin", { headers: { cookie } }); csrf = page.body.match(/name="csrf" value="([^"]+)"/)?.[1];
    await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, action: "unlock" }), redirect: "manual" });
    const heartbeat = await app.request("/api/v1/heartbeat", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${activation.body.token}` }, body: JSON.stringify({ sequence: 1 }) });
    assert.equal(heartbeat.response.status, 200);
    assert.ok(heartbeat.body.account.expiresAt > originalExpiry);
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM sessions").get().count, 1);
  } finally { await app.close(); }
});

test("security: production rejects non-HTTPS requests and admin requires CSRF", async () => {
  const db = openDatabase();
  const server = http.createServer(createApp({ db, adminPasswordHash: hashPassword("very-long-admin-password"), production: true }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/v1/activate`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(response.status, 426);
  } finally { await new Promise((resolve) => server.close(resolve)); db.close(); }
});

test("security: forwarded HTTPS is accepted only when trusted proxy is explicit", async () => {
  for (const trustProxy of [false, true]) {
    const db = openDatabase();
    const server = http.createServer(createApp({ db, adminPasswordHash: hashPassword("very-long-admin-password"), production: true, trustProxy }));
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/admin/login`, { headers: { "x-forwarded-proto": "https" }, redirect: "manual" });
      assert.equal(response.status, trustProxy ? 200 : 426);
    } finally { await new Promise((resolve) => server.close(resolve)); db.close(); }
  }
});

test("security: docker userland gateway is trusted only when dockerGateway is configured", async () => {
  // Logic thuần: gateway phải khớp (có hỗ trợ IPv4-mapped), và phải được cấu hình.
  assert.equal(isGateway("::ffff:172.17.0.1", "172.17.0.1"), true);
  assert.equal(isGateway("172.17.0.1", "172.17.0.1"), true);
  assert.equal(isGateway("10.0.0.5", "172.17.0.1"), false);
  assert.equal(isGateway("::ffff:172.17.0.1", null), false);

  // HTTP qua loopback không bị ảnh hưởng bởi flag gateway.
  for (const dockerGateway of [null, "172.17.0.1"]) {
    const db = openDatabase();
    const server = http.createServer(createApp({ db, adminPasswordHash: hashPassword("very-long-admin-password"), production: true, trustProxy: true, dockerGateway }));
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/admin/login`, { headers: { "x-forwarded-proto": "https" }, redirect: "manual" });
      assert.equal(response.status, 200);
    } finally { await new Promise((resolve) => server.close(resolve)); db.close(); }
  }
});

test("security: admin cookie flags, CSRF and login rate limit are enforced", async () => {
  const app = await fixture();
  try {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const denied = await app.request("/admin/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: "wrong-password-value" }), redirect: "manual" });
      assert.equal(denied.response.status, 401);
    }
    const limited = await app.request("/admin/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: "very-long-admin-password" }), redirect: "manual" });
    assert.equal(limited.response.status, 429);
  } finally { await app.close(); }

  const fresh = await fixture();
  try {
    const login = await fresh.request("/admin/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: "very-long-admin-password" }), redirect: "manual" });
    const setCookie = login.response.headers.getSetCookie()[0];
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    const cookie = await fresh.createAccount().then((created) => created.cookie);
    assert.match(cookie, /^zpm_admin=/);
    const denied = await fresh.request("/admin/accounts", { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ plan: "Pro", days: "30" }) });
    assert.equal(denied.response.status, 403);
  } finally { await fresh.close(); }
});

test("admin can edit account fields and archive without deleting audit history", async () => {
  const app = await fixture();
  try {
    const { cookie, accountId } = await app.createAccount();
    let token = await csrfFor(app, cookie);
    await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, action: "edit", plan: "Enterprise", note: "updated", expiresAt: "2027-12-31" }), redirect: "manual" });
    let account = app.db.prepare("SELECT * FROM accounts WHERE id=?").get(accountId);
    assert.equal(account.plan, "Enterprise");
    assert.equal(account.note, "updated");
    assert.equal(account.expires_at, "2027-12-31T01:00:00.000Z");
    token = await csrfFor(app, cookie);
    await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, action: "archive" }), redirect: "manual" });
    account = app.db.prepare("SELECT * FROM accounts WHERE id=?").get(accountId);
    assert.ok(account.archived_at);
    assert.ok(app.db.prepare("SELECT * FROM audit WHERE account_id=? AND event='admin_archive'").get(accountId));
  } finally { await app.close(); }
});

test("admin preserves archived accounts, key hashes and binding tombstones permanently", async () => {
  const app = await fixture();
  try {
    const { cookie, accountId, key } = await app.createAccount();
    await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    const hash = app.db.prepare("SELECT key_hash FROM account_keys WHERE account_id=?").get(accountId).key_hash;
    let token = await csrfFor(app, cookie);
    await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, action: "archive" }), redirect: "manual" });
    const archivedPage = await app.request("/admin", { headers: { cookie } });
    // UI mới hiển thị account đã archive trong view "Lưu trữ" với hành động
    // duy nhất là "Khôi phục" (restore) — không có đường xoá cứng nào.
    assert.match(archivedPage.body, new RegExp(`action="/admin/accounts/${accountId}/action"><input type="hidden" name="csrf" value="[^"]+"><input type="hidden" name="action" value="restore"`));
    assert.match(archivedPage.body, /Khôi phục</);
    assert.equal(archivedPage.body.includes("Xóa vĩnh viễn"), false);
    assert.equal(archivedPage.body.includes("/delete"), false);

    token = await csrfFor(app, cookie);
    const deleted = await app.request(`/admin/accounts/${accountId}/delete`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token }), redirect: "manual" });
    assert.equal(deleted.response.status, 404);
    assert.ok(app.db.prepare("SELECT id FROM accounts WHERE id=? AND archived_at IS NOT NULL").get(accountId));
    assert.equal(app.db.prepare("SELECT key_hash FROM account_keys WHERE account_id=?").get(accountId).key_hash, hash);
    assert.ok(app.db.prepare("SELECT uid FROM devices WHERE account_id=? AND released_at IS NOT NULL").get(accountId));
  } finally { await app.close(); }
});

test("admin reset releases the binding as history without deleting account or key", async () => {
  const app = await fixture();
  try {
    const account = await app.createAccount();
    const activation = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: account.key, uid: uid("a") }) });
    const deviceId = app.db.prepare("SELECT id FROM devices WHERE account_id=? AND released_at IS NULL").get(account.accountId).id;
    const token = await csrfFor(app, account.cookie);
    const reset = await app.request(`/admin/accounts/${account.accountId}/action`, { method: "POST", headers: { cookie: account.cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, action: "reset_binding" }), redirect: "manual" });
    assert.equal(reset.response.status, 303);
    assert.ok(app.db.prepare("SELECT released_at FROM devices WHERE id=?").get(deviceId).released_at);
    assert.ok(app.db.prepare("SELECT revoked_at FROM sessions WHERE token_hash=?").get(sha256(activation.body.token)).revoked_at);
    assert.ok(app.db.prepare("SELECT id FROM accounts WHERE id=? AND archived_at IS NULL").get(account.accountId));
    assert.ok(app.db.prepare("SELECT key_hash FROM account_keys WHERE account_id=?").get(account.accountId));

    const rebound = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: account.key, uid: uid("b") }) });
    assert.equal(rebound.response.status, 200);
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM devices WHERE account_id=?").get(account.accountId).count, 2);
    assert.equal(app.db.prepare("SELECT uid FROM devices WHERE account_id=? AND released_at IS NULL").get(account.accountId).uid, uid("b"));
  } finally { await app.close(); }
});

test("database rejects deleting issued keys/accounts and replacing immutable key identity", async () => {
  const app = await fixture();
  try {
    const account = await app.createAccount();
    const original = app.db.prepare("SELECT key_hash FROM account_keys WHERE account_id=?").get(account.accountId).key_hash;
    assert.throws(() => app.db.prepare("UPDATE account_keys SET key_hash=? WHERE account_id=?").run(sha256("replacement"), account.accountId), /issued keys cannot be replaced/);
    assert.throws(() => app.db.prepare("DELETE FROM account_keys WHERE account_id=?").run(account.accountId), /issued keys cannot be deleted/);
    assert.throws(() => app.db.prepare("DELETE FROM accounts WHERE id=?").run(account.accountId), /issued accounts cannot be deleted/);
    assert.equal(app.db.prepare("SELECT key_hash FROM account_keys WHERE account_id=?").get(account.accountId).key_hash, original);
  } finally { await app.close(); }
});

test("admin exposes a copy-key action only on the one-time creation response", async () => {
  const app = await fixture();
  try {
    const created = await app.createAccount();
    const page = await app.request("/admin", { headers: { cookie: created.cookie } });
    assert.equal(page.body.includes("data-copy-key"), false);
    const script = await app.request("/admin.js");
    assert.equal(script.response.status, 200);
    assert.match(script.body, /navigator\.clipboard\.writeText/);
  } finally { await app.close(); }
});

test("admin renders escaped account data containing template placeholders exactly once", async () => {
  const app = await fixture();
  try {
    const cookie = await app.createAccount().then((created) => created.cookie);
    const token = await csrfFor(app, cookie);
    const plan = `Plan {{AUDIT_ROWS}} "'<>&`;
    const note = `Note {{MESSAGE_ACTION}} "'<>&`;
    const result = await app.request("/admin/accounts", { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, plan, days: "30", note }) });
    assert.equal(result.response.status, 200);
    assert.ok(result.body.includes("Plan {{AUDIT_ROWS}} &quot;&#039;&lt;&gt;&amp;"));
    assert.ok(result.body.includes("Note {{MESSAGE_ACTION}} &quot;&#039;&lt;&gt;&amp;"));
    assert.equal(result.body.includes(`value="${plan}"`), false);
    assert.equal(result.body.includes(`value="${note}"`), false);
  } finally { await app.close(); }
});

test("admin product menu navigates between 292ZM and 292VPN", async () => {
  const app = await fixture();
  try {
    const cookie = await app.createAccount().then((created) => created.cookie);
    const zpool = await app.request("/admin", { headers: { cookie } });
    assert.match(zpool.body, /class="nav-item active" href="\/admin" aria-current="page">[\s\S]*?<span>292ZM<\/span>/);
    assert.match(zpool.body, /<strong id="currentViewLabel">292ZM account quản lý<\/strong>/);

    const vpn = await app.request("/admin?product=292vpn", { headers: { cookie } });
    assert.match(vpn.body, /class="nav-item active" href="\/admin\?product=292vpn" aria-current="page">[\s\S]*?<span>292VPN<\/span>/);
    assert.match(vpn.body, /<strong id="currentViewLabel">292VPN account quản lý<\/strong>/);
  } finally { await app.close(); }
});

test("admin product menu shows independent account counts", async () => {
  const app = await fixture();
  try {
    const zpoolAccount = await app.createAccount();
    const token = await csrfFor(app, zpoolAccount.cookie);
    for (const name of ["VPN One", "VPN Two"]) {
      const created = await app.request("/admin/accounts", {
        method: "POST",
        headers: { cookie: zpoolAccount.cookie, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ csrf: token, product: "292vpn", name, plan: "VPN 30", days: "30" }),
      });
      assert.equal(created.response.status, 200);
    }

    for (const path of ["/admin", "/admin?product=292vpn"]) {
      const page = await app.request(path, { headers: { cookie: zpoolAccount.cookie } });
      assert.match(page.body, /href="\/admin"[^>]*>[\s\S]*?<span>292ZM<\/span><b>1<\/b>/);
      assert.match(page.body, /href="\/admin\?product=292vpn"[^>]*>[\s\S]*?<span>292VPN<\/span><b>2<\/b>/);
    }
  } finally { await app.close(); }
});

test("admin assets disable caching to keep HTML, CSS and JavaScript in sync", async () => {
  const app = await fixture();
  try {
    for (const path of ["/admin.css", "/admin.js"]) {
      const asset = await app.request(path);
      assert.equal(asset.response.status, 200);
      assert.equal(asset.response.headers.get("cache-control"), "no-store");
    }
  } finally { await app.close(); }
});

test("admin client script keeps confirmation, sidebar ARIA and toast state defensive", async () => {
  const app = await fixture();
  try {
    const script = await app.request("/admin.js");
    assert.equal(script.response.status, 200);
    assert.match(script.body, /function closeSidebar\(\)[\s\S]*aria-expanded", "false"/);
    assert.match(script.body, /setView\(view\)[\s\S]*closeSidebar\(\)/);
    assert.match(script.body, /sidebar-backdrop"\)\) return closeSidebar\(\)/);
    assert.match(script.body, /pendingForm = null;\s*confirmDialog\.returnValue = "";\s*pendingForm = form;/);
    assert.match(script.body, /const confirmedForm = confirmDialog\.returnValue === "confirm" \? pendingForm : null;\s*pendingForm = null;\s*confirmDialog\.returnValue = "";/);
    assert.match(script.body, /toast\?\.dataset\.message\?\.trim\(\)/);
    assert.match(script.body, /protonSessionSort\.direction === 1\) protonSessionSort\.direction = -1/);
    const page = await app.request("/admin", { headers: { cookie: await app.login() } });
    assert.match(page.body, /data-proton-sort="customer"/);
    assert.match(page.body, /data-proton-sort="expiresAt"/);
    assert.match(page.body, /data-proton-sort="timeLeft"/);
  } finally { await app.close(); }
});

test("admin dialogs close only when clicking outside their visible bounds", async () => {
  const app = await fixture();
  try {
    const script = await app.request("/admin.js");
    assert.equal(script.response.status, 200);
    assert.match(script.body, /function closeDialog\(dialog\)/);
    assert.match(script.body, /backdropDialog && target === backdropDialog/);
    assert.match(script.body, /event\.clientX < bounds\.left[\s\S]*event\.clientY > bounds\.bottom/);
    assert.match(script.body, /if \(outside\) closeDialog\(backdropDialog\)/);
    assert.match(script.body, /closeDialog\(target\.closest\("dialog"\)\)/);
  } finally { await app.close(); }
});

test("security: heartbeat sequence update is atomic against replay", async () => {
  const app = await fixture();
  try {
    const { key } = await app.createAccount();
    const activation = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    const options = { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${activation.body.token}` }, body: JSON.stringify({ sequence: 1 }) };
    const [first, second] = await Promise.all([app.request("/api/v1/heartbeat", options), app.request("/api/v1/heartbeat", options)]);
    assert.deepEqual([first.response.status, second.response.status].sort(), [200, 409]);
    const conflict = first.response.status === 409 ? first : second;
    assert.equal(conflict.body.lastSequence, 1);
    assert.equal(app.db.prepare("SELECT last_sequence FROM sessions").get().last_sequence, 1);
  } finally { await app.close(); }
});

test("security: malformed JSON returns 400 without terminating the server", async () => {
  const app = await fixture();
  try {
    const malformed = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
    assert.equal(malformed.response.status, 400);
    const health = await app.request("/health");
    assert.equal(health.response.status, 200);
    assert.equal(health.body.ok, true);
  } finally { await app.close(); }
});

test("security: full key never reaches the admin DOM and reveal requires auth + CSRF", async () => {
  const app = await fixture();
  try {
    const { cookie, key, accountId } = await app.createAccount();
    const page = await app.request("/admin", { headers: { cookie } });
    // Key thật không được nhúng vào HTML dưới bất kỳ dạng nào, và secret XOR cũ phải biến mất.
    assert.equal(page.body.includes(key), false);
    assert.equal(page.body.includes("data-enc-key"), false);
    assert.equal(page.body.includes("zpool-key-protection"), false);

    // Không có cookie -> 401.
    const anonymous = await app.request(`/admin/accounts/${accountId}/reveal-key`, { method: "POST" });
    assert.equal(anonymous.response.status, 401);

    // Có cookie nhưng thiếu CSRF -> 403.
    const noCsrf = await app.request(`/admin/accounts/${accountId}/reveal-key`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: "{}" });
    assert.equal(noCsrf.response.status, 403);

    // Đủ cookie + CSRF -> trả key thật và ghi audit.
    const token = await csrfFor(app, cookie);
    const revealed = await app.request(`/admin/accounts/${accountId}/reveal-key`, { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": token }, body: "{}" });
    assert.equal(revealed.response.status, 200);
    assert.equal(revealed.body.key, key);
    assert.ok(app.db.prepare("SELECT id FROM audit WHERE event='admin_reveal_key' AND account_id=?").get(accountId));
  } finally { await app.close(); }
});

test("security: stored full key is AES-GCM and unreadable without the configured secret", async () => {
  const app = await fixture();
  try {
    const { key } = await app.createAccount();
    const stored = app.db.prepare("SELECT full_key FROM account_keys").get().full_key;
    assert.match(stored, /^gcm:/);
    assert.equal(stored.includes(key), false);
    // Secret sai thì không giải mã được (GCM auth tag phải fail, không trả rác).
    assert.equal(decryptText(stored, "a-completely-different-secret"), "");
    assert.equal(decryptText(stored, KEY_SECRET), key);
  } finally { await app.close(); }
});

test("regression: CSRF token stays stable across renders so a second tab keeps working", async () => {
  const app = await fixture();
  try {
    const { cookie, accountId } = await app.createAccount();
    const firstTab = await csrfFor(app, cookie);
    // Mở "tab thứ hai" — trước đây lệnh này rotate csrf_hash và giết token của tab 1.
    const secondTab = await csrfFor(app, cookie);
    assert.equal(firstTab, secondTab);
    const submitted = await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: firstTab, action: "extend" }), redirect: "manual" });
    assert.equal(submitted.response.status, 303);
    // Token của session khác vẫn phải bị từ chối.
    const otherCookie = await app.login();
    const foreign = await app.request(`/admin/accounts/${accountId}/action`, { method: "POST", headers: { cookie: otherCookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: firstTab, action: "extend" }), redirect: "manual" });
    assert.equal(foreign.response.status, 403);
  } finally { await app.close(); }
});

test("regression: extend uses GMT+7 08:00 identically for single and bulk actions", async () => {
  const app = await fixture();
  try {
    const single = await app.createAccount();
    let token = await csrfFor(app, single.cookie);
    await app.request(`/admin/accounts/${single.accountId}/action`, { method: "POST", headers: { cookie: single.cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: token, action: "extend" }), redirect: "manual" });
    const singleExpiry = app.db.prepare("SELECT expires_at FROM accounts WHERE id=?").get(single.accountId).expires_at;

    const bulk = await app.createAccount();
    token = await csrfFor(app, bulk.cookie);
    const applied = await app.request("/admin/accounts/bulk-action", { method: "POST", headers: { cookie: bulk.cookie, "content-type": "application/json", "x-csrf-token": token }, body: JSON.stringify({ csrf: token, action: "extend", ids: [bulk.accountId] }) });
    assert.equal(applied.response.status, 200);
    const bulkExpiry = app.db.prepare("SELECT expires_at FROM accounts WHERE id=?").get(bulk.accountId).expires_at;

    // Cả hai đường dẫn phải cho cùng một mốc, và mốc đó là 08:00 GMT+7 = 01:00Z.
    assert.equal(singleExpiry, bulkExpiry);
    assert.match(singleExpiry, /T01:00:00\.000Z$/);
  } finally { await app.close(); }
});

test("regression: issued key hash cannot be replaced through admin edit", async () => {
  const app = await fixture();
  try {
    const account = await app.createAccount();
    const original = app.db.prepare("SELECT key_hash FROM account_keys WHERE account_id=?").get(account.accountId).key_hash;
    const token = await csrfFor(app, account.cookie);
    const edited = await app.request(`/admin/accounts/${account.accountId}/action`, {
      method: "POST",
      headers: { cookie: account.cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: token, action: "edit", plan: "Pro", expiresAt: "2027-12-31", newKey: "292sv-ZP-REPLACEMENT-KEY-VALUE-1" }),
      redirect: "manual",
    });
    assert.equal(edited.response.status, 409);
    assert.equal(app.db.prepare("SELECT key_hash FROM account_keys WHERE account_id=?").get(account.accountId).key_hash, original);
  } finally { await app.close(); }
});

test("binding: switching keys archives source atomically and old key never works again", async () => {
  const app = await fixture();
  try {
    const first = await app.createAccount();
    const second = await app.createAccount();
    const original = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: first.key, uid: uid("a") }) });
    const switched = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: second.key, uid: uid("a") }) });
    assert.equal(switched.response.status, 200);
    assert.ok(app.db.prepare("SELECT archived_at FROM accounts WHERE id=?").get(first.accountId).archived_at);
    assert.ok(app.db.prepare("SELECT revoked_at FROM sessions WHERE token_hash=?").get(sha256(original.body.token)).revoked_at);
    assert.ok(app.db.prepare("SELECT released_at FROM devices WHERE account_id=?").get(first.accountId).released_at);
    assert.equal(app.db.prepare("SELECT account_id FROM devices WHERE uid=? AND released_at IS NULL").get(uid("a")).account_id, second.accountId);
    for (const candidateUid of [uid("a"), uid("b")]) {
      const denied = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: first.key, uid: candidateUid }) });
      assert.equal(denied.response.status, 403);
    }
    assert.equal(JSON.stringify(app.db.prepare("SELECT * FROM audit WHERE account_id=? ORDER BY id DESC LIMIT 1").get(first.accountId)).includes(first.key), false);
  } finally { await app.close(); }
});

test("binding: target key on another UID is rejected without archiving the source", async () => {
  const app = await fixture();
  try {
    const source = await app.createAccount();
    const target = await app.createAccount();
    await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: source.key, uid: uid("a") }) });
    await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: target.key, uid: uid("b") }) });
    const denied = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: target.key, uid: uid("a") }) });
    assert.equal(denied.response.status, 403);
    assert.equal(app.db.prepare("SELECT archived_at FROM accounts WHERE id=?").get(source.accountId).archived_at, null);
    assert.equal(app.db.prepare("SELECT account_id FROM devices WHERE uid=? AND released_at IS NULL").get(uid("a")).account_id, source.accountId);
  } finally { await app.close(); }
});

test("binding: failed target insert rolls back source archive, release and session revoke", async () => {
  const app = await fixture();
  try {
    const source = await app.createAccount();
    const target = await app.createAccount();
    const activation = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: source.key, uid: uid("a") }) });
    app.db.exec(`CREATE TRIGGER fail_target_binding BEFORE INSERT ON devices WHEN NEW.account_id=${target.accountId} BEGIN SELECT RAISE(ABORT, 'injected binding failure'); END`);
    const failed = await app.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: target.key, uid: uid("a") }) });
    assert.equal(failed.response.status, 500);
    assert.equal(app.db.prepare("SELECT archived_at FROM accounts WHERE id=?").get(source.accountId).archived_at, null);
    assert.equal(app.db.prepare("SELECT released_at FROM devices WHERE account_id=?").get(source.accountId).released_at, null);
    assert.equal(app.db.prepare("SELECT revoked_at FROM sessions WHERE token_hash=?").get(sha256(activation.body.token)).revoked_at, null);
    assert.equal(app.db.prepare("SELECT account_id FROM devices WHERE uid=? AND released_at IS NULL").get(uid("a")).account_id, source.accountId);
  } finally { await app.close(); }
});

test("binding: concurrent activations leave one current binding and archive the replaced key", async () => {
  const app = await fixture();
  try {
    const first = await app.createAccount();
    const second = await app.createAccount();
    const options = (key) => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("c") }) });
    const results = await Promise.all([app.request("/api/v1/activate", options(first.key)), app.request("/api/v1/activate", options(second.key))]);
    assert.deepEqual(results.map((item) => item.response.status), [200, 200]);
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM devices WHERE uid=? AND released_at IS NULL").get(uid("c")).count, 1);
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM devices WHERE uid=?").get(uid("c")).count, 2);
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM accounts WHERE id IN (?,?) AND archived_at IS NOT NULL").get(first.accountId, second.accountId).count, 1);
    assert.deepEqual(app.db.prepare("PRAGMA foreign_key_check").all(), []);
  } finally { await app.close(); }
});

test("binding: archived key remains a tombstone after database restart", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zpm-tombstone-"));
  const filename = path.join(directory, "accounts.sqlite");
  let first;
  let restarted;
  try {
    first = await fixture({ filename });
    const oldAccount = await first.createAccount();
    const currentAccount = await first.createAccount();
    await first.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: oldAccount.key, uid: uid("a") }) });
    const switched = await first.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: currentAccount.key, uid: uid("a") }) });
    assert.equal(switched.response.status, 200);
    await first.close();
    first = null;

    restarted = await fixture({ filename });
    for (const candidateUid of [uid("a"), uid("b")]) {
      const denied = await restarted.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: oldAccount.key, uid: candidateUid }) });
      assert.equal(denied.response.status, 403);
    }
    const current = await restarted.request("/api/v1/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: currentAccount.key, uid: uid("a") }) });
    assert.equal(current.response.status, 200);
    assert.ok(restarted.db.prepare("SELECT archived_at FROM accounts WHERE id=?").get(oldAccount.accountId).archived_at);
    assert.equal(restarted.db.prepare("SELECT COUNT(*) count FROM devices WHERE uid=? AND released_at IS NULL").get(uid("a")).count, 1);
  } finally {
    if (first) await first.close();
    if (restarted) await restarted.close();
    removeTempDirectory(directory);
  }
});

test("migration: legacy device IDs and session FKs survive migration and restart", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zpm-binding-"));
  const filename = path.join(directory, "accounts.sqlite");
  try {
    const legacy = new DatabaseSync(filename);
    legacy.exec(`
      PRAGMA foreign_keys=ON;
      CREATE TABLE accounts(id INTEGER PRIMARY KEY, plan TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active', activated_at TEXT, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE account_keys(id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE, key_hash TEXT NOT NULL UNIQUE, key_hint TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE devices(id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE, uid TEXT NOT NULL UNIQUE, last_seen_at TEXT, created_at TEXT NOT NULL);
      CREATE TABLE sessions(id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, last_sequence INTEGER NOT NULL DEFAULT 0, revoked_at TEXT, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL);
      CREATE TABLE commands(id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, type TEXT NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT);
      CREATE TABLE admin_sessions(id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, csrf_hash TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE audit(id INTEGER PRIMARY KEY, event TEXT NOT NULL, account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL, uid_hint TEXT, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
      INSERT INTO accounts VALUES(7,'Pro','','active','2026-01-01','2027-01-01','2026-01-01','2026-01-01');
      INSERT INTO devices VALUES(11,7,'${uid("d")}','2026-01-01','2026-01-01');
      INSERT INTO sessions VALUES(13,7,11,'hash',0,NULL,'2026-01-01','2026-01-01');
    `);
    legacy.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    legacy.close();
    for (let restart = 0; restart < 2; restart += 1) {
      const db = openDatabase(filename);
      assert.equal(db.prepare("SELECT id, released_at FROM devices").get().id, 11);
      assert.equal(db.prepare("SELECT device_id FROM sessions WHERE id=13").get().device_id, 11);
      assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
      assert.equal(db.prepare("SELECT COUNT(*) count FROM pragma_index_list('devices') WHERE partial=1 AND [unique]=1").get().count, 1);
      assert.equal(db.prepare("SELECT COUNT(*) count FROM sqlite_master WHERE type='trigger' AND name IN ('prevent_account_delete','prevent_account_key_delete','prevent_account_key_replacement')").get().count, 3);
      db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
      db.close();
    }
  } finally {
    await new Promise((resolve) => setImmediate(resolve));
    removeTempDirectory(directory);
  }
});

test("292vpn: catalog có SG/HK WireGuard và cấp peer riêng theo node", async () => {
  const makeConfig = (address) => `[Interface]\nPrivateKey = test-private-key-${address}\nAddress = ${address}/32\n\n[Peer]\nPublicKey = test-public-key\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.test:443\n`;
  const calls = [];
  const provisioner = (name, address) => ({
    configured: true,
    catalogConfigured: true,
    async provision(allocationId) { calls.push([name, allocationId]); return makeConfig(address); },
  });
  const app = await fixture({
    wireGuardProvisionerSg: provisioner("sg", "10.203.71.2"),
    wireGuardProvisionerHk: provisioner("hk", "10.203.72.2"),
  });
  try {
    const cookie = await app.login();
    const csrf = await csrfFor(app, cookie);
    const created = await app.request("/admin/accounts", { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, product: "292vpn", name: "SG HK WireGuard", plan: "VPN 30", days: "30" }) });
    const key = created.body.match(/Key mới \(chỉ hiển thị lần này\): ([A-Za-z0-9_-]+)/)?.[1];
    const activated = await app.request("/api/vpn/activate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, uid: uid("a") }) });
    assert.equal(activated.response.status, 200, JSON.stringify({ key, body: activated.body }));
    const headers = { authorization: `Bearer ${activated.body.token}` };
    const nodes = await app.request("/api/vpn/nodes", { headers });
    assert.equal(nodes.response.status, 200, JSON.stringify(nodes.body));
    assert.deepEqual(nodes.body.nodes.map((node) => node.id), ["vn-hanoi-1", "sg-wg-1", "hk-wg-1"]);
    for (const [nodeId, name, address] of [["sg-wg-1", "SG - Singapore (WG)", "10.203.71.2"], ["hk-wg-1", "HK - Hong Kong (WG)", "10.203.72.2"]]) {
      const result = await app.request("/api/vpn/configs/issue", { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify({ node_id: nodeId }) });
      assert.equal(result.response.status, 200);
      assert.equal(result.body.name, name);
      assert.equal(result.body.protocol, "wireguard");
      assert.match(result.body.config_text, new RegExp(`Address = ${address}/32`));
    }
    assert.deepEqual(calls.map(([name]) => name), ["sg", "hk"]);
  } finally { await app.close(); }
});

test("proton: session list coalesces concurrent requests and reuses short cache", async () => {
  const calls = [];
  const app = await fixture({ fetchImpl: async (url, options) => {
    calls.push({ url, options });
    await new Promise((resolve) => setTimeout(resolve, 20));
    return new Response(JSON.stringify({ Sessions: [{ UID: "manager-session", LocalizedClientName: "Windows VPN" }] }), { headers: { "content-type": "application/json" } });
  } });
  try {
    const admin = await protonAdmin(app); const account = await createProtonAccount(app, admin);
    const path = `/admin/proton/accounts/${account.id}/sessions`;
    const [first, second] = await Promise.all([app.request(path, { headers: { cookie: admin.cookie } }), app.request(path, { headers: { cookie: admin.cookie } })]);
    assert.equal(first.response.status, 200); assert.equal(second.response.status, 200); assert.equal(calls.length, 1);
    const cached = await app.request(path, { headers: { cookie: admin.cookie } });
    assert.equal(cached.response.status, 200); assert.equal(calls.length, 1);
    const fresh = await app.request(`${path}?fresh=1`, { headers: { cookie: admin.cookie } });
    assert.equal(fresh.response.status, 200); assert.equal(calls.length, 2);
  } finally { await app.close(); }
});

test("bulk create: tạo batch riêng theo product và không trộn 292ZM với 292VPN", async () => {
  const app = await fixture();
  try {
    const cookie = await app.login();
    const csrf = await csrfFor(app, cookie);
    const create = (product, prefix) => app.request("/admin/accounts/bulk-create", {
      method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf, product, count: "3", prefix, plan: "Batch", days: "30" }),
    });
    const zm = await create("292zm", "ZM-");
    const vpn = await create("292vpn", "VPN-");
    assert.equal(zm.response.status, 200); assert.equal(vpn.response.status, 200);
    assert.deepEqual(app.db.prepare("SELECT product, COUNT(*) count FROM accounts GROUP BY product ORDER BY product").all().map((row) => ({ product: row.product, count: row.count })), [{ product: "292vpn", count: 3 }, { product: "292zm", count: 3 }]);
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM accounts WHERE name LIKE 'ZM-%' AND product='292vpn'").get().count, 0);
    assert.equal(app.db.prepare("SELECT COUNT(*) count FROM accounts WHERE name LIKE 'VPN-%' AND product='292zm'").get().count, 0);
  } finally { await app.close(); }
});

test("regression: expired login attempts are pruned after the rate-limit window", async () => {
  const app = await fixture();
  try {
    for (let i = 0; i < 3; i += 1) {
      await app.request("/admin/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: "wrong-password-value" }), redirect: "manual" });
    }
    // Sau khi cửa sổ 15 phút trôi qua, entry cũ phải bị dọn thay vì tồn tại mãi.
    app.advance(16 * 60000);
    const allowed = await app.request("/admin/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: "very-long-admin-password" }), redirect: "manual" });
    assert.equal(allowed.response.status, 303);
  } finally { await app.close(); }
});

test("regression: expiry counters tolerate malformed timestamps without NaN", async () => {
  const app = await fixture();
  try {
    const { cookie, accountId } = await app.createAccount();
    app.db.prepare("UPDATE accounts SET expires_at='not-a-date' WHERE id=?").run(accountId);
    const page = await app.request("/admin", { headers: { cookie } });
    assert.equal(page.response.status, 200);
    assert.equal(page.body.includes("NaN"), false);
    assert.equal(page.body.includes("Invalid Date"), false);
    // Placeholder bị gõ sai trước đây không bao giờ được thay -> không được lọt ra HTML.
    assert.equal(page.body.includes("{{DEPLETIING_COUNT}}"), false);
    assert.equal(/\{\{[A-Z_]+\}\}/.test(page.body), false);
  } finally { await app.close(); }
});

test("vless: list requires admin and returns only projected VLESS metadata", async () => {
  const calls = [];
  const token = "panel-super-secret-token";
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return panelJson([vlessInbound(), vlessInbound({ id: 8, protocol: "trojan" })]);
  };
  const app = await fixture({ xui: { baseUrl: "https://panel.example", token }, fetchImpl });
  try {
    const anonymous = await app.request("/admin/vless");
    assert.equal(anonymous.response.status, 401);
    assert.equal(calls.length, 0);

    const cookie = await app.login();
    const listed = await app.request("/admin/vless", { headers: { cookie } });
    assert.equal(listed.response.status, 200);
    assert.equal(listed.body.configured, true);
    assert.equal(listed.body.inbounds.length, 1);
    assert.deepEqual(listed.body.inbounds[0].clients[0], {
      email: "existing@example.com", enabled: true, limitIp: 2, totalBytes: 1073741824, expiryTime: 0, up: 10, down: 20, online: false,
    });
    assert.equal(JSON.stringify(listed.body).includes("must-not-leak"), false);
    assert.equal(JSON.stringify(listed.body).includes(token), false);
    assert.equal(calls[0].url, "https://panel.example/panel/api/inbounds/list");
    assert.equal(calls[0].options.headers.authorization, `Bearer ${token}`);
  } finally { await app.close(); }
});

test("vless: online status derives from lastOnline within the configured window", async () => {
  const fetchImpl = async () => panelJson([vlessInbound({
    settings: JSON.stringify({ clients: [
      { email: "active", enable: true },
      { email: "stale", enable: true },
      { email: "never", enable: true },
      { email: "disabled", enable: false },
    ] }),
    clientStats: [
      { email: "active", up: 1, down: 1, lastOnline: Date.parse("2026-07-30T00:00:00.000Z") },
      { email: "stale", up: 1, down: 1, lastOnline: Date.parse("2026-07-28T00:00:00.000Z") },
      { email: "never", up: 0, down: 0 },
    ],
  })]);
  const app = await fixture({ xui: { baseUrl: "https://panel.example", token: "secret" }, fetchImpl });
  try {
    const cookie = await app.login();
    const listed = await app.request("/admin/vless", { headers: { cookie } });
    const clients = listed.body.inbounds[0].clients;
    assert.equal(clients.find((c) => c.email === "active").online, true);
    assert.equal(clients.find((c) => c.email === "stale").online, false);
    assert.equal(clients.find((c) => c.email === "never").online, false);
    assert.equal(clients.find((c) => c.email === "disabled").online, false);
    assert.equal(clients.find((c) => c.email === "disabled").enabled, false);
  } finally { await app.close(); }

  const custom = await fixture({
    xui: { baseUrl: "https://panel.example", token: "secret", onlineWindowMs: 60 * 60000 },
    fetchImpl: async () => panelJson([vlessInbound({
      settings: JSON.stringify({ clients: [{ email: "active", enable: true }] }),
      clientStats: [{ email: "active", up: 1, down: 1, lastOnline: Date.parse("2026-07-29T23:30:00.000Z") }],
    })]),
  });
  try {
    const cookie = await custom.login();
    const listed = await custom.request("/admin/vless", { headers: { cookie } });
    assert.equal(listed.body.inbounds[0].clients[0].online, true);
  } finally { await custom.close(); }
});

test("vless: create follows panel contract, returns a VLESS URI and audits no secret", async () => {
  const calls = [];
  const key = "vless://uuid@example.test:443?security=tls#created";
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith("/panel/api/inbounds/list")) return panelJson([vlessInbound()]);
    if (url.endsWith("/panel/api/clients/add")) return panelJson(null);
    if (url.endsWith("/panel/api/clients/links/new%40example.com")) return panelJson(["trojan://ignored", key]);
    return panelJson(null, { success: false });
  };
  const app = await fixture({ xui: { baseUrl: "https://panel.example/", token: "secret" }, fetchImpl });
  try {
    const cookie = await app.login();
    const csrf = await csrfFor(app, cookie);
    const created = await app.request("/admin/vless/clients", {
      method: "POST",
      headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({ inboundId: 7, email: "new@example.com", limitIp: 3, limitGb: 1.5, limitDays: 2 }),
    });
    assert.equal(created.response.status, 201);
    assert.equal(created.body.key, key);
    assert.deepEqual(JSON.parse(calls[1].options.body), {
      client: { email: "new@example.com", totalGB: 1610612736, expiryTime: Date.parse("2026-08-01T00:00:00.000Z"), tgId: 0, limitIp: 3, enable: true },
      inboundIds: [7],
    });
    assert.equal(calls[1].options.method, "POST");
    assert.equal(calls[2].url, "https://panel.example/panel/api/clients/links/new%40example.com");
    const audit = app.db.prepare("SELECT detail FROM audit WHERE event='admin_vless_create'").get();
    assert.match(audit.detail, /email=new@example\.com; inbound=7/);
    assert.equal(audit.detail.includes(key), false);
    assert.equal(JSON.stringify(app.db.prepare("SELECT * FROM audit").all()).includes(key), false);
  } finally { await app.close(); }
});

test("vless: auth, CSRF and invalid create input are rejected before panel mutation", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => { calls.push({ url, options }); return panelJson([vlessInbound()]); };
  const app = await fixture({ xui: { baseUrl: "https://panel.example", token: "secret" }, fetchImpl });
  try {
    const anonymous = await app.request("/admin/vless/clients", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(anonymous.response.status, 401);
    const cookie = await app.login();
    const noCsrf = await app.request("/admin/vless/clients", { method: "POST", headers: { cookie, "content-type": "application/json" }, body: "{}" });
    assert.equal(noCsrf.response.status, 403);
    const csrf = await csrfFor(app, cookie);
    for (const body of [
      { inboundId: "NaN", email: "valid", limitIp: 1, limitGb: 0, limitDays: 0 },
      { inboundId: 7.5, email: "valid", limitIp: 1, limitGb: 0, limitDays: 0 },
      { inboundId: 7, email: "", limitIp: 1, limitGb: 0, limitDays: 0 },
      { inboundId: 7, email: "a".repeat(101), limitIp: 1, limitGb: 0, limitDays: 0 },
      { inboundId: 7, email: "bad name", limitIp: 1, limitGb: 0, limitDays: 0 },
      { inboundId: 7, email: "valid", limitIp: -1, limitGb: 0, limitDays: 0 },
      { inboundId: 7, email: "valid", limitIp: 1001, limitGb: 0, limitDays: 0 },
      { inboundId: 7, email: "valid", limitIp: 1, limitGb: "NaN", limitDays: 0 },
      { inboundId: 7, email: "valid", limitIp: 1, limitGb: -1, limitDays: 0 },
      { inboundId: 7, email: "valid", limitIp: 1, limitGb: 1000001, limitDays: 0 },
      { inboundId: 7, email: "valid", limitIp: 1, limitGb: 0, limitDays: -1 },
      { inboundId: 7, email: "valid", limitIp: 1, limitGb: 0, limitDays: 36501 },
      { inboundId: 7, email: "valid", limitIp: "", limitGb: 0, limitDays: 0 },
    ]) {
      const denied = await app.request("/admin/vless/clients", { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: JSON.stringify(body) });
      assert.equal(denied.response.status, 400);
    }
    assert.equal(calls.length, 0);

    const missingInbound = await app.request("/admin/vless/clients", { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: JSON.stringify({ inboundId: 99, email: "valid", limitIp: 1, limitGb: 0, limitDays: 0 }) });
    assert.equal(missingInbound.response.status, 400);
    assert.equal(calls.length, 1);
    assert.equal(calls.some((call) => call.url.endsWith("/panel/api/clients/add")), false);

    const duplicate = await app.request("/admin/vless/clients", { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: JSON.stringify({ inboundId: 7, email: "existing@example.com", limitIp: 1, limitGb: 0, limitDays: 0 }) });
    assert.equal(duplicate.response.status, 409);
    assert.equal(calls.some((call) => call.url.endsWith("/panel/api/clients/add")), false);
  } finally { await app.close(); }

  const disabled = await fixture({
    xui: { baseUrl: "https://panel.example", token: "secret" },
    fetchImpl: async () => panelJson([vlessInbound({ enable: false, settings: JSON.stringify({ clients: [] }), clientStats: [] })]),
  });
  try {
    const cookie = await disabled.login();
    const csrf = await csrfFor(disabled, cookie);
    const denied = await disabled.request("/admin/vless/clients", { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: JSON.stringify({ inboundId: 7, email: "new", limitIp: 0, limitGb: 0, limitDays: 0 }) });
    assert.equal(denied.response.status, 400);
  } finally { await disabled.close(); }
});

test("vless: malformed panel client data and malformed VLESS URI are rejected", async () => {
  const malformedList = await fixture({
    xui: { baseUrl: "https://panel.example", token: "secret" },
    fetchImpl: async () => panelJson([vlessInbound({ settings: {} })]),
  });
  try {
    const cookie = await malformedList.login();
    const listed = await malformedList.request("/admin/vless", { headers: { cookie } });
    assert.equal(listed.response.status, 502);
    assert.deepEqual(listed.body, { error: "X-UI Panel trả cấu hình inbound không hợp lệ." });
  } finally { await malformedList.close(); }

  const malformedLink = await fixture({
    xui: { baseUrl: "https://panel.example", token: "secret" },
    fetchImpl: async (url) => url.endsWith("/inbounds/list")
      ? panelJson([vlessInbound({ settings: JSON.stringify({ clients: [{ email: "client", enable: true }] }), clientStats: [] })])
      : panelJson(["vless://missing-host"]),
  });
  try {
    const cookie = await malformedLink.login();
    const csrf = await csrfFor(malformedLink, cookie);
    const revealed = await malformedLink.request("/admin/vless/clients/client/reveal", { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: "{}" });
    assert.equal(revealed.response.status, 502);
    assert.deepEqual(revealed.body, { error: "Panel không trả về VLESS key hợp lệ." });
  } finally { await malformedLink.close(); }
});

test("vless: reveal/delete encode email, require CSRF and use keepTraffic=0", async () => {
  const calls = [];
  const key = "vless://uuid@example.test:443#copy";
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith("/inbounds/list")) return panelJson([vlessInbound({ settings: JSON.stringify({ clients: [{ email: "name@example.com", enable: true }] }), clientStats: [] })]);
    if (url.includes("/links/")) return panelJson([key]);
    return panelJson(null);
  };
  const app = await fixture({ xui: { baseUrl: "https://panel.example", token: "secret" }, fetchImpl });
  try {
    const anonymousReveal = await app.request("/admin/vless/clients/name%40example.com/reveal", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(anonymousReveal.response.status, 401);
    const anonymousDelete = await app.request("/admin/vless/clients/name%40example.com", { method: "DELETE", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(anonymousDelete.response.status, 401);
    const cookie = await app.login();
    const csrf = await csrfFor(app, cookie);
    const noCsrf = await app.request("/admin/vless/clients/name%40example.com/reveal", { method: "POST", headers: { cookie, "content-type": "application/json" }, body: "{}" });
    assert.equal(noCsrf.response.status, 403);
    assert.equal(calls.length, 0);
    const deleteNoCsrf = await app.request("/admin/vless/clients/name%40example.com", { method: "DELETE", headers: { cookie, "content-type": "application/json" }, body: "{}" });
    assert.equal(deleteNoCsrf.response.status, 403);
    assert.equal(calls.length, 0);

    const revealed = await app.request("/admin/vless/clients/name%40example.com/reveal", { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: "{}" });
    assert.equal(revealed.body.key, key);
    const deleted = await app.request("/admin/vless/clients/name%40example.com", { method: "DELETE", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: "{}" });
    assert.equal(deleted.response.status, 200);
    assert.equal(calls[1].url, "https://panel.example/panel/api/clients/links/name%40example.com");
    assert.equal(calls[3].url, "https://panel.example/panel/api/clients/del/name%40example.com?keepTraffic=0");
    assert.equal(calls[3].options.method, "POST");
    const audits = app.db.prepare("SELECT event, detail FROM audit WHERE event LIKE 'admin_vless_%' ORDER BY id").all();
    assert.deepEqual(audits.map((row) => row.event), ["admin_vless_reveal", "admin_vless_delete"]);
    assert.equal(JSON.stringify(audits).includes(key), false);
  } finally { await app.close(); }
});

test("vless: ambiguous email and failed delete are rejected without mutation audit", async () => {
  const duplicate = await fixture({
    xui: { baseUrl: "https://panel.example", token: "secret" },
    fetchImpl: async () => panelJson([
      vlessInbound(),
      vlessInbound({ id: 9, remark: "Duplicate", settings: JSON.stringify({ clients: [{ email: "existing@example.com", enable: true }] }), clientStats: [] }),
    ]),
  });
  try {
    const cookie = await duplicate.login();
    const csrf = await csrfFor(duplicate, cookie);
    const revealed = await duplicate.request("/admin/vless/clients/existing%40example.com/reveal", { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: "{}" });
    assert.equal(revealed.response.status, 409);
    const deleted = await duplicate.request("/admin/vless/clients/existing%40example.com", { method: "DELETE", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: "{}" });
    assert.equal(deleted.response.status, 409);
    assert.equal(duplicate.db.prepare("SELECT COUNT(*) AS count FROM audit WHERE event IN ('admin_vless_reveal','admin_vless_delete')").get().count, 0);
  } finally { await duplicate.close(); }

  const failedDelete = await fixture({
    xui: { baseUrl: "https://panel.example", token: "secret" },
    fetchImpl: async (url) => url.endsWith("/inbounds/list") ? panelJson([vlessInbound()]) : panelJson(null, { success: false }),
  });
  try {
    const cookie = await failedDelete.login();
    const csrf = await csrfFor(failedDelete, cookie);
    const deleted = await failedDelete.request("/admin/vless/clients/existing%40example.com", { method: "DELETE", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: "{}" });
    assert.equal(deleted.response.status, 502);
    assert.deepEqual(deleted.body, { error: "X-UI Panel không thể hoàn tất yêu cầu." });
    assert.equal(failedDelete.db.prepare("SELECT id FROM audit WHERE event='admin_vless_delete'").get(), undefined);
  } finally { await failedDelete.close(); }
});

test("vless: partial create, bad link, timeout and missing secure config fail safely", async () => {
  const partialCalls = [];
  const partial = await fixture({
    xui: { baseUrl: "https://panel.example", token: "secret" },
    fetchImpl: async (url, options) => {
      partialCalls.push({ url, options });
      if (url.endsWith("/inbounds/list")) return panelJson([vlessInbound()]);
      if (url.endsWith("/clients/add")) return panelJson(null);
      return panelJson(["not-a-vless-uri"]);
    },
  });
  try {
    const cookie = await partial.login();
    const csrf = await csrfFor(partial, cookie);
    const created = await partial.request("/admin/vless/clients", { method: "POST", headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf }, body: JSON.stringify({ inboundId: 7, email: "partial", limitIp: 0, limitGb: 0, limitDays: 0 }) });
    assert.equal(created.response.status, 502);
    assert.equal(created.body.created, true);
    assert.equal(JSON.stringify(created.body).includes("not-a-vless-uri"), false);
    assert.ok(partial.db.prepare("SELECT id FROM audit WHERE event='admin_vless_create'").get());
  } finally { await partial.close(); }

  const unconfigured = await fixture({ xui: { baseUrl: "http://panel.example", token: "secret" }, fetchImpl: async () => { throw new Error("must not run"); } });
  try {
    const cookie = await unconfigured.login();
    const listed = await unconfigured.request("/admin/vless", { headers: { cookie } });
    assert.equal(listed.response.status, 200);
    assert.equal(listed.body.configured, false);
    assert.equal(JSON.stringify(listed.body).includes("secret"), false);
  } finally { await unconfigured.close(); }

  const timeout = await fixture({
    xui: { baseUrl: "https://panel.example", token: "secret", timeoutMs: 5 },
    fetchImpl: async (url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    }),
  });
  try {
    const cookie = await timeout.login();
    const listed = await timeout.request("/admin/vless", { headers: { cookie } });
    assert.equal(listed.response.status, 504);
    assert.deepEqual(listed.body, { error: "Proton hoặc helper renew phản hồi quá chậm." });
  } finally { await timeout.close(); }
});
