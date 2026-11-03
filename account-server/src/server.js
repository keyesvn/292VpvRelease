"use strict";

const http = require("node:http");
const { createApp } = require("./app");
const { openDatabase } = require("./database");
const { createWireGuardProvisioner } = require("./wireguard");

const port = Number(process.env.PORT || 8080);
const databasePath = process.env.DATABASE_PATH || "/data/accounts.sqlite";
const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
if (!adminPasswordHash) throw new Error("ADMIN_PASSWORD_HASH là bắt buộc. Chạy scripts/hash-password.js để tạo.");
if (process.env.NODE_ENV === "production" && (!process.env.KEY_ENCRYPTION_SECRET || process.env.KEY_ENCRYPTION_SECRET.length < 16)) {
  throw new Error("KEY_ENCRYPTION_SECRET là bắt buộc trong production và phải dài ít nhất 16 ký tự.");
}
const db = openDatabase(databasePath);
const dockerGateway = (() => {
  try {
    const fs = require("node:fs");
    const route = fs.readFileSync("/proc/net/route", "utf8");
    for (const line of route.split("\n")) {
      const columns = line.trim().split(/\s+/);
      if (columns.length >= 3 && columns[0] !== "Iface" && columns[1] === "00000000") {
        const hex = columns[2];
        return `${parseInt(hex.slice(6, 8), 16) || 0}.${parseInt(hex.slice(4, 6), 16) || 0}.${parseInt(hex.slice(2, 4), 16) || 0}.${parseInt(hex.slice(0, 2), 16) || 0}`;
      }
    }
  } catch {}
  return null;
})();
const wireGuardProvisioner = createWireGuardProvisioner({
  host: process.env.VPN_WIREGUARD_HOST || process.env["292VPN_WIREGUARD_HOST"] || "",
  user: process.env.VPN_WIREGUARD_USER || process.env["292VPN_WIREGUARD_USER"] || "root",
  identityFile: process.env.VPN_WIREGUARD_IDENTITY_FILE || process.env["292VPN_WIREGUARD_IDENTITY_FILE"] || "",
  knownHostsFile: process.env.VPN_WIREGUARD_KNOWN_HOSTS_FILE || process.env["292VPN_WIREGUARD_KNOWN_HOSTS_FILE"] || "",
  endpoint: process.env.VPN_WIREGUARD_ENDPOINT || process.env["292VPN_WIREGUARD_ENDPOINT"] || "",
  serverPublicKey: process.env.VPN_WIREGUARD_SERVER_PUBLIC_KEY || process.env["292VPN_WIREGUARD_SERVER_PUBLIC_KEY"] || "",
});
const wireGuardProvisionerHcm = createWireGuardProvisioner({
  host: process.env.VPN_WIREGUARD_HOST_HCM || process.env["292VPN_WIREGUARD_HOST_HCM"] || "",
  user: process.env.VPN_WIREGUARD_USER || process.env["292VPN_WIREGUARD_USER"] || "root",
  identityFile: process.env.VPN_WIREGUARD_IDENTITY_FILE || process.env["292VPN_WIREGUARD_IDENTITY_FILE"] || "",
  knownHostsFile: process.env.VPN_WIREGUARD_KNOWN_HOSTS_FILE || process.env["292VPN_WIREGUARD_KNOWN_HOSTS_FILE"] || "",
  endpoint: process.env.VPN_WIREGUARD_ENDPOINT_HCM || process.env["292VPN_WIREGUARD_ENDPOINT_HCM"] || "",
  serverPublicKey: process.env.VPN_WIREGUARD_SERVER_PUBLIC_KEY_HCM || process.env["292VPN_WIREGUARD_SERVER_PUBLIC_KEY_HCM"] || "",
});
const wireGuardProvisionerSg = createWireGuardProvisioner({
  host: process.env.VPN_WIREGUARD_HOST_SG || process.env["292VPN_WIREGUARD_HOST_SG"] || "",
  user: process.env.VPN_WIREGUARD_USER_SG || process.env["292VPN_WIREGUARD_USER_SG"] || "root",
  identityFile: process.env.VPN_WIREGUARD_IDENTITY_FILE_SG || process.env["292VPN_WIREGUARD_IDENTITY_FILE_SG"] || process.env.VPN_WIREGUARD_IDENTITY_FILE || process.env["292VPN_WIREGUARD_IDENTITY_FILE"] || "",
  knownHostsFile: process.env.VPN_WIREGUARD_KNOWN_HOSTS_FILE_SG || process.env["292VPN_WIREGUARD_KNOWN_HOSTS_FILE_SG"] || process.env.VPN_WIREGUARD_KNOWN_HOSTS_FILE || process.env["292VPN_WIREGUARD_KNOWN_HOSTS_FILE"] || "",
  endpoint: process.env.VPN_WIREGUARD_ENDPOINT_SG || process.env["292VPN_WIREGUARD_ENDPOINT_SG"] || "",
  serverPublicKey: process.env.VPN_WIREGUARD_SERVER_PUBLIC_KEY_SG || process.env["292VPN_WIREGUARD_SERVER_PUBLIC_KEY_SG"] || "",
  addressPrefix: process.env.VPN_WIREGUARD_ADDRESS_PREFIX_SG || process.env["292VPN_WIREGUARD_ADDRESS_PREFIX_SG"] || "10.203.71.",
});
const wireGuardProvisionerHk = createWireGuardProvisioner({
  host: process.env.VPN_WIREGUARD_HOST_HK || process.env["292VPN_WIREGUARD_HOST_HK"] || "",
  user: process.env.VPN_WIREGUARD_USER_HK || process.env["292VPN_WIREGUARD_USER_HK"] || "root",
  identityFile: process.env.VPN_WIREGUARD_IDENTITY_FILE_HK || process.env["292VPN_WIREGUARD_IDENTITY_FILE_HK"] || process.env.VPN_WIREGUARD_IDENTITY_FILE || process.env["292VPN_WIREGUARD_IDENTITY_FILE"] || "",
  knownHostsFile: process.env.VPN_WIREGUARD_KNOWN_HOSTS_FILE_HK || process.env["292VPN_WIREGUARD_KNOWN_HOSTS_FILE_HK"] || process.env.VPN_WIREGUARD_KNOWN_HOSTS_FILE || process.env["292VPN_WIREGUARD_KNOWN_HOSTS_FILE"] || "",
  endpoint: process.env.VPN_WIREGUARD_ENDPOINT_HK || process.env["292VPN_WIREGUARD_ENDPOINT_HK"] || "",
  serverPublicKey: process.env.VPN_WIREGUARD_SERVER_PUBLIC_KEY_HK || process.env["292VPN_WIREGUARD_SERVER_PUBLIC_KEY_HK"] || "",
  addressPrefix: process.env.VPN_WIREGUARD_ADDRESS_PREFIX_HK || process.env["292VPN_WIREGUARD_ADDRESS_PREFIX_HK"] || "10.203.72.",
});
// Node biến mất khỏi client sau một lần deploy luôn là do thiếu biến môi
// trường khi container dựng lại. Cảnh báo ngay khi khởi động để lỗi hiện ra
// trong `docker logs` thay vì chỉ thấy trên điện thoại của người dùng.
const disabledNodes = [];
if (!process.env.VPN_PANEL_API_URL && !process.env["292VPN_PANEL_API_URL"]) disabledNodes.push("vn-hanoi-1: thiếu VPN_PANEL_API_URL (X-UI panel)");
else if (!(Number(process.env.VPN_VPN_INBOUND_ID || process.env["292VPN_VPN_INBOUND_ID"]) >= 1)) disabledNodes.push("vn-hanoi-1: thiếu VPN_VPN_INBOUND_ID");
if (!process.env.VPN_HYSTERIA2_URL && !process.env["292VPN_HYSTERIA2_URL"]) disabledNodes.push("vn-hanoi-2: thiếu VPN_HYSTERIA2_URL");
if (!wireGuardProvisionerSg.configured) disabledNodes.push("sg-wg-1: thiếu VPN_WIREGUARD_*_SG");
if (!wireGuardProvisionerHk.configured) disabledNodes.push("hk-wg-1: thiếu VPN_WIREGUARD_*_HK");
if (!wireGuardProvisioner.configured) disabledNodes.push("vn-hanoi-3: thiếu VPN_WIREGUARD_* (host/endpoint/public key/identity)");
if (!wireGuardProvisionerHcm.configured) disabledNodes.push("vn-hcm-1: thiếu VPN_WIREGUARD_*_HCM");
if (disabledNodes.length) console.warn(`[292vpn] CẢNH BÁO: một số node VPN sẽ không thể cấp cấu hình do thiếu cấu hình:\n  - ${disabledNodes.join("\n  - ")}`);
const server = http.createServer(createApp({
  db,
  adminPasswordHash,
  production: process.env.NODE_ENV === "production",
  trustProxy: process.env.TRUST_PROXY === "1",
  dockerGateway,
  hysteria2Url: process.env.VPN_HYSTERIA2_URL || process.env["292VPN_HYSTERIA2_URL"] || "",
  wireGuardProvisioner: wireGuardProvisioner,
  wireGuardProvisionerHcm: wireGuardProvisionerHcm,
  wireGuardProvisionerSg,
  wireGuardProvisionerHk,
  xui: {
    baseUrl: process.env.VPN_PANEL_API_URL || process.env["292VPN_PANEL_API_URL"] || "",
    token: process.env.VPN_PANEL_API_TOKEN || process.env["292VPN_PANEL_API_TOKEN"] || "",
    username: process.env.VPN_PANEL_USERNAME || process.env["292VPN_PANEL_USERNAME"] || "",
    password: process.env.VPN_PANEL_PASSWORD || process.env["292VPN_PANEL_PASSWORD"] || "",
    vpnInboundId: Number(process.env.VPN_VPN_INBOUND_ID || process.env["292VPN_VPN_INBOUND_ID"] || 0),
    allowInsecureHttp: (process.env.VPN_ALLOW_INSECURE_HTTP || process.env["292VPN_ALLOW_INSECURE_HTTP"]) === "1",
    onlineWindowMs: (Number(process.env.VPN_ONLINE_WINDOW_HOURS || process.env["292VPN_ONLINE_WINDOW_HOURS"]) || 24) * 3600 * 1000,
  },
  gpm: {
    email: process.env.GPM_EMAIL || process.env.GPM_email || "",
    password: process.env.GPM_PASSWORD || process.env.GPM_pass || "",
    baseUrl: process.env.GPM_API_BASE_URL || "",
    autoExchange: process.env.GPM_AUTO_EXCHANGE !== "0",
    autoExchangeIntervalMs: Number(process.env.GPM_AUTO_EXCHANGE_INTERVAL_MS) || 60000,
    expiringWindowMs: (Number(process.env.GPM_EXPIRING_WINDOW_HOURS) || 72) * 3600000,
  },
  proton: {
    baseUrl: process.env.PROTON_API_BASE_URL || "https://account.protonvpn.com",
    appVersion: process.env.PROTON_APP_VERSION || "",
    autoRevoke: process.env.PROTON_AUTO_REVOKE === "1",
    autoRevokeIntervalMs: Number(process.env.PROTON_AUTO_REVOKE_INTERVAL_MS) || 60000,
    workerConcurrency: Number(process.env.PROTON_WORKER_CONCURRENCY) || 3,
    enforceAllowlist: process.env.PROTON_ENFORCE_ALLOWLIST !== "0",
    sessionGraceMs: Number(process.env.PROTON_SESSION_GRACE_MS) || 1800000,
    cookie: process.env.PROTON_COOKIE || "",
    password: process.env.PROTON_PASSWORD || "",
    refreshCommand: process.env.PROTON_REFRESH_COMMAND || "",
    refreshArgs: (() => {
      const raw = String(process.env.PROTON_REFRESH_ARGS || "").trim();
      if (!raw) return [];
      try { return JSON.parse(raw).map(String); } catch {}
      // Docker --env-file strips the inner quotes from values such as
      // ["/app/scripts/refresh-proton.py"]. Accept that deterministic bracket
      // form without invoking a shell or interpreting arbitrary syntax.
      const match = raw.match(/^\[(.*)\]$/s);
      return match ? match[1].split(",").map((value) => value.trim().replace(/^['"]|['"]$/g, "")).filter(Boolean) : [];
    })(),
    refreshTimeoutMs: Number(process.env.PROTON_REFRESH_TIMEOUT_MS) || 120000,
    timeoutMs: Number(process.env.PROTON_TIMEOUT_MS) || undefined,
  },
}));
server.listen(port, "0.0.0.0", () => console.log(`Account server listening on ${port}`));

function shutdown() { server.close(() => { db.close(); process.exit(0); }); }
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
