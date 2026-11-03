"use strict";

const { execFile } = require("node:child_process");

function createWireGuardProvisioner(options = {}) {
  const host = String(options.host || "").trim();
  const user = String(options.user || "root").trim();
  const identityFile = String(options.identityFile || "").trim();
  const knownHostsFile = String(options.knownHostsFile || "").trim();
  const endpoint = String(options.endpoint || "").trim();
  const serverPublicKey = String(options.serverPublicKey || "").trim();
  const addressPrefix = String(options.addressPrefix || "").trim();
  const timeoutMs = Number(options.timeoutMs) || 15000;
  // The catalog can safely advertise a node with public connection metadata even
  // when the account server cannot currently provision a new peer. Keep these
  // states separate so a temporary SSH secret/mount problem does not make the
  // VPN server disappear from clients.
  const catalogConfigured = Boolean(host && user && endpoint && serverPublicKey);
  const configured = Boolean(catalogConfigured && identityFile && knownHostsFile);

  async function provision(allocationId) {
    if (!configured) throw Object.assign(new Error("WireGuard provisioning chưa được cấu hình."), { status: 503 });
    if (!/^[a-z0-9-]{1,80}$/.test(allocationId)) throw Object.assign(new Error("WireGuard allocation không hợp lệ."), { status: 400 });
    const stdout = await run("ssh", [
      "-i", identityFile,
      "-o", "BatchMode=yes",
      "-o", "IdentitiesOnly=yes",
      "-o", `UserKnownHostsFile=${knownHostsFile}`,
      "-o", "StrictHostKeyChecking=yes",
      "-o", "LogLevel=ERROR",
      `${user}@${host}`,
      `provision ${allocationId}`,
    ], timeoutMs);
    const payload = JSON.parse(stdout);
    if (!/^[A-Za-z0-9+/]{43}=$/.test(String(payload.privateKey || ""))) throw new Error("WireGuard provisioner trả private key không hợp lệ.");
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(payload.address || "")) || String(payload.address).split(".").some((part) => Number(part) > 255) || (addressPrefix && !String(payload.address).startsWith(addressPrefix))) {
      throw new Error("WireGuard provisioner trả địa chỉ không hợp lệ.");
    }
    return `[Interface]\nPrivateKey = ${payload.privateKey}\nAddress = ${payload.address}/32\nDNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\nPublicKey = ${serverPublicKey}\nAllowedIPs = 0.0.0.0/0\nEndpoint = ${endpoint}\nPersistentKeepalive = 20\n`;
  }

  return { configured, catalogConfigured, provision };
}

function run(file, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { timeout: timeoutMs, maxBuffer: 64 * 1024 }, (error, stdout) => {
      if (error) return reject(Object.assign(new Error("Không thể cấp cấu hình WireGuard."), { status: 502 }));
      resolve(String(stdout).trim());
    });
  });
}

module.exports = { createWireGuardProvisioner };
