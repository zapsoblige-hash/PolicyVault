"use strict";

/*
 * STAGING-ONLY private kaspad RPC transport (Phase E, directive §13).
 *
 * The operator's testnet-10 kaspad binds its JSON wRPC to 127.0.0.1:18210
 * (loopback only — correct private posture). Staging app CONTAINERS
 * cannot reach the host loopback, so this forwarder listens on the
 * DOCKER BRIDGE GATEWAY ADDRESS ONLY (a host-internal RFC1918 interface
 * unreachable from the LAN or the internet) and forwards raw TCP to the
 * loopback RPC.
 *
 * This is a documented BOOTSTRAP/STAGING topology, not the production
 * kaspad tier (production: dedicated kaspad host in the provider VPC,
 * RPC bound to the VPC-private interface, provider firewall).
 *
 * Safety properties:
 *   - REFUSES to bind anything but a private (RFC1918) or loopback IP —
 *     it can never become a public RPC endpoint by misconfiguration.
 *   - TESTNET ONLY: refuses to start if the target port is the mainnet
 *     JSON wRPC port (18110).
 *   - bounded concurrent connections; idle-less pipes are destroyed with
 *     the peer.
 *
 * Usage: node tools/staging-kaspad-proxy.js [bindIp]
 *   bindIp default: the docker0 gateway (auto-detected, else 172.17.0.1)
 */

const net = require("net");
const os = require("os");

const LISTEN_PORT = 18210; // testnet-10 JSON wRPC
const TARGET_HOST = "127.0.0.1";
const TARGET_PORT = 18210;
const MAX_CONNS = 64;

if (TARGET_PORT === 18110 || LISTEN_PORT === 18110) {
  console.error("staging-kaspad-proxy: mainnet RPC port refused — staging is testnet-10 only");
  process.exit(1);
}

function dockerBridgeIp() {
  const ifs = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifs)) {
    if (!name.startsWith("docker")) continue;
    for (const a of addrs || []) {
      if (a.family === "IPv4") return a.address;
    }
  }
  return "172.17.0.1";
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (parts[0] === 127) return true; // loopback (testing)
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

const bindIp = process.argv[2] || dockerBridgeIp();
if (!isPrivateIPv4(bindIp)) {
  console.error(`staging-kaspad-proxy: refusing to bind non-private address ${bindIp} — the RPC must never become public`);
  process.exit(1);
}

let active = 0;
const server = net.createServer((client) => {
  if (active >= MAX_CONNS) {
    client.destroy();
    return;
  }
  active += 1;
  const upstream = net.connect(TARGET_PORT, TARGET_HOST);
  const halt = () => {
    client.destroy();
    upstream.destroy();
  };
  client.on("error", halt);
  upstream.on("error", halt);
  client.on("close", () => {
    active -= 1;
    upstream.destroy();
  });
  upstream.on("close", () => client.destroy());
  client.pipe(upstream);
  upstream.pipe(client);
  console.log(`[${new Date().toISOString()}] rpc connection from ${client.remoteAddress} (active ${active})`);
});

server.listen(LISTEN_PORT, bindIp, () => {
  console.log(`staging-kaspad-proxy: ${bindIp}:${LISTEN_PORT} -> ${TARGET_HOST}:${TARGET_PORT} (testnet-10 JSON wRPC; private bridge only)`);
});
server.on("error", (e) => {
  console.error(`staging-kaspad-proxy: ${e.message}`);
  process.exit(1);
});
