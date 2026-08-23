"use strict";

/*
 * Durable append-only audit log. Every meaningful vault operation produces
 * an event. Application-layer record; never a consensus value.
 */

const fs = require("fs");
const path = require("path");

function auditPath(config) {
  return path.join(config.dataRoot, "audit", "events.log");
}

function appendAudit(config, event) {
  const dir = path.join(config.dataRoot, "audit");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const record = { at: new Date().toISOString(), ...event };
  fs.appendFileSync(auditPath(config), JSON.stringify(record) + "\n", { mode: 0o600 });
  return record;
}

function readAudit(config, { vaultId, limit = 200 } = {}) {
  const file = auditPath(config);
  if (!fs.existsSync(file)) {
    return [];
  }
  const events = fs
    .readFileSync(file, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  const filtered = vaultId ? events.filter((e) => e.vaultId === vaultId) : events;
  return filtered.slice(-limit).reverse();
}

module.exports = { appendAudit, readAudit };
