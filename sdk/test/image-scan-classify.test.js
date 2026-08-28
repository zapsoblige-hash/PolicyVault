"use strict";

/*
 * UNIT — image privacy scanner path classification (Phase E-R).
 *
 * The layer scan in tools/image-privacy-scan.sh gained a NARROW
 * benign-class filter after the first real-image run surfaced three
 * textual false-positive classes (public CA trust store *.pem, the
 * stock empty /var/backups/ directory entry, node_modules module dirs
 * literally named keys/). This suite drives the scanner's
 * --classify-paths mode (the EXACT grep logic the layer walk applies —
 * no docker required) and proves:
 *   - every real private-material path class still FAILS the scan
 *   - the three classified benign classes are filtered
 *   - the filter is not wider than its classification (files inside
 *     var/backups, wallets/ under node_modules, keys/ outside
 *     node_modules all still fail)
 */

const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { spawnSync } = require("child_process");

const SCRIPT = path.join(__dirname, "..", "..", "tools", "image-privacy-scan.sh");

function classify(paths) {
  const r = spawnSync("bash", [SCRIPT, "--classify-paths"], {
    input: paths.join("\n") + "\n",
    encoding: "utf8"
  });
  return { code: r.status, out: (r.stdout || "").trim() };
}

const FORBIDDEN_VECTORS = [
  "app/.git/config",
  "app/POLICYVAULT_CONTINUATION_NOTES.md",
  "app/PHASE E DIRECTIVE.md",
  "app/docs.zip",
  "app/data/vaults/v1.json",
  "app/data-mainnet/requests/r.json",
  "app/keys/owner.key",
  "app/wallets/w.dat",
  "app/secrets/token",
  "app/backups/db.dump",
  "app/server/.env",
  "app/.env.production",
  "app/deploy/staging.env",
  "home/pv/.ssh/id_rsa",
  "home/pv/.config/gh/hosts.yml",
  "home/pv/.aws/credentials",
  "home/pv/.kube/config",
  "app/certs/server.pem",
  "root/id_ed25519",
  "app/cloudflared-tunnel-cred.json",
  // narrowness of the benign filter:
  "var/backups/dpkg.status.0", // a FILE inside var/backups still fails
  "app/sdk/node_modules/evil/wallets/hot.dat", // only keys/ is exempted under node_modules
  "app/sdk/keys/delegate.key", // keys/ outside node_modules still fails
  "usr/lib/ssl/private.pem" // only the cert.pem public-bundle symlink is exempted
];

const BENIGN_VECTORS = [
  "etc/ssl/certs/Amazon_Root_CA_1.pem",
  "etc/ssl/certs/COMODO_ECC_Certification_Authority.pem",
  "var/backups/",
  "app/sdk/node_modules/es5-ext/array/#/keys/",
  "app/sdk/node_modules/es5-ext/array/#/keys/implement.js",
  "app/sdk/node_modules/es5-ext/object/keys/index.js"
];

const NEUTRAL_VECTORS = [
  "app/server/src/server.js",
  "app/sdk/src/store.js",
  "app/web/index.html",
  "usr/local/bin/node"
];

test("every forbidden path class fails the classifier individually", () => {
  for (const p of FORBIDDEN_VECTORS) {
    const r = classify([p]);
    assert.strictEqual(r.code, 1, `expected FAIL for ${p}`);
    assert.ok(r.out.includes(p), `violation output must name ${p}`);
  }
});

test("classified benign classes and neutral paths pass clean", () => {
  const r = classify([...BENIGN_VECTORS, ...NEUTRAL_VECTORS]);
  assert.strictEqual(r.code, 0, `expected CLEAN, got violations:\n${r.out}`);
  assert.strictEqual(r.out, "");
});

test("one forbidden path among benign noise is still caught alone", () => {
  const r = classify([...BENIGN_VECTORS, "app/keys/owner.key", ...NEUTRAL_VECTORS]);
  assert.strictEqual(r.code, 1);
  assert.strictEqual(r.out, "app/keys/owner.key");
});

test("real-image false-positive regression: the exact Phase E-R hit set is clean", () => {
  // The literal first-run hits from the real policyvault-app:staging image.
  const r = classify([
    "app/sdk/node_modules/es5-ext/array/#/keys/",
    "app/sdk/node_modules/es5-ext/array/#/keys/implement.js",
    "app/sdk/node_modules/es5-ext/array/#/keys/index.js",
    "app/sdk/node_modules/es5-ext/array/#/keys/is-implemented.js",
    "app/sdk/node_modules/es5-ext/array/#/keys/shim.js",
    "app/sdk/node_modules/es5-ext/object/keys/",
    "app/sdk/node_modules/es5-ext/object/keys/implement.js",
    "app/sdk/node_modules/es5-ext/object/keys/index.js",
    "app/sdk/node_modules/es5-ext/object/keys/is-implemented.js",
    "app/sdk/node_modules/es5-ext/object/keys/shim.js",
    "etc/ssl/certs/ACCVRAIZ1.pem",
    "etc/ssl/certs/Amazon_Root_CA_4.pem",
    "usr/lib/ssl/cert.pem",
    "var/backups/"
  ]);
  assert.strictEqual(r.code, 0, `expected CLEAN, got:\n${r.out}`);
});
