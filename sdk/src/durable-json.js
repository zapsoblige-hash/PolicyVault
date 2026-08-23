"use strict";

/*
 * Durable filesystem persistence for funds-critical JSON.
 *
 * Pattern (proven in JobVault): write to a temp file, fsync the file,
 * atomically install under the final name (rename, or link for
 * create-only claims), then fsync the directory. `createOnly` uses
 * link() so an existing destination is never replaced — the basis for
 * durable claims.
 *
 * BigInt values are serialized as decimal strings.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = fs.openSync(directory, "r");
    fs.fsyncSync(descriptor);
  } catch {
    /*
     * Some filesystems do not support directory fsync. File-level fsync
     * still provides the important durability guarantee.
     */
  } finally {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Nothing useful to do here.
      }
    }
  }
}

function temporaryPathFor(filePath) {
  return path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.tmp-${process.pid}-${crypto.randomUUID()}`
  );
}

function writeTemporaryFile({ temporaryPath, serialized, mode }) {
  let descriptor;
  try {
    descriptor = fs.openSync(temporaryPath, "wx", mode);
    fs.writeFileSync(descriptor, serialized);
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) {
      fs.closeSync(descriptor);
    }
  }
}

function persistSerializedDurably({ filePath, serialized, mode = 0o600, createOnly = false }) {
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });

  const temporaryPath = temporaryPathFor(filePath);

  try {
    writeTemporaryFile({ temporaryPath, serialized, mode });

    if (createOnly) {
      /*
       * link() installs the fully fsynced inode under its final name
       * without replacing an existing destination (EEXIST on conflict).
       */
      fs.linkSync(temporaryPath, filePath);
      fs.unlinkSync(temporaryPath);
    } else {
      /* Same-directory rename atomically replaces the previous version. */
      fs.renameSync(temporaryPath, filePath);
    }

    fs.chmodSync(filePath, mode);
    fsyncDirectory(directory);
  } catch (error) {
    try {
      if (fs.existsSync(temporaryPath)) {
        fs.unlinkSync(temporaryPath);
      }
    } catch {
      // Preserve the original error.
    }
    throw error;
  }

  return filePath;
}

function stringifyStable(value) {
  return (
    JSON.stringify(value, (_, item) => (typeof item === "bigint" ? item.toString() : item), 2) + "\n"
  );
}

function persistJsonDurably({ filePath, value, mode = 0o600, createOnly = false }) {
  return persistSerializedDurably({
    filePath,
    serialized: stringifyStable(value),
    mode,
    createOnly
  });
}

/*
 * Read a JSON file, failing closed (throw) on missing/corrupt content.
 */
function readJsonStrict(filePath, label = "file") {
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new Error(`durable-json: cannot read ${label} at ${filePath}: ${error.message}`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`durable-json: corrupt ${label} at ${filePath}: ${error.message}`);
  }
}

module.exports = {
  persistSerializedDurably,
  persistJsonDurably,
  readJsonStrict,
  stringifyStable
};
