"use strict";
// Explicit, task-local gate environment. Loaded only with node --require;
// ordinary tests and production configuration do not import this file.
const path = require("node:path");
const fs = require("node:fs");
const scratch = path.resolve(__dirname, "../../.claude/codex-cp13/tmp");
fs.mkdirSync(scratch, { recursive: true });
process.env.TMPDIR = scratch;
process.env.POLICYVAULT_TEST_PG_HOST = "127.0.0.1";
process.env.POLICYVAULT_TEST_PG_PORT = "5432";
process.env.POLICYVAULT_TEST_PG_USER = "pvdev";
process.env.POLICYVAULT_TEST_PG_DATABASE = "postgres";
