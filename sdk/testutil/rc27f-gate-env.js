"use strict";
const fs = require("node:fs"), path = require("node:path");
const scratch = path.resolve(__dirname, "../../.claude/codex-rc27f/tmp");
fs.mkdirSync(scratch, { recursive: true });
process.env.TMPDIR = scratch;
process.env.POLICYVAULT_TEST_PG_HOST = "127.0.0.1";
process.env.POLICYVAULT_TEST_PG_PORT = "5432";
process.env.POLICYVAULT_TEST_PG_USER = "pvdev";
process.env.POLICYVAULT_TEST_PG_DATABASE = "postgres";
