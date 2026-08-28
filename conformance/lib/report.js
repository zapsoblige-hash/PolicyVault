"use strict";

/*
 * Machine-readable conformance evidence (spec §10) — one JSON artifact per
 * run (path × scenario × outcome) plus a human summary. This is the
 * acceptance-evidence format an RC record cites.
 *
 * Outcome vocabulary:
 *   PASS                 — the path behaved equivalently (assertions held)
 *   LIMITATION_ASSERTED  — a DECLARED path limitation was verified present
 *                          (the absence itself is the assertion)
 *   FAIL                 — an assertion failed (the run's tests also fail)
 *   SKIPPED_ENV          — environment gap (e.g. missing encoder binary);
 *                          never a driven-surface defect
 *   N/A                  — the scenario does not apply to the path and no
 *                          limitation assertion exists for it
 */

const fs = require("fs");
const path = require("path");

const RESULTS_SCHEMA = "policyvault-conformance-results/v1";

class ConformanceReport {
  constructor({ suite, paths }) {
    this.meta = {
      schema: RESULTS_SCHEMA,
      suite,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      server: null, // { networkId, apiVersion, buildId? } — filled from live discovery
      paths
    };
    this.rows = []; // { scenario, path, outcome, note }
  }

  setServer(info) {
    this.meta.server = info;
  }

  record(scenario, pathId, outcomeLabel, note) {
    this.rows.push({ scenario, path: pathId, outcome: outcomeLabel, ...(note ? { note } : {}) });
  }

  /* Run `fn` for one scenario×path cell; records `label` (default PASS) on
   * success — pass label "LIMITATION_ASSERTED" for a cell whose assertion
   * is a documented absence — or FAIL + rethrow. */
  async cell(scenario, pathId, fn, note, label = "PASS") {
    try {
      await fn();
      this.record(scenario, pathId, label, note);
    } catch (error) {
      this.record(scenario, pathId, "FAIL", (error && error.message ? error.message : String(error)).slice(0, 400));
      throw error;
    }
  }

  totals() {
    const t = {};
    for (const r of this.rows) t[r.outcome] = (t[r.outcome] || 0) + 1;
    return t;
  }

  finish() {
    this.meta.finishedAt = new Date().toISOString();
    return { ...this.meta, totals: this.totals(), results: this.rows };
  }

  write(filePath) {
    const doc = this.finish();
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(doc, null, 2)}\n`);
    return doc;
  }

  humanSummary() {
    const byScenario = new Map();
    for (const r of this.rows) {
      if (!byScenario.has(r.scenario)) byScenario.set(r.scenario, []);
      byScenario.get(r.scenario).push(r);
    }
    const lines = [];
    lines.push(`AGENT-INTEGRATION CONFORMANCE — ${this.meta.suite}`);
    if (this.meta.server) {
      lines.push(`server: network=${this.meta.server.networkId} api=${this.meta.server.apiVersion}${this.meta.server.buildId ? ` build=${this.meta.server.buildId}` : ""}`);
    }
    lines.push(`paths: ${this.meta.paths.map((p) => p.id).join(", ")}`);
    for (const [scenario, rows] of byScenario) {
      lines.push(`  ${scenario}: ${rows.map((r) => `${r.path}=${r.outcome}`).join("  ")}`);
    }
    const t = this.totals();
    lines.push(`totals: ${Object.entries(t).map(([k, v]) => `${k}=${v}`).join("  ")}`);
    return lines.join("\n");
  }
}

module.exports = { ConformanceReport, RESULTS_SCHEMA };
