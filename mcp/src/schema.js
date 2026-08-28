"use strict";

/*
 * Minimal CLOSED-schema validator for MCP tool arguments.
 *
 * Zero dependencies by mission rule, so this implements exactly the JSON
 * Schema subset the tool catalog uses — nothing more, and every schema in
 * mcp/src/tools.js is written inside this subset:
 *
 *   type: "object" | "array" | "string" | "integer" | "boolean"
 *   properties / required / additionalProperties:false   (objects)
 *   items / minItems / maxItems                          (arrays)
 *   pattern / maxLength / enum                           (strings)
 *   minimum / maximum                                    (integers)
 *
 * FAIL-CLOSED SEMANTICS (the point of the exercise):
 *   - every object schema is CLOSED: unknown properties are refused, so a
 *     hostile or confused model cannot smuggle extra fields toward the API
 *     (including "__proto__"/"constructor" keys — own JSON properties are
 *     enumerated and refused like any other unknown key);
 *   - "integer" accepts ONLY a JSON number that is a safe integer — 1.5,
 *     NaN-ish text, 1e300 and "1" (string) all fail;
 *   - consensus amounts are NEVER JSON numbers in this catalog — they are
 *     decimal STRINGS with anchored patterns, so floats, negatives,
 *     exponents, leading zeros, unicode digits and confusables are refused
 *     by the pattern (all patterns are ASCII-anchored: any non-ASCII
 *     character fails);
 *   - depth and node-count caps refuse degenerate/oversized structures
 *     before any downstream work;
 *   - a schema node using an unsupported keyword/type is itself a refusal
 *     (defect surfaces loudly, never as silent acceptance).
 *
 * ERROR REPORTING / INJECTION STANCE: failure messages carry the JSON
 * path and the RULE that failed — never the offending value. Hostile
 * argument content therefore cannot ride back into model-visible text
 * through validation errors.
 */

const MAX_DEPTH = 16;
const MAX_NODES = 20000;

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function validateAgainstSchema(value, schema, path, errors, budget) {
  if (errors.length >= 8) return; // enough to act on; bounded output
  if (budget.nodes-- <= 0) {
    errors.push(`${path}: structure exceeds the node budget (${MAX_NODES})`);
    return;
  }
  if (budget.depth <= 0) {
    errors.push(`${path}: structure exceeds the depth limit (${MAX_DEPTH})`);
    return;
  }
  if (!isPlainObject(schema) || typeof schema.type !== "string") {
    errors.push(`${path}: schema node is invalid (unsupported form) — refusing`);
    return;
  }

  switch (schema.type) {
    case "object": {
      if (!isPlainObject(value)) {
        errors.push(`${path}: must be a JSON object`);
        return;
      }
      if (schema.additionalProperties !== false) {
        errors.push(`${path}: schema node is not CLOSED (additionalProperties must be false) — refusing`);
        return;
      }
      const props = schema.properties ?? {};
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(props, key)) {
          // The offending KEY is client-authored content and is NEVER
          // echoed (an identifier-shaped key can still carry injection
          // text); the permitted set is our own schema vocabulary.
          errors.push(`${path}: unknown property (closed schema; permitted: [${Object.keys(props).join(", ")}])`);
        }
      }
      for (const key of schema.required ?? []) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) {
          errors.push(`${path}.${key}: required property is missing`);
        }
      }
      for (const [key, sub] of Object.entries(props)) {
        if (Object.prototype.hasOwnProperty.call(value, key)) {
          validateAgainstSchema(value[key], sub, `${path}.${key}`, errors, { nodes: budget.nodes, depth: budget.depth - 1 });
        }
      }
      return;
    }
    case "array": {
      if (!Array.isArray(value)) {
        errors.push(`${path}: must be a JSON array`);
        return;
      }
      if (schema.minItems !== undefined && value.length < schema.minItems) {
        errors.push(`${path}: fewer than ${schema.minItems} item(s)`);
      }
      if (schema.maxItems !== undefined && value.length > schema.maxItems) {
        errors.push(`${path}: more than ${schema.maxItems} item(s)`);
        return; // refuse before walking a hostile mega-array
      }
      if (!isPlainObject(schema.items)) {
        errors.push(`${path}: schema node is invalid (array without items) — refusing`);
        return;
      }
      for (let i = 0; i < value.length; i++) {
        validateAgainstSchema(value[i], schema.items, `${path}[${i}]`, errors, { nodes: budget.nodes, depth: budget.depth - 1 });
        if (errors.length >= 8) return;
      }
      return;
    }
    case "string": {
      if (typeof value !== "string") {
        errors.push(`${path}: must be a string`);
        return;
      }
      if (schema.maxLength !== undefined && value.length > schema.maxLength) {
        errors.push(`${path}: longer than ${schema.maxLength} characters`);
        return;
      }
      if (schema.enum !== undefined && !schema.enum.includes(value)) {
        errors.push(`${path}: not one of the permitted values [${schema.enum.join(", ")}]`);
        return;
      }
      if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
        errors.push(`${path}: does not match the required pattern ${schema.pattern}`);
      }
      return;
    }
    case "integer": {
      if (typeof value !== "number" || !Number.isSafeInteger(value)) {
        errors.push(`${path}: must be a JSON integer (floats, strings, and unsafe magnitudes are refused)`);
        return;
      }
      if (schema.minimum !== undefined && value < schema.minimum) {
        errors.push(`${path}: below the minimum ${schema.minimum}`);
      }
      if (schema.maximum !== undefined && value > schema.maximum) {
        errors.push(`${path}: above the maximum ${schema.maximum}`);
      }
      return;
    }
    case "boolean": {
      if (typeof value !== "boolean") {
        errors.push(`${path}: must be true or false`);
      }
      return;
    }
    default:
      errors.push(`${path}: schema node uses unsupported type ${JSON.stringify(schema.type)} — refusing`);
  }
}

/*
 * validateToolArguments(args, inputSchema) -> { ok: true } |
 * { ok: false, errors: [...] }. `args` must already be a parsed JSON
 * value; the caller enforces the serialized-size cap BEFORE parsing work.
 */
function validateToolArguments(args, inputSchema) {
  const errors = [];
  validateAgainstSchema(args, inputSchema, "arguments", errors, { nodes: MAX_NODES, depth: MAX_DEPTH });
  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

module.exports = { validateToolArguments, MAX_DEPTH, MAX_NODES };
