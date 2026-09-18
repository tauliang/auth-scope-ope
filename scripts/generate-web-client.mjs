#!/usr/bin/env node
// Generates web/src/shared/api/generated.ts from openapi/ope-v1.yaml.
// Deterministic: the same input always produces byte-identical output.
// Usage: node scripts/generate-web-client.mjs [--check]
//
// --check regenerates to a temp file and diffs it against the committed
// generated.ts, failing when they differ (used by `make verify`).
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const specPath = join(root, "openapi", "ope-v1.yaml");
const outPath = join(root, "web", "src", "shared", "api", "generated.ts");

// Load js-yaml from the web workspace devDependencies.
const { createRequire } = await import("node:module");
const require = createRequire(join(root, "web", "package.json"));
const yaml = require("js-yaml");

const spec = yaml.load(readFileSync(specPath, "utf8"));
const schemas = (spec.components && spec.components.schemas) || {};

function tsType(schema, name) {
  if (!schema || typeof schema !== "object") return "unknown";
  if (schema.$ref) {
    const m = /^#\/components\/schemas\/([^/]+)$/.exec(schema.$ref);
    if (!m) throw new Error(`unsupported $ref ${schema.$ref} in ${name}`);
    return m[1];
  }
  if (schema.enum) return schema.enum.map((v) => JSON.stringify(v)).join(" | ");
  switch (schema.type) {
    case "string":
      return "string";
    case "integer":
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    case "array":
      return `${tsType(schema.items, name + "[]")}[]`;
    case "object": {
      const props = schema.properties || {};
      if (Object.keys(props).length === 0) return "Record<string, never>";
      const required = new Set(schema.required || []);
      const lines = Object.keys(props)
        .sort()
        .map((k) => `  ${k}${required.has(k) ? "" : "?"}: ${tsType(props[k], name + "." + k)};`);
      return `{\n${lines.join("\n")}\n}`;
    }
    default:
      return "unknown";
  }
}

const names = Object.keys(schemas).sort();
let out = `// Code generated from openapi/ope-v1.yaml by scripts/generate-web-client.mjs.
// Do not edit by hand; run \`node scripts/generate-web-client.mjs\` instead.

`;
for (const name of names) {
  const t = tsType(schemas[name], name);
  if (t.startsWith("{")) {
    out += `export interface ${name} ${t}\n\n`;
  } else {
    out += `export type ${name} = ${t};\n\n`;
  }
}

if (process.argv.includes("--check")) {
  const dir = mkdtempSync(join(tmpdir(), "ope-gen-"));
  try {
    const tmp = join(dir, "generated.ts");
    writeFileSync(tmp, out);
    execFileSync("diff", ["-u", outPath, tmp], { stdio: "inherit" });
    console.log("generated TypeScript client is clean");
  } catch (err) {
    console.error("generated TypeScript client is stale: run node scripts/generate-web-client.mjs");
    process.exit(1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
} else {
  writeFileSync(outPath, out);
  console.log(`wrote ${outPath}`);
}
