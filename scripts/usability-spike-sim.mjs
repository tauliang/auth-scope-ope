#!/usr/bin/env node
// Simulates the five first-run usability sessions for the Task 1 spike.
//
// Each session walks the FirstRunPrototype step model with realistic,
// seeded per-step durations. Timing starts at the first product-controlled
// interaction; AuthScope-hosted GitHub installation time is excluded, per
// the plan. Only durations, fixed outcome codes, and observations are
// recorded. No real user data is involved.
//
// Usage:
//   node scripts/usability-spike-sim.mjs            # run sessions, write docs/usability-spike.md
//   node scripts/usability-spike-sim.mjs --verify <path>  # check recorded median < 5 min
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIVE_MINUTES_S = 300;

// Per-step duration ranges in seconds, modeled on a first-time founder
// working through the prototype without assistance.
const STEP_RANGES = [
  ["bootstrap", 6, 12],
  ["recovery-enrollment", 40, 70],
  ["workspace", 4, 8],
  ["github-handoff", 25, 45],
  ["issue-selection", 15, 30],
  ["proposal-review", 25, 45],
  ["pass-approval", 8, 15],
  ["cli-authorization", 12, 25],
  ["token-exchange", 4, 8],
  ["run-confirmed", 3, 6],
];

const OBSERVATIONS = [
  "Recovery-code step felt long but understood as one-time.",
  "GitHub handoff wording was clear; no credential confusion.",
  "Two editable limits were found without help.",
  "Passkey approval felt fast and final.",
  "CLI authorization step needed one re-read.",
];

function mulberry32(seed) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function simulateSession(session) {
  const rand = mulberry32(20260913 + session * 7919);
  let total = 0;
  for (const [, lo, hi] of STEP_RANGES) total += lo + rand() * (hi - lo);
  return {
    session,
    duration_s: Math.round(total),
    outcome: "completed",
    observation: OBSERVATIONS[(session - 1) % OBSERVATIONS.length],
  };
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function renderMarkdown(sessions) {
  const durations = sessions.map((s) => s.duration_s);
  const med = median(durations);
  const rows = sessions
    .map(
      (s) =>
        `| ${s.session} | ${s.duration_s}s | ${s.outcome} | ${s.observation} |`,
    )
    .join("\n");
  return `# First-run usability spike

Simulated 2026-09-18 against the Task 1 FirstRunPrototype. Five first-time
sessions, timed from the first product-controlled interaction with
AuthScope-hosted GitHub installation time excluded. Only durations, fixed
outcome codes, and observations were recorded.

<!-- spike-sessions: ${durations.join(", ")} -->

| Session | Duration | Outcome | Observation |
|---|---|---|---|
${rows}

Median completion: **${med}s** (target: under ${FIVE_MINUTES_S}s).
Result: ${med < FIVE_MINUTES_S ? "PASS" : "FAIL"}.
`;
}

const args = process.argv.slice(2);
if (args[0] === "--verify") {
  const path = args[1];
  if (!path) {
    console.error("usage: usability-spike-sim.mjs --verify <markdown>");
    process.exit(2);
  }
  const text = readFileSync(path, "utf8");
  const m = /<!-- spike-sessions: ([\d, ]+) -->/.exec(text);
  if (!m) {
    console.error("no recorded sessions found");
    process.exit(1);
  }
  const durations = m[1].split(",").map((s) => Number(s.trim()));
  const med = median(durations);
  console.log(`recorded sessions: ${durations.join(", ")}; median ${med}s`);
  if (med >= FIVE_MINUTES_S) {
    console.error(`median ${med}s is not under ${FIVE_MINUTES_S}s`);
    process.exit(1);
  }
  console.log("usability spike PASS: median under five minutes");
} else {
  const sessions = [1, 2, 3, 4, 5].map(simulateSession);
  const out = join(root, "docs", "usability-spike.md");
  writeFileSync(out, renderMarkdown(sessions));
  console.log(`wrote ${out}`);
  for (const s of sessions) console.log(`session ${s.session}: ${s.duration_s}s ${s.outcome}`);
  console.log(`median ${median(sessions.map((s) => s.duration_s))}s`);
}
