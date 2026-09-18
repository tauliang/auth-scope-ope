/// <reference types="vite/client" />

// Minimal node ambient for vite.config.ts, which reads OPE_API from the
// environment. This keeps the web workspace free of a @types/node
// dependency for a single env lookup.
declare const process: {
  env: Record<string, string | undefined>;
};
