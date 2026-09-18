import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// OPE_API overrides the API target for the dev proxy. The e2e harness
// sets it per instance so two web servers can front two API servers.
//
// The API server pins the request host to the configured origin host,
// so the proxy must forward the browser's Host header unchanged;
// without changeOrigin: false the proxy rewrites Host to the API
// target and every mutation is rejected as a forbidden host.
const apiTarget = process.env.OPE_API ?? 'http://127.0.0.1:8080';
const apiProxy = {
  target: apiTarget,
  changeOrigin: false,
};

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': apiProxy,
      '/healthz': apiProxy,
      '/readyz': apiProxy,
    },
  },
});
