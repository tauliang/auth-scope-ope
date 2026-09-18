import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      thresholds: {
        statements: 85,
        lines: 85,
        functions: 80,
        branches: 80,
      },
      exclude: [
        'src/main.tsx',
        'src/test/**',
        '**/*.test.*',
        'vite.config.ts',
        'vitest.config.ts',
      ],
    },
  },
});
