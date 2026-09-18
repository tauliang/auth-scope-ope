// ESLint flat config for the OPE web UI. The lint script is
// `eslint . --max-warnings 0`: zero warnings tolerated.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: ['dist/', 'coverage/', 'node_modules/', '.vite/'],
  },
  {
    rules: {
      // The generated API client mirrors the OpenAPI document; its
      // index signatures are intentional.
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
);
