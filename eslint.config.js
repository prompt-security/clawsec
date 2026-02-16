// NOTE: @eslint/js is pinned to ~9.x because v10 introduces a peerOptional
// dependency on eslint@^10, and the typescript-eslint / react plugin ecosystem
// hasn't published eslint-10-compatible releases yet. Upgrade @eslint/js to ^10
// once @typescript-eslint and eslint-plugin-react declare eslint@^10 support.
import js from '@eslint/js';
import typescript from '@typescript-eslint/eslint-plugin';
import typescriptParser from '@typescript-eslint/parser';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';

export default [
  js.configs.recommended,
  // TypeScript/React files
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: typescriptParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: { jsx: true }
      },
      globals: {
        // Browser globals
        console: 'readonly',
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        fetch: 'readonly',
        setTimeout: 'readonly',
        clearInterval: 'readonly',
        setInterval: 'readonly',
        URL: 'readonly',
        Response: 'readonly',
        HTMLElement: 'readonly',
        MouseEvent: 'readonly',
        KeyboardEvent: 'readonly',
        // Node.js globals (for Vite config, build scripts)
        process: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly'
      }
    },
    plugins: {
      '@typescript-eslint': typescript,
      'react': react,
      'react-hooks': reactHooks
    },
    rules: {
      ...typescript.configs.recommended.rules,
      ...react.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      'react/react-in-jsx-scope': 'off',
      'react/prop-types': 'off',
      'react/no-unescaped-entities': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/no-explicit-any': 'warn'
    },
    settings: {
      react: { version: 'detect' }
    }
  },
  // Node.js scripts (.mjs files)
  {
    files: ['**/*.mjs'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        setInterval: 'readonly',
        clearTimeout: 'readonly',
        clearInterval: 'readonly',
        URL: 'readonly'
      }
    },
    rules: {
      'no-empty': ['error', { allowEmptyCatch: true }]
    }
  },
  // Node.js scripts (.js files in scripts directory)
  {
    files: ['scripts/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        setInterval: 'readonly',
        clearTimeout: 'readonly',
        clearInterval: 'readonly',
        URL: 'readonly'
      }
    },
    rules: {
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }]
    }
  },
  {
    ignores: ['dist/', 'node_modules/', '*.config.js', 'public/']
  }
];
