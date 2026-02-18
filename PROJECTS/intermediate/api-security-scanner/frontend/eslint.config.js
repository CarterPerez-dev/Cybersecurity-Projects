// ===================
// © AngelaMos | 2025
// eslint.config.js
// ===================
import js from '@eslint/js'
import prettierConfig from 'eslint-config-prettier'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: ['dist', 'vite.config.ts', '*.min.js', 'eslint.config.js'],
  },

  js.configs.recommended,

  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  {
    files: ['**/*.{ts,tsx}'],
    plugins: {
      react,
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
      'jsx-a11y': jsxA11y,
    },
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: ['./tsconfig.app.json', './tsconfig.node.json'],
        tsconfigRootDir: import.meta.dirname,
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    settings: {
      react: {
        version: 'detect',
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      '@typescript-eslint/explicit-function-return-type': [
        'error',
        {
          allowExpressions: true,
          allowTypedFunctionExpressions: true,
          allowHigherOrderFunctions: true,
          allowDirectConstAssertionInArrowFunctions: true,
          allowedNames: ['Component'],
        },
      ],
      '@typescript-eslint/naming-convention': 'off',
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/array-type': ['error', { default: 'array' }],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-confusing-void-expression': 'off',
      '@typescript-eslint/no-unnecessary-condition': 'off',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/strict-boolean-expressions': [
        'error',
        {
          allowString: false,
          allowNumber: false,
          allowNullableObject: false,
          allowNullableString: true,
          allowAny: true,
        },
      ],

      '@typescript-eslint/prefer-as-const': 'error',
      '@typescript-eslint/consistent-type-definitions': ['error', 'interface'],

      'react/prop-types': 'off',
      'react/jsx-uses-react': 'off',
      'react/react-in-jsx-scope': 'off',
      'react/jsx-no-leaked-render': ['error', { validStrategies: ['ternary'] }],
      'react/jsx-key': [
        'error',
        {
          checkFragmentShorthand: true,
          checkKeyMustBeforeSpread: true,
          warnOnDuplicates: true,
        },
      ],
      'react/jsx-no-useless-fragment': ['error', { allowExpressions: false }],
      'react/jsx-pascal-case': ['error', { allowAllCaps: false }],
      'react/no-array-index-key': 'warn',
      'react/no-unstable-nested-components': 'error',

      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',

      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],

      'jsx-a11y/alt-text': 'error',
      'jsx-a11y/anchor-has-content': 'error',
      'jsx-a11y/click-events-have-key-events': 'error',
      'jsx-a11y/no-static-element-interactions': 'error',

      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'no-debugger': 'error',
      'no-alert': 'error',
      'no-var': 'error',
      'prefer-const': 'error',
      'prefer-template': 'error',
      'object-shorthand': 'error',
      'no-nested-ternary': 'error',
      'max-depth': ['error', 6],
      'max-lines': [
        'error',
        { max: 2000, skipBlankLines: true, skipComments: true },
      ],
      complexity: ['error', 55],
    },
  },

  {
    files: ['src/main.tsx'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off', // Allow document.getElementById('root')!
    },
  },

  prettierConfig
)
