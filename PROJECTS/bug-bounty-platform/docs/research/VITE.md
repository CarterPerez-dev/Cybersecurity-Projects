# Production-ready React + Vite 6 template for 2025

A senior frontend engineer building a reusable FastAPI + React + TypeScript template in 2025 should use **Vite 6** with **pnpm**, **Biome** for linting/formatting, **Zustand** for client state, **TanStack Query** for server state, and **Tailwind CSS v4** for styling. This configuration prioritizes developer experience, build performance, and production reliability while avoiding over-engineering.

The most significant shift in 2025 is the consolidation of tooling: Biome replaces ESLint + Prettier with **35x faster performance**, ESLint's flat config (`eslint.config.js`) is now mandatory, and Vite 6's Environment API enables better SSR handling. TypeScript's `moduleResolution: "bundler"` is the correct setting for Vite projects, and the `splitVendorChunkPlugin` has been deprecated in favor of manual chunks.

## Vite 6 brings breaking changes that matter

Vite 6 introduced several breaking changes from Vite 5 that affect production templates. The `resolve.conditions` default now explicitly includes `['module', 'browser', 'development|production']`, affecting how packages resolve. JSON stringify behavior changed to `'auto'` mode, and Sass now uses the modern API by default—the legacy API was removed entirely in Vite 7.

A production-ready `vite.config.ts` should handle environment-specific builds, FastAPI proxy setup, and proper chunk splitting:

```typescript
import { defineConfig, loadEnv, type PluginOption } from 'vite'
import react from '@vitejs/plugin-react'
import tsconfigPaths from 'vite-tsconfig-paths'
import { visualizer } from 'rollup-plugin-visualizer'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const isProduction = mode === 'production'
  
  return {
    base: env.VITE_BASE_URL || '/',
    plugins: [
      react(),
      tsconfigPaths(),
      isProduction && visualizer({
        open: true,
        gzipSize: true,
        brotliSize: true,
      }) as PluginOption,
    ].filter(Boolean),
    
    build: {
      target: 'ES2022',
      sourcemap: isProduction ? 'hidden' : true,
      minify: 'esbuild',
      rollupOptions: {
        output: {
          manualChunks: {
            'react-vendor': ['react', 'react-dom'],
            'router': ['react-router-dom'],
          },
        },
      },
    },
    
    server: {
      port: 3000,
      proxy: {
        '/api': {
          target: 'http://localhost:8000',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  }
})
```

The `splitVendorChunkPlugin` was deprecated and removed in Vite 7—use `manualChunks` for vendor splitting. Source maps should be `'hidden'` in production to enable error tracking while preventing source code exposure.

## TypeScript configuration requires the bundler resolution strategy

Vite projects require `moduleResolution: "bundler"` rather than `node16`, enabling extensionless imports and proper handling of package.json exports. The multi-file tsconfig approach separates browser (app) and Node.js (config) environments:

```json
// tsconfig.app.json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "strict": true,
    "noEmit": true,
    "verbatimModuleSyntax": true,
    "erasableSyntaxOnly": true,
    "baseUrl": ".",
    "paths": { "@/*": ["./src/*"] }
  },
  "include": ["src"]
}
```

Key TypeScript 5.x features worth enabling include **verbatimModuleSyntax** (enforces explicit type imports), **erasableSyntaxOnly** (ensures transpiler compatibility), and **noUncheckedSideEffectImports** (catches missing side-effect imports). The `vite-tsconfig-paths` plugin automatically syncs path aliases between TypeScript and Vite.

Type-safe environment variables require a declaration file:

```typescript
// src/vite-env.d.ts
interface ImportMetaEnv {
  readonly VITE_API_URL: string
  readonly VITE_APP_TITLE: string
}
```

## Biome replaces ESLint and Prettier with dramatic speed gains

**Biome is production-ready in 2025** with 800,000+ weekly npm downloads, 97% Prettier compatibility, and 35x faster performance than ESLint + Prettier combined. Major companies including Shopify, Airbnb, and Mercedes-Benz use it in production.

```json
// biome.json
{
  "$schema": "https://biomejs.dev/schemas/1.0.0/schema.json",
  "formatter": {
    "indentStyle": "space",
    "indentWidth": 2,
    "lineWidth": 100
  },
  "linter": {
    "rules": {
      "recommended": true,
      "correctness": { "noUnusedVariables": "error" }
    }
  },
  "organizeImports": { "enabled": true }
}
```

Migration from ESLint is straightforward: `npx @biomejs/biome migrate eslint --write`. For teams not ready to switch, ESLint's **flat config** (`eslint.config.js`) is now mandatory—the legacy `.eslintrc` format will be removed in ESLint 10. Use `typescript-eslint` with `eslint-plugin-react`, `eslint-plugin-react-hooks`, and `eslint-plugin-jsx-a11y` for accessibility.

**Oxlint** (50-100x faster than ESLint, written in Rust) reached 1.0 stability and can complement ESLint using `eslint-plugin-oxlint` to disable overlapping rules.

## Project structure should be feature-based for scalability

Feature-based organization groups related code by domain, enabling independent team workflows:

```
src/
├── features/           # Domain modules
│   ├── auth/
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── api/
│   │   └── types.ts
│   └── posts/
├── components/ui/      # Shared primitives (Button, Modal)
├── hooks/              # Shared custom hooks
├── lib/
│   ├── api/client.ts   # Axios instance with interceptors
│   └── query/          # TanStack Query config
├── stores/             # Zustand stores
└── types/              # Global TypeScript types
```

**State management hierarchy for 2025**: Use **TanStack Query** for all server state (API data caching), **Zustand** (~2.5KB) for global client state, and **React Context** only for simple shared state like themes. Never store fetched API data in Zustand—let React Query handle caching.

The Zustand pattern with persistence:

```typescript
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const useAuthStore = create()(
  persist(
    (set) => ({
      user: null,
      token: null,
      login: (user, token) => set({ user, token }),
      logout: () => set({ user: null, token: null }),
    }),
    { name: 'auth-storage', partialize: (s) => ({ token: s.token }) }
  )
)
```

## Package managers and enterprise tooling choices

**pnpm** is the recommended package manager for production: 70% disk space savings, strict dependency resolution preventing phantom dependencies, and excellent monorepo support. Benchmarks show pnpm with cache/lockfile completing installs in **761ms** versus npm's 1.3s.

| Tool | Recommendation |
|------|----------------|
| Package manager | **pnpm** (or Bun for new projects) |
| Git hooks | **Lefthook** (parallel execution, Go binary) |
| Formatting/linting | **Biome** (or ESLint flat config + Prettier) |
| Testing | **Vitest** with React Testing Library |
| API mocking | **MSW 2.0** for dev and testing |
| Dep updates | **Renovate** (superior to Dependabot for monorepos) |

Essential config files for a production template:
- `.editorconfig` — Cross-IDE consistency, still relevant
- `.nvmrc` — Node version pinning (critical for CI/CD)
- `browserslist` in package.json — Target browser specification
- `lefthook.yml` — Pre-commit linting and type checking

Skip Stylelint when using Tailwind CSS—the Tailwind IntelliSense VS Code extension provides sufficient class ordering.

## Production hardening requires deliberate security measures

**Error tracking** with Sentry requires the `@sentry/vite-plugin` to upload source maps, with `filesToDeleteAfterUpload` to prevent source code leakage:

```typescript
sentryVitePlugin({
  sourcemaps: {
    filesToDeleteAfterUpload: ["./**/*.map"],
  },
})
```

**Critical security practices**:
- Never put secrets in `VITE_` environment variables—they're embedded in the client bundle
- Use `sourcemap: 'hidden'` in production (creates maps for error tracking without exposing them)
- Implement CSP headers via your server/CDN, not meta tags
- React auto-escapes JSX, but never use `dangerouslySetInnerHTML` with user input

**Web Vitals tracking** is essential. The core metrics for 2025 are LCP (<2.5s), INP (<200ms, replaced FID), and CLS (<0.1). Use the attribution build (`web-vitals/attribution`) for debugging performance issues.

For bundle optimization, use `rollup-plugin-visualizer` to identify bloat, implement route-based lazy loading with `React.lazy()`, and preload routes on hover for faster transitions.

## Cutting-edge tools: what's actually production-ready

| Tool | Status | Recommendation |
|------|--------|----------------|
| **Biome** | ✅ Production-ready | Use it—replaces ESLint + Prettier |
| **Bun** | ✅ Stable for package management | Viable alternative to pnpm |
| **Oxlint** | ✅ 1.0 stable | Complement ESLint for speed |
| **Lightning CSS** | ✅ Stable in Vite | Skip if using Tailwind (requires PostCSS) |
| **Rspack** | ✅ 1.0 production-ready | Drop-in Webpack replacement |
| **Turbopack** | ⚠️ Next.js only, alpha for prod | Wait for broader ecosystem support |

Lightning CSS provides 100x faster CSS processing than PostCSS but isn't compatible with Tailwind CSS. Use it only for vanilla CSS workflows.

## CI/CD pipeline essentials

A production CI pipeline should include type checking, linting, bundle size monitoring, and Lighthouse audits:

```yaml
- run: pnpm install --frozen-lockfile
- run: pnpm typecheck      # tsc --noEmit
- run: pnpm lint           # biome ci
- run: pnpm build
- run: lhci autorun        # Lighthouse CI
```

Use **compressed-size-action** or **size-limit** for bundle size monitoring to catch regressions before deployment. Lighthouse CI with performance budgets (`categories:performance > 0.9`) prevents performance degradation.

**Renovate** is superior to Dependabot for monorepos, offering advanced grouping, a dependency dashboard, and support for 90+ package managers versus Dependabot's 14.

## Essential plugins for a production Vite template

```typescript
plugins: [
  react(),
  tsconfigPaths(),                    // Path alias sync
  svgr({ include: '**/*.svg?react' }), // SVG as components
  checker({ typescript: true }),       // Dev-time type errors
  VitePWA({ registerType: 'autoUpdate' }), // If PWA needed
  isProduction && visualizer(),        // Bundle analysis
]
```

Include PWA support only when offline capability or installability adds genuine user value—it introduces complexity that many applications don't need.

## The complete recommended stack

For a senior-level, production-ready React + Vite 6 + FastAPI template in 2025:

- **Build tool**: Vite 6 with `manualChunks` for vendor splitting
- **Package manager**: pnpm with strict lockfile
- **TypeScript**: Strict mode, `moduleResolution: "bundler"`, path aliases
- **Linting/formatting**: Biome (or ESLint flat config + Prettier)
- **Styling**: Tailwind CSS v4 with CSS-first configuration
- **State**: TanStack Query (server) + Zustand (client)
- **Routing**: React Router v6 with lazy loading
- **Testing**: Vitest + React Testing Library + MSW
- **Error tracking**: Sentry with hidden source maps
- **Git hooks**: Lefthook + lint-staged
- **CI/CD**: Type check → Lint → Build → Lighthouse

This configuration balances modern tooling with production stability, avoiding bleeding-edge tools that haven't proven enterprise reliability while embracing genuinely superior alternatives like Biome that have earned industry trust.
