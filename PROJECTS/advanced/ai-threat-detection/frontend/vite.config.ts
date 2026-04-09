/**
 * ©AngelaMos | 2026
 * vite.config.ts
 *
 * Vite build configuration with dev proxy and manual chunk
 * splitting
 *
 * Loads environment from the parent directory via loadEnv,
 * resolves VITE_API_TARGET for the dev server proxy
 * (/api rewrite and /ws WebSocket passthrough), sets @ path
 * alias to src, enables SCSS preprocessing, builds to
 * esnext with oxc minification and hidden sourcemaps in
 * production, and splits vendor chunks into vendor-react
 * (react-dom, react-router), vendor-query (TanStack), and
 * vendor-state (zustand). Connects to src/main.tsx,
 * src/App.tsx, src/config.ts
 */

import path from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'
import tsconfigPaths from 'vite-tsconfig-paths'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, path.resolve(__dirname, '..'), '')
  const isDev = mode === 'development'
  const apiTarget =
    process.env.VITE_API_TARGET || env.VITE_API_TARGET || 'http://localhost:8000'

  return {
    plugins: [react(), tsconfigPaths()],

    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },

    css: {
      preprocessorOptions: {
        scss: {},
      },
    },

    server: {
      port: 5173,
      host: '0.0.0.0',
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api/, ''),
        },
        '/ws': {
          target: apiTarget,
          ws: true,
          changeOrigin: true,
        },
      },
    },

    build: {
      target: 'esnext',
      cssTarget: 'chrome100',
      sourcemap: isDev ? true : 'hidden',
      minify: 'oxc',
      rollupOptions: {
        output: {
          manualChunks(id: string): string | undefined {
            if (id.includes('node_modules')) {
              if (id.includes('react-dom') || id.includes('react-router')) {
                return 'vendor-react'
              }
              if (id.includes('@tanstack/react-query')) {
                return 'vendor-query'
              }
              if (id.includes('zustand')) {
                return 'vendor-state'
              }
            }
            return undefined
          },
        },
      },
    },

    preview: {
      port: 4173,
    },
  }
})
