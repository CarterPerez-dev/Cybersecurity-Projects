/**
 * ©AngelaMos | 2026
 * vite.config.ts
 *
 * Vite build configuration with React plugin, path
 * aliases, dev proxy, SCSS preprocessing, and manual
 * chunk splitting
 *
 * Configures @vitejs/plugin-react and vite-tsconfig-paths
 * plugins, resolves @ alias to ./src, enables SCSS
 * preprocessing, and sets up a dev server on port 5173
 * with /api proxy to VITE_API_TARGET (fallback localhost
 * :8000) that strips the /api prefix. Production builds
 * target esnext with oxc minification, hidden sourcemaps,
 * and manual chunks splitting react-dom/react-router into
 * vendor-react, @tanstack/react-query into vendor-query,
 * and zustand into vendor-state. Environment variables are
 * loaded from the parent directory via loadEnv
 *
 * Connects to:
 *   src/App.tsx     - root application component
 *   src/config.ts   - VITE_API_URL consumed at runtime
 *   tsconfig.json   - path aliases resolved by plugin
 */

import path from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'
import tsconfigPaths from 'vite-tsconfig-paths'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, path.resolve(__dirname, '..'), '')
  const isDev = mode === 'development'

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
          target: env.VITE_API_TARGET || 'http://localhost:8000',
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api/, ''),
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
