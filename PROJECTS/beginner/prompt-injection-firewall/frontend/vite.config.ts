/**
 * ©AngelaMos | 2025
 * vite.config.ts
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
