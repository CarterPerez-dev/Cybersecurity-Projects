// ===================
// © AngelaMos | 2026
// routers.tsx
//
// Browser router definition with lazy-loaded routes
// wrapped in a Shell layout
//
// Declares three route entries under a single Shell
// parent: ROUTES.HOME loads the landing page, ROUTES
// .ANALYSIS loads the analysis results page, and a
// wildcard catch-all falls back to landing. Both page
// components use React.lazy via react-router-dom's
// lazy() convention for code-split chunk loading
//
// Connects to:
//   config.ts       - ROUTES path constants
//   shell.tsx       - Shell layout wrapper
//   pages/landing   - lazy-loaded upload page
//   pages/analysis  - lazy-loaded results page
// ===================

import { createBrowserRouter, type RouteObject } from 'react-router-dom'
import { ROUTES } from '@/config'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    element: <Shell />,
    children: [
      {
        path: ROUTES.HOME,
        lazy: () => import('@/pages/landing'),
      },
      {
        path: ROUTES.ANALYSIS,
        lazy: () => import('@/pages/analysis'),
      },
      {
        path: '*',
        lazy: () => import('@/pages/landing'),
      },
    ],
  },
]

export const router = createBrowserRouter(routes)
