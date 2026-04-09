// ===================
// © AngelaMos | 2026
// routers.tsx
//
// Browser router with lazy-loaded page routes under the
// Shell layout
//
// Defines a createBrowserRouter with Shell as the root
// layout element containing 3 lazy-loaded child routes:
// dashboard (/), threats (/threats), and models (/models).
// Unknown paths redirect to the dashboard via Navigate
// ===================

import { createBrowserRouter, Navigate, type RouteObject } from 'react-router-dom'
import { ROUTES } from '@/config'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    element: <Shell />,
    children: [
      {
        path: ROUTES.DASHBOARD,
        lazy: () => import('@/pages/dashboard'),
      },
      {
        path: ROUTES.THREATS,
        lazy: () => import('@/pages/threats'),
      },
      {
        path: ROUTES.MODELS,
        lazy: () => import('@/pages/models'),
      },
    ],
  },
  {
    path: '*',
    element: <Navigate to={ROUTES.DASHBOARD} replace />,
  },
]

export const router = createBrowserRouter(routes)
