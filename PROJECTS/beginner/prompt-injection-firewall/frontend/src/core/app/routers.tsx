// ===================
// © AngelaMos | 2026
// routers.tsx
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
        lazy: () => import('@/pages/arena'),
      },
      {
        path: '*',
        lazy: () => import('@/pages/arena'),
      },
    ],
  },
]

export const router = createBrowserRouter(routes)
