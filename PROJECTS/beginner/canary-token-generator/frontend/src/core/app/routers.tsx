// ===================
// ©AngelaMos | 2026
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
        lazy: () => import('@/pages/landing'),
      },
      {
        path: ROUTES.MANAGE,
        lazy: () => import('@/pages/manage'),
      },
      {
        path: '*',
        lazy: () => import('@/pages/notfound'),
      },
    ],
  },
]

export const router = createBrowserRouter(routes)
