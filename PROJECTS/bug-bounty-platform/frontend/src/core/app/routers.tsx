// ===================
// © AngelaMos | 2025
// routers.tsx
// ===================

import { createBrowserRouter, type RouteObject } from 'react-router-dom'
import { UserRole } from '@/api/types'
import { ROUTES } from '@/config'
import { ProtectedRoute } from './protected-route'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    element: <ProtectedRoute />,
    children: [
      {
        element: <Shell />,
        children: [
          {
            path: ROUTES.HOME,
            lazy: () => import('@/pages/home'),
          },
          {
            path: ROUTES.DASHBOARD,
            lazy: () => import('@/pages/home'),
          },
          {
            path: ROUTES.SETTINGS,
            lazy: () => import('@/pages/home'),
          },
        ],
      },
    ],
  },
  {
    element: <ProtectedRoute allowedRoles={[UserRole.ADMIN]} />,
    children: [
      {
        element: <Shell />,
        children: [],
      },
    ],
  },
  {
    path: ROUTES.LOGIN,
    lazy: () => import('@/pages/home'),
  },
  {
    path: ROUTES.REGISTER,
    lazy: () => import('@/pages/home'),
  },
  {
    path: ROUTES.UNAUTHORIZED,
    lazy: () => import('@/pages/home'),
  },
]

export const router = createBrowserRouter(routes)
