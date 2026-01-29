// ===================
// AngelaMos | 2026
// routers.tsx
// ===================

import { createBrowserRouter, type RouteObject } from 'react-router-dom'
import { UserRole } from '@/api/types'
import { ROUTES } from '@/config'
import { ProtectedRoute } from './protected-route'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    path: ROUTES.HOME,
    lazy: () => import('@/routes/landing'),
  },
  {
    path: ROUTES.LOGIN,
    lazy: () => import('@/routes/login'),
  },
  {
    path: ROUTES.REGISTER,
    lazy: () => import('@/routes/register'),
  },
  {
    element: <ProtectedRoute />,
    children: [
      {
        element: <Shell />,
        children: [
          {
            path: ROUTES.DASHBOARD,
            lazy: () => import('@/routes/dashboard'),
          },
          {
            path: ROUTES.SETTINGS,
            lazy: () => import('@/routes/settings'),
          },
          {
            path: ROUTES.PROGRAMS.LIST,
            lazy: () => import('@/routes/programs'),
          },
          {
            path: '/programs/:slug',
            lazy: () => import('@/routes/programs/[slug]'),
          },
          {
            path: '/programs/:slug/submit',
            lazy: () => import('@/routes/programs/[slug]/submit'),
          },
          {
            path: ROUTES.REPORTS.LIST,
            lazy: () => import('@/routes/reports'),
          },
          {
            path: '/reports/:id',
            lazy: () => import('@/routes/reports/[id]'),
          },
          {
            path: ROUTES.COMPANY.PROGRAMS,
            lazy: () => import('@/routes/company/programs'),
          },
          {
            path: ROUTES.COMPANY.NEW_PROGRAM,
            lazy: () => import('@/routes/company/programs/new'),
          },
          {
            path: '/company/programs/:slug/edit',
            lazy: () => import('@/routes/company/programs/[id]/edit'),
          },
          {
            path: ROUTES.COMPANY.INBOX,
            lazy: () => import('@/routes/company/inbox'),
          },
          {
            path: '/company/reports/:id',
            lazy: () => import('@/routes/company/reports/[id]'),
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
        children: [
          {
            path: ROUTES.ADMIN.DASHBOARD,
            lazy: () => import('@/routes/admin/stats'),
          },
          {
            path: ROUTES.ADMIN.USERS,
            lazy: () => import('@/routes/admin'),
          },
          {
            path: ROUTES.ADMIN.PROGRAMS,
            lazy: () => import('@/routes/admin/programs'),
          },
          {
            path: ROUTES.ADMIN.REPORTS,
            lazy: () => import('@/routes/admin/reports'),
          },
        ],
      },
    ],
  },
  {
    path: ROUTES.UNAUTHORIZED,
    lazy: () => import('@/routes/landing'),
  },
  {
    path: '*',
    lazy: () => import('@/routes/landing'),
  },
]

export const router = createBrowserRouter(routes)
