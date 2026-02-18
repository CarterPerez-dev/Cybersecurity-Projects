/**
 * ©AngelaMos | 2025
 * Application routing configuration
 */

import { createBrowserRouter, Navigate } from 'react-router-dom'
import { ProtectedRoute } from '@/components/common/ProtectedRoute'
import { DashboardPage } from '@/pages/DashboardPage'
import { LoginPage } from '@/pages/LoginPage'
import { RegisterPage } from '@/pages/RegisterPage'
import { ScanResultsPage } from '@/pages/ScanResultsPage'

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/register',
    element: <RegisterPage />,
  },
  {
    path: '/',
    element: (
      <ProtectedRoute>
        <DashboardPage />
      </ProtectedRoute>
    ),
  },
  {
    path: '/scans/:id',
    element: (
      <ProtectedRoute>
        <ScanResultsPage />
      </ProtectedRoute>
    ),
  },
  {
    path: '*',
    element: <Navigate to="/" replace />,
  },
])
