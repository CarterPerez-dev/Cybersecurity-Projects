// ===================
// © AngelaMos | 2025
// protected-route.tsx
// ===================

import { Navigate, Outlet, useLocation } from 'react-router-dom'
import type { UserRole } from '@/api/types'
import { ROUTES } from '@/config'
import { useAuthStore } from '@/core/lib'

interface ProtectedRouteProps {
  allowedRoles?: UserRole[]
  redirectTo?: string
}

export function ProtectedRoute({
  allowedRoles,
  redirectTo = ROUTES.LOGIN,
}: ProtectedRouteProps): React.ReactElement {
  const location = useLocation()
  const { isAuthenticated, isLoading, user } = useAuthStore()

  if (isLoading) {
    return <div>Loading...</div>
  }

  if (!isAuthenticated) {
    return (
      <Navigate
        to={redirectTo}
        state={{ from: location.pathname + location.search }}
        replace
      />
    )
  }

  if (
    allowedRoles !== undefined &&
    allowedRoles.length > 0 &&
    user !== null &&
    !allowedRoles.includes(user.role)
  ) {
    return <Navigate to={ROUTES.UNAUTHORIZED} replace />
  }

  return <Outlet />
}
