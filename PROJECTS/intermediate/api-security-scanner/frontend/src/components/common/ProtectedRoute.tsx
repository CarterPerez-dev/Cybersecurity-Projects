// ===========================
// ProtectedRoute.tsx
// ©AngelaMos | 2025
// ===========================

import { Navigate } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'

interface ProtectedRouteProps {
  children: React.ReactNode
}

export const ProtectedRoute = ({
  children,
}: ProtectedRouteProps): React.ReactElement => {
  const { isAuthenticated, isLoading } = useAuthStore()

  if (isLoading) {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          backgroundColor: '#000',
          color: '#fff',
        }}
      >
        <p>Loading...</p>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return children as React.ReactElement
}
