/**
 * ©AngelaMos | 2025
 * Main application component
 */

import { QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { useEffect } from 'react'
import { RouterProvider } from 'react-router-dom'
import { Toaster } from 'sonner'
import { queryClient } from '@/lib/queryClient'
import { router } from '@/router'
import { useAuthStore } from '@/store/authStore'

const AuthInitializer = (): null => {
  const loadUserFromStorage = useAuthStore((state) => state.loadUserFromStorage)

  useEffect(() => {
    loadUserFromStorage()
  }, [loadUserFromStorage])

  return null
}

function App(): React.ReactElement {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthInitializer />
      <RouterProvider router={router} />
      <Toaster position="top-right" closeButton duration={4500} theme="dark" />
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  )
}

export default App
