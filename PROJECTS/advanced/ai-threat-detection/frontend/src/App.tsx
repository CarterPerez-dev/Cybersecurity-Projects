// ===================
// © AngelaMos | 2026
// App.tsx
//
// Root React component with providers and routing
//
// Wraps the application in QueryClientProvider (TanStack
// React Query), provides the browser router via
// RouterProvider, renders a dark-themed Sonner toast
// container at top-right styled by toast.scss design tokens,
// and includes ReactQueryDevtools in development mode
// ===================

import { QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { RouterProvider } from 'react-router-dom'
import { Toaster } from 'sonner'

import { queryClient } from '@/core/api'
import { router } from '@/core/app/routers'
import '@/core/app/toast.scss'

export default function App(): React.ReactElement {
  return (
    <QueryClientProvider client={queryClient}>
      <div className="app">
        <RouterProvider router={router} />
        <Toaster position="top-right" duration={2000} theme="dark" />
      </div>
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  )
}
