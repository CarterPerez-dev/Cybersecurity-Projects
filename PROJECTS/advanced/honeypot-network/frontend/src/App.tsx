// ===================
// ©AngelaMos | 2026
// App.tsx
// ===================

import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from 'react-router-dom'
import { Toaster } from 'sonner'
import { queryClient } from '@/core/api'
import { router } from '@/core/app/router'

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <Toaster position="bottom-right" theme="dark" richColors />
    </QueryClientProvider>
  )
}
