// ===========================
// ©AngelaMos | 2026
// App.tsx
// ===========================

import { QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { RouterProvider } from 'react-router-dom'
import { Toaster } from 'sonner'

import { queryClient } from '@/core/api'
import { router } from '@/core/app/routers'
import '@/core/app/toast.module.scss'

export default function App(): React.ReactElement {
  return (
    <QueryClientProvider client={queryClient}>
      <div className="app">
        <RouterProvider router={router} />
        <Toaster
          position="top-right"
          duration={2000}
          theme="dark"
          toastOptions={{
            style: {
              background: 'hsl(0, 0%, 12.2%)',
              border: '1px solid hsl(0, 0%, 18%)',
              color: 'hsl(0, 0%, 98%)',
            },
          }}
        />
      </div>
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  )
}
