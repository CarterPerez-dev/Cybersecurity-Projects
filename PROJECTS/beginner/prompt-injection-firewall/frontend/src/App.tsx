// ===========================
// ©AngelaMos | 2026
// App.tsx
// ===========================

import { QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { RouterProvider } from 'react-router-dom'
import { Toaster } from 'sonner'

import { TOAST } from '@/config'
import { queryClient } from '@/core/api'
import { router } from '@/core/app/routers'
import toastStyles from '@/core/app/toast.module.scss'

export default function App(): React.ReactElement {
  return (
    <QueryClientProvider client={queryClient}>
      <div className="app">
        <RouterProvider router={router} />
        <Toaster
          position={TOAST.POSITION}
          duration={TOAST.DURATION}
          toastOptions={{
            unstyled: true,
            classNames: {
              toast: toastStyles.toast,
              title: toastStyles.toastTitle,
            },
          }}
        />
      </div>
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  )
}
