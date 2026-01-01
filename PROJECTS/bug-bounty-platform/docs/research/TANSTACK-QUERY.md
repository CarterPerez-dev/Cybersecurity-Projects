# TanStack Query v5 production architecture for React + FastAPI in 2025

**TanStack Query v5 represents a significant evolution** with unified API signatures, stable Suspense support, and improved TypeScript inference. For a production React + Vite + FastAPI template, the architecture centers on centralized QueryClient configuration, feature-based hook organization using `queryOptions`, Zod runtime validation, Axios interceptors for JWT refresh, and layered error handling. The key insight: v5's `queryOptions` helper eliminates the need for custom wrapper hooks in most cases, while the removal of `onSuccess`/`onError` from queries pushes error handling to global QueryCache callbacks—a cleaner separation of concerns for production applications.

## V5 breaking changes demand immediate attention

The most impactful v5 change is the **unified object syntax**—all hooks now accept only a single object parameter. The old `useQuery(key, fn, options)` pattern is gone:

```typescript
// v4 (multiple signatures) → v5 (single object only)
useQuery(['todos'], fetchTodos, { staleTime: 5000 })  // ❌ Removed
useQuery({ queryKey: ['todos'], queryFn: fetchTodos, staleTime: 5000 })  // ✅ Required
```

**Critical renames** affect every v4 codebase: `cacheTime` becomes `gcTime` (garbage collection time), `isLoading` becomes `isPending` for status checks, and the new `isLoading` now equals `isPending && isFetching`. The `useErrorBoundary` option is now `throwOnError`, and `keepPreviousData` migrates to `placeholderData: keepPreviousData` import.

**Removed features** include query-level `onSuccess`, `onError`, and `onSettled` callbacks. Use global QueryCache callbacks instead:

```typescript
const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error, query) => {
      if (query.state.data !== undefined) {
        toast.error(`Background update failed: ${error.message}`)
      }
    }
  })
})
```

Infinite queries now **require `initialPageParam`**—it's no longer optional. A codemod exists for migration via `npx jscodeshift` with the `@tanstack/react-query` transform.

## QueryClient configuration for production workloads

The optimal production configuration balances freshness against network efficiency. The **5-minute staleTime default** suits most dashboard-style data, while static reference data like countries or categories should use `Infinity`:

```typescript
// src/core/api/query.config.ts
import { QueryClient, QueryCache, MutationCache } from '@tanstack/react-query'
import { ApiError, ApiErrorCode } from './errors'

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5,        // 5 minutes
      gcTime: 1000 * 60 * 30,          // 30 minutes
      retry: (failureCount, error) => {
        if (error instanceof ApiError) {
          // Don't retry auth or not-found errors
          if ([ApiErrorCode.AUTHENTICATION_ERROR, 
               ApiErrorCode.NOT_FOUND,
               ApiErrorCode.VALIDATION_ERROR].includes(error.code)) {
            return false
          }
        }
        return failureCount < 3
      },
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      refetchOnWindowFocus: true,      // Essential for data freshness
      refetchOnMount: true,
      refetchOnReconnect: true,
      networkMode: 'online',
      structuralSharing: true,         // Maintains referential equality
    },
    mutations: {
      retry: 0,                        // Mutations shouldn't auto-retry
      networkMode: 'online',
    },
  },
  queryCache: new QueryCache({
    onError: (error, query) => {
      // Only toast for background refetch failures
      if (query.state.data !== undefined) {
        toast.error(`Update failed: ${error.message}`)
      }
      Sentry.captureException(error, { extra: { queryKey: query.queryKey } })
    },
  }),
  mutationCache: new MutationCache({
    onError: (error, _variables, _context, mutation) => {
      if (!mutation.options.onError) {
        toast.error(`Operation failed: ${error.message}`)
      }
    },
  }),
})
```

**staleTime recommendations by data type**: Static data (Infinity), semi-static like user profile (**5-30 minutes**), frequently changing dashboard data (**30s-2 minutes**), real-time feeds (**0** with `refetchInterval`). The `gcTime` must exceed `staleTime` to enable instant rendering from cache while background refetch occurs.

## Axios remains the production choice for API configuration

Despite native fetch improvements, **Axios still leads** for production applications due to built-in interceptors, automatic JSON handling, and superior TypeScript support with `AxiosError` type narrowing. For bundle-conscious apps, consider `ky` (~3KB) or `wretch` (~2KB).

```typescript
// src/core/api/api.config.ts
import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig } from 'axios'

const getBaseURL = (): string => {
  const env = import.meta.env.MODE
  return import.meta.env.VITE_API_BASE_URL || ({
    development: '/api/v1',  // Uses Vite proxy
    staging: 'https://staging-api.example.com/api/v1',
    production: 'https://api.example.com/api/v1',
  }[env] || '/api/v1')
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})
```

The **Vite proxy configuration** eliminates CORS issues in development:

```typescript
// vite.config.ts
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
```

## JWT refresh flow belongs in Axios interceptors

The **hybrid approach** is optimal: token injection and refresh in Axios interceptors, network retry in TanStack Query. This keeps auth concerns centralized while leveraging TanStack Query's built-in retry for transient failures:

```typescript
// src/core/api/interceptors.ts
let isRefreshing = false
let refreshSubscribers: ((token: string) => void)[] = []

apiClient.interceptors.request.use((config) => {
  const token = tokenStorage.getAccessToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }
    
    if (error.response?.status === 401 && 
        !originalRequest._retry && 
        !originalRequest.url?.includes('/auth/refresh')) {
      
      if (isRefreshing) {
        // Queue requests during refresh
        return new Promise((resolve) => {
          refreshSubscribers.push((newToken) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`
            resolve(apiClient(originalRequest))
          })
        })
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        const { access_token, refresh_token } = await refreshTokens()
        tokenStorage.setAccessToken(access_token)
        if (refresh_token) tokenStorage.setRefreshToken(refresh_token)
        
        // Retry queued requests
        refreshSubscribers.forEach((cb) => cb(access_token))
        refreshSubscribers = []
        
        originalRequest.headers.Authorization = `Bearer ${access_token}`
        return apiClient(originalRequest)
      } catch {
        tokenStorage.clearTokens()
        window.location.href = '/login'
        return Promise.reject(error)
      } finally {
        isRefreshing = false
      }
    }
    return Promise.reject(transformAxiosError(error))
  }
)
```

## Query key factories with queryOptions define the modern pattern

The v5 `queryOptions` helper provides **type-safe query definitions** that work everywhere—`useQuery`, `useSuspenseQuery`, `prefetchQuery`, and cache operations. This replaces the need for custom hooks in many cases:

```typescript
// src/api/hooks/useUsers.ts
import { queryOptions, useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { userService } from '../services/users'

// Query key factory with embedded queryOptions
export const userQueries = {
  all: () => ['users'] as const,
  lists: () => [...userQueries.all(), 'list'] as const,
  list: (filters: { page?: number; limit?: number }) =>
    queryOptions({
      queryKey: [...userQueries.lists(), filters] as const,
      queryFn: () => userService.getAll(filters),
      staleTime: 1000 * 60 * 5,
    }),
  details: () => [...userQueries.all(), 'detail'] as const,
  detail: (id: number) =>
    queryOptions({
      queryKey: [...userQueries.details(), id] as const,
      queryFn: () => userService.getById(id),
      staleTime: 1000 * 60 * 2,
    }),
}

// Usage - type safety flows automatically
export const useUsers = (page = 1, limit = 10) => 
  useQuery(userQueries.list({ page, limit }))

export const useUser = (id: number) => 
  useQuery({ ...userQueries.detail(id), enabled: !!id })

// Cache operations are type-safe
const queryClient = useQueryClient()
queryClient.setQueryData(userQueries.detail(5).queryKey, updatedUser) // Typed!
```

**Hook organization follows feature-based structure**: queries and mutations co-located in feature folders, not a global `queryKeys.ts`. The pattern `todoKeys.all → todoKeys.lists() → todoKeys.list(filters)` enables hierarchical invalidation.

## Mutations require explicit callback separation

TanStack Query recommends **separating logic callbacks from UI callbacks**. Logic in `useMutation` runs even if the component unmounts; UI actions in `mutate()` call don't:

```typescript
export function useUpdateUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: userService.update,
    // Logic: always runs
    onMutate: async (newData) => {
      await queryClient.cancelQueries({ queryKey: userQueries.detail(newData.id).queryKey })
      const previousUser = queryClient.getQueryData(userQueries.detail(newData.id).queryKey)
      queryClient.setQueryData(userQueries.detail(newData.id).queryKey, (old) => ({ ...old, ...newData }))
      return { previousUser }
    },
    onError: (err, newData, context) => {
      queryClient.setQueryData(userQueries.detail(newData.id).queryKey, context?.previousUser)
    },
    onSettled: (data, error, variables) => {
      queryClient.invalidateQueries({ queryKey: userQueries.detail(variables.id).queryKey })
    },
  })
}

// Component usage
const updateUser = useUpdateUser()
updateUser.mutate(userData, {
  // UI: only runs if component still mounted
  onSuccess: () => navigate('/users'),
})
```

**Optimistic updates via UI** (using `mutation.variables` in render) is simpler than cache manipulation for many cases, with automatic cleanup on error.

## Zod validates at the API boundary for type safety

**Validate in the query function**, not in components. Zod remains the recommended choice for 2025 due to ecosystem maturity, though Valibot offers 90%+ smaller bundles:

```typescript
// src/api/types/user.types.ts
import { z } from 'zod'

export const userSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  firstName: z.string(),
  lastName: z.string(),
  role: z.enum(['admin', 'user', 'guest']),
  createdAt: z.string().datetime(),
})

export const usersResponseSchema = z.object({
  data: z.array(userSchema),
  total: z.number(),
  page: z.number(),
})

export type User = z.infer<typeof userSchema>
export type UsersResponse = z.infer<typeof usersResponseSchema>

// src/api/services/users.ts
export const userService = {
  getAll: async (params: { page?: number; limit?: number }): Promise<UsersResponse> => {
    const response = await apiClient.get('/users', { params })
    return usersResponseSchema.parse(response.data) // Runtime validation
  },
  getById: async (id: number): Promise<User> => {
    const response = await apiClient.get(`/users/${id}`)
    return userSchema.parse(response.data)
  },
}
```

**Validation errors should be caught and transformed** into actionable API errors, not allowed to crash the application. Use `safeParse` when you need graceful handling.

## Error handling flows through three layers

The production pattern establishes **three error handling layers**: Axios interceptor transforms errors, QueryCache handles global concerns, and component-level handles specific UI:

```typescript
// src/core/api/errors.ts
export enum ApiErrorCode {
  NETWORK_ERROR = 'NETWORK_ERROR',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  NOT_FOUND = 'NOT_FOUND',
  SERVER_ERROR = 'SERVER_ERROR',
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly code: ApiErrorCode,
    public readonly statusCode: number,
    public readonly details?: Record<string, string[]>
  ) {
    super(message)
    this.name = 'ApiError'
  }

  getUserMessage(): string {
    const messages: Record<ApiErrorCode, string> = {
      [ApiErrorCode.NETWORK_ERROR]: 'Unable to connect. Check your internet.',
      [ApiErrorCode.VALIDATION_ERROR]: 'Please check your input.',
      [ApiErrorCode.AUTHENTICATION_ERROR]: 'Session expired. Please log in.',
      [ApiErrorCode.NOT_FOUND]: 'Resource not found.',
      [ApiErrorCode.SERVER_ERROR]: 'Something went wrong. Try again.',
    }
    return messages[this.code] || this.message
  }
}

// Register global error type
declare module '@tanstack/react-query' {
  interface Register {
    defaultError: ApiError
  }
}
```

**throwOnError configuration** determines Error Boundary behavior. Use a function for granular control: `throwOnError: (error) => error.statusCode >= 500` sends only server errors to boundaries.

## Loading states changed significantly in v5

The **naming changes** affect every component: v4's `isLoading` (no data yet) is now `isPending`, while v5's `isLoading` means `isPending && isFetching` (first fetch in flight). Use `isRefetching` (equals `isFetching && !isPending`) for background update indicators:

```typescript
function UserList() {
  const { data, isPending, isFetching, isRefetching } = useQuery(userQueries.list({}))

  if (isPending) return <Skeleton />  // Initial load
  
  return (
    <div className={isRefetching ? 'opacity-75' : ''}>
      {data.map(user => <UserCard key={user.id} {...user} />)}
      {isRefetching && <RefreshIndicator />}
    </div>
  )
}
```

**placeholderData with keepPreviousData** prevents loading flicker during pagination:

```typescript
import { keepPreviousData } from '@tanstack/react-query'

const { data, isPlaceholderData } = useQuery({
  queryKey: ['users', page],
  queryFn: () => fetchUsers(page),
  placeholderData: keepPreviousData,
})
```

## Suspense is production-ready with dedicated hooks

**useSuspenseQuery is now stable** in v5 and guarantees `data` is never undefined. The key difference: `enabled`, `placeholderData`, and error callbacks aren't available—use component composition for conditional queries:

```typescript
import { useSuspenseQuery, QueryErrorResetBoundary } from '@tanstack/react-query'
import { ErrorBoundary } from 'react-error-boundary'

function UserProfile({ userId }: { userId: number }) {
  const { data } = useSuspenseQuery(userQueries.detail(userId))
  // data is User, never undefined
  return <div>{data.firstName}</div>
}

// Parent provides Suspense and Error boundaries
function UserProfilePage({ userId }: { userId: number }) {
  return (
    <QueryErrorResetBoundary>
      {({ reset }) => (
        <ErrorBoundary onReset={reset} fallbackRender={({ resetErrorBoundary }) => (
          <button onClick={resetErrorBoundary}>Retry</button>
        )}>
          <Suspense fallback={<Skeleton />}>
            <UserProfile userId={userId} />
          </Suspense>
        </ErrorBoundary>
      )}
    </QueryErrorResetBoundary>
  )
}
```

**Avoid waterfall requests** with `useSuspenseQueries` for parallel data fetching within Suspense boundaries.

## Caching strategies vary by data volatility

| Data Type | staleTime | gcTime | Strategy |
|-----------|-----------|--------|----------|
| Static reference (countries) | `Infinity` | `Infinity` | Fetch once, cache forever |
| User profile | 5-30 min | 1 hour | Background refresh on focus |
| Dashboard metrics | 30s-2 min | 10 min | Frequent background updates |
| Real-time (prices) | 0 | 1-5 min | Use `refetchInterval` |

**Prefetching on hover** improves perceived performance dramatically:

```typescript
function UserLink({ userId }: { userId: number }) {
  const queryClient = useQueryClient()
  
  const prefetch = () => {
    queryClient.prefetchQuery(userQueries.detail(userId))
  }

  return (
    <Link 
      to={`/users/${userId}`}
      onMouseEnter={prefetch}
      onFocus={prefetch}
    >
      View User
    </Link>
  )
}
```

## Offline support uses persistence plugins

For offline-first applications, combine `PersistQueryClientProvider` with LocalStorage (small caches) or IndexedDB (large datasets):

```typescript
import { PersistQueryClientProvider } from '@tanstack/react-query-persist-client'
import { createSyncStoragePersister } from '@tanstack/query-sync-storage-persister'

const persister = createSyncStoragePersister({
  storage: window.localStorage,
  key: 'QUERY_CACHE',
  throttleTime: 1000,
})

// gcTime must match or exceed persistence maxAge
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { gcTime: 1000 * 60 * 60 * 24 },  // 24 hours
  },
})

function App() {
  return (
    <PersistQueryClientProvider 
      client={queryClient}
      persistOptions={{ 
        persister, 
        maxAge: 1000 * 60 * 60 * 24,
        buster: APP_VERSION,  // Invalidate on version change
      }}
    >
      <YourApp />
    </PersistQueryClientProvider>
  )
}
```

## WebSocket integration updates cache directly

For real-time features, **update the query cache from WebSocket events**. Use `setQueryData` for frequent small updates, `invalidateQueries` for complex state changes:

```typescript
useEffect(() => {
  const socket = io(WS_URL)
  
  socket.on('user:updated', (user: User) => {
    queryClient.setQueryData(userQueries.detail(user.id).queryKey, user)
    queryClient.setQueryData(userQueries.list({}).queryKey, (old) => 
      old?.data.map(u => u.id === user.id ? user : u)
    )
  })
  
  socket.on('user:created', () => {
    queryClient.invalidateQueries({ queryKey: userQueries.lists() })
  })
  
  return () => socket.disconnect()
}, [queryClient])
```

## Testing patterns use QueryClient wrapper

```typescript
// test-utils.tsx
const createTestQueryClient = () => new QueryClient({
  defaultOptions: {
    queries: { retry: false, gcTime: Infinity },
  },
})

export function renderWithClient(ui: React.ReactElement) {
  const testQueryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={testQueryClient}>
      {ui}
    </QueryClientProvider>
  )
}

// With MSW for API mocking
import { setupServer } from 'msw/node'
import { http, HttpResponse } from 'msw'

const server = setupServer(
  http.get('/api/users/:id', ({ params }) => 
    HttpResponse.json({ id: params.id, name: 'Test User' })
  )
)
```

## DevTools load conditionally in production

DevTools are **automatically excluded in production builds**. For on-demand production debugging, lazy-load from the production bundle:

```typescript
const ReactQueryDevtoolsProduction = lazy(() =>
  import('@tanstack/react-query-devtools/production').then((d) => ({
    default: d.ReactQueryDevtools,
  }))
)

// Toggle with window.toggleDevtools() in console
```

## Recommended file structure synthesizes all patterns

```
src/
├── core/
│   └── api/
│       ├── query.config.ts     # QueryClient with defaults
│       ├── api.config.ts       # Axios instance + base config
│       ├── interceptors.ts     # Auth + error interceptors
│       └── errors.ts           # ApiError class + transformer
├── api/
│   ├── hooks/
│   │   ├── useUsers.ts         # Query factories + hooks + mutations
│   │   ├── usePosts.ts
│   │   └── useAuth.ts
│   ├── services/
│   │   ├── users.ts            # Type-safe API functions with Zod
│   │   ├── posts.ts
│   │   └── auth.ts
│   └── types/
│       ├── user.types.ts       # Zod schemas + inferred types
│       ├── post.types.ts
│       └── common.types.ts     # Shared schemas (pagination, etc.)
├── components/
│   └── providers/
│       └── QueryProvider.tsx   # QueryClientProvider + DevTools
└── App.tsx
```

## Conclusion

Building a production TanStack Query v5 architecture requires embracing the **unified object API**, leveraging `queryOptions` for type-safe query definitions, and establishing clear boundaries between API configuration (Axios interceptors), caching behavior (QueryClient defaults), and UI concerns (component-level error handling). The removal of per-query callbacks in v5 isn't a limitation—it's a forcing function toward cleaner global error handling via QueryCache. 

The key anti-patterns to avoid: storing JWTs in localStorage (use HttpOnly cookies + memory), over-using custom hooks when `queryOptions` suffices, handling auth refresh in TanStack Query's retry logic (interceptors are cleaner), and neglecting `staleTime` configuration (the default `0` causes excessive refetching). For FastAPI backends, the Axios + Zod combination provides the strongest type safety from API response to component render.
