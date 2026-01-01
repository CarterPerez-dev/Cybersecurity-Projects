# React 19 Production Architecture Guide for Vite SPA (2025)

Building a modern React 19 application with Vite, TanStack Query, Zustand, and React Router requires understanding significant new features and architectural patterns that have matured in 2025. This guide provides senior-level recommendations for your FastAPI template based on comprehensive research of current best practices.

## React 19 delivers production-ready improvements

React 19 (stable since December 2024) introduces **Actions** for async data mutations, new hooks (`useActionState`, `useOptimistic`, `use()`), and refs as regular props without `forwardRef`. The React Compiler reached v1.0 in October 2025 and is now production-ready, automatically handling memoization that developers previously managed with `useMemo` and `useCallback`.

The most impactful changes for your SPA architecture are the new form handling primitives and the elimination of `forwardRef` boilerplate. Server Components remain framework-only (Next.js, Remix) and aren't relevant for Vite SPAs.

### Key React 19 features to adopt immediately

**Actions and async transitions** fundamentally change mutation handling. The `useTransition` hook now supports async functions directly:

```tsx
function UpdateProfile() {
  const [isPending, startTransition] = useTransition();

  const handleSubmit = () => {
    startTransition(async () => {
      const error = await updateProfile(formData);
      if (error) setError(error);
    });
  };
}
```

**`useActionState`** (renamed from `useFormState`) provides built-in pending states and error handling for forms:

```tsx
const [error, submitAction, isPending] = useActionState(
  async (prevState, formData) => {
    const result = await createItem(formData.get('name'));
    return result.error ?? null;
  },
  null
);

return (
  <form action={submitAction}>
    <input name="name" />
    <button disabled={isPending}>Create</button>
    {error && <p>{error}</p>}
  </form>
);
```

**`useOptimistic`** enables instant UI feedback while async operations complete—React automatically reverts on failure:

```tsx
const [optimisticItems, addOptimistic] = useOptimistic(items, 
  (state, newItem) => [...state, { ...newItem, pending: true }]
);
```

**Refs as props** eliminates `forwardRef` boilerplate entirely:

```tsx
// React 19 - ref is just a prop now
function MyInput({ placeholder, ref }: { placeholder: string; ref?: Ref<HTMLInputElement> }) {
  return <input ref={ref} placeholder={placeholder} />;
}
```

### React Compiler is production-ready

The React Compiler v1.0 (October 2025) automatically adds memoization at build time, eliminating most manual `useMemo`, `useCallback`, and `React.memo` usage. For Vite, enable it via Babel:

```ts
// vite.config.ts
export default defineConfig({
  plugins: [
    react({
      babel: {
        plugins: ['babel-plugin-react-compiler'],
      },
    }),
  ],
});
```

Run `npx react-compiler-healthcheck@latest` before enabling—your code must follow React's rules (pure components, hooks rules). **For new projects, enable the compiler. For existing code with manual memoization, keep existing optimizations temporarily** while the compiler handles new code.

---

## Entry point and provider architecture

### main.tsx best practices

StrictMode has **zero performance impact in production**—it only runs development checks. Always enable it. React 19 adds new error handling callbacks to `createRoot`:

```tsx
// main.tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ErrorBoundary } from 'react-error-boundary';
import App from './App';
import './styles.css';

// Initialize monitoring BEFORE React renders
import { initMonitoring } from './lib/monitoring';
initMonitoring();

const root = createRoot(document.getElementById('root')!, {
  // React 19: new error callbacks
  onUncaughtError: (error, info) => {
    monitoring.captureError(error, { componentStack: info.componentStack });
  },
  onCaughtError: (error, info) => {
    monitoring.captureError(error, { severity: 'warning' });
  },
});

root.render(
  <StrictMode>
    <ErrorBoundary FallbackComponent={GlobalErrorFallback}>
      <App />
    </ErrorBoundary>
  </StrictMode>
);

// Service worker registration after render
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  import('virtual:pwa-register').then(({ registerSW }) => {
    registerSW({ immediate: true });
  });
}
```

### Provider ordering matters

Providers can only access context from providers **above** them in the tree. The recommended order (outside → inside): QueryClient → Router → Auth → Theme → Error Boundary → Suspense.

```tsx
// App.tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider, createBrowserRouter } from 'react-router-dom';
import { Toaster } from 'sonner';
import { routes } from './routes';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 60_000 },
  },
});

const router = createBrowserRouter(routes);

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <Toaster richColors position="top-right" />
    </QueryClientProvider>
  );
}
```

**QueryClientProvider wraps Router** so route loaders can access the query client for prefetching. Toast components stay outside error boundaries so they remain functional when errors occur.

### Theme and sidebar state belongs in Zustand

For frequently-changing UI state like theme or sidebar collapse, **Zustand outperforms Context** with selective re-renders and built-in persistence:

```tsx
// stores/ui.store.ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface UIStore {
  theme: 'light' | 'dark' | 'system';
  sidebarCollapsed: boolean;
  setTheme: (theme: UIStore['theme']) => void;
  toggleSidebar: () => void;
}

export const useUIStore = create<UIStore>()(
  persist(
    (set) => ({
      theme: 'system',
      sidebarCollapsed: false,
      setTheme: (theme) => set({ theme }),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
    }),
    { name: 'ui-storage' }
  )
);
```

---

## Shell architecture with React Router layout routes

Use React Router v6+ **layout routes** (pathless routes with `element` and `children`) rather than manual shell wrapper components. This integrates with data loading, provides automatic `Outlet` rendering, and enables multiple distinct layouts.

```tsx
// routes/index.tsx
import { createBrowserRouter } from 'react-router-dom';

export const router = createBrowserRouter([
  // Auth layout (centered, no sidebar)
  {
    element: <AuthLayout />,
    children: [
      { path: '/login', lazy: () => import('@/pages/auth/Login') },
      { path: '/register', lazy: () => import('@/pages/auth/Register') },
    ],
  },
  
  // Protected app layout (sidebar + header)
  {
    element: <ProtectedRoute />,
    children: [{
      element: <AppShell />,
      children: [
        { path: '/', lazy: () => import('@/pages/Dashboard') },
        { path: '/settings', lazy: () => import('@/pages/Settings') },
        { path: '*', element: <NotFound /> },
      ],
    }],
  },
]);
```

### The AppShell component

```tsx
// layouts/AppShell.tsx
import { Outlet, ScrollRestoration } from 'react-router-dom';
import { Suspense } from 'react';
import { ErrorBoundary } from 'react-error-boundary';

export function AppShell() {
  return (
    <div className="shell">
      <Sidebar />
      <div className="shell__main">
        <Header />
        <main className="shell__content">
          <ErrorBoundary FallbackComponent={RouteErrorFallback}>
            <Suspense fallback={<PageSkeleton />}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
      <ScrollRestoration getKey={(location) => location.pathname} />
    </div>
  );
}
```

**Shell is inside routes** (as a layout route element) so it can access router context, use `Outlet` for children, and different routes can have different shells.

---

## Protected routes with auth state

The **wrapper component pattern** provides cleaner loading state handling and return-URL preservation than route loaders:

```tsx
// routes/guards/ProtectedRoute.tsx
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuthStore } from '@/stores/auth.store';

export function ProtectedRoute() {
  const { isAuthenticated, isLoading } = useAuthStore();
  const location = useLocation();

  if (isLoading) {
    return <AuthLoadingSpinner />;
  }

  if (!isAuthenticated) {
    return (
      <Navigate 
        to="/login" 
        state={{ from: location.pathname + location.search }}
        replace 
      />
    );
  }

  return <Outlet />;
}
```

### Return-to-URL handling in Login

```tsx
function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from || '/';

  const handleLogin = async (credentials: Credentials) => {
    await login(credentials);
    navigate(from, { replace: true });
  };
}
```

### Role-based access control extension

```tsx
interface ProtectedRouteProps {
  allowedRoles?: string[];
}

export function ProtectedRoute({ allowedRoles }: ProtectedRouteProps) {
  const { user, isAuthenticated, isLoading } = useAuthStore();
  
  if (isLoading) return <AuthLoadingSpinner />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  
  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/unauthorized" replace />;
  }
  
  return <Outlet />;
}
```

---

## Routing patterns with TanStack Query integration

Use `createBrowserRouter` (Data Router) for all new projects—it enables loaders, actions, and per-route error boundaries. **Combine route loaders with TanStack Query**: loaders initiate prefetches early, TanStack Query manages caching and refetching.

```tsx
// Shared query options
const dashboardQueryOptions = queryOptions({
  queryKey: ['dashboard'],
  queryFn: fetchDashboard,
  staleTime: 5 * 60 * 1000,
});

// Route definition with loader prefetch
{
  path: '/dashboard',
  loader: ({ context: { queryClient } }) => {
    queryClient.ensureQueryData(dashboardQueryOptions);
    return null;
  },
  lazy: () => import('./pages/Dashboard'),
}

// Component uses TanStack Query for full benefits
function Dashboard() {
  const { data } = useSuspenseQuery(dashboardQueryOptions);
  return <DashboardContent data={data} />;
}
```

### Route-based code splitting with `lazy()`

React Router's `lazy()` is superior to `React.lazy()` for routes—it loads component, loader, and error boundary in parallel:

```tsx
// Routes load all exports in parallel
{
  path: '/analytics',
  lazy: () => import('./routes/analytics'),
}

// routes/analytics.tsx
export async function loader() { return fetchAnalytics(); }
export function Component() { /* ... */ }
export function ErrorBoundary() { return <AnalyticsError />; }
```

---

## Error boundaries and Suspense strategy

Error boundaries remain **class components only** in React 19. Use `react-error-boundary` library for functional wrapper:

```tsx
import { ErrorBoundary } from 'react-error-boundary';
import { QueryErrorResetBoundary } from '@tanstack/react-query';

// Combined pattern for data fetching
<QueryErrorResetBoundary>
  {({ reset }) => (
    <ErrorBoundary
      onReset={reset}
      fallbackRender={({ error, resetErrorBoundary }) => (
        <div>
          <p>Error: {error.message}</p>
          <button onClick={resetErrorBoundary}>Retry</button>
        </div>
      )}
    >
      <Suspense fallback={<PageSkeleton />}>
        <DataComponent />
      </Suspense>
    </ErrorBoundary>
  )}
</QueryErrorResetBoundary>
```

### Layered error boundary strategy

- **Global** (in main.tsx): Catches catastrophic failures, shows full-page error
- **Route-level** (in Shell): Isolates page failures, allows navigation to continue
- **Component-level**: Isolates non-critical features (widgets, charts)

### Suspense with useSuspenseQuery

`useSuspenseQuery` in TanStack Query v5 is **production-ready** and guarantees data is defined:

```tsx
function UserProfile({ userId }: { userId: string }) {
  // data is always defined - TypeScript knows this!
  const { data } = useSuspenseQuery({
    queryKey: ['user', userId],
    queryFn: () => fetchUser(userId),
  });
  
  return <h1>{data.name}</h1>;
}
```

**Avoid waterfall loading** by using `useSuspenseQueries` for parallel fetches or prefetching in route loaders.

---

## Performance optimization with React 19

### When to still use manual memoization

With React Compiler enabled, most memoization is automatic. **Still use manual memoization for**:

- Values used as effect dependencies where you need precise control
- External library integrations requiring reference stability
- Expensive calculations the compiler can't detect

```tsx
// Still useful: effect dependency with specific identity
const chartOptions = useMemo(() => ({
  responsive: true,
  plugins: { legend: { position: 'top' } }
}), []);

useEffect(() => {
  chart.update(chartOptions);
}, [chartOptions]);
```

### useTransition for non-urgent updates

```tsx
function SearchWithTransition() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [isPending, startTransition] = useTransition();

  const handleSearch = (value: string) => {
    setQuery(value); // Urgent: update input immediately
    startTransition(() => {
      setResults(filterLargeDataset(value)); // Non-urgent
    });
  };

  return (
    <>
      <input value={query} onChange={(e) => handleSearch(e.target.value)} />
      <ResultsList results={results} style={{ opacity: isPending ? 0.7 : 1 }} />
    </>
  );
}
```

### Virtual scrolling for large lists

For lists over **100 items**, use TanStack Virtual (~5.5M weekly downloads) or react-virtuoso (easiest API for dynamic heights):

```tsx
import { useVirtualizer } from '@tanstack/react-virtual';

function VirtualList({ items }: { items: Item[] }) {
  const parentRef = useRef<HTMLDivElement>(null);
  
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 50,
    overscan: 5,
  });
  
  return (
    <div ref={parentRef} style={{ height: 400, overflow: 'auto' }}>
      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualizer.getVirtualItems().map((virtualItem) => (
          <div
            key={virtualItem.key}
            style={{
              position: 'absolute',
              transform: `translateY(${virtualItem.start}px)`,
              height: virtualItem.size,
            }}
          >
            {items[virtualItem.index].name}
          </div>
        ))}
      </div>
    </div>
  );
}
```

---

## State management philosophy

### Decision tree for state location

| State Type | Where to Store |
|------------|----------------|
| Server/async data | TanStack Query |
| Global UI state (theme, sidebar) | Zustand |
| Local UI state (dropdown open) | useState |
| URL-shareable state (filters, pagination) | URL search params |
| Form state | React Hook Form |
| Auth tokens | Zustand + persist middleware |

### Zustand TypeScript patterns

```tsx
import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (user: User, token: string) => void;
  logout: () => void;
}

// Curried create<T>()() required for proper inference with middleware
export const useAuthStore = create<AuthState>()(
  devtools(
    persist(
      (set) => ({
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: true,
        login: (user, token) => set({ user, token, isAuthenticated: true, isLoading: false }),
        logout: () => set({ user: null, token: null, isAuthenticated: false }),
      }),
      { name: 'auth-storage' }
    )
  )
);

// Selectors for optimized re-renders
export const useUser = () => useAuthStore((s) => s.user);
export const useIsAuthenticated = () => useAuthStore((s) => s.isAuthenticated);
```

---

## TypeScript patterns for React 19

### Component props typing

**Plain functions with typed props are recommended** over `React.FC`:

```tsx
// ✅ Recommended pattern
interface ButtonProps {
  variant: 'primary' | 'secondary';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
  onClick?: () => void;
}

function Button({ variant, size = 'md', children, onClick }: ButtonProps) {
  return <button className={`btn-${variant} btn-${size}`} onClick={onClick}>{children}</button>;
}
```

### Generic components

```tsx
interface ListProps<T> {
  items: T[];
  renderItem: (item: T) => React.ReactNode;
  keyExtractor: (item: T) => string;
}

function List<T>({ items, renderItem, keyExtractor }: ListProps<T>) {
  return (
    <ul>
      {items.map((item) => (
        <li key={keyExtractor(item)}>{renderItem(item)}</li>
      ))}
    </ul>
  );
}

// Usage - TypeScript infers T
<List
  items={users}
  renderItem={(user) => <span>{user.name}</span>}
  keyExtractor={(user) => user.id}
/>
```

### Event handler typing

```tsx
const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();
  const formData = new FormData(e.currentTarget);
};

const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  setValue(e.target.value);
};
```

---

## Forms with React Hook Form and Zod

```tsx
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const schema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

type FormData = z.infer<typeof schema>;

function LoginForm() {
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<FormData>({
    resolver: zodResolver(schema),
  });

  const onSubmit = async (data: FormData) => {
    await login(data);
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('email')} />
      {errors.email && <span>{errors.email.message}</span>}
      
      <input type="password" {...register('password')} />
      {errors.password && <span>{errors.password.message}</span>}
      
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Loading...' : 'Login'}
      </button>
    </form>
  );
}
```

---

## Vite build optimization

```ts
// vite.config.ts
import { defineConfig, splitVendorChunkPlugin } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [
    react({
      babel: {
        plugins: ['babel-plugin-react-compiler'],
      },
    }),
    splitVendorChunkPlugin(),
  ],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-query': ['@tanstack/react-query'],
        },
      },
    },
    chunkSizeWarningLimit: 500,
  },
});
```

---

## Migration checklist from React 18

```bash
# 1. Update packages
npm install --save-exact react@^19.0.0 react-dom@^19.0.0
npm install --save-exact @types/react@^19 @types/react-dom@^19

# 2. Run codemods
npx codemod@latest react/19/migration-recipe
npx types-react-codemod@latest preset-19 ./src

# 3. Check for compiler compatibility
npx react-compiler-healthcheck@latest

# 4. Add React Compiler
npm install --save-dev babel-plugin-react-compiler@latest
```

**Key breaking changes**: `useRef` requires an argument (`useRef(undefined)` not `useRef()`), ref callbacks can't have implicit returns, `ReactDOM.render` replaced by `createRoot`, `findDOMNode` removed.

---

## Anti-patterns to avoid

- **Don't drill props** through many levels—use Zustand or Context for truly global state
- **Don't overuse Context** for frequently changing state—it triggers full subtree re-renders
- **Don't use array indices as keys** in lists that can reorder or have deletions
- **Don't forget cleanup functions** in useEffect for subscriptions and abort controllers
- **Don't ignore `exhaustive-deps`** ESLint rule—use functional state updates to avoid stale closures
- **Don't create promises in render** when using `use()`—cache them in parent components or use TanStack Query

## Conclusion

For your React 19 + Vite + FastAPI template, adopt the **React Compiler** for automatic memoization, use **layout routes** for shell architecture, combine **route loaders with TanStack Query** for optimal data loading, and keep **Zustand for UI state** while TanStack Query handles server state. The new `useActionState` and `useOptimistic` hooks provide excellent form UX patterns, and `ref` as a prop eliminates forwardRef boilerplate. Layer error boundaries at global, route, and component levels with Suspense boundaries at route transitions for the best user experience.
