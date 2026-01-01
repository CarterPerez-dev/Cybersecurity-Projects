# Zustand Production Patterns: JWT Auth + UI State Management (2025)

**Comprehensive Research for React + Vite + FastAPI Production Template**

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Zustand v4+ Fundamentals](#zustand-v4-fundamentals)
3. [JWT Token Storage: The 2025 Consensus](#jwt-token-storage-the-2025-consensus)
4. [Auth Store Architecture](#auth-store-architecture)
5. [Token Refresh Patterns](#token-refresh-patterns)
6. [UI State Stores (Per-Page Patterns)](#ui-state-stores-per-page-patterns)
7. [Persistence Middleware Deep Dive](#persistence-middleware-deep-dive)
8. [Selectors & Performance Optimization](#selectors--performance-optimization)
9. [Form State Management](#form-state-management)
10. [Cross-Tab Synchronization](#cross-tab-synchronization)
11. [Protected Routes Integration](#protected-routes-integration)
12. [TypeScript Patterns](#typescript-patterns)
13. [Middleware Combinations](#middleware-combinations)
14. [Testing Strategies](#testing-strategies)
15. [Security Best Practices](#security-best-practices)
16. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)
17. [Production Checklist](#production-checklist)

---

## Executive Summary

### The 2025 Consensus for JWT Storage in SPAs

**Short Answer:** Access token in **memory** (React state/Zustand), refresh token in **httpOnly cookie**.

**Why this matters:**
- Access tokens in localStorage = XSS vulnerable
- Both tokens in httpOnly cookies = CSRF vulnerable + can't set `Authorization` header
- Memory-only = lost on refresh (bad UX)
- **The hybrid approach** balances security and UX

### Key Architectural Decisions

1. **Auth Store**: Store access token in Zustand (memory), use httpOnly cookies for refresh token
2. **UI Stores**: Per-page stores for UI state with selective persistence
3. **Form State**: Use Zustand for drafts, React Hook Form for validation
4. **Token Refresh**: Axios interceptors on 401, with request queue pattern
5. **Persistence**: `partialize` to exclude sensitive data, version for migrations
6. **Selectors**: Use `useShallow` for multiple selections, atomic selectors for primitives
7. **Cross-Tab**: BroadcastChannel or localStorage events for sync

---

## Zustand v4+ Fundamentals

### What's New in v4+

**Major Changes from v3:**
- **Curried create syntax**: `create<T>()(...)` for better TypeScript inference
- **Improved middleware typing**: Automatic type inference for middleware chains
- **`useShallow` hook**: Replaces `shallow` import for React components
- **Vanilla store separation**: `createStore` for vanilla JS, `create` for React
- **Better devtools integration**: Enhanced Redux DevTools support

### Basic Store Creation (v4 Pattern)

```typescript
// src/core/lib/auth.store.ts
import { create } from 'zustand'

interface AuthState {
  accessToken: string | null
  user: User | null
  isAuthenticated: boolean
}

interface AuthActions {
  setTokens: (token: string, user: User) => void
  clearAuth: () => void
}

type AuthStore = AuthState & AuthActions

// v4 curried syntax for better TypeScript inference
export const useAuthStore = create<AuthStore>()((set) => ({
  // State
  accessToken: null,
  user: null,
  isAuthenticated: false,
  
  // Actions
  setTokens: (token, user) => set({ 
    accessToken: token, 
    user, 
    isAuthenticated: true 
  }),
  clearAuth: () => set({ 
    accessToken: null, 
    user: null, 
    isAuthenticated: false 
  }),
}))
```

### Slice Pattern for Large Stores

```typescript
// src/pages/Dashboard/stores/slices/dashboard-ui.slice.ts
import { StateCreator } from 'zustand'

interface DashboardUISlice {
  isSidebarOpen: boolean
  activeModal: 'create' | 'edit' | null
  toggleSidebar: () => void
  openModal: (type: 'create' | 'edit') => void
  closeModal: () => void
}

export const createDashboardUISlice: StateCreator<
  DashboardUISlice,
  [],
  [],
  DashboardUISlice
> = (set) => ({
  isSidebarOpen: true,
  activeModal: null,
  
  toggleSidebar: () => set((state) => ({ 
    isSidebarOpen: !state.isSidebarOpen 
  })),
  openModal: (type) => set({ activeModal: type }),
  closeModal: () => set({ activeModal: null }),
})

// Combine slices
import { create } from 'zustand'
import { createDashboardUISlice } from './slices/dashboard-ui.slice'

export const useDashboardStore = create<DashboardUISlice>()((...a) => ({
  ...createDashboardUISlice(...a),
}))
```

---

## JWT Token Storage: The 2025 Consensus

### The Security Landscape

**localStorage/sessionStorage:**
- ❌ **Vulnerable to XSS** - Any malicious script can read tokens
- ✅ Easy to implement
- ✅ Persists across refreshes

**httpOnly Cookies:**
- ✅ **Immune to XSS** - JavaScript cannot read the cookie
- ❌ Vulnerable to CSRF (mitigated with SameSite=Strict)
- ❌ Cannot set `Authorization: Bearer` header from client
- ✅ Automatically sent with requests

**Memory Only (React State/Zustand):**
- ✅ **Immune to XSS** - No persistence layer to attack
- ❌ Lost on page refresh (bad UX)
- ❌ Lost on new tab (bad UX)

### The 2025 Best Practice: Hybrid Approach

```
┌─────────────────────────────────────────┐
│  CLIENT (Browser)                       │
│                                         │
│  ┌─────────────────┐  ┌──────────────┐ │
│  │ Zustand Store   │  │ httpOnly     │ │
│  │ (Memory)        │  │ Cookie       │ │
│  │                 │  │              │ │
│  │ accessToken ✓   │  │ refreshToken │ │
│  │ user data ✓     │  │ (server-set) │ │
│  └─────────────────┘  └──────────────┘ │
│                                         │
└─────────────────────────────────────────┘
          │                      │
          │ Bearer {access}      │ Cookie (auto)
          ▼                      ▼
┌─────────────────────────────────────────┐
│  SERVER (FastAPI)                       │
│                                         │
│  POST /auth/login                       │
│  → Returns: { accessToken, user }       │
│  → Sets: refreshToken in httpOnly cookie│
│                                         │
│  GET /auth/refresh                      │
│  → Reads: refreshToken from cookie      │
│  → Returns: { accessToken }             │
└─────────────────────────────────────────┘
```

### Implementation: Auth Store

```typescript
// src/core/lib/auth.store.ts
import { create } from 'zustand'
import { devtools } from 'zustand/middleware'

interface User {
  id: string
  email: string
  name: string
  role: string
}

interface AuthState {
  // Access token stored in memory
  accessToken: string | null
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
}

interface AuthActions {
  setAuth: (token: string, user: User) => void
  clearAuth: () => void
  refreshAccessToken: () => Promise<void>
  setLoading: (loading: boolean) => void
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  devtools(
    (set, get) => ({
      // State
      accessToken: null,
      user: null,
      isAuthenticated: false,
      isLoading: true,
      
      // Actions
      setAuth: (token, user) => set({ 
        accessToken: token,
        user,
        isAuthenticated: true,
        isLoading: false
      }, false, 'auth/setAuth'),
      
      clearAuth: () => set({ 
        accessToken: null,
        user: null,
        isAuthenticated: false,
        isLoading: false
      }, false, 'auth/clearAuth'),
      
      refreshAccessToken: async () => {
        try {
          // Call refresh endpoint (refresh token sent via httpOnly cookie)
          const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            credentials: 'include', // Important: sends cookies
          })
          
          if (!response.ok) {
            throw new Error('Refresh failed')
          }
          
          const { accessToken, user } = await response.json()
          get().setAuth(accessToken, user)
        } catch (error) {
          get().clearAuth()
          throw error
        }
      },
      
      setLoading: (loading) => set({ isLoading: loading }),
    }),
    { name: 'AuthStore' }
  )
)

// Convenient selectors
export const selectAccessToken = (state: AuthStore) => state.accessToken
export const selectUser = (state: AuthStore) => state.user
export const selectIsAuthenticated = (state: AuthStore) => state.isAuthenticated
export const selectIsLoading = (state: AuthStore) => state.isLoading
```

### Why This Works

1. **Access Token in Memory**:
   - Used for API requests via `Authorization: Bearer {token}`
   - XSS attacks can't steal it from localStorage
   - Lost on refresh, but we use refresh token to get a new one

2. **Refresh Token in httpOnly Cookie**:
   - Set by server: `Set-Cookie: refreshToken=...; HttpOnly; Secure; SameSite=Strict`
   - JavaScript cannot read it (XSS protection)
   - CSRF mitigated by SameSite=Strict
   - Automatically sent on `/auth/refresh` requests

3. **Page Refresh Flow**:
   ```
   User refreshes page
   → Access token lost (Zustand memory cleared)
   → App calls /auth/refresh on mount
   → Browser automatically sends refreshToken cookie
   → Server returns new accessToken
   → Store in Zustand
   ```

### Security Considerations

**XSS Protection:**
- ✅ Access token not in localStorage = safe from XSS
- ✅ Refresh token not readable by JS = safe from XSS
- ⚠️ Still need CSP headers and input sanitization

**CSRF Protection:**
- ✅ SameSite=Strict prevents cross-origin requests with cookies
- ✅ Access token uses `Authorization` header (not cookies) = CSRF immune
- ⚠️ For older browsers, implement CSRF token pattern

**Token Expiry:**
- Access token: Short-lived (5-15 minutes)
- Refresh token: Longer-lived (7-30 days)
- Implement token rotation on refresh

---

## Auth Store Architecture

### Full Production Auth Store

```typescript
// src/core/lib/auth.store.ts
import { create } from 'zustand'
import { devtools } from 'zustand/middleware'
import { api } from '@/core/api/client'

interface User {
  id: string
  email: string
  name: string
  role: 'admin' | 'user'
  permissions: string[]
}

interface AuthState {
  accessToken: string | null
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
}

interface AuthActions {
  // Core auth actions
  setAuth: (token: string, user: User) => void
  clearAuth: () => void
  
  // Login/Logout
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  
  // Token management
  refreshAccessToken: () => Promise<void>
  
  // Utility
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  checkAuth: () => Promise<void>
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  devtools(
    (set, get) => ({
      // Initial State
      accessToken: null,
      user: null,
      isAuthenticated: false,
      isLoading: true,
      error: null,
      
      // Core Actions
      setAuth: (token, user) => set(
        { 
          accessToken: token,
          user,
          isAuthenticated: true,
          isLoading: false,
          error: null
        },
        false,
        'auth/setAuth'
      ),
      
      clearAuth: () => set(
        { 
          accessToken: null,
          user: null,
          isAuthenticated: false,
          isLoading: false,
          error: null
        },
        false,
        'auth/clearAuth'
      ),
      
      // Login
      login: async (email, password) => {
        set({ isLoading: true, error: null })
        try {
          // Server sets refreshToken as httpOnly cookie
          const { accessToken, user } = await api.post('/auth/login', {
            email,
            password
          })
          get().setAuth(accessToken, user)
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Login failed'
          set({ error: message, isLoading: false })
          throw error
        }
      },
      
      // Logout
      logout: async () => {
        try {
          // Server clears refreshToken cookie
          await api.post('/auth/logout')
        } finally {
          get().clearAuth()
        }
      },
      
      // Refresh Token
      refreshAccessToken: async () => {
        try {
          // refreshToken sent automatically via httpOnly cookie
          const { accessToken, user } = await api.post('/auth/refresh')
          get().setAuth(accessToken, user)
        } catch (error) {
          get().clearAuth()
          throw error
        }
      },
      
      // Check Auth on App Mount
      checkAuth: async () => {
        set({ isLoading: true })
        try {
          await get().refreshAccessToken()
        } catch {
          get().clearAuth()
        }
      },
      
      // Utility
      setLoading: (loading) => set({ isLoading: loading }),
      setError: (error) => set({ error }),
    }),
    { name: 'AuthStore' }
  )
)

// Selectors
export const selectAuth = (state: AuthStore) => ({
  accessToken: state.accessToken,
  user: state.user,
  isAuthenticated: state.isAuthenticated,
})

export const selectIsLoading = (state: AuthStore) => state.isLoading
export const selectUser = (state: AuthStore) => state.user
export const selectHasRole = (role: string) => (state: AuthStore) => 
  state.user?.role === role
export const selectHasPermission = (permission: string) => (state: AuthStore) =>
  state.user?.permissions.includes(permission)
```

### FastAPI Backend Integration

```python
# backend/app/routes/auth.py
from fastapi import APIRouter, Response, Depends, HTTPException
from fastapi.security import HTTPBearer
from datetime import datetime, timedelta
import jwt

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()

@router.post("/login")
async def login(
    credentials: LoginCredentials,
    response: Response
):
    # Validate credentials
    user = await authenticate_user(credentials.email, credentials.password)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    
    # Generate tokens
    access_token = create_access_token(user.id, expires_delta=timedelta(minutes=15))
    refresh_token = create_refresh_token(user.id, expires_delta=timedelta(days=30))
    
    # Set refresh token as httpOnly cookie
    response.set_cookie(
        key="refreshToken",
        value=refresh_token,
        httponly=True,
        secure=True,  # HTTPS only
        samesite="strict",  # CSRF protection
        max_age=30 * 24 * 60 * 60  # 30 days
    )
    
    # Return access token in response body
    return {
        "accessToken": access_token,
        "user": user.to_dict()
    }

@router.post("/refresh")
async def refresh(request: Request):
    # Extract refresh token from cookie
    refresh_token = request.cookies.get("refreshToken")
    if not refresh_token:
        raise HTTPException(401, "No refresh token")
    
    try:
        # Validate refresh token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload["sub"]
        user = await get_user(user_id)
        
        # Generate new access token
        access_token = create_access_token(user.id, expires_delta=timedelta(minutes=15))
        
        return {
            "accessToken": access_token,
            "user": user.to_dict()
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid refresh token")

@router.post("/logout")
async def logout(response: Response):
    # Clear refresh token cookie
    response.delete_cookie(
        key="refreshToken",
        httponly=True,
        secure=True,
        samesite="strict"
    )
    return {"message": "Logged out"}
```

---

## Token Refresh Patterns

### Axios Interceptor Setup

```typescript
// src/core/api/client.ts
import axios from 'axios'
import { useAuthStore } from '@/core/lib/auth.store'

// Create axios instance
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true, // Important: sends cookies
})

// Request queue for handling concurrent requests during token refresh
let isRefreshing = false
let failedQueue: Array<{
  resolve: (value?: any) => void
  reject: (reason?: any) => void
}> = []

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error)
    } else {
      prom.resolve(token)
    }
  })
  failedQueue = []
}

// Request interceptor: Add access token to headers
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().accessToken
    
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor: Handle 401 and refresh token
api.interceptors.response.use(
  (response) => response.data, // Return data directly
  async (error) => {
    const originalRequest = error.config
    
    // If error is not 401 or request already retried, reject
    if (error.response?.status !== 401 || originalRequest._retry) {
      return Promise.reject(error)
    }
    
    // If token refresh is already in progress, queue this request
    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject })
      })
        .then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`
          return api(originalRequest)
        })
        .catch((err) => Promise.reject(err))
    }
    
    // Mark request as retried
    originalRequest._retry = true
    isRefreshing = true
    
    try {
      // Attempt to refresh token
      await useAuthStore.getState().refreshAccessToken()
      const newToken = useAuthStore.getState().accessToken
      
      // Process queued requests
      processQueue(null, newToken)
      
      // Retry original request with new token
      originalRequest.headers.Authorization = `Bearer ${newToken}`
      return api(originalRequest)
    } catch (refreshError) {
      // Refresh failed - clear auth and reject all queued requests
      processQueue(refreshError, null)
      useAuthStore.getState().clearAuth()
      
      // Redirect to login
      window.location.href = '/login'
      
      return Promise.reject(refreshError)
    } finally {
      isRefreshing = false
    }
  }
)
```

### Alternative: Proactive Token Refresh

```typescript
// src/core/api/token-refresh.ts
import { useAuthStore } from '@/core/lib/auth.store'
import { jwtDecode } from 'jwt-decode'

interface JwtPayload {
  exp: number
  iat: number
  sub: string
}

// Start background token refresh
export function startTokenRefreshTimer() {
  const checkAndRefresh = async () => {
    const { accessToken, refreshAccessToken } = useAuthStore.getState()
    
    if (!accessToken) return
    
    try {
      const decoded = jwtDecode<JwtPayload>(accessToken)
      const expiresAt = decoded.exp * 1000 // Convert to ms
      const now = Date.now()
      const timeUntilExpiry = expiresAt - now
      
      // Refresh if token expires in less than 2 minutes
      if (timeUntilExpiry < 2 * 60 * 1000) {
        await refreshAccessToken()
      }
    } catch (error) {
      console.error('Token refresh check failed:', error)
    }
  }
  
  // Check every minute
  setInterval(checkAndRefresh, 60 * 1000)
  
  // Also check immediately
  checkAndRefresh()
}

// In App.tsx
import { startTokenRefreshTimer } from '@/core/api/token-refresh'

function App() {
  useEffect(() => {
    const timer = startTokenRefreshTimer()
    return () => clearInterval(timer)
  }, [])
  
  // ...
}
```

### Request Queue Pattern Explained

**Why we need it:**
When an access token expires, multiple API requests might fail with 401 simultaneously. Without a queue, each request would try to refresh the token, causing race conditions.

**How it works:**
1. First 401 triggers refresh, sets `isRefreshing = true`
2. Subsequent 401s are queued in `failedQueue`
3. After successful refresh, all queued requests are retried with new token
4. If refresh fails, all queued requests are rejected

**Visual Flow:**
```
Request 1 (401) ─┐
Request 2 (401) ─┼─→ Queued ─→ Wait for refresh
Request 3 (401) ─┘
                 │
                 ├─ isRefreshing = true
                 ├─ Call /auth/refresh
                 ├─ Get new accessToken
                 ├─ Process queue with new token
                 └─ isRefreshing = false
                      │
                      ├─→ Request 1 retried ✓
                      ├─→ Request 2 retried ✓
                      └─→ Request 3 retried ✓
```

---

## UI State Stores (Per-Page Patterns)

### When to Create a UI Store

**Create a per-page UI store when:**
- UI state needs persistence across refreshes (sidebar open/closed, view mode)
- State is shared across multiple components in that page
- State is complex (modals, multi-step forms, filters)

**Don't create a store when:**
- State is local to one component (use `useState`)
- State doesn't need persistence
- State is server-derived (use TanStack Query)

### Dashboard UI Store Example

```typescript
// src/pages/Dashboard/stores/dashboard-ui.store.ts
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { devtools } from 'zustand/middleware'

interface DashboardUIState {
  // Sidebar
  isSidebarOpen: boolean
  sidebarWidth: number
  
  // Modals
  activeModal: 'create' | 'edit' | 'delete' | null
  modalData: any | null
  
  // View preferences
  viewMode: 'grid' | 'list'
  sortBy: 'name' | 'date' | 'size'
  sortOrder: 'asc' | 'desc'
  
  // Filters
  filters: {
    status: string[]
    tags: string[]
    dateRange: { start: string; end: string } | null
  }
  
  // Selection
  selectedItems: Set<string>
}

interface DashboardUIActions {
  // Sidebar
  toggleSidebar: () => void
  setSidebarWidth: (width: number) => void
  
  // Modals
  openModal: (type: 'create' | 'edit' | 'delete', data?: any) => void
  closeModal: () => void
  
  // View
  setViewMode: (mode: 'grid' | 'list') => void
  setSortBy: (sortBy: string, order: 'asc' | 'desc') => void
  
  // Filters
  setFilter: (key: keyof DashboardUIState['filters'], value: any) => void
  clearFilters: () => void
  
  // Selection
  selectItem: (id: string) => void
  deselectItem: (id: string) => void
  clearSelection: () => void
  selectAll: (ids: string[]) => void
}

type DashboardUIStore = DashboardUIState & DashboardUIActions

export const useDashboardUIStore = create<DashboardUIStore>()(
  devtools(
    persist(
      (set, get) => ({
        // State
        isSidebarOpen: true,
        sidebarWidth: 280,
        activeModal: null,
        modalData: null,
        viewMode: 'grid',
        sortBy: 'date',
        sortOrder: 'desc',
        filters: {
          status: [],
          tags: [],
          dateRange: null,
        },
        selectedItems: new Set(),
        
        // Actions
        toggleSidebar: () => set((state) => ({ 
          isSidebarOpen: !state.isSidebarOpen 
        })),
        
        setSidebarWidth: (width) => set({ sidebarWidth: width }),
        
        openModal: (type, data = null) => set({ 
          activeModal: type,
          modalData: data
        }),
        
        closeModal: () => set({ 
          activeModal: null,
          modalData: null
        }),
        
        setViewMode: (mode) => set({ viewMode: mode }),
        
        setSortBy: (sortBy, order) => set({ 
          sortBy: sortBy as any,
          sortOrder: order
        }),
        
        setFilter: (key, value) => set((state) => ({
          filters: { ...state.filters, [key]: value }
        })),
        
        clearFilters: () => set({
          filters: {
            status: [],
            tags: [],
            dateRange: null,
          }
        }),
        
        selectItem: (id) => set((state) => {
          const newSet = new Set(state.selectedItems)
          newSet.add(id)
          return { selectedItems: newSet }
        }),
        
        deselectItem: (id) => set((state) => {
          const newSet = new Set(state.selectedItems)
          newSet.delete(id)
          return { selectedItems: newSet }
        }),
        
        clearSelection: () => set({ selectedItems: new Set() }),
        
        selectAll: (ids) => set({ selectedItems: new Set(ids) }),
      }),
      {
        name: 'dashboard-ui-storage',
        storage: createJSONStorage(() => localStorage),
        
        // Only persist certain fields
        partialize: (state) => ({
          isSidebarOpen: state.isSidebarOpen,
          sidebarWidth: state.sidebarWidth,
          viewMode: state.viewMode,
          sortBy: state.sortBy,
          sortOrder: state.sortOrder,
          // Don't persist: modals, selection, filters (ephemeral)
        }),
        
        // Custom serialization for Set
        serialize: (state) => {
          return JSON.stringify({
            state: {
              ...state.state,
              selectedItems: Array.from(state.state.selectedItems)
            }
          })
        },
        
        deserialize: (str) => {
          const parsed = JSON.parse(str)
          return {
            state: {
              ...parsed.state,
              selectedItems: new Set(parsed.state.selectedItems || [])
            }
          }
        },
      }
    ),
    { name: 'DashboardUI' }
  )
)

// Selectors
export const selectSidebar = (state: DashboardUIStore) => ({
  isOpen: state.isSidebarOpen,
  width: state.sidebarWidth,
})

export const selectModal = (state: DashboardUIStore) => ({
  type: state.activeModal,
  data: state.modalData,
})

export const selectView = (state: DashboardUIStore) => ({
  mode: state.viewMode,
  sortBy: state.sortBy,
  sortOrder: state.sortOrder,
})
```

### Usage in Components

```typescript
// src/pages/Dashboard/components/Sidebar.tsx
import { useDashboardUIStore } from '../stores/dashboard-ui.store'
import { useShallow } from 'zustand/react/shallow'

function Sidebar() {
  // Efficient: Only re-renders when these values change
  const { isOpen, width } = useDashboardUIStore(
    useShallow((state) => ({
      isOpen: state.isSidebarOpen,
      width: state.sidebarWidth,
    }))
  )
  
  const toggleSidebar = useDashboardUIStore((state) => state.toggleSidebar)
  
  return (
    <aside 
      className={`sidebar ${isOpen ? 'open' : 'closed'}`}
      style={{ width: isOpen ? `${width}px` : '0' }}
    >
      <button onClick={toggleSidebar}>Toggle</button>
      {/* Sidebar content */}
    </aside>
  )
}
```

---

## Persistence Middleware Deep Dive

### partialize: Selective Persistence

**Rule:** Never persist functions, only persist necessary state.

```typescript
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

interface StoreState {
  // Persist
  theme: 'light' | 'dark'
  preferences: { fontSize: number }
  
  // Don't persist (ephemeral)
  isModalOpen: boolean
  currentPage: number
}

const useStore = create<StoreState>()(
  persist(
    (set) => ({
      theme: 'light',
      preferences: { fontSize: 14 },
      isModalOpen: false,
      currentPage: 1,
      // actions...
    }),
    {
      name: 'app-settings',
      
      // Method 1: Whitelist specific keys
      partialize: (state) => ({
        theme: state.theme,
        preferences: state.preferences,
      }),
      
      // Method 2: Blacklist keys (filter out unwanted)
      // partialize: (state) => 
      //   Object.fromEntries(
      //     Object.entries(state).filter(([key]) => 
      //       !['isModalOpen', 'currentPage'].includes(key)
      //     )
      //   ),
    }
  )
)
```

### Version Management & Migration

```typescript
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface StoreV2 {
  version: 2
  settings: {
    theme: 'light' | 'dark' | 'auto' // Added 'auto'
    locale: string // Added locale
  }
}

const useStore = create<StoreV2>()(
  persist(
    (set) => ({
      version: 2,
      settings: {
        theme: 'light',
        locale: 'en',
      },
    }),
    {
      name: 'app-store',
      version: 2, // Current version
      
      // Migration function
      migrate: (persistedState: any, version: number) => {
        if (version === 1) {
          // Migrate from v1 to v2
          return {
            version: 2,
            settings: {
              theme: persistedState.theme || 'light',
              locale: 'en', // New field with default
            },
          }
        }
        
        return persistedState
      },
      
      // Called if migration fails
      onRehydrateStorage: () => (state, error) => {
        if (error) {
          console.error('Hydration failed:', error)
          // Could reset to defaults here
        }
      },
    }
  )
)
```

### Storage Options

```typescript
// localStorage (default) - persists forever
storage: createJSONStorage(() => localStorage)

// sessionStorage - cleared on tab close
storage: createJSONStorage(() => sessionStorage)

// IndexedDB - for large data
import { get, set, del } from 'idb-keyval'

storage: {
  getItem: async (name) => {
    return (await get(name)) || null
  },
  setItem: async (name, value) => {
    await set(name, value)
  },
  removeItem: async (name) => {
    await del(name)
  },
}

// Custom encryption
import CryptoJS from 'crypto-js'

const SECRET_KEY = import.meta.env.VITE_STORAGE_KEY

storage: {
  getItem: (name) => {
    const encrypted = localStorage.getItem(name)
    if (!encrypted) return null
    
    try {
      const decrypted = CryptoJS.AES.decrypt(encrypted, SECRET_KEY).toString(
        CryptoJS.enc.Utf8
      )
      return decrypted
    } catch {
      return null
    }
  },
  setItem: (name, value) => {
    const encrypted = CryptoJS.AES.encrypt(value, SECRET_KEY).toString()
    localStorage.setItem(name, encrypted)
  },
  removeItem: (name) => localStorage.removeItem(name),
}
```

### Handling Storage Quota

```typescript
import { persist } from 'zustand/middleware'

persist(
  (set) => ({ /* store */ }),
  {
    name: 'app-store',
    
    onRehydrateStorage: () => (state, error) => {
      if (error) {
        // Check if quota exceeded
        if (error.name === 'QuotaExceededError') {
          console.error('Storage quota exceeded')
          
          // Strategy 1: Clear old data
          const storeNames = ['old-store-1', 'old-store-2']
          storeNames.forEach(name => localStorage.removeItem(name))
          
          // Strategy 2: Compress data
          // Strategy 3: Move to IndexedDB
        }
      }
    },
  }
)
```

---

## Selectors & Performance Optimization

### The Golden Rule

**Atomic selectors** for primitives = ✅ Efficient  
**Object selectors** without `useShallow` = ❌ Re-renders on every store update

### Atomic Selectors (Recommended)

```typescript
// ✅ GOOD: Atomic selectors
function Component() {
  // Only re-renders when count changes
  const count = useStore((state) => state.count)
  
  // Only re-renders when increment changes (never, it's a function)
  const increment = useStore((state) => state.increment)
  
  return <button onClick={increment}>{count}</button>
}
```

### Object Selectors with useShallow

```typescript
import { useShallow } from 'zustand/react/shallow'

// ✅ GOOD: Object selector with useShallow
function Component() {
  const { count, text, increment } = useStore(
    useShallow((state) => ({
      count: state.count,
      text: state.text,
      increment: state.increment,
    }))
  )
  
  return (
    <div>
      <p>{count} - {text}</p>
      <button onClick={increment}>+</button>
    </div>
  )
}
```

### Array Selectors

```typescript
// ✅ GOOD: Array selector with useShallow
const [nuts, honey] = useStore(
  useShallow((state) => [state.nuts, state.honey])
)

// ✅ GOOD: Computed array with useShallow
const names = useStore(
  useShallow((state) => Object.keys(state.users))
)
```

### Anti-Pattern: Subscribing to Entire Store

```typescript
// ❌ BAD: Re-renders on ANY state change
const state = useStore()

// ❌ BAD: Same problem
const { count, text, increment } = useStore((state) => ({
  count: state.count,
  text: state.text,
  increment: state.increment,
}))
// Missing useShallow means new object every render!
```

### Custom Selectors for Reusability

```typescript
// src/pages/Dashboard/stores/dashboard-ui.store.ts

// Export selectors with the store
export const selectSidebar = (state: DashboardUIStore) => ({
  isOpen: state.isSidebarOpen,
  width: state.sidebarWidth,
})

export const selectFilters = (state: DashboardUIStore) => state.filters

export const selectHasSelection = (state: DashboardUIStore) => 
  state.selectedItems.size > 0

// Usage
import { useDashboardUIStore, selectSidebar } from '../stores/dashboard-ui.store'
import { useShallow } from 'zustand/react/shallow'

function Sidebar() {
  const sidebar = useDashboardUIStore(useShallow(selectSidebar))
  // ...
}
```

### Derived State / Computed Values

```typescript
// Method 1: Compute in selector
const totalPrice = useStore((state) =>
  state.cart.reduce((sum, item) => sum + item.price * item.quantity, 0)
)

// Method 2: Memoize with useMemo
const totalPrice = useMemo(
  () => cart.reduce((sum, item) => sum + item.price * item.quantity, 0),
  [cart]
)

// Method 3: Store computed values (if expensive)
interface StoreState {
  cart: CartItem[]
  _totalPrice: number // Cached computed value
  
  addToCart: (item: CartItem) => void
}

const useStore = create<StoreState>((set) => ({
  cart: [],
  _totalPrice: 0,
  
  addToCart: (item) => set((state) => {
    const newCart = [...state.cart, item]
    const newTotal = newCart.reduce(
      (sum, i) => sum + i.price * i.quantity,
      0
    )
    return {
      cart: newCart,
      _totalPrice: newTotal,
    }
  }),
}))
```

### Performance Monitoring

```typescript
// Detect unnecessary re-renders
function Component() {
  const renderCount = useRef(0)
  renderCount.current++
  
  console.log(`Component rendered ${renderCount.current} times`)
  
  const count = useStore((state) => state.count)
  
  return <div>{count}</div>
}

// React DevTools Profiler
// Use React DevTools to identify components that re-render too often
```

---

## Form State Management

### When to Use Zustand for Forms

**Use Zustand when:**
- ✅ Draft persistence across refreshes
- ✅ Multi-step forms with state across pages
- ✅ Form state shared across components
- ✅ Auto-save functionality

**Use React Hook Form when:**
- ✅ Form validation
- ✅ Field-level errors
- ✅ Controlled inputs
- ✅ Schema validation (Zod, Yup)

### The Hybrid Approach (Recommended)

```typescript
// src/pages/Dashboard/stores/form-drafts.store.ts
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

interface FormDraft {
  formId: string
  data: Record<string, any>
  lastSaved: number
}

interface FormDraftsState {
  drafts: Record<string, FormDraft>
}

interface FormDraftsActions {
  saveDraft: (formId: string, data: Record<string, any>) => void
  loadDraft: (formId: string) => FormDraft | null
  deleteDraft: (formId: string) => void
  clearOldDrafts: (maxAgeMs: number) => void
}

type FormDraftsStore = FormDraftsState & FormDraftsActions

export const useFormDraftsStore = create<FormDraftsStore>()(
  persist(
    (set, get) => ({
      drafts: {},
      
      saveDraft: (formId, data) => set((state) => ({
        drafts: {
          ...state.drafts,
          [formId]: {
            formId,
            data,
            lastSaved: Date.now(),
          },
        },
      })),
      
      loadDraft: (formId) => {
        return get().drafts[formId] || null
      },
      
      deleteDraft: (formId) => set((state) => {
        const newDrafts = { ...state.drafts }
        delete newDrafts[formId]
        return { drafts: newDrafts }
      }),
      
      clearOldDrafts: (maxAgeMs) => set((state) => {
        const now = Date.now()
        const newDrafts = Object.fromEntries(
          Object.entries(state.drafts).filter(
            ([_, draft]) => now - draft.lastSaved < maxAgeMs
          )
        )
        return { drafts: newDrafts }
      }),
    }),
    {
      name: 'form-drafts-storage',
      storage: createJSONStorage(() => localStorage),
    }
  )
)
```

### Form Component with React Hook Form + Zustand

```typescript
// src/pages/Dashboard/components/CreateForm.tsx
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useFormDraftsStore } from '../stores/form-drafts.store'
import { useEffect } from 'react'
import { useDebouncedCallback } from 'use-debounce'

const formSchema = z.object({
  title: z.string().min(1, 'Title required'),
  description: z.string().min(10, 'Description too short'),
  tags: z.array(z.string()),
})

type FormData = z.infer<typeof formSchema>

function CreateForm() {
  const FORM_ID = 'create-item-form'
  const { saveDraft, loadDraft, deleteDraft } = useFormDraftsStore()
  
  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors },
  } = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: () => {
      // Load draft on mount
      const draft = loadDraft(FORM_ID)
      return draft?.data || {
        title: '',
        description: '',
        tags: [],
      }
    },
  })
  
  // Auto-save draft on form changes (debounced)
  const formData = watch()
  
  const saveDraftDebounced = useDebouncedCallback(
    (data: FormData) => {
      saveDraft(FORM_ID, data)
      console.log('Draft saved')
    },
    1000 // Save after 1 second of no typing
  )
  
  useEffect(() => {
    saveDraftDebounced(formData)
  }, [formData, saveDraftDebounced])
  
  // Submit form
  const onSubmit = async (data: FormData) => {
    try {
      await api.post('/items', data)
      
      // Clear draft on successful submit
      deleteDraft(FORM_ID)
      reset()
      
      toast.success('Item created!')
    } catch (error) {
      toast.error('Failed to create item')
    }
  }
  
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('title')} />
      {errors.title && <span>{errors.title.message}</span>}
      
      <textarea {...register('description')} />
      {errors.description && <span>{errors.description.message}</span>}
      
      <button type="submit">Create</button>
      <button type="button" onClick={() => deleteDraft(FORM_ID)}>
        Discard Draft
      </button>
    </form>
  )
}
```

### Auto-Save Pattern

```typescript
// src/hooks/useAutoSave.ts
import { useEffect } from 'react'
import { useDebouncedCallback } from 'use-debounce'

export function useAutoSave<T>(
  data: T,
  saveFunction: (data: T) => void,
  delay: number = 1000
) {
  const debouncedSave = useDebouncedCallback(saveFunction, delay)
  
  useEffect(() => {
    debouncedSave(data)
  }, [data, debouncedSave])
  
  return debouncedSave
}

// Usage
const formData = watch()
useAutoSave(formData, (data) => saveDraft(FORM_ID, data))
```

---

## Cross-Tab Synchronization

### Method 1: localStorage Events (Built-in)

```typescript
// src/core/lib/storage-sync.ts
import { useEffect } from 'react'

export function useCrossTabSync<T>(
  storageKey: string,
  onUpdate: (newValue: T) => void
) {
  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === storageKey && e.newValue) {
        try {
          const parsed = JSON.parse(e.newValue)
          onUpdate(parsed.state)
        } catch (error) {
          console.error('Failed to parse storage update:', error)
        }
      }
    }
    
    window.addEventListener('storage', handleStorageChange)
    
    return () => {
      window.removeEventListener('storage', handleStorageChange)
    }
  }, [storageKey, onUpdate])
}

// Usage with Zustand store
import { useAuthStore } from '@/core/lib/auth.store'
import { useCrossTabSync } from '@/core/lib/storage-sync'

function App() {
  const setAuth = useAuthStore((state) => state.setAuth)
  const clearAuth = useAuthStore((state) => state.clearAuth)
  
  // Sync auth state across tabs
  useCrossTabSync('auth-storage', (newState) => {
    if (newState.isAuthenticated) {
      setAuth(newState.accessToken, newState.user)
    } else {
      clearAuth()
    }
  })
  
  return <div>...</div>
}
```

### Method 2: BroadcastChannel (Modern)

```typescript
// src/core/lib/broadcast-sync.ts
export class StorageBroadcast<T> {
  private channel: BroadcastChannel
  
  constructor(
    private channelName: string,
    private onMessage: (data: T) => void
  ) {
    this.channel = new BroadcastChannel(channelName)
    this.channel.onmessage = (event) => {
      this.onMessage(event.data)
    }
  }
  
  send(data: T) {
    this.channel.postMessage(data)
  }
  
  close() {
    this.channel.close()
  }
}

// Create a Zustand middleware for broadcast sync
import { StateCreator, StoreMutatorIdentifier } from 'zustand'

type BroadcastSync = <
  T extends object,
  Mps extends [StoreMutatorIdentifier, unknown][] = [],
  Mcs extends [StoreMutatorIdentifier, unknown][] = []
>(
  f: StateCreator<T, Mps, Mcs>,
  channelName: string
) => StateCreator<T, Mps, Mcs>

export const broadcastSync: BroadcastSync = (f, channelName) => (set, get, api) => {
  const channel = new BroadcastChannel(channelName)
  
  // Listen for updates from other tabs
  channel.onmessage = (event) => {
    set(event.data, true) // Replace state
  }
  
  // Override set to broadcast changes
  const setState = api.setState
  api.setState = (update, replace, action) => {
    setState(update, replace, action)
    
    // Broadcast the new state to other tabs
    const state = api.getState()
    channel.postMessage(state)
  }
  
  return f(set, get, api)
}

// Usage
import { create } from 'zustand'
import { broadcastSync } from './broadcast-sync'

const useStore = create(
  broadcastSync(
    (set) => ({
      count: 0,
      increment: () => set((state) => ({ count: state.count + 1 })),
    }),
    'my-store-channel'
  )
)
```

### Method 3: Third-Party Library (zustand-sync-tabs)

```bash
npm install zustand-sync-tabs
```

```typescript
import { create } from 'zustand'
import { syncTabs } from 'zustand-sync-tabs'

const useStore = create(
  syncTabs(
    (set) => ({
      count: 0,
      increment: () => set((state) => ({ count: state.count + 1 })),
    }),
    { name: 'my-channel' }
  )
)
```

### Logout Sync Pattern

```typescript
// Ensure logout in one tab logs out all tabs
const useAuthStore = create<AuthStore>()(
  devtools(
    (set) => ({
      // ...
      
      logout: async () => {
        try {
          await api.post('/auth/logout')
        } finally {
          set({ 
            accessToken: null,
            user: null,
            isAuthenticated: false
          })
          
          // Broadcast logout to other tabs
          const channel = new BroadcastChannel('auth-sync')
          channel.postMessage({ type: 'LOGOUT' })
          channel.close()
        }
      },
    })
  )
)

// Listen for logout in App.tsx
useEffect(() => {
  const channel = new BroadcastChannel('auth-sync')
  
  channel.onmessage = (event) => {
    if (event.data.type === 'LOGOUT') {
      useAuthStore.getState().clearAuth()
      window.location.href = '/login'
    }
  }
  
  return () => channel.close()
}, [])
```

---

## Protected Routes Integration

### React Router v6/v7 Protected Route Pattern

```typescript
// src/core/components/ProtectedRoute.tsx
import { Navigate, useLocation, Outlet } from 'react-router-dom'
import { useAuthStore } from '@/core/lib/auth.store'
import { useEffect } from 'react'

interface ProtectedRouteProps {
  requiredRole?: string
  requiredPermission?: string
  redirectTo?: string
}

export function ProtectedRoute({
  requiredRole,
  requiredPermission,
  redirectTo = '/login',
}: ProtectedRouteProps) {
  const location = useLocation()
  const { isAuthenticated, isLoading, user, checkAuth } = useAuthStore()
  
  // Check auth on mount
  useEffect(() => {
    if (!isAuthenticated && !isLoading) {
      checkAuth()
    }
  }, [isAuthenticated, isLoading, checkAuth])
  
  // Show loading spinner while checking auth
  if (isLoading) {
    return <div>Loading...</div>
  }
  
  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to={redirectTo} state={{ from: location }} replace />
  }
  
  // Check role if required
  if (requiredRole && user?.role !== requiredRole) {
    return <Navigate to="/forbidden" replace />
  }
  
  // Check permission if required
  if (requiredPermission && !user?.permissions.includes(requiredPermission)) {
    return <Navigate to="/forbidden" replace />
  }
  
  // Render protected content
  return <Outlet />
}
```

### Route Configuration

```typescript
// src/App.tsx
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ProtectedRoute } from '@/core/components/ProtectedRoute'
import { useAuthStore } from '@/core/lib/auth.store'
import { useEffect } from 'react'

function App() {
  const checkAuth = useAuthStore((state) => state.checkAuth)
  
  // Check auth on app mount
  useEffect(() => {
    checkAuth()
  }, [checkAuth])
  
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes */}
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        
        {/* Protected routes */}
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/profile" element={<Profile />} />
        </Route>
        
        {/* Admin-only routes */}
        <Route element={<ProtectedRoute requiredRole="admin" />}>
          <Route path="/admin" element={<AdminPanel />} />
          <Route path="/admin/users" element={<UserManagement />} />
        </Route>
        
        {/* Permission-based routes */}
        <Route element={<ProtectedRoute requiredPermission="edit:posts" />}>
          <Route path="/posts/edit/:id" element={<EditPost />} />
        </Route>
        
        {/* 404 */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  )
}
```

### Login Redirect Pattern

```typescript
// src/pages/Login/LoginPage.tsx
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/core/lib/auth.store'

function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const login = useAuthStore((state) => state.login)
  
  // Get intended destination from location state
  const from = location.state?.from?.pathname || '/dashboard'
  
  const handleLogin = async (email: string, password: string) => {
    try {
      await login(email, password)
      
      // Redirect to intended destination
      navigate(from, { replace: true })
    } catch (error) {
      toast.error('Login failed')
    }
  }
  
  return <LoginForm onSubmit={handleLogin} />
}
```

### Public Route Guard (Redirect Authenticated Users)

```typescript
// src/core/components/PublicRoute.tsx
import { Navigate, Outlet } from 'react-router-dom'
import { useAuthStore } from '@/core/lib/auth.store'

export function PublicRoute() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)
  
  // If authenticated, redirect to dashboard
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }
  
  return <Outlet />
}

// Usage
<Route element={<PublicRoute />}>
  <Route path="/login" element={<LoginPage />} />
  <Route path="/register" element={<RegisterPage />} />
</Route>
```

---

## TypeScript Patterns

### Type-Safe Store Creation

```typescript
// src/core/types/store.types.ts
import { StateCreator } from 'zustand'

// Separate state from actions for clarity
export interface TodoState {
  todos: Todo[]
  filter: 'all' | 'active' | 'completed'
}

export interface TodoActions {
  addTodo: (text: string) => void
  toggleTodo: (id: string) => void
  deleteTodo: (id: string) => void
  setFilter: (filter: TodoState['filter']) => void
}

export type TodoStore = TodoState & TodoActions

// Store creator with proper typing
export const createTodoStore: StateCreator<TodoStore> = (set) => ({
  // State
  todos: [],
  filter: 'all',
  
  // Actions
  addTodo: (text) => set((state) => ({
    todos: [...state.todos, { id: nanoid(), text, completed: false }]
  })),
  
  toggleTodo: (id) => set((state) => ({
    todos: state.todos.map(todo =>
      todo.id === id ? { ...todo, completed: !todo.completed } : todo
    )
  })),
  
  deleteTodo: (id) => set((state) => ({
    todos: state.todos.filter(todo => todo.id !== id)
  })),
  
  setFilter: (filter) => set({ filter }),
})
```

### Typing Middleware Combinations

```typescript
// Correct TypeScript for middleware chains
import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'

interface MyState {
  count: number
  nested: { value: number }
  increase: () => void
}

// Option 1: Let TypeScript infer (recommended)
const useStore = create<MyState>()(
  devtools(
    persist(
      immer((set) => ({
        count: 0,
        nested: { value: 0 },
        increase: () => set((state) => {
          state.count++ // Immer mutable syntax
        }),
      })),
      { name: 'my-store' }
    )
  )
)

// Option 2: Explicit typing with StateCreator
import { StateCreator } from 'zustand'

type Mutators = [
  ['zustand/devtools', never],
  ['zustand/persist', unknown],
  ['zustand/immer', never]
]

const storeCreator: StateCreator<
  MyState,
  Mutators,
  [],
  MyState
> = (set) => ({
  count: 0,
  nested: { value: 0 },
  increase: () => set((state) => {
    state.count++
  }),
})

const useStore = create<MyState>()(
  devtools(
    persist(
      immer(storeCreator),
      { name: 'my-store' }
    )
  )
)
```

### Slice Pattern with TypeScript

```typescript
// src/stores/slices/auth.slice.ts
import { StateCreator } from 'zustand'

export interface AuthSlice {
  user: User | null
  isAuthenticated: boolean
  login: (user: User) => void
  logout: () => void
}

// Define mutators if using middleware
type StoreState = AuthSlice & UISlice // Combined store type

export const createAuthSlice: StateCreator<
  StoreState,
  [],
  [],
  AuthSlice
> = (set) => ({
  user: null,
  isAuthenticated: false,
  login: (user) => set({ user, isAuthenticated: true }),
  logout: () => set({ user: null, isAuthenticated: false }),
})

// src/stores/slices/ui.slice.ts
export interface UISlice {
  theme: 'light' | 'dark'
  toggleTheme: () => void
}

export const createUISlice: StateCreator<
  StoreState,
  [],
  [],
  UISlice
> = (set) => ({
  theme: 'light',
  toggleTheme: () => set((state) => ({
    theme: state.theme === 'light' ? 'dark' : 'light'
  })),
})

// src/stores/app.store.ts
import { create } from 'zustand'
import { createAuthSlice, AuthSlice } from './slices/auth.slice'
import { createUISlice, UISlice } from './slices/ui.slice'

type AppStore = AuthSlice & UISlice

export const useAppStore = create<AppStore>()((...a) => ({
  ...createAuthSlice(...a),
  ...createUISlice(...a),
}))
```

### Selector Type Safety

```typescript
// Type-safe selector exports
export const selectUser = (state: AuthStore) => state.user
export const selectIsAuthenticated = (state: AuthStore) => state.isAuthenticated

export const selectUserEmail = (state: AuthStore) => state.user?.email
// Return type: string | undefined

// With default value
export const selectUserRole = (state: AuthStore) => state.user?.role ?? 'guest'
// Return type: string

// Computed selector
export const selectIsAdmin = (state: AuthStore) => state.user?.role === 'admin'
// Return type: boolean
```

---

## Middleware Combinations

### Middleware Order Matters

**General Rule:** Inner middleware modifies state logic, outer middleware observes/persists.

```typescript
// Recommended order:
create(
  devtools(        // Outermost: observe all changes
    persist(       // Persist after all transformations
      immer(       // Innermost: enables mutable updates
        (set) => ({
          // store
        })
      )
    )
  )
)
```

**Why this order:**
1. **immer**: Innermost, transforms `set` to allow mutable updates
2. **persist**: Middle, saves state after immer transforms it
3. **devtools**: Outermost, logs all state changes for debugging

### Common Combinations

#### 1. Persist + DevTools

```typescript
import { create } from 'zustand'
import { devtools, persist, createJSONStorage } from 'zustand/middleware'

const useStore = create<MyState>()(
  devtools(
    persist(
      (set) => ({
        count: 0,
        increment: () => set((state) => ({ count: state.count + 1 })),
      }),
      {
        name: 'counter-storage',
        storage: createJSONStorage(() => localStorage),
      }
    ),
    { name: 'CounterStore' }
  )
)
```

#### 2. Persist + Immer + DevTools

```typescript
import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'

interface NestedState {
  nested: {
    deeply: {
      value: number
    }
  }
  increment: () => void
}

const useStore = create<NestedState>()(
  devtools(
    persist(
      immer((set) => ({
        nested: { deeply: { value: 0 } },
        increment: () => set((state) => {
          state.nested.deeply.value++ // Mutable with Immer!
        }),
      })),
      { name: 'nested-storage' }
    ),
    { name: 'NestedStore' }
  )
)
```

#### 3. Persist (Partial) + DevTools

```typescript
const useStore = create<MyState>()(
  devtools(
    persist(
      (set) => ({
        // Persisted
        theme: 'light',
        preferences: {},
        
        // Not persisted
        currentPage: 1,
        isModalOpen: false,
        
        // Actions
        setTheme: (theme) => set({ theme }),
      }),
      {
        name: 'settings-storage',
        partialize: (state) => ({
          theme: state.theme,
          preferences: state.preferences,
        }),
      }
    ),
    { name: 'SettingsStore' }
  )
)
```

### Production-Ready Auth Store with All Middleware

```typescript
// src/core/lib/auth.store.ts
import { create } from 'zustand'
import { devtools, persist, createJSONStorage } from 'zustand/middleware'

interface AuthState {
  accessToken: string | null
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
}

interface AuthActions {
  setAuth: (token: string, user: User) => void
  clearAuth: () => void
  refreshAccessToken: () => Promise<void>
  checkAuth: () => Promise<void>
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  devtools(
    persist(
      (set, get) => ({
        // State
        accessToken: null,
        user: null,
        isAuthenticated: false,
        isLoading: true,
        
        // Actions
        setAuth: (token, user) => set(
          { accessToken: token, user, isAuthenticated: true, isLoading: false },
          false,
          'auth/setAuth'
        ),
        
        clearAuth: () => set(
          { accessToken: null, user: null, isAuthenticated: false, isLoading: false },
          false,
          'auth/clearAuth'
        ),
        
        refreshAccessToken: async () => {
          try {
            const { accessToken, user } = await api.post('/auth/refresh')
            get().setAuth(accessToken, user)
          } catch (error) {
            get().clearAuth()
            throw error
          }
        },
        
        checkAuth: async () => {
          set({ isLoading: true })
          try {
            await get().refreshAccessToken()
          } catch {
            get().clearAuth()
          }
        },
      }),
      {
        name: 'auth-storage',
        
        // Only persist user data, NOT the access token
        partialize: (state) => ({
          user: state.user,
          isAuthenticated: state.isAuthenticated,
        }),
        
        storage: createJSONStorage(() => sessionStorage),
        
        onRehydrateStorage: () => (state, error) => {
          if (error) {
            console.error('Auth hydration failed:', error)
          }
          
          // After rehydration, check if we need to refresh token
          if (state?.isAuthenticated) {
            state.checkAuth()
          }
        },
      }
    ),
    { name: 'AuthStore' }
  )
)
```

---

## Testing Strategies

### Testing Zustand Stores

```typescript
// src/core/lib/__tests__/auth.store.test.ts
import { renderHook, act } from '@testing-library/react'
import { useAuthStore } from '../auth.store'

describe('AuthStore', () => {
  beforeEach(() => {
    // Reset store before each test
    useAuthStore.setState({
      accessToken: null,
      user: null,
      isAuthenticated: false,
      isLoading: false,
    })
  })
  
  it('should set auth state', () => {
    const { result } = renderHook(() => useAuthStore())
    
    const mockUser = { id: '1', email: 'test@example.com', name: 'Test' }
    const mockToken = 'mock-token'
    
    act(() => {
      result.current.setAuth(mockToken, mockUser)
    })
    
    expect(result.current.accessToken).toBe(mockToken)
    expect(result.current.user).toEqual(mockUser)
    expect(result.current.isAuthenticated).toBe(true)
  })
  
  it('should clear auth state', () => {
    const { result } = renderHook(() => useAuthStore())
    
    // Set auth first
    act(() => {
      result.current.setAuth('token', { id: '1', email: 'test@example.com' })
    })
    
    // Clear auth
    act(() => {
      result.current.clearAuth()
    })
    
    expect(result.current.accessToken).toBeNull()
    expect(result.current.user).toBeNull()
    expect(result.current.isAuthenticated).toBe(false)
  })
})
```

### Testing with Mock API

```typescript
import { vi } from 'vitest'

vi.mock('@/core/api/client', () => ({
  api: {
    post: vi.fn(),
  },
}))

import { api } from '@/core/api/client'

describe('AuthStore async actions', () => {
  it('should handle login success', async () => {
    const mockResponse = {
      accessToken: 'new-token',
      user: { id: '1', email: 'test@example.com' },
    }
    
    vi.mocked(api.post).mockResolvedValue(mockResponse)
    
    const { result } = renderHook(() => useAuthStore())
    
    await act(async () => {
      await result.current.login('test@example.com', 'password')
    })
    
    expect(result.current.accessToken).toBe('new-token')
    expect(result.current.isAuthenticated).toBe(true)
  })
  
  it('should handle login failure', async () => {
    vi.mocked(api.post).mockRejectedValue(new Error('Login failed'))
    
    const { result } = renderHook(() => useAuthStore())
    
    await expect(
      act(async () => {
        await result.current.login('test@example.com', 'wrong-password')
      })
    ).rejects.toThrow('Login failed')
    
    expect(result.current.isAuthenticated).toBe(false)
  })
})
```

### Testing Components with Zustand

```typescript
import { render, screen } from '@testing-library/react'
import { useAuthStore } from '@/core/lib/auth.store'
import { Dashboard } from './Dashboard'

describe('Dashboard', () => {
  it('should show user name', () => {
    // Set store state
    useAuthStore.setState({
      user: { id: '1', name: 'John Doe', email: 'john@example.com' },
      isAuthenticated: true,
    })
    
    render(<Dashboard />)
    
    expect(screen.getByText('Welcome, John Doe')).toBeInTheDocument()
  })
})
```

---

## Security Best Practices

### 1. Never Store Sensitive Data in Persistence

```typescript
// ❌ BAD: Persisting access token
persist(
  (set) => ({
    accessToken: 'token', // XSS vulnerable!
    user: {},
  }),
  { name: 'auth' }
)

// ✅ GOOD: Only persist non-sensitive data
persist(
  (set) => ({
    accessToken: 'token', // In memory only
    user: {},
  }),
  {
    name: 'auth',
    partialize: (state) => ({
      user: state.user, // Only persist user data
    }),
  }
)
```

### 2. Encrypt Sensitive Persisted Data

```typescript
import CryptoJS from 'crypto-js'

const SECRET_KEY = import.meta.env.VITE_STORAGE_KEY

persist(
  (set) => ({ /* store */ }),
  {
    name: 'sensitive-store',
    storage: {
      getItem: (name) => {
        const encrypted = localStorage.getItem(name)
        if (!encrypted) return null
        
        try {
          const decrypted = CryptoJS.AES.decrypt(
            encrypted,
            SECRET_KEY
          ).toString(CryptoJS.enc.Utf8)
          return decrypted
        } catch {
          return null
        }
      },
      setItem: (name, value) => {
        const encrypted = CryptoJS.AES.encrypt(
          value,
          SECRET_KEY
        ).toString()
        localStorage.setItem(name, encrypted)
      },
      removeItem: (name) => localStorage.removeItem(name),
    },
  }
)
```

### 3. Clear Sensitive Data on Logout

```typescript
const useAuthStore = create<AuthStore>((set) => ({
  logout: async () => {
    // Clear tokens from memory
    set({
      accessToken: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,
    })
    
    // Clear persisted data
    localStorage.removeItem('auth-storage')
    sessionStorage.clear()
    
    // Call logout endpoint (clears httpOnly cookie)
    await api.post('/auth/logout')
    
    // Redirect to login
    window.location.href = '/login'
  },
}))
```

### 4. Content Security Policy (CSP)

```html
<!-- public/index.html -->
<meta 
  http-equiv="Content-Security-Policy" 
  content="
    default-src 'self';
    script-src 'self' 'unsafe-inline';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    connect-src 'self' https://api.yourapp.com;
  "
/>
```

### 5. Token Rotation on Refresh

```python
# backend/app/routes/auth.py
@router.post("/refresh")
async def refresh(request: Request, response: Response):
    refresh_token = request.cookies.get("refreshToken")
    
    # Validate old refresh token
    payload = validate_refresh_token(refresh_token)
    user_id = payload["sub"]
    
    # Generate NEW tokens (rotate)
    new_access_token = create_access_token(user_id)
    new_refresh_token = create_refresh_token(user_id)  # New refresh token!
    
    # Invalidate old refresh token
    await invalidate_token(refresh_token)
    
    # Set new refresh token
    response.set_cookie(
        key="refreshToken",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    
    return {
        "accessToken": new_access_token,
        "user": await get_user(user_id),
    }
```

### 6. Rate Limiting

```typescript
// Simple in-memory rate limiter for client-side
class RateLimiter {
  private requests: number[] = []
  
  constructor(
    private maxRequests: number,
    private windowMs: number
  ) {}
  
  isAllowed(): boolean {
    const now = Date.now()
    const windowStart = now - this.windowMs
    
    // Remove old requests
    this.requests = this.requests.filter(time => time > windowStart)
    
    if (this.requests.length < this.maxRequests) {
      this.requests.push(now)
      return true
    }
    
    return false
  }
}

// Usage in store
const refreshLimiter = new RateLimiter(5, 60 * 1000) // 5 requests per minute

const useAuthStore = create<AuthStore>((set, get) => ({
  refreshAccessToken: async () => {
    if (!refreshLimiter.isAllowed()) {
      throw new Error('Too many refresh attempts')
    }
    
    // ... refresh logic
  },
}))
```

---

## Anti-Patterns to Avoid

### 1. ❌ Subscribing to Entire Store

```typescript
// ❌ BAD: Re-renders on every state change
function Component() {
  const state = useStore()
  return <div>{state.count}</div>
}

// ✅ GOOD: Only re-renders when count changes
function Component() {
  const count = useStore((state) => state.count)
  return <div>{count}</div>
}
```

### 2. ❌ Creating New Objects Without useShallow

```typescript
// ❌ BAD: Creates new object every render
function Component() {
  const { count, text } = useStore((state) => ({
    count: state.count,
    text: state.text,
  }))
  return <div>{count} - {text}</div>
}

// ✅ GOOD: Use useShallow
import { useShallow } from 'zustand/react/shallow'

function Component() {
  const { count, text } = useStore(
    useShallow((state) => ({
      count: state.count,
      text: state.text,
    }))
  )
  return <div>{count} - {text}</div>
}
```

### 3. ❌ Persisting Functions

```typescript
// ❌ BAD: Persisting actions
persist(
  (set) => ({
    count: 0,
    increment: () => set((s) => ({ count: s.count + 1 })),
  }),
  { name: 'store' } // Functions will be serialized as null!
)

// ✅ GOOD: Only persist state
persist(
  (set) => ({
    count: 0,
    increment: () => set((s) => ({ count: s.count + 1 })),
  }),
  {
    name: 'store',
    partialize: (state) => ({ count: state.count }),
  }
)
```

### 4. ❌ Storing Derived State

```typescript
// ❌ BAD: Storing computed values
const useStore = create((set) => ({
  items: [],
  totalPrice: 0, // Derived from items!
  
  addItem: (item) => set((state) => ({
    items: [...state.items, item],
    totalPrice: state.totalPrice + item.price, // Error-prone!
  })),
}))

// ✅ GOOD: Compute on the fly
const useStore = create((set) => ({
  items: [],
  addItem: (item) => set((state) => ({
    items: [...state.items, item],
  })),
}))

// Compute in component or selector
const totalPrice = useStore((state) =>
  state.items.reduce((sum, item) => sum + item.price, 0)
)
```

### 5. ❌ Not Cleaning Up Persisted Data

```typescript
// ❌ BAD: Old drafts pile up forever
persist(
  (set) => ({
    drafts: { /* hundreds of old drafts */ },
  }),
  { name: 'drafts' }
)

// ✅ GOOD: Clean up old data
const useStore = create(
  persist(
    (set, get) => ({
      drafts: {},
      
      // Add cleanup action
      cleanupOldDrafts: () => set((state) => {
        const now = Date.now()
        const maxAge = 7 * 24 * 60 * 60 * 1000 // 7 days
        
        const freshDrafts = Object.fromEntries(
          Object.entries(state.drafts).filter(
            ([_, draft]) => now - draft.lastSaved < maxAge
          )
        )
        
        return { drafts: freshDrafts }
      }),
    }),
    { name: 'drafts' }
  )
)

// Call cleanup periodically
useEffect(() => {
  const interval = setInterval(() => {
    useStore.getState().cleanupOldDrafts()
  }, 24 * 60 * 60 * 1000) // Daily
  
  return () => clearInterval(interval)
}, [])
```

### 6. ❌ Multiple Stores When One Would Do

```typescript
// ❌ BAD: Over-engineering
const useStore1 = create((set) => ({ count1: 0 }))
const useStore2 = create((set) => ({ count2: 0 }))
const useStore3 = create((set) => ({ count3: 0 }))

// ✅ GOOD: Use slices in one store
const useStore = create((set) => ({
  count1: 0,
  count2: 0,
  count3: 0,
  // Or use slice pattern if complex
}))
```

### 7. ❌ Ignoring Middleware Order

```typescript
// ❌ BAD: Devtools inside persist
const useStore = create(
  persist(
    devtools(
      (set) => ({ count: 0 })
    )
  )
)
// Devtools won't see persisted state correctly!

// ✅ GOOD: Devtools outside persist
const useStore = create(
  devtools(
    persist(
      (set) => ({ count: 0 })
    )
  )
)
```

### 8. ❌ Storing Non-Serializable Data

```typescript
// ❌ BAD: Storing class instances
persist(
  (set) => ({
    date: new Date(), // Loses methods after serialization!
    map: new Map(),   // Serializes to {}
    set: new Set(),   // Serializes to {}
  }),
  { name: 'store' }
)

// ✅ GOOD: Store primitive/plain data
persist(
  (set) => ({
    date: Date.now(), // Timestamp
    map: { key: 'value' }, // Plain object
    set: ['item1', 'item2'], // Array
  }),
  { name: 'store' }
)
```

---

## Production Checklist

### Security
- [ ] Access tokens in memory (Zustand), not localStorage
- [ ] Refresh tokens in httpOnly cookies
- [ ] CSRF protection with SameSite=Strict
- [ ] Content Security Policy headers
- [ ] Token rotation on refresh
- [ ] Rate limiting for auth endpoints
- [ ] Encryption for sensitive persisted data
- [ ] Clear auth on logout (memory + storage)

### Performance
- [ ] Atomic selectors for primitives
- [ ] `useShallow` for object selectors
- [ ] `partialize` to limit persisted data
- [ ] Cleanup old persisted data (TTL)
- [ ] Avoid derived state in store
- [ ] Split large stores into slices
- [ ] Lazy load page stores

### TypeScript
- [ ] Proper typing for stores
- [ ] Type-safe selectors
- [ ] Correct middleware typing
- [ ] Slice pattern with StateCreator
- [ ] Avoid `any` types

### Testing
- [ ] Unit tests for store actions
- [ ] Mock API calls
- [ ] Test persistence behavior
- [ ] Test cross-component integration
- [ ] Test protected routes

### DevTools
- [ ] DevTools enabled in development
- [ ] Action names for better debugging
- [ ] Store names for multiple stores

### Middleware
- [ ] Correct middleware order
- [ ] Only persist necessary state
- [ ] Version management for migrations
- [ ] Error handling in onRehydrateStorage

### Auth
- [ ] checkAuth on app mount
- [ ] Token refresh on 401
- [ ] Request queue during refresh
- [ ] Logout synced across tabs
- [ ] Protected route guards
- [ ] Role-based access control

---

## Final Architecture Diagram

```
┌────────────────────────────────────────────────────────┐
│                     React App                          │
│                                                        │
│  ┌──────────────────────────────────────────────┐   │
│  │         Protected Routes                     │   │
│  │  ┌────────────────┐  ┌──────────────────┐  │   │
│  │  │  Dashboard     │  │  Settings        │  │   │
│  │  │                │  │                  │  │   │
│  │  │  Components    │  │  Components      │  │   │
│  │  │     │          │  │     │            │  │   │
│  │  │     └──────────┼──┼─────┘            │  │   │
│  │  └────────────────┘  └──────────────────┘  │   │
│  └──────────────┬───────────────┬──────────────┘   │
│                 │               │                   │
│  ┌──────────────▼───────────────▼──────────────┐   │
│  │            Zustand Stores                    │   │
│  │                                              │   │
│  │  ┌──────────────┐  ┌──────────────────┐    │   │
│  │  │ Auth Store   │  │ UI Stores        │    │   │
│  │  │ (Memory)     │  │ (Persist)        │    │   │
│  │  │              │  │                  │    │   │
│  │  │ accessToken ✓│  │ Dashboard UI     │    │   │
│  │  │ user ✓       │  │ Settings UI      │    │   │
│  │  │ isAuth ✓     │  │ Form Drafts      │    │   │
│  │  └──────┬───────┘  └──────────────────┘    │   │
│  │         │                                   │   │
│  │         │ Token for API calls               │   │
│  └─────────┼───────────────────────────────────┘   │
│            │                                        │
│  ┌─────────▼──────────────────────────────────┐   │
│  │        Axios Interceptors                   │   │
│  │                                             │   │
│  │  • Add Bearer token to requests             │   │
│  │  • Handle 401 -> refresh token              │   │
│  │  • Queue concurrent requests                │   │
│  └─────────┬───────────────────────────────────┘   │
└────────────┼────────────────────────────────────────┘
             │
             │ API Requests
             ▼
┌────────────────────────────────────────────────────────┐
│                  FastAPI Backend                       │
│                                                        │
│  POST /auth/login                                      │
│  → Returns: { accessToken, user }                     │
│  → Sets: refreshToken httpOnly cookie                 │
│                                                        │
│  POST /auth/refresh                                    │
│  → Reads: refreshToken from cookie                    │
│  → Returns: { accessToken, user }                     │
│                                                        │
│  POST /auth/logout                                     │
│  → Clears: refreshToken cookie                        │
└────────────────────────────────────────────────────────┘
```

---

## Conclusion

This guide provides production-ready patterns for:

1. **JWT Security**: Memory + httpOnly cookie hybrid
2. **UI State**: Per-page stores with selective persistence
3. **Performance**: Atomic selectors, useShallow, partialize
4. **TypeScript**: Full type safety with proper patterns
5. **Testing**: Comprehensive test strategies
6. **Security**: XSS/CSRF protection, encryption, rate limiting

**Key Takeaways:**
- Access token in memory, refresh token in httpOnly cookie
- Use `useShallow` for object/array selectors
- Only persist non-sensitive, necessary state
- Test stores in isolation, components with store state
- Follow middleware order: devtools -> persist -> immer
- Clean up old persisted data with TTL

**Next Steps:**
1. Implement auth store with httpOnly cookies
2. Set up axios interceptors with request queue
3. Create per-page UI stores with persistence
4. Add protected route guards
5. Write tests for critical flows
6. Monitor performance with React DevTools

---

**Resources:**
- [Zustand Docs](https://zustand.docs.pmnd.rs/)
- [Zustand GitHub](https://github.com/pmndrs/zustand)
- [JWT Best Practices (OWASP)](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [React Router Protected Routes](https://ui.dev/react-router-protected-routes-authentication)

Built for production SPAs in 2025. 🚀
