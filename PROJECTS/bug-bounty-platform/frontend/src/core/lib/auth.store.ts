// ===================
// © AngelaMos | 2025
// auth.store.ts
// ===================

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { type UserResponse, UserRole } from '@/api/types'
import { STORAGE_KEYS } from '@/config'

interface AuthState {
  user: UserResponse | null
  accessToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
}

interface AuthActions {
  login: (user: UserResponse, accessToken: string) => void
  logout: () => void
  setLoading: (loading: boolean) => void
  setAccessToken: (token: string | null) => void
  updateUser: (updates: Partial<UserResponse>) => void
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  devtools(
    persist(
      (set) => ({
        user: null,
        accessToken: null,
        isAuthenticated: false,
        isLoading: false,

        login: (user, accessToken) =>
          set(
            {
              user,
              accessToken,
              isAuthenticated: true,
              isLoading: false,
            },
            false,
            'auth/login'
          ),

        logout: () =>
          set(
            {
              user: null,
              accessToken: null,
              isAuthenticated: false,
              isLoading: false,
            },
            false,
            'auth/logout'
          ),

        setLoading: (loading) =>
          set({ isLoading: loading }, false, 'auth/setLoading'),

        setAccessToken: (token) =>
          set({ accessToken: token }, false, 'auth/setAccessToken'),

        updateUser: (updates) =>
          set(
            (state) => ({
              user: state.user !== null ? { ...state.user, ...updates } : null,
            }),
            false,
            'auth/updateUser'
          ),
      }),
      {
        name: STORAGE_KEYS.AUTH,
        partialize: (state) => ({
          user: state.user,
          isAuthenticated: state.isAuthenticated,
        }),
      }
    ),
    { name: 'AuthStore' }
  )
)

export const useUser = (): UserResponse | null => useAuthStore((s) => s.user)
export const useIsAuthenticated = (): boolean =>
  useAuthStore((s) => s.isAuthenticated)
export const useIsAuthLoading = (): boolean => useAuthStore((s) => s.isLoading)
export const useAccessToken = (): string | null =>
  useAuthStore((s) => s.accessToken)

export const useHasRole = (role: UserRole): boolean => {
  const user = useAuthStore((s) => s.user)
  return user !== null && user.role === role
}

export const useIsAdmin = (): boolean => {
  const user = useAuthStore((s) => s.user)
  return user !== null && user.role === UserRole.ADMIN
}

export { UserRole }
