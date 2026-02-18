// ===========================
// authStore.ts
// ©AngelaMos | 2025
// ===========================

import { create } from 'zustand'
import { immer } from 'zustand/middleware/immer'
import { STORAGE_KEYS } from '@/config/constants'
import type { AuthUser } from '@/types/auth.types'

interface AuthState {
  user: AuthUser | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
}

interface AuthActions {
  setAuth: (user: AuthUser, token: string) => void
  clearAuth: () => void
  loadUserFromStorage: () => void
  setLoading: (loading: boolean) => void
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  immer((set) => ({
    user: null,
    token: null,
    isAuthenticated: false,
    isLoading: true,

    setAuth: (user: AuthUser, token: string): void => {
      set((state) => {
        state.user = user
        state.token = token
        state.isAuthenticated = true
        state.isLoading = false
      })

      localStorage.setItem(STORAGE_KEYS.AUTH_TOKEN, token)
      localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user))
    },

    clearAuth: (): void => {
      set((state) => {
        state.user = null
        state.token = null
        state.isAuthenticated = false
        state.isLoading = false
      })

      localStorage.removeItem(STORAGE_KEYS.AUTH_TOKEN)
      localStorage.removeItem(STORAGE_KEYS.USER)
    },

    loadUserFromStorage: (): void => {
      const token = localStorage.getItem(STORAGE_KEYS.AUTH_TOKEN)
      const userJson = localStorage.getItem(STORAGE_KEYS.USER)

      if (
        token !== null &&
        token !== undefined &&
        userJson !== null &&
        userJson !== undefined
      ) {
        try {
          const user = JSON.parse(userJson) as AuthUser

          set((state) => {
            state.user = user
            state.token = token
            state.isAuthenticated = true
            state.isLoading = false
          })
        } catch {
          set((state) => {
            state.isLoading = false
          })
        }
      } else {
        set((state) => {
          state.isLoading = false
        })
      }
    },

    setLoading: (loading: boolean): void => {
      set((state) => {
        state.isLoading = loading
      })
    },
  }))
)
