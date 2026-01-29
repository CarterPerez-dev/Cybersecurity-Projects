/**
 * ©AngelaMos | 2025
 * auth.form.store.ts
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'

interface AuthFormState {
  loginEmail: string
  registerEmail: string
  setLoginEmail: (email: string) => void
  setRegisterEmail: (email: string) => void
  clearLoginForm: () => void
  clearRegisterForm: () => void
}

export const useAuthFormStore = create<AuthFormState>()(
  devtools(
    persist(
      (set) => ({
        loginEmail: '',
        registerEmail: '',

        setLoginEmail: (email) =>
          set({ loginEmail: email }, false, 'authForm/setLoginEmail'),

        setRegisterEmail: (email) =>
          set({ registerEmail: email }, false, 'authForm/setRegisterEmail'),

        clearLoginForm: () =>
          set({ loginEmail: '' }, false, 'authForm/clearLoginForm'),

        clearRegisterForm: () =>
          set({ registerEmail: '' }, false, 'authForm/clearRegisterForm'),
      }),
      {
        name: 'auth-form-storage',
      }
    ),
    { name: 'AuthFormStore' }
  )
)
