// ===========================
// uiStore.ts
// ©AngelaMos | 2025
// ===========================

import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'
import type { ScanTestType } from '@/config/constants'

interface LoginFormState {
  email: string
  password: string
  expiresAt: number | null
}

interface RegisterFormState {
  email: string
  password: string
  confirmPassword: string
  expiresAt: number | null
}

interface ScanFormState {
  targetUrl: string
  authToken: string
  selectedTests: ScanTestType[]
  maxRequests: string
  expiresAt: number | null
}

interface TestResultsState {
  expandedTests: Record<number, boolean>
}

interface UIState {
  loginForm: LoginFormState
  registerForm: RegisterFormState
  scanForm: ScanFormState
  testResults: TestResultsState
}

interface UIActions {
  setLoginFormField: (
    field: keyof Omit<LoginFormState, 'expiresAt'>,
    value: string
  ) => void
  setRegisterFormField: (
    field: keyof Omit<RegisterFormState, 'expiresAt'>,
    value: string
  ) => void
  setScanFormField: (
    field: keyof Omit<ScanFormState, 'expiresAt'>,
    value: string | ScanTestType[]
  ) => void
  toggleTestExpanded: (testId: number) => void
  clearLoginForm: () => void
  clearRegisterForm: () => void
  clearScanForm: () => void
  clearExpiredData: () => void
}

type UIStore = UIState & UIActions

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000

const getExpiry = (): number => Date.now() + SEVEN_DAYS_MS

const initialLoginForm: LoginFormState = {
  email: '',
  password: '',
  expiresAt: null,
}

const initialRegisterForm: RegisterFormState = {
  email: '',
  password: '',
  confirmPassword: '',
  expiresAt: null,
}

const initialScanForm: ScanFormState = {
  targetUrl: '',
  authToken: '',
  selectedTests: [],
  maxRequests: '50',
  expiresAt: null,
}

const initialTestResults: TestResultsState = {
  expandedTests: {},
}

export const useUIStore = create<UIStore>()(
  persist(
    immer((set) => ({
      loginForm: initialLoginForm,
      registerForm: initialRegisterForm,
      scanForm: initialScanForm,
      testResults: initialTestResults,

      setLoginFormField: (field, value): void => {
        set((state) => {
          state.loginForm[field] = value
          state.loginForm.expiresAt = getExpiry()
        })
      },

      setRegisterFormField: (field, value): void => {
        set((state) => {
          state.registerForm[field] = value
          state.registerForm.expiresAt = getExpiry()
        })
      },

      setScanFormField: (field, value): void => {
        set((state) => {
          state.scanForm[field] = value as never
          state.scanForm.expiresAt = getExpiry()
        })
      },

      toggleTestExpanded: (testId): void => {
        set((state) => {
          const currentValue = state.testResults.expandedTests[testId] ?? false
          state.testResults.expandedTests[testId] = !currentValue
        })
      },

      clearLoginForm: (): void => {
        set((state) => {
          state.loginForm = initialLoginForm
        })
      },

      clearRegisterForm: (): void => {
        set((state) => {
          state.registerForm = initialRegisterForm
        })
      },

      clearScanForm: (): void => {
        set((state) => {
          state.scanForm = initialScanForm
        })
      },

      clearExpiredData: (): void => {
        set((state) => {
          const now = Date.now()

          if (
            state.loginForm.expiresAt !== null &&
            state.loginForm.expiresAt < now
          ) {
            state.loginForm = initialLoginForm
          }

          if (
            state.registerForm.expiresAt !== null &&
            state.registerForm.expiresAt < now
          ) {
            state.registerForm = initialRegisterForm
          }

          if (
            state.scanForm.expiresAt !== null &&
            state.scanForm.expiresAt < now
          ) {
            state.scanForm = initialScanForm
          }
        })
      },
    })),
    {
      name: 'ui-storage',
      partialize: (state) => ({
        loginForm: state.loginForm,
        registerForm: state.registerForm,
        scanForm: state.scanForm,
        testResults: state.testResults,
      }),
    }
  )
)
