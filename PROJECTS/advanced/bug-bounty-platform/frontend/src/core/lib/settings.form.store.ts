/**
 * ©AngelaMos | 2026
 * settings.form.store.ts
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'

interface SettingsFormState {
  fullName: string
  setFullName: (fullName: string) => void
  clearForm: () => void
}

const initialState = {
  fullName: '',
}

export const useSettingsFormStore = create<SettingsFormState>()(
  devtools(
    persist(
      (set) => ({
        ...initialState,

        setFullName: (fullName) =>
          set({ fullName }, false, 'settingsForm/setFullName'),

        clearForm: () => set(initialState, false, 'settingsForm/clearForm'),
      }),
      {
        name: 'settings-form-storage',
      }
    ),
    { name: 'SettingsFormStore' }
  )
)
