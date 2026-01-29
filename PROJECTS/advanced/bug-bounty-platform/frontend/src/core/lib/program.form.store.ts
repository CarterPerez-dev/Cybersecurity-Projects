/**
 * ©AngelaMos | 2026
 * program.form.store.ts
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { ProgramVisibility } from '@/api/types'

interface ProgramFormState {
  name: string
  slug: string
  description: string
  rules: string
  responseSlaHours: number
  visibility: ProgramVisibility
  setName: (name: string) => void
  setSlug: (slug: string) => void
  setDescription: (description: string) => void
  setRules: (rules: string) => void
  setResponseSlaHours: (hours: number) => void
  setVisibility: (visibility: ProgramVisibility) => void
  clearForm: () => void
}

const initialState = {
  name: '',
  slug: '',
  description: '',
  rules: '',
  responseSlaHours: 72,
  visibility: ProgramVisibility.PUBLIC,
}

export const useProgramFormStore = create<ProgramFormState>()(
  devtools(
    persist(
      (set) => ({
        ...initialState,

        setName: (name) => set({ name }, false, 'programForm/setName'),

        setSlug: (slug) => set({ slug }, false, 'programForm/setSlug'),

        setDescription: (description) =>
          set({ description }, false, 'programForm/setDescription'),

        setRules: (rules) => set({ rules }, false, 'programForm/setRules'),

        setResponseSlaHours: (hours) =>
          set(
            { responseSlaHours: hours },
            false,
            'programForm/setResponseSlaHours'
          ),

        setVisibility: (visibility) =>
          set({ visibility }, false, 'programForm/setVisibility'),

        clearForm: () => set(initialState, false, 'programForm/clearForm'),
      }),
      {
        name: 'program-form-storage',
      }
    ),
    { name: 'ProgramFormStore' }
  )
)
