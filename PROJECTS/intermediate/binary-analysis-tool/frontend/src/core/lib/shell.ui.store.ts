/**
 * ©AngelaMos | 2026
 * shell.ui.store.ts
 *
 * Zustand UI state store with devtools and localStorage
 * persistence
 *
 * Manages global theme (light/dark/system), sidebar open
 * state, and sidebar collapsed state through a single
 * Zustand store wrapped in devtools (named "UIStore" for
 * Redux DevTools inspection) and persist middleware that
 * serializes theme and sidebarCollapsed to localStorage
 * under the "ui-storage" key. Exports three selector
 * hooks (useTheme, useSidebarOpen, useSidebarCollapsed)
 * for granular subscriptions without re-renders
 *
 * Connects to:
 *   config.ts   - STORAGE_KEYS.UI matches persist key
 *   shell.tsx   - consumes sidebar/theme state
 *   pages/      - theme-aware rendering
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'

type Theme = 'light' | 'dark' | 'system'

interface UIState {
  theme: Theme
  sidebarOpen: boolean
  sidebarCollapsed: boolean
  setTheme: (theme: Theme) => void
  toggleSidebar: () => void
  setSidebarOpen: (open: boolean) => void
  toggleSidebarCollapsed: () => void
}

export const useUIStore = create<UIState>()(
  devtools(
    persist(
      (set) => ({
        theme: 'dark',
        sidebarOpen: false,
        sidebarCollapsed: false,

        setTheme: (theme) => set({ theme }, false, 'ui/setTheme'),

        toggleSidebar: () =>
          set(
            (state) => ({ sidebarOpen: !state.sidebarOpen }),
            false,
            'ui/toggleSidebar'
          ),

        setSidebarOpen: (open) =>
          set({ sidebarOpen: open }, false, 'ui/setSidebarOpen'),

        toggleSidebarCollapsed: () =>
          set(
            (state) => ({ sidebarCollapsed: !state.sidebarCollapsed }),
            false,
            'ui/toggleSidebarCollapsed'
          ),
      }),
      {
        name: 'ui-storage',
        partialize: (state) => ({
          theme: state.theme,
          sidebarCollapsed: state.sidebarCollapsed,
        }),
      }
    ),
    { name: 'UIStore' }
  )
)

export const useTheme = (): Theme => useUIStore((s) => s.theme)
export const useSidebarOpen = (): boolean => useUIStore((s) => s.sidebarOpen)
export const useSidebarCollapsed = (): boolean =>
  useUIStore((s) => s.sidebarCollapsed)
