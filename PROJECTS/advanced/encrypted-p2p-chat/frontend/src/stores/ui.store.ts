/**
 * UI state store
 * Manages sidebar, modals, and other UI state
 */

import { atom, computed } from "nanostores"

type ModalType =
  | "new-conversation"
  | "user-search"
  | "settings"
  | "profile"
  | "encryption-info"
  | "confirm-logout"
  | null

interface ToastNotification {
  id: string
  variant: "info" | "success" | "warning" | "error"
  title: string
  description?: string
  duration?: number
}

export const $sidebarOpen = atom<boolean>(true)

export const $sidebarCollapsed = atom<boolean>(false)

export const $activeModal = atom<ModalType>(null)

export const $modalData = atom<Record<string, unknown>>({})

export const $toasts = atom<ToastNotification[]>([])

export const $isLoading = atom<boolean>(false)

export const $loadingMessage = atom<string>("")

export const $isMobile = atom<boolean>(false)

export const $searchQuery = atom<string>("")

export const $hasActiveModal = computed(
  $activeModal,
  (modal) => modal !== null
)

let toastIdCounter = 0

export function toggleSidebar(): void {
  $sidebarOpen.set(!$sidebarOpen.get())
}

export function openSidebar(): void {
  $sidebarOpen.set(true)
}

export function closeSidebar(): void {
  $sidebarOpen.set(false)
}

export function toggleSidebarCollapsed(): void {
  $sidebarCollapsed.set(!$sidebarCollapsed.get())
}

export function openModal(type: ModalType, data?: Record<string, unknown>): void {
  $activeModal.set(type)
  $modalData.set(data ?? {})
}

export function closeModal(): void {
  $activeModal.set(null)
  $modalData.set({})
}

export function showToast(
  variant: ToastNotification["variant"],
  title: string,
  description?: string,
  duration?: number
): string {
  const existingToasts = $toasts.get()
  const duplicate = existingToasts.find(
    (t) => t.title === title && t.description === description && t.variant === variant
  )

  if (duplicate !== undefined) {
    return duplicate.id
  }

  const id = `toast-${++toastIdCounter}`
  const toast: ToastNotification = {
    id,
    variant,
    title,
    description,
    duration: duration ?? 5000,
  }

  $toasts.set([...existingToasts, toast])

  const toastDuration = toast.duration ?? 5000
  if (toastDuration > 0) {
    setTimeout(() => {
      dismissToast(id)
    }, toastDuration)
  }

  return id
}

export function dismissToast(id: string): void {
  $toasts.set($toasts.get().filter((t) => t.id !== id))
}

export function clearAllToasts(): void {
  $toasts.set([])
}

export function setLoading(loading: boolean, message?: string): void {
  $isLoading.set(loading)
  $loadingMessage.set(message ?? "")
}

export function setIsMobile(isMobile: boolean): void {
  $isMobile.set(isMobile)
}

export function setSearchQuery(query: string): void {
  $searchQuery.set(query)
}

export function clearSearchQuery(): void {
  $searchQuery.set("")
}

export type { ModalType, ToastNotification }
