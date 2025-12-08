/**
 * Authentication state store
 * Manages current user and authentication status
 */

import { atom, computed } from "nanostores"
import { persistentAtom } from "@nanostores/persistent"
import type { User, Session } from "../types"

export const $currentUser = atom<User | null>(null)

const $userIdRaw = persistentAtom<string>("chat:user_id", "", {
  encode: (value: string) => value,
  decode: (value: string) => value,
})

export const $userId = computed($userIdRaw, (id) => id !== "" ? id : null)

export const $isAuthenticated = computed($userId, (id) => id !== null)

export const $session = atom<Session | null>(null)

export function setCurrentUser(user: User | null): void {
  $currentUser.set(user)
  $userIdRaw.set(user?.id ?? "")

  if (user !== null) {
    $session.set({
      userId: user.id,
      username: user.username,
      displayName: user.display_name,
      isActive: user.is_active,
      authenticatedAt: new Date().toISOString(),
    })
  } else {
    $session.set(null)
  }
}

export function logout(): void {
  $currentUser.set(null)
  $userIdRaw.set("")
  $session.set(null)
}

export function updateUserDisplayName(displayName: string): void {
  const user = $currentUser.get()
  if (user !== null) {
    $currentUser.set({ ...user, display_name: displayName })

    const session = $session.get()
    if (session !== null) {
      $session.set({ ...session, displayName })
    }
  }
}
