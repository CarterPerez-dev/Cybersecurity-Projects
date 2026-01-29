/**
 * Presence store
 * Manages user online/offline status
 */

import { map } from "nanostores"
import type { PresenceStatus, UserPresence } from "../types"

export const $presenceByUser = map<Record<string, UserPresence>>({})

export function setUserPresence(
  userId: string,
  status: PresenceStatus,
  lastSeen: string
): void {
  $presenceByUser.setKey(userId, {
    user_id: userId,
    status,
    last_seen: lastSeen,
  })
}

export function updateUserStatus(userId: string, status: PresenceStatus): void {
  const presence = $presenceByUser.get()[userId]
  if (presence !== undefined) {
    $presenceByUser.setKey(userId, {
      ...presence,
      status,
      last_seen: new Date().toISOString(),
    })
  } else {
    setUserPresence(userId, status, new Date().toISOString())
  }
}

export function getUserPresence(userId: string): UserPresence | null {
  return $presenceByUser.get()[userId] ?? null
}

export function getUserStatus(userId: string): PresenceStatus {
  return $presenceByUser.get()[userId]?.status ?? "offline"
}

export function isUserOnline(userId: string): boolean {
  const status = getUserStatus(userId)
  return status === "online"
}

export function getOnlineUserIds(): string[] {
  const presences = $presenceByUser.get()
  return Object.entries(presences)
    .filter(([_, p]) => p.status === "online")
    .map(([id]) => id)
}

export function setMultiplePresences(presences: UserPresence[]): void {
  const presenceMap = { ...$presenceByUser.get() }
  for (const presence of presences) {
    presenceMap[presence.user_id] = presence
  }
  $presenceByUser.set(presenceMap)
}

export function removeUserPresence(userId: string): void {
  const { [userId]: _, ...rest } = $presenceByUser.get()
  $presenceByUser.set(rest)
}

export function clearAllPresences(): void {
  $presenceByUser.set({})
}
