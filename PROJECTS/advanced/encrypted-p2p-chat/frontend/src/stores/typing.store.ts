/**
 * Typing indicators store
 * Manages typing status per room
 */

import { map, computed } from "nanostores"
import type { TypingState } from "../types"
import { $activeRoomId } from "./rooms.store"

const TYPING_TIMEOUT_MS = 5000

export const $typingByRoom = map<Record<string, TypingState[]>>({})

const typingTimeouts = new Map<string, ReturnType<typeof setTimeout>>()

export const $activeRoomTyping = computed(
  [$typingByRoom, $activeRoomId],
  (typing, roomId) => (roomId ? typing[roomId] ?? [] : [])
)

export const $activeRoomTypingUsernames = computed(
  $activeRoomTyping,
  (typingUsers) => typingUsers.map((t) => t.username)
)

function getTimeoutKey(roomId: string, userId: string): string {
  return `${roomId}:${userId}`
}

export function setUserTyping(
  roomId: string,
  userId: string,
  username: string,
  isTyping: boolean
): void {
  const timeoutKey = getTimeoutKey(roomId, userId)
  const existingTimeout = typingTimeouts.get(timeoutKey)

  if (existingTimeout !== undefined) {
    clearTimeout(existingTimeout)
    typingTimeouts.delete(timeoutKey)
  }

  const currentTyping = $typingByRoom.get()[roomId] ?? []
  const filteredTyping = currentTyping.filter((t) => t.user_id !== userId)

  if (isTyping) {
    const typingState: TypingState = {
      user_id: userId,
      username,
      started_at: new Date().toISOString(),
    }

    $typingByRoom.setKey(roomId, [...filteredTyping, typingState])

    const timeout = setTimeout(() => {
      removeUserTyping(roomId, userId)
    }, TYPING_TIMEOUT_MS)

    typingTimeouts.set(timeoutKey, timeout)
  } else {
    $typingByRoom.setKey(roomId, filteredTyping)
  }
}

export function removeUserTyping(roomId: string, userId: string): void {
  const timeoutKey = getTimeoutKey(roomId, userId)
  const existingTimeout = typingTimeouts.get(timeoutKey)

  if (existingTimeout !== undefined) {
    clearTimeout(existingTimeout)
    typingTimeouts.delete(timeoutKey)
  }

  const currentTyping = $typingByRoom.get()[roomId] ?? []
  $typingByRoom.setKey(
    roomId,
    currentTyping.filter((t) => t.user_id !== userId)
  )
}

export function clearRoomTyping(roomId: string): void {
  const currentTyping = $typingByRoom.get()[roomId] ?? []

  for (const typing of currentTyping) {
    const timeoutKey = getTimeoutKey(roomId, typing.user_id)
    const timeout = typingTimeouts.get(timeoutKey)
    if (timeout !== undefined) {
      clearTimeout(timeout)
      typingTimeouts.delete(timeoutKey)
    }
  }

  $typingByRoom.setKey(roomId, [])
}

export function clearAllTyping(): void {
  for (const timeout of typingTimeouts.values()) {
    clearTimeout(timeout)
  }
  typingTimeouts.clear()
  $typingByRoom.set({})
}

export function getTypingUsers(roomId: string): TypingState[] {
  return $typingByRoom.get()[roomId] ?? []
}

export function isAnyoneTyping(roomId: string): boolean {
  const typing = $typingByRoom.get()[roomId]
  return typing !== undefined && typing.length > 0
}
