/**
 * Messages store
 * Manages message cache per room
 */

import { map, computed } from "nanostores"
import type { Message, MessageStatus } from "../types"
import { $activeRoomId } from "./rooms.store"

export const $messagesByRoom = map<Record<string, Message[]>>({})

export const $pendingMessages = map<Record<string, Message[]>>({})

export const $hasMoreByRoom = map<Record<string, boolean>>({})

export const $oldestMessageIdByRoom = map<Record<string, string | undefined>>({})

export const $activeRoomMessages = computed(
  [$messagesByRoom, $activeRoomId],
  (messages, roomId) => (roomId ? messages[roomId] ?? [] : [])
)

export const $activeRoomPendingMessages = computed(
  [$pendingMessages, $activeRoomId],
  (pending, roomId) => (roomId ? pending[roomId] ?? [] : [])
)

export function addMessage(roomId: string, message: Message): void {
  const messages = $messagesByRoom.get()[roomId] ?? []
  const exists = messages.some((m) => m.id === message.id)

  if (!exists) {
    $messagesByRoom.setKey(roomId, [...messages, message])
  }
}

export function prependMessages(roomId: string, newMessages: Message[]): void {
  const existing = $messagesByRoom.get()[roomId] ?? []
  const existingIds = new Set(existing.map((m) => m.id))
  const uniqueNew = newMessages.filter((m) => !existingIds.has(m.id))

  if (uniqueNew.length > 0) {
    $messagesByRoom.setKey(roomId, [...uniqueNew, ...existing])

    if (uniqueNew.length > 0) {
      const oldest = uniqueNew.reduce((a, b) =>
        new Date(a.created_at) < new Date(b.created_at) ? a : b
      )
      $oldestMessageIdByRoom.setKey(roomId, oldest.id)
    }
  }
}

export function updateMessageStatus(
  roomId: string,
  messageId: string,
  status: MessageStatus
): void {
  const messages = $messagesByRoom.get()[roomId]
  if (messages === undefined) return

  const index = messages.findIndex((m) => m.id === messageId)
  if (index === -1) return

  const updated = [...messages]
  updated[index] = { ...updated[index], status }
  $messagesByRoom.setKey(roomId, updated)
}

export function updateMessageContent(
  roomId: string,
  messageId: string,
  content: string
): void {
  const messages = $messagesByRoom.get()[roomId]
  if (messages === undefined) return

  const index = messages.findIndex((m) => m.id === messageId)
  if (index === -1) return

  const updated = [...messages]
  updated[index] = { ...updated[index], content }
  $messagesByRoom.setKey(roomId, updated)
}

export function addPendingMessage(roomId: string, message: Message): void {
  const pending = $pendingMessages.get()[roomId] ?? []
  $pendingMessages.setKey(roomId, [...pending, message])
}

export function removePendingMessage(roomId: string, messageId: string): void {
  const pending = $pendingMessages.get()[roomId] ?? []
  $pendingMessages.setKey(
    roomId,
    pending.filter((m) => m.id !== messageId)
  )
}

export function confirmPendingMessage(
  roomId: string,
  tempId: string,
  confirmedMessage: Message
): void {
  removePendingMessage(roomId, tempId)
  addMessage(roomId, confirmedMessage)
}

export function setRoomMessages(roomId: string, messages: Message[]): void {
  $messagesByRoom.setKey(roomId, messages)

  if (messages.length > 0) {
    const oldest = messages.reduce((a, b) =>
      new Date(a.created_at) < new Date(b.created_at) ? a : b
    )
    $oldestMessageIdByRoom.setKey(roomId, oldest.id)
  }
}

export function setHasMore(roomId: string, hasMore: boolean): void {
  $hasMoreByRoom.setKey(roomId, hasMore)
}

export function getHasMore(roomId: string): boolean {
  return $hasMoreByRoom.get()[roomId] ?? true
}

export function getOldestMessageId(roomId: string): string | undefined {
  return $oldestMessageIdByRoom.get()[roomId]
}

export function clearRoomMessages(roomId: string): void {
  $messagesByRoom.setKey(roomId, [])
  $pendingMessages.setKey(roomId, [])
  $hasMoreByRoom.setKey(roomId, true)
  $oldestMessageIdByRoom.setKey(roomId, undefined)
}

export function clearAllMessages(): void {
  $messagesByRoom.set({})
  $pendingMessages.set({})
  $hasMoreByRoom.set({})
  $oldestMessageIdByRoom.set({})
}

export function getMessageById(roomId: string, messageId: string): Message | null {
  const messages = $messagesByRoom.get()[roomId]
  return messages?.find((m) => m.id === messageId) ?? null
}
