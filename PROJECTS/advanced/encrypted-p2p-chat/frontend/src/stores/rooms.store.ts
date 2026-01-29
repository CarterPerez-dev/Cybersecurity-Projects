/**
 * Rooms/Conversations store
 * Manages chat rooms and active conversation state
 */

import { atom, computed, map } from "nanostores"
import type { Room } from "../types"

export const $rooms = map<Record<string, Room>>({})

export const $activeRoomId = atom<string | null>(null)

export const $activeRoom = computed(
  [$rooms, $activeRoomId],
  (rooms, activeId) => (activeId ? rooms[activeId] ?? null : null)
)

export const $roomList = computed($rooms, (rooms) =>
  Object.values(rooms).sort((a, b) => {
    const aTime = a.last_message?.created_at ?? a.updated_at
    const bTime = b.last_message?.created_at ?? b.updated_at
    return new Date(bTime).getTime() - new Date(aTime).getTime()
  })
)

export const $totalUnreadCount = computed($rooms, (rooms) =>
  Object.values(rooms).reduce((sum, room) => sum + room.unread_count, 0)
)

export function setActiveRoom(roomId: string | null): void {
  $activeRoomId.set(roomId)
}

export function addRoom(room: Room): void {
  $rooms.setKey(room.id, room)
}

export function updateRoom(roomId: string, updates: Partial<Room>): void {
  const room = $rooms.get()[roomId]
  if (room !== undefined) {
    $rooms.setKey(roomId, { ...room, ...updates })
  }
}

export function removeRoom(roomId: string): void {
  const { [roomId]: _, ...rest } = $rooms.get()
  $rooms.set(rest)

  if ($activeRoomId.get() === roomId) {
    $activeRoomId.set(null)
  }
}

export function setRooms(rooms: Room[]): void {
  const roomMap: Record<string, Room> = {}
  for (const room of rooms) {
    roomMap[room.id] = room
  }
  $rooms.set(roomMap)
}

export function clearUnreadCount(roomId: string): void {
  updateRoom(roomId, { unread_count: 0 })
}

export function incrementUnreadCount(roomId: string): void {
  const room = $rooms.get()[roomId]
  if (room !== undefined) {
    updateRoom(roomId, { unread_count: room.unread_count + 1 })
  }
}

export function getRoomById(roomId: string): Room | null {
  return $rooms.get()[roomId] ?? null
}

export function clearRooms(): void {
  $rooms.set({})
  $activeRoomId.set(null)
}
