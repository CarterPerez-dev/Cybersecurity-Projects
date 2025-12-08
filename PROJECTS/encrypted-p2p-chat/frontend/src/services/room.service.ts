/**
 * ©AngelaMos | 2025
 * room.service.ts
 */

import { api } from "../lib/api-client"
import type { Message, Room } from "../types"
import {
  setRooms,
  addRoom,
  setRoomMessages,
  setHasMore,
} from "../stores"

export async function loadRooms(userId: string): Promise<Room[]> {
  console.log("[RoomService] loadRooms called with userId:", userId)
  try {
    const response = await api.rooms.list(userId)
    console.log("[RoomService] API response:", response)
    console.log("[RoomService] rooms count:", response.rooms.length)
    setRooms(response.rooms)
    return response.rooms
  } catch (err) {
    console.error("[RoomService] Failed to load rooms:", err)
    return []
  }
}

export async function createRoom(
  creatorId: string,
  participantId: string,
  roomType: "direct" | "group" | "ephemeral" = "direct"
): Promise<Room | null> {
  try {
    const room = await api.rooms.create({
      creator_id: creatorId,
      participant_id: participantId,
      room_type: roomType,
    })
    addRoom(room)
    return room
  } catch (err) {
    console.error("[RoomService] Failed to create room:", err)
    return null
  }
}

export async function loadMessages(
  roomId: string,
  limit: number = 50,
  offset: number = 0
): Promise<Message[]> {
  try {
    const response = await api.rooms.getMessages(roomId, limit, offset)
    const messages: Message[] = response.messages.map((msg) => ({
      id: msg.id,
      room_id: msg.room_id,
      sender_id: msg.sender_id,
      sender_username: msg.sender_username,
      content: "[Encrypted message]",
      status: "delivered" as const,
      is_encrypted: true,
      encrypted_content: msg.ciphertext,
      nonce: msg.nonce,
      header: msg.header,
      created_at: msg.created_at,
      updated_at: msg.created_at,
    }))
    const reversedMessages = messages.reverse()
    setRoomMessages(roomId, reversedMessages)
    setHasMore(roomId, response.has_more)
    return reversedMessages
  } catch (err) {
    console.error("[RoomService] Failed to load messages:", err)
    return []
  }
}

export const roomService = {
  loadRooms,
  createRoom,
  loadMessages,
}
