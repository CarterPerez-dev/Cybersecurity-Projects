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
  $userId,
} from "../stores"
import {
  getDecryptedMessages,
  getDecryptedMessage,
  saveDecryptedMessage,
  cryptoService,
} from "../crypto"

export async function loadRooms(userId: string): Promise<Room[]> {
  try {
    const response = await api.rooms.list(userId)
    setRooms(response.rooms)
    return response.rooms
  } catch {
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
    const localMessages = await getDecryptedMessages(roomId, limit)
    const localMessageIds = new Set(localMessages.map((m) => m.id))

    if (localMessages.length > 0) {
      setRoomMessages(roomId, localMessages)
    }

    const response = await api.rooms.getMessages(roomId, limit, offset)
    const serverMessages = response.messages.reverse()

    const newMessages: Message[] = []

    const currentUserId = $userId.get()

    for (const msg of serverMessages) {
      if (localMessageIds.has(msg.id)) {
        continue
      }

      let content = "[Encrypted - from another session]"
      const isOwnMessage = msg.sender_id === currentUserId

      if (isOwnMessage) {
        const localCopy = await getDecryptedMessage(msg.id)
        if (localCopy) {
          content = localCopy.content
        } else {
          content = "[Your message - not stored locally]"
        }
      } else {
        try {
          content = await cryptoService.decrypt(
            msg.sender_id,
            msg.ciphertext,
            msg.nonce,
            msg.header
          )
        } catch {
          content = "[Encrypted - from another session]"
        }
      }

      const decryptedMessage: Message = {
        id: msg.id,
        room_id: msg.room_id,
        sender_id: msg.sender_id,
        sender_username: msg.sender_username,
        content,
        status: "delivered" as const,
        is_encrypted: true,
        encrypted_content: msg.ciphertext,
        nonce: msg.nonce,
        header: msg.header,
        created_at: msg.created_at,
        updated_at: msg.created_at,
      }

      if (!content.startsWith("[Encrypted") && !content.startsWith("[Your message")) {
        void saveDecryptedMessage(decryptedMessage)
      }

      newMessages.push(decryptedMessage)
    }

    const allMessages = [...localMessages, ...newMessages]
    const uniqueMessages = Array.from(
      new Map(allMessages.map((m) => [m.id, m])).values()
    ).sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())

    setRoomMessages(roomId, uniqueMessages)
    setHasMore(roomId, response.has_more)
    return uniqueMessages
  } catch (err) {
    console.error("[RoomService] Failed to load messages:", err)
    const localMessages = await getDecryptedMessages(roomId, limit)
    if (localMessages.length > 0) {
      setRoomMessages(roomId, localMessages)
    }
    return localMessages
  }
}

export const roomService = {
  loadRooms,
  createRoom,
  loadMessages,
}
