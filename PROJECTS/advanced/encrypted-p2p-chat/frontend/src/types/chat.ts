// ===================
// © AngelaMos | 2025
// chat.ts
// ===================
export type MessageStatus = "sending" | "sent" | "delivered" | "read" | "failed"

export type PresenceStatus = "online" | "away" | "offline"

export type RoomType = "direct" | "group" | "ephemeral"

export interface Message {
  id: string
  room_id: string
  sender_id: string
  sender_username: string
  content: string
  status: MessageStatus
  is_encrypted: boolean
  encrypted_content?: string
  nonce?: string
  header?: string
  created_at: string
  updated_at: string
  delivered_at?: string
  read_at?: string
}

export interface Room {
  id: string
  type: RoomType
  name?: string
  participants: Participant[]
  last_message?: Message
  unread_count: number
  is_encrypted: boolean
  created_at: string
  updated_at: string
}

export interface Participant {
  user_id: string
  username: string
  display_name: string
  role: "owner" | "admin" | "member"
  joined_at: string
}

export interface Conversation {
  room: Room
  messages: Message[]
  typing_users: string[]
  has_more_messages: boolean
  oldest_message_id?: string
}

export interface TypingState {
  user_id: string
  username: string
  started_at: string
}

export interface UserPresence {
  user_id: string
  status: PresenceStatus
  last_seen: string
}

export interface ReadReceipt {
  message_id: string
  user_id: string
  read_at: string
}

export interface FileAttachment {
  id: string
  message_id: string
  filename: string
  mime_type: string
  size_bytes: number
  url: string
  thumbnail_url?: string
  is_encrypted: boolean
}

export const MESSAGE_MAX_LENGTH = 50000
export const DEFAULT_MESSAGE_LIMIT = 50
export const MAX_MESSAGE_LIMIT = 200
