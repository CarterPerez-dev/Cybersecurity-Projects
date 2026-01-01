// ===================
// © AngelaMos | 2025
// message-handlers.ts
// ===================
import type {
  WSMessage,
  EncryptedMessageWS,
  TypingIndicatorWS,
  PresenceUpdateWS,
  ReadReceiptWS,
  ErrorMessageWS,
  RoomCreatedWS,
  MessageSentWS,
  Message,
  Room,
} from "../types"
import {
  isEncryptedMessageWS,
  isTypingIndicatorWS,
  isPresenceUpdateWS,
  isReadReceiptWS,
  isErrorMessageWS,
  isRoomCreatedWS,
  isMessageSentWS,
} from "../types/guards"
import {
  addMessage,
  updateMessageStatus,
  confirmPendingMessage,
} from "../stores/messages.store"
import {
  addRoom,
} from "../stores/rooms.store"
import {
  setUserPresence,
} from "../stores/presence.store"
import {
  setUserTyping,
} from "../stores/typing.store"
import { showToast } from "../stores/ui.store"
import { cryptoService, saveDecryptedMessage, updateMessageId } from "../crypto"

type MessageHandler<T extends WSMessage> = (message: T) => void

async function encryptedMessageHandler(message: EncryptedMessageWS): Promise<void> {
  let decryptedContent: string

  try {
    decryptedContent = await cryptoService.decrypt(
      message.sender_id,
      message.ciphertext,
      message.nonce,
      message.header
    )
  } catch {
    decryptedContent = "[Encrypted message - decryption failed]"
  }

  const chatMessage: Message = {
    id: message.message_id,
    room_id: message.room_id,
    sender_id: message.sender_id,
    sender_username: message.sender_username,
    content: decryptedContent,
    status: "delivered",
    is_encrypted: true,
    encrypted_content: message.ciphertext,
    nonce: message.nonce,
    header: message.header,
    created_at: message.timestamp ?? new Date().toISOString(),
    updated_at: message.timestamp ?? new Date().toISOString(),
  }

  addMessage(message.room_id, chatMessage)
  void saveDecryptedMessage(chatMessage)
}

const typingIndicatorHandler: MessageHandler<TypingIndicatorWS> = (message) => {
  setUserTyping(
    message.room_id,
    message.user_id,
    message.username,
    message.is_typing
  )
}

const presenceUpdateHandler: MessageHandler<PresenceUpdateWS> = (message) => {
  setUserPresence(
    message.user_id,
    message.status,
    message.last_seen
  )
}

const readReceiptHandler: MessageHandler<ReadReceiptWS> = (message) => {
  updateMessageStatus(message.room_id, message.message_id, "read")
}

const errorMessageHandler: MessageHandler<ErrorMessageWS> = (message) => {
  showToast("error", "CONNECTION ERROR", message.error_message.toUpperCase())
}

const roomCreatedHandler: MessageHandler<RoomCreatedWS> = (message) => {
  const room: Room = {
    id: message.room_id,
    type: message.room_type as "direct" | "group" | "ephemeral",
    name: message.name,
    participants: message.participants,
    unread_count: 0,
    is_encrypted: message.is_encrypted,
    created_at: message.created_at,
    updated_at: message.updated_at,
  }

  addRoom(room)
  showToast("info", "NEW CHAT", `NEW CONVERSATION STARTED`)
}

const messageSentHandler: MessageHandler<MessageSentWS> = (message) => {
  const confirmedMessage: Message = {
    id: message.message_id,
    room_id: message.room_id,
    sender_id: "",
    sender_username: "",
    content: "",
    status: "sent",
    is_encrypted: true,
    created_at: message.created_at,
    updated_at: message.created_at,
  }

  confirmPendingMessage(message.room_id, message.temp_id, confirmedMessage)
  void updateMessageId(message.temp_id, message.message_id)
}

export function handleWSMessage(message: WSMessage): void {
  if (isEncryptedMessageWS(message)) {
    void encryptedMessageHandler(message)
  } else if (isTypingIndicatorWS(message)) {
    typingIndicatorHandler(message)
  } else if (isPresenceUpdateWS(message)) {
    presenceUpdateHandler(message)
  } else if (isReadReceiptWS(message)) {
    readReceiptHandler(message)
  } else if (isErrorMessageWS(message)) {
    errorMessageHandler(message)
  } else if (isRoomCreatedWS(message)) {
    roomCreatedHandler(message)
  } else if (isMessageSentWS(message)) {
    messageSentHandler(message)
  }
}

export async function handleEncryptedMessage(message: EncryptedMessageWS): Promise<void> {
  await encryptedMessageHandler(message)
}

export function handleTypingIndicator(message: TypingIndicatorWS): void {
  typingIndicatorHandler(message)
}

export function handlePresenceUpdate(message: PresenceUpdateWS): void {
  presenceUpdateHandler(message)
}

export function handleReadReceipt(message: ReadReceiptWS): void {
  readReceiptHandler(message)
}

export function handleErrorMessage(message: ErrorMessageWS): void {
  errorMessageHandler(message)
}
