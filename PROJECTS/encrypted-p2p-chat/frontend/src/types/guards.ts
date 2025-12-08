/**
 * Type guards for runtime type checking
 */

import type {
  User,
  Message,
  Room,
  MessageStatus,
  PresenceStatus,
  RoomType,
  PreKeyBundle,
  ApiErrorResponse,
  ValidationError,
  WSMessage,
  EncryptedMessageWS,
  TypingIndicatorWS,
  PresenceUpdateWS,
  ReadReceiptWS,
  HeartbeatWS,
  ErrorMessageWS,
  RoomCreatedWS,
  MessageSentWS,
} from "./index"

export function isString(value: unknown): value is string {
  return typeof value === "string"
}

export function isNumber(value: unknown): value is number {
  return typeof value === "number" && !Number.isNaN(value)
}

export function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean"
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value)
}

export function isNonEmptyString(value: unknown): value is string {
  return isString(value) && value.length > 0
}

export function isUser(value: unknown): value is User {
  if (!isObject(value)) return false

  return (
    isNonEmptyString(value.id) &&
    isNonEmptyString(value.username) &&
    isNonEmptyString(value.display_name) &&
    isBoolean(value.is_active) &&
    isBoolean(value.is_verified) &&
    isNonEmptyString(value.created_at)
  )
}

export function isMessageStatus(value: unknown): value is MessageStatus {
  return (
    value === "sending" ||
    value === "sent" ||
    value === "delivered" ||
    value === "read" ||
    value === "failed"
  )
}

export function isPresenceStatus(value: unknown): value is PresenceStatus {
  return value === "online" || value === "away" || value === "offline"
}

export function isRoomType(value: unknown): value is RoomType {
  return value === "direct" || value === "group" || value === "ephemeral"
}

export function isMessage(value: unknown): value is Message {
  if (!isObject(value)) return false

  return (
    isNonEmptyString(value.id) &&
    isNonEmptyString(value.room_id) &&
    isNonEmptyString(value.sender_id) &&
    isNonEmptyString(value.sender_username) &&
    isString(value.content) &&
    isMessageStatus(value.status) &&
    isBoolean(value.is_encrypted) &&
    isNonEmptyString(value.created_at)
  )
}

export function isRoom(value: unknown): value is Room {
  if (!isObject(value)) return false

  return (
    isNonEmptyString(value.id) &&
    isRoomType(value.type) &&
    isArray(value.participants) &&
    isNumber(value.unread_count) &&
    isBoolean(value.is_encrypted) &&
    isNonEmptyString(value.created_at) &&
    isNonEmptyString(value.updated_at)
  )
}

export function isPreKeyBundle(value: unknown): value is PreKeyBundle {
  if (!isObject(value)) return false

  return (
    isNonEmptyString(value.identity_key) &&
    isNonEmptyString(value.signed_prekey) &&
    isNonEmptyString(value.signed_prekey_signature) &&
    (value.one_time_prekey === null || isString(value.one_time_prekey))
  )
}

export function isValidationError(value: unknown): value is ValidationError {
  if (!isObject(value)) return false

  return isNonEmptyString(value.field) && isNonEmptyString(value.message)
}

export function isValidationErrorArray(value: unknown): value is ValidationError[] {
  return isArray(value) && value.every(isValidationError)
}

export function isApiErrorResponse(value: unknown): value is ApiErrorResponse {
  if (!isObject(value)) return false

  return isString(value.detail) || isValidationErrorArray(value.detail)
}

export function isEncryptedMessageWS(value: unknown): value is EncryptedMessageWS {
  if (!isObject(value)) return false

  return (
    value.type === "encrypted_message" &&
    isNonEmptyString(value.message_id) &&
    isNonEmptyString(value.sender_id) &&
    isNonEmptyString(value.recipient_id) &&
    isNonEmptyString(value.room_id) &&
    isString(value.content) &&
    isString(value.ciphertext) &&
    isString(value.nonce) &&
    isString(value.header) &&
    isNonEmptyString(value.sender_username)
  )
}

export function isTypingIndicatorWS(value: unknown): value is TypingIndicatorWS {
  if (!isObject(value)) return false

  return (
    value.type === "typing" &&
    isNonEmptyString(value.user_id) &&
    isNonEmptyString(value.room_id) &&
    isBoolean(value.is_typing) &&
    isNonEmptyString(value.username)
  )
}

export function isPresenceUpdateWS(value: unknown): value is PresenceUpdateWS {
  if (!isObject(value)) return false

  return (
    value.type === "presence" &&
    isNonEmptyString(value.user_id) &&
    isPresenceStatus(value.status) &&
    isNonEmptyString(value.last_seen)
  )
}

export function isReadReceiptWS(value: unknown): value is ReadReceiptWS {
  if (!isObject(value)) return false

  return (
    value.type === "receipt" &&
    isNonEmptyString(value.message_id) &&
    isNonEmptyString(value.room_id) &&
    isNonEmptyString(value.user_id) &&
    isNonEmptyString(value.read_at)
  )
}

export function isHeartbeatWS(value: unknown): value is HeartbeatWS {
  if (!isObject(value)) return false

  return value.type === "heartbeat"
}

export function isErrorMessageWS(value: unknown): value is ErrorMessageWS {
  if (!isObject(value)) return false

  return (
    value.type === "error" &&
    isNonEmptyString(value.error_code) &&
    isNonEmptyString(value.error_message)
  )
}

export function isRoomCreatedWS(value: unknown): value is RoomCreatedWS {
  if (!isObject(value)) return false

  return (
    value.type === "room_created" &&
    isNonEmptyString(value.room_id) &&
    isNonEmptyString(value.room_type) &&
    isArray(value.participants) &&
    isBoolean(value.is_encrypted) &&
    isNonEmptyString(value.created_at) &&
    isNonEmptyString(value.updated_at)
  )
}

export function isMessageSentWS(value: unknown): value is MessageSentWS {
  if (!isObject(value)) return false

  return (
    value.type === "message_sent" &&
    isNonEmptyString(value.temp_id) &&
    isNonEmptyString(value.message_id) &&
    isNonEmptyString(value.room_id) &&
    isNonEmptyString(value.status) &&
    isNonEmptyString(value.created_at)
  )
}

export function isWSMessage(value: unknown): value is WSMessage {
  return (
    isEncryptedMessageWS(value) ||
    isTypingIndicatorWS(value) ||
    isPresenceUpdateWS(value) ||
    isReadReceiptWS(value) ||
    isHeartbeatWS(value) ||
    isErrorMessageWS(value) ||
    isRoomCreatedWS(value) ||
    isMessageSentWS(value)
  )
}

export function assertNever(value: never, message?: string): never {
  throw new Error(message ?? `Unexpected value: ${JSON.stringify(value)}`)
}

export function isDefined<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined
}

export function isPublicKeyCredential(value: Credential | null): value is PublicKeyCredential {
  return value !== null && value.type === "public-key"
}
