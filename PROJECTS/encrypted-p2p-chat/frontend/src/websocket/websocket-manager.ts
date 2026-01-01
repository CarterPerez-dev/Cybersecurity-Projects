// ===================
// ©AngelaMos | 2025
// websocket-manager.ts
// ===================
import { atom, computed } from "nanostores"
import {
  WS_URL,
  WS_HEARTBEAT_INTERVAL,
  WS_RECONNECT_DELAY,
} from "../config"
import { $userId } from "../stores"
import type {
  WSMessage,
  WSOutgoingMessage,
  WSOutgoingHeartbeat,
  WSOutgoingTyping,
  WSOutgoingPresence,
  WSOutgoingReceipt,
  WSOutgoingEncryptedMessage,
} from "../types"
import { handleWSMessage } from "./message-handlers"
import {
  isWSMessage,
  isEncryptedMessageWS,
  isTypingIndicatorWS,
  isPresenceUpdateWS,
  isReadReceiptWS,
  isHeartbeatWS,
  isErrorMessageWS,
  isRoomCreatedWS,
  isMessageSentWS,
} from "../types/guards"

export type ConnectionStatus = "disconnected" | "connecting" | "connected" | "reconnecting"

export const $connectionStatus = atom<ConnectionStatus>("disconnected")
export const $reconnectAttempts = atom<number>(0)
export const $lastError = atom<string | null>(null)

export const $isConnected = computed(
  $connectionStatus,
  (status) => status === "connected"
)

const MAX_RECONNECT_ATTEMPTS = 10
const MAX_RECONNECT_DELAY = 30000
const FATAL_ERROR_CODES = ["max_connections", "unauthorized", "invalid_user", "database_error"]

class WebSocketManager {
  private ws: WebSocket | null = null
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null
  private messageQueue: WSOutgoingMessage[] = []
  private intentionalClose = false
  private fatalError = false

  connect(): void {
    const userId = $userId.get()
    if (!userId) {
      $lastError.set("Cannot connect: User not authenticated")
      return
    }

    if (this.ws?.readyState === WebSocket.OPEN) {
      return
    }

    if (this.fatalError) {
      return
    }

    this.intentionalClose = false
    $connectionStatus.set("connecting")
    $lastError.set(null)

    const wsUrl = `${WS_URL}/ws?user_id=${userId}`
    this.ws = new WebSocket(wsUrl)

    this.ws.onopen = this.handleOpen.bind(this)
    this.ws.onmessage = this.handleMessage.bind(this)
    this.ws.onclose = this.handleClose.bind(this)
    this.ws.onerror = this.handleError.bind(this)
  }

  disconnect(): void {
    this.intentionalClose = true
    this.fatalError = false
    this.cleanup()
    $connectionStatus.set("disconnected")
    $reconnectAttempts.set(0)
  }

  send(message: WSOutgoingMessage): boolean {
    if (this.ws?.readyState !== WebSocket.OPEN) {
      this.messageQueue.push(message)
      return false
    }

    try {
      this.ws.send(JSON.stringify(message))
      return true
    } catch {
      this.messageQueue.push(message)
      return false
    }
  }

  sendEncryptedMessage(
    recipientId: string,
    roomId: string,
    encrypted: { ciphertext: string; nonce: string; header: string },
    tempId: string
  ): boolean {
    const message: WSOutgoingEncryptedMessage = {
      type: "encrypted_message",
      recipient_id: recipientId,
      room_id: roomId,
      ciphertext: encrypted.ciphertext,
      nonce: encrypted.nonce,
      header: encrypted.header,
      temp_id: tempId,
    }
    return this.send(message)
  }

  sendTypingIndicator(roomId: string, isTyping: boolean): boolean {
    const message: WSOutgoingTyping = {
      type: "typing",
      room_id: roomId,
      is_typing: isTyping,
    }
    return this.send(message)
  }

  sendPresenceUpdate(status: "online" | "away" | "offline"): boolean {
    const message: WSOutgoingPresence = {
      type: "presence",
      status,
    }
    return this.send(message)
  }

  sendReadReceipt(messageId: string, roomId: string): boolean {
    const message: WSOutgoingReceipt = {
      type: "receipt",
      message_id: messageId,
      room_id: roomId,
    }
    return this.send(message)
  }

  getStatus(): ConnectionStatus {
    return $connectionStatus.get()
  }

  private handleOpen(): void {
    $connectionStatus.set("connected")
    $reconnectAttempts.set(0)
    $lastError.set(null)

    this.startHeartbeat()
    this.sendPresenceUpdate("online")
    this.flushMessageQueue()
  }

  private handleMessage(event: MessageEvent): void {
    try {
      const data: unknown = JSON.parse(event.data as string)

      if (!isWSMessage(data)) {
        return
      }

      this.routeMessage(data)
    } catch {
      return
    }
  }

  private routeMessage(message: WSMessage): void {
    if (isEncryptedMessageWS(message)) {
      handleWSMessage(message)
    } else if (isTypingIndicatorWS(message)) {
      handleWSMessage(message)
    } else if (isPresenceUpdateWS(message)) {
      handleWSMessage(message)
    } else if (isReadReceiptWS(message)) {
      handleWSMessage(message)
    } else if (isHeartbeatWS(message)) {
      return
    } else if (isErrorMessageWS(message)) {
      if (FATAL_ERROR_CODES.includes(message.error_code)) {
        this.fatalError = true
        $lastError.set(message.error_message)
      }
      handleWSMessage(message)
    } else if (isRoomCreatedWS(message)) {
      handleWSMessage(message)
    } else if (isMessageSentWS(message)) {
      handleWSMessage(message)
    }
  }

  private handleClose(event: CloseEvent): void {
    this.cleanup()

    if (this.intentionalClose) {
      $connectionStatus.set("disconnected")
      return
    }

    if (this.fatalError) {
      $connectionStatus.set("disconnected")
      return
    }

    const attempts = $reconnectAttempts.get()

    if (attempts >= MAX_RECONNECT_ATTEMPTS) {
      $connectionStatus.set("disconnected")
      const reason = event.reason !== "" ? event.reason : "Unknown reason"
      $lastError.set(`Connection failed after maximum retry attempts (code: ${event.code}, reason: ${reason})`)
      return
    }

    if (!event.wasClean) {
      $lastError.set(`Connection closed unexpectedly (code: ${event.code})`)
    }

    $connectionStatus.set("reconnecting")
    $reconnectAttempts.set(attempts + 1)

    const delay = Math.min(
      WS_RECONNECT_DELAY * Math.pow(2, attempts),
      MAX_RECONNECT_DELAY
    )

    this.reconnectTimeout = setTimeout(() => {
      this.connect()
    }, delay)
  }

  private handleError(_event: Event): void {
    $lastError.set("WebSocket connection error")
  }

  private startHeartbeat(): void {
    this.stopHeartbeat()

    this.heartbeatInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        const heartbeat: WSOutgoingHeartbeat = {
          type: "heartbeat",
          timestamp: new Date().toISOString(),
        }
        this.ws.send(JSON.stringify(heartbeat))
      }
    }, WS_HEARTBEAT_INTERVAL)
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval !== null) {
      clearInterval(this.heartbeatInterval)
      this.heartbeatInterval = null
    }
  }

  private flushMessageQueue(): void {
    while (this.messageQueue.length > 0 && this.ws?.readyState === WebSocket.OPEN) {
      const message = this.messageQueue.shift()
      if (message !== undefined) {
        try {
          this.ws.send(JSON.stringify(message))
        } catch {
          this.messageQueue.unshift(message)
          break
        }
      }
    }
  }

  private cleanup(): void {
    this.stopHeartbeat()

    if (this.reconnectTimeout !== null) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }

    if (this.ws !== null) {
      this.ws.onopen = null
      this.ws.onmessage = null
      this.ws.onclose = null
      this.ws.onerror = null

      if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
        this.ws.close()
      }
      this.ws = null
    }
  }
}

export const wsManager = new WebSocketManager()

export function connectWebSocket(): void {
  wsManager.connect()
}

export function disconnectWebSocket(): void {
  wsManager.disconnect()
}

export function sendWSMessage(message: WSOutgoingMessage): boolean {
  return wsManager.send(message)
}
