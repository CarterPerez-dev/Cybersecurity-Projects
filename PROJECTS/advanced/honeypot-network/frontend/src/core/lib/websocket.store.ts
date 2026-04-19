// ©AngelaMos | 2026
// websocket.store.ts

import { create } from 'zustand'
import type { HoneypotEvent } from '@/api/types'

const WS_URL = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/events`
const MAX_EVENTS = 200
const RECONNECT_BASE_MS = 1000
const RECONNECT_MAX_MS = 30_000

interface WebSocketState {
  connected: boolean
  events: HoneypotEvent[]
  eventCount: number
  connect: () => void
  disconnect: () => void
}

export const useWebSocketStore = create<WebSocketState>((set, get) => {
  let ws: WebSocket | null = null
  let reconnectDelay = RECONNECT_BASE_MS
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null

  function scheduleReconnect() {
    if (reconnectTimer) return
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      get().connect()
    }, reconnectDelay)
    reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS)
  }

  return {
    connected: false,
    events: [],
    eventCount: 0,

    connect() {
      if (ws?.readyState === WebSocket.OPEN) return

      ws = new WebSocket(WS_URL)

      ws.onopen = () => {
        reconnectDelay = RECONNECT_BASE_MS
        set({ connected: true })
      }

      ws.onmessage = (msg) => {
        const event = JSON.parse(msg.data) as HoneypotEvent
        set((state) => ({
          events: [event, ...state.events].slice(0, MAX_EVENTS),
          eventCount: state.eventCount + 1,
        }))
      }

      ws.onclose = () => {
        set({ connected: false })
        scheduleReconnect()
      }

      ws.onerror = () => {
        ws?.close()
      }
    },

    disconnect() {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer)
        reconnectTimer = null
      }
      ws?.close()
      ws = null
      set({ connected: false })
    },
  }
})
