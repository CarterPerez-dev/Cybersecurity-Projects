// ===================
// © AngelaMos | 2026
// useAlerts.ts
//
// WebSocket alert stream hook with Zustand state and
// exponential reconnect
//
// Maintains a Zustand AlertState store holding the alert
// ring buffer (capped at ALERTS.MAX_ITEMS), connection
// status, and error state. useAlerts opens a WebSocket to
// WS_ENDPOINTS.ALERTS, validates incoming JSON frames
// against WebSocketAlertSchema via safeParse, stamps each
// with a crypto.randomUUID id, and prepends to the store.
// On close the hook schedules reconnection with exponential
// backoff (RECONNECT_BASE_MS * 2^attempt, capped at
// RECONNECT_MAX_MS). Cleanup on unmount closes the socket
// and clears the retry timer. Connects to api/types/
// websocket.types, config, components/alert-feed
// ===================

import { useEffect, useRef } from 'react'
import { create } from 'zustand'
import { type WebSocketAlert, WebSocketAlertSchema } from '@/api/types'
import { ALERTS, WS_ENDPOINTS } from '@/config'

interface AlertState {
  alerts: WebSocketAlert[]
  isConnected: boolean
  connectionError: string | null
  addAlert: (alert: WebSocketAlert) => void
  setConnected: (connected: boolean) => void
  setError: (error: string | null) => void
  clear: () => void
}

const useAlertStore = create<AlertState>()((set) => ({
  alerts: [],
  isConnected: false,
  connectionError: null,

  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, ALERTS.MAX_ITEMS),
    })),

  setConnected: (connected) =>
    set({ isConnected: connected, connectionError: null }),

  setError: (error) => set({ isConnected: false, connectionError: error }),

  clear: () => set({ alerts: [], isConnected: false, connectionError: null }),
}))

function getWsUrl(): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}${WS_ENDPOINTS.ALERTS}`
}

export function useAlerts() {
  const wsRef = useRef<WebSocket | null>(null)
  const retryCountRef = useRef(0)
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const { alerts, isConnected, connectionError } = useAlertStore()
  const { addAlert, setConnected, setError, clear } = useAlertStore()

  useEffect(() => {
    function connect() {
      const ws = new WebSocket(getWsUrl())
      wsRef.current = ws

      ws.onopen = () => {
        retryCountRef.current = 0
        setConnected(true)
      }

      ws.onmessage = (event) => {
        const parsed = WebSocketAlertSchema.safeParse(JSON.parse(event.data))
        if (parsed.success) {
          addAlert({ ...parsed.data, id: crypto.randomUUID() })
        }
      }

      ws.onclose = () => {
        setConnected(false)
        scheduleReconnect()
      }

      ws.onerror = () => {
        setError('WebSocket connection failed')
        ws.close()
      }
    }

    function scheduleReconnect() {
      const delay = Math.min(
        ALERTS.RECONNECT_BASE_MS * 2 ** retryCountRef.current,
        ALERTS.RECONNECT_MAX_MS
      )
      retryCountRef.current += 1
      retryTimerRef.current = setTimeout(connect, delay)
    }

    connect()

    return () => {
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current)
      }
      if (wsRef.current) {
        wsRef.current.close()
      }
      clear()
    }
  }, [addAlert, setConnected, setError, clear])

  return { alerts, isConnected, connectionError }
}
