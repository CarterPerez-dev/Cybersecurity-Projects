// ===================
// © AngelaMos | 2025
// Chat.tsx
// ===================
import { Show, onMount, onCleanup, createEffect } from "solid-js"
import type { JSX } from "solid-js"
import type { Participant } from "../types"
import { useStore } from "@nanostores/solid"
import { AppShell, ProtectedRoute } from "../components/Layout"
import {
  MessageList,
  ChatHeader,
  ChatInput,
  NewConversation,
} from "../components/Chat"
import {
  $activeRoom,
  $activeRoomId,
  $activeModal,
  $userId,
  $currentUser,
  showToast,
  setActiveRoom,
  openModal,
  closeModal,
  addMessage,
} from "../stores"
import {
  connectWebSocket,
  disconnectWebSocket,
  wsManager,
} from "../websocket"
import { roomService } from "../services"
import { cryptoService, saveDecryptedMessage } from "../crypto"

export default function Chat(): JSX.Element {
  const activeRoom = useStore($activeRoom)
  const activeRoomId = useStore($activeRoomId)
  const userId = useStore($userId)
  const activeModal = useStore($activeModal)

  createEffect(() => {
    const roomId = activeRoomId()
    if (roomId) {
      roomService.loadMessages(roomId)
    }
  })

  onMount(async () => {
    const currentUserId = userId()
    if (currentUserId) {
      try {
        await cryptoService.initialize(currentUserId)
      } catch {
      }
      connectWebSocket()
      await roomService.loadRooms(currentUserId)
    }
  })

  onCleanup(() => {
    disconnectWebSocket()
  })

  const handleSendMessage = async (content: string): Promise<void> => {
    const roomId = activeRoomId()
    const room = activeRoom()
    const currentUserId = userId()
    const user = $currentUser.get()

    if (roomId === null || room === null) {
      showToast("error", "SEND FAILED", "NO ACTIVE ROOM")
      return
    }

    if (currentUserId === null) {
      showToast("error", "SEND FAILED", "NOT AUTHENTICATED")
      return
    }

    const recipientId = room.participants.find((p: Participant) => p.user_id !== currentUserId)?.user_id

    if (recipientId === undefined) {
      showToast("error", "SEND FAILED", "NO RECIPIENT FOUND")
      return
    }

    const tempId = `temp-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const now = new Date().toISOString()

    const messageToSend = {
      id: tempId,
      room_id: roomId,
      sender_id: currentUserId,
      sender_username: user?.username ?? "me",
      content,
      status: "sending" as const,
      is_encrypted: true,
      created_at: now,
      updated_at: now,
    }

    addMessage(roomId, messageToSend)

    try {
      const encrypted = await cryptoService.encrypt(recipientId, content)
      const sent = wsManager.sendEncryptedMessage(
        recipientId,
        roomId,
        encrypted,
        tempId
      )

      if (sent) {
        void saveDecryptedMessage(messageToSend)
      } else {
        showToast("error", "SEND FAILED", "NOT CONNECTED")
      }
    } catch (error) {
      console.error("[Chat] Encryption failed:", error)
      showToast("error", "SEND FAILED", "ENCRYPTION ERROR")
    }
  }

  const handleCreateRoom = async (targetUserId: string): Promise<void> => {
    const currentUserId = userId()

    if (currentUserId === null) {
      showToast("error", "FAILED", "NOT AUTHENTICATED")
      return
    }

    const room = await roomService.createRoom(currentUserId, targetUserId)

    if (room) {
      setActiveRoom(room.id)
      closeModal()
    } else {
      showToast("error", "FAILED", "COULD NOT CREATE CONVERSATION")
    }
  }

  const handleNewChat = (): void => {
    openModal("new-conversation")
  }

  return (
    <ProtectedRoute>
      <AppShell>
        <div class="h-full flex flex-col bg-black">
          <Show
            when={activeRoomId()}
            fallback={<EmptyState onNewChat={handleNewChat} />}
            keyed
          >
            {(roomId) => (
              <>
                <ChatHeader
                  room={activeRoom()}
                />
                <MessageList
                  roomId={roomId}
                />
                <ChatInput
                  roomId={roomId}
                  recipientId={activeRoom()?.participants.find((p: Participant) => p.user_id !== userId())?.user_id ?? ""}
                  onSend={handleSendMessage}
                />
              </>
            )}
          </Show>
        </div>

        <NewConversation
          isOpen={activeModal() === "new-conversation"}
          onClose={closeModal}
          onCreateRoom={handleCreateRoom}
        />
      </AppShell>
    </ProtectedRoute>
  )
}

interface EmptyStateProps {
  onNewChat: () => void
}

function EmptyState(props: EmptyStateProps): JSX.Element {
  return (
    <div class="h-full flex flex-col items-center justify-center p-4">
      <div class="text-center">
        <ChatIcon />
        <h2 class="font-pixel text-sm text-orange mt-4 mb-2">
          SELECT A CONVERSATION
        </h2>
        <p class="font-pixel text-[10px] text-gray mb-6">
          CHOOSE A CHAT FROM THE SIDEBAR OR START A NEW ONE
        </p>
        <button
          type="button"
          onClick={() => props.onNewChat()}
          class="px-6 py-3 border-2 border-orange text-orange font-pixel text-[10px] hover:bg-orange hover:text-black transition-colors"
        >
          START NEW CHAT
        </button>
      </div>
    </div>
  )
}

function ChatIcon(): JSX.Element {
  return (
    <svg width="48" height="48" viewBox="0 0 48 48" fill="currentColor" class="text-orange mx-auto">
      <rect x="8" y="8" width="32" height="4" />
      <rect x="4" y="12" width="4" height="24" />
      <rect x="40" y="12" width="4" height="24" />
      <rect x="8" y="36" width="12" height="4" />
      <rect x="28" y="36" width="12" height="4" />
      <rect x="20" y="40" width="4" height="4" />
      <rect x="16" y="44" width="4" height="4" />
      <rect x="12" y="18" width="24" height="2" />
      <rect x="12" y="24" width="16" height="2" />
      <rect x="12" y="30" width="20" height="2" />
    </svg>
  )
}
