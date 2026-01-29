// ===================
// © AngelaMos | 2025
// ConversationList.tsx
// ===================
import { Show, For, createMemo } from "solid-js"
import type { JSX } from "solid-js"
import { useStore } from "@nanostores/solid"
import { $rooms, $activeRoomId, setActiveRoom } from "../../stores"
import { ConversationItem } from "./ConversationItem"
import { Spinner } from "../UI/Spinner"
import type { Room } from "../../types"

interface ConversationListProps {
  loading?: boolean
  onNewChat?: () => void
  class?: string
}

export function ConversationList(props: ConversationListProps): JSX.Element {
  const rooms = useStore($rooms)
  const activeRoomId = useStore($activeRoomId)

  const sortedRooms = createMemo((): Room[] => {
    const roomsMap = rooms()
    const roomList: Room[] = Object.values(roomsMap)
    return roomList.sort((a, b) => {
      const aTime = a.last_message?.created_at ?? a.updated_at
      const bTime = b.last_message?.created_at ?? b.updated_at
      return new Date(bTime).getTime() - new Date(aTime).getTime()
    })
  })

  const handleRoomClick = (roomId: string): void => {
    setActiveRoom(roomId)
  }

  return (
    <div class={`flex flex-col h-full ${props.class ?? ""}`}>
      <div class="flex items-center justify-between px-4 py-3 border-b-2 border-dark-gray">
        <h2 class="font-pixel text-[10px] text-orange">
          CONVERSATIONS
        </h2>
        <Show when={props.onNewChat}>
          <button
            type="button"
            onClick={() => props.onNewChat?.()}
            class="w-6 h-6 flex items-center justify-center border-2 border-orange text-orange hover:bg-orange hover:text-black transition-colors"
            aria-label="New conversation"
          >
            <PlusIcon />
          </button>
        </Show>
      </div>

      <div class="flex-1 overflow-y-auto scrollbar-pixel">
        <Show
          when={props.loading !== true}
          fallback={
            <div class="flex items-center justify-center py-8">
              <Spinner size="md" />
            </div>
          }
        >
          <Show
            when={sortedRooms().length > 0}
            fallback={<EmptyConversations onNewChat={props.onNewChat} />}
          >
            <div class="p-2 space-y-2">
              <For each={sortedRooms()}>
                {(room) => (
                  <ConversationItem
                    room={room}
                    isActive={room.id === activeRoomId()}
                    onClick={() => handleRoomClick(room.id)}
                  />
                )}
              </For>
            </div>
          </Show>
        </Show>
      </div>
    </div>
  )
}

interface EmptyConversationsProps {
  onNewChat?: () => void
}

function EmptyConversations(props: EmptyConversationsProps): JSX.Element {
  return (
    <div class="flex flex-col items-center justify-center py-12 px-4">
      <ChatIcon />
      <p class="font-pixel text-[10px] text-gray mt-4 text-center">
        NO CONVERSATIONS
      </p>
      <p class="font-pixel text-[8px] text-gray mt-1 text-center">
        START A NEW CHAT TO BEGIN
      </p>
      <Show when={props.onNewChat}>
        <button
          type="button"
          onClick={() => props.onNewChat?.()}
          class="mt-4 px-4 py-2 border-2 border-orange text-orange font-pixel text-[10px] hover:bg-orange hover:text-black transition-colors"
        >
          NEW CHAT
        </button>
      </Show>
    </div>
  )
}

function PlusIcon(): JSX.Element {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
      <rect x="5" y="1" width="2" height="10" />
      <rect x="1" y="5" width="10" height="2" />
    </svg>
  )
}

function ChatIcon(): JSX.Element {
  return (
    <svg width="40" height="40" viewBox="0 0 40 40" fill="currentColor" class="text-dark-gray">
      <rect x="6" y="6" width="28" height="3" />
      <rect x="3" y="9" width="3" height="20" />
      <rect x="34" y="9" width="3" height="20" />
      <rect x="6" y="29" width="10" height="3" />
      <rect x="24" y="29" width="10" height="3" />
      <rect x="16" y="32" width="3" height="3" />
      <rect x="13" y="35" width="3" height="3" />
      <rect x="10" y="14" width="20" height="2" />
      <rect x="10" y="20" width="14" height="2" />
    </svg>
  )
}
