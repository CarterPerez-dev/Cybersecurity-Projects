/**
 * Sidebar - Room list only
 */

import type { JSX } from "solid-js"
import { Show, Index, createMemo } from "solid-js"
import type { Participant } from "../../types"
import { useStore } from "@nanostores/solid"
import {
  $currentUser,
  $rooms,
  $activeRoomId,
  $totalUnreadCount,
  setActiveRoom,
  openModal,
} from "../../stores"
import { Avatar } from "../UI/Avatar"
import { Badge } from "../UI/Badge"
import { IconButton } from "../UI/IconButton"

export function Sidebar(): JSX.Element {
  const currentUser = useStore($currentUser)
  const rooms = useStore($rooms)
  const activeRoomId = useStore($activeRoomId)
  const totalUnread = useStore($totalUnreadCount)

  const sortedRooms = createMemo(() => {
    const arr = Object.values(rooms())
    return arr.sort((a, b) => {
      const aTime = a.last_message?.created_at ?? a.updated_at
      const bTime = b.last_message?.created_at ?? b.updated_at
      return new Date(bTime).getTime() - new Date(aTime).getTime()
    })
  })

  return (
    <div class="flex flex-col h-full bg-black">
      <div class="p-4 border-b-2 border-orange">
        <div class="flex items-center justify-between">
          <h2 class="font-pixel text-[10px] text-orange uppercase">Messages</h2>
          <Show when={totalUnread() > 0}>
            <Badge variant="primary" size="xs">{totalUnread()}</Badge>
          </Show>
        </div>
      </div>

      <div class="p-2">
        <IconButton
          icon={<PlusIcon />}
          ariaLabel="New conversation"
          variant="subtle"
          size="sm"
          class="w-full justify-start gap-2 px-3"
          onClick={() => openModal("new-conversation")}
        />
      </div>

      <div class="flex-1 overflow-y-auto p-2">
        <Index each={sortedRooms()}>
          {(room, idx) => {
            const isActive = createMemo(() => activeRoomId() === room().id)
            const other = createMemo(() => room().participants?.find((p: Participant) => p.user_id !== currentUser()?.id))
            const displayName = createMemo(() => room().name ?? other()?.display_name ?? "Chat")

            return (
              <button
                type="button"
                data-room-id={room().id}
                data-active={isActive()}
                onClick={() => setActiveRoom(room().id)}
                style={{
                  width: "100%",
                  display: "flex",
                  "align-items": "center",
                  gap: "12px",
                  padding: "12px",
                  "margin-bottom": "4px",
                  border: isActive() ? "2px solid #FF5300" : "2px solid transparent",
                  background: isActive() ? "#FF5300" : "black",
                  color: isActive() ? "black" : "white",
                  cursor: "pointer",
                  "text-align": "left",
                }}
              >
                <Avatar
                  alt={displayName()}
                  size="sm"
                  fallback={displayName().slice(0, 2)}
                />
                <div style={{ flex: 1, "min-width": 0 }}>
                  <span class="font-pixel text-[10px] truncate block">
                    {displayName()}
                  </span>
                  <Show when={room().last_message}>
                    <p
                      class="font-pixel text-[8px] truncate mt-0.5"
                      style={{ color: isActive() ? "rgba(0,0,0,0.7)" : "#888" }}
                    >
                      {room().last_message?.content}
                    </p>
                  </Show>
                </div>
              </button>
            )
          }}
        </Index>
        <Show when={sortedRooms().length === 0}>
          <div class="p-4 text-center">
            <p class="font-pixel text-[8px] text-gray">NO CONVERSATIONS YET</p>
          </div>
        </Show>
      </div>
    </div>
  )
}

function PlusIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="7" y="2" width="2" height="12" />
      <rect x="2" y="7" width="12" height="2" />
    </svg>
  )
}
