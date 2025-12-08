/**
 * 8-bit styled sidebar component
 */

import type { JSX } from "solid-js"
import { Show, For } from "solid-js"
import type { Room, Participant } from "../../types"
import { A, useLocation } from "@solidjs/router"
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
  const location = useLocation()

  const roomList = (): Room[] => {
    const roomsObj = rooms()
    console.log("[Sidebar] rooms store:", roomsObj)
    const roomArray: Room[] = Object.values(roomsObj)
    console.log("[Sidebar] roomArray length:", roomArray.length)
    return roomArray.sort((a, b) => {
      const aTime = a.last_message?.created_at ?? a.updated_at
      const bTime = b.last_message?.created_at ?? b.updated_at
      return new Date(bTime).getTime() - new Date(aTime).getTime()
    })
  }

  const isActive = (path: string): boolean => location.pathname === path

  return (
    <div class="h-full flex flex-col bg-black">
      <div class="p-4 border-b-2 border-orange">
        <div class="flex items-center justify-between">
          <h2 class="font-pixel text-[10px] text-orange uppercase">
            Messages
          </h2>
          <Show when={totalUnread() > 0}>
            <Badge variant="primary" size="xs">
              {totalUnread()}
            </Badge>
          </Show>
        </div>
      </div>

      <div class="p-2">
        <IconButton
          icon={<NewChatIcon />}
          ariaLabel="New conversation"
          variant="subtle"
          size="sm"
          class="w-full justify-start gap-2 px-3"
          onClick={() => openModal("new-conversation")}
        />
      </div>

      <nav class="flex-1 overflow-y-auto scrollbar-pixel">
        <div class="p-2 space-y-1">
          <For each={roomList()}>
            {(room) => {
              const isSelected = (): boolean => activeRoomId() === room.id
              const otherParticipant = (): Participant | undefined =>
                room.participants?.find((p: Participant) => p.user_id !== currentUser()?.id)

              return (
                <button
                  type="button"
                  onClick={() => setActiveRoom(room.id)}
                  class={`
                    w-full flex items-center gap-3 p-3
                    border-2 transition-colors duration-100
                    ${isSelected()
                      ? "bg-orange text-black border-orange"
                      : "bg-black text-white border-transparent hover:border-orange"
                    }
                  `}
                >
                  <Avatar
                    alt={room.name ?? otherParticipant()?.display_name ?? "Chat"}
                    size="sm"
                    fallback={room.name?.slice(0, 2) ?? otherParticipant()?.display_name?.slice(0, 2)}
                  />
                  <div class="flex-1 min-w-0 text-left">
                    <div class="flex items-center justify-between">
                      <span class="font-pixel text-[10px] truncate">
                        {room.name ?? otherParticipant()?.display_name ?? "Chat"}
                      </span>
                      <Show when={room.unread_count > 0}>
                        <Badge variant="primary" size="xs">
                          {room.unread_count}
                        </Badge>
                      </Show>
                    </div>
                    <Show when={room.last_message} keyed>
                      {(lastMsg) => (
                        <p class={`font-pixel text-[8px] truncate mt-0.5 ${
                          isSelected() ? "text-black/70" : "text-gray"
                        }`}>
                          {lastMsg.content}
                        </p>
                      )}
                    </Show>
                  </div>
                </button>
              )
            }}
          </For>
        </div>

        <Show when={roomList().length === 0}>
          <div class="p-4 text-center">
            <p class="font-pixel text-[8px] text-gray">
              NO CONVERSATIONS YET
            </p>
            <p class="font-pixel text-[8px] text-gray mt-2">
              START A NEW CHAT TO BEGIN
            </p>
          </div>
        </Show>
      </nav>

      <div class="p-3 border-t-2 border-orange">
        <Show when={currentUser()} keyed>
          {(user) => (
            <A
              href="/settings"
              class={`
                flex items-center gap-3 p-2
                border-2 transition-colors duration-100
                ${isActive("/settings")
                  ? "bg-orange text-black border-orange"
                  : "border-transparent hover:border-orange"
                }
              `}
            >
              <Avatar
                alt={user.display_name}
                size="sm"
                fallback={user.display_name.slice(0, 2)}
              />
              <div class="flex-1 min-w-0">
                <span class="font-pixel text-[10px] truncate block">
                  {user.display_name}
                </span>
                <span class={`font-pixel text-[8px] ${
                  isActive("/settings") ? "text-black/70" : "text-gray"
                }`}>
                  @{user.username}
                </span>
              </div>
              <SettingsIcon />
            </A>
          )}
        </Show>
      </div>
    </div>
  )
}

function NewChatIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="7" y="2" width="2" height="12" />
      <rect x="2" y="7" width="12" height="2" />
    </svg>
  )
}

function SettingsIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" class="text-gray">
      <rect x="7" y="1" width="2" height="2" />
      <rect x="5" y="3" width="6" height="2" />
      <rect x="7" y="5" width="2" height="2" />
      <rect x="7" y="9" width="2" height="2" />
      <rect x="5" y="11" width="6" height="2" />
      <rect x="7" y="13" width="2" height="2" />
    </svg>
  )
}
