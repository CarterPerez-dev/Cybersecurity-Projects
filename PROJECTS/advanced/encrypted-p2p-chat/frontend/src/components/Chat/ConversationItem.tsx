// ===================
// © AngelaMos | 2025
// ConversationItem.tsx
// ===================
import { Show } from "solid-js"
import type { JSX } from "solid-js"
import type { Room, Participant } from "../../types"
import { OnlineStatus } from "./OnlineStatus"
import { EncryptionBadge } from "./EncryptionBadge"
import { getUserStatus } from "../../stores"
import { formatRelativeTime } from "../../lib/date"

interface ConversationItemProps {
  room: Room
  isActive: boolean
  onClick: () => void
  class?: string
}

export function ConversationItem(props: ConversationItemProps): JSX.Element {
  const otherParticipant = (): Participant | null => {
    if (props.room.type !== "direct") return null
    return props.room.participants[0] ?? null
  }

  const displayName = (): string => {
    if (props.room.name) return props.room.name
    const other = otherParticipant()
    return other?.display_name ?? other?.username ?? "CHAT"
  }

  const initials = (): string => {
    const name = displayName()
    return name.slice(0, 2).toUpperCase()
  }

  const lastMessagePreview = (): string => {
    const msg = props.room.last_message
    if (msg === null || msg === undefined) return "NO MESSAGES"
    if (msg.is_encrypted) return "ENCRYPTED MESSAGE"
    const content = msg.content.slice(0, 40)
    return content.length < msg.content.length ? `${content}...` : content
  }

  const lastMessageTime = (): string => {
    const msg = props.room.last_message
    if (msg === null || msg === undefined) return ""
    return formatRelativeTime(msg.created_at)
  }

  const containerClasses = (): string => {
    const base = "w-full p-3 border-2 transition-colors cursor-pointer"
    if (props.isActive) {
      return `${base} bg-orange text-black border-orange`
    }
    return `${base} bg-black text-white border-dark-gray hover:border-orange`
  }

  return (
    <button
      type="button"
      class={`${containerClasses()} ${props.class ?? ""}`}
      onClick={() => props.onClick()}
    >
      <div class="flex items-start gap-3">
        <div class="relative flex-shrink-0">
          <div class={`w-10 h-10 border-2 flex items-center justify-center ${props.isActive ? "border-black" : "border-orange"}`}>
            <span class={`font-pixel text-[10px] ${props.isActive ? "text-black" : "text-orange"}`}>
              {initials()}
            </span>
          </div>
          <Show when={otherParticipant()} keyed>
            {(participant) => (
              <div class="absolute -bottom-1 -right-1">
                <OnlineStatus
                  status={getUserStatus(participant.user_id)}
                  size="sm"
                />
              </div>
            )}
          </Show>
        </div>

        <div class="flex-1 min-w-0 text-left">
          <div class="flex items-center justify-between gap-2">
            <span class={`font-pixel text-[10px] truncate ${props.isActive ? "text-black" : "text-white"}`}>
              {displayName()}
            </span>
            <span class={`font-pixel text-[8px] flex-shrink-0 ${props.isActive ? "text-black/60" : "text-gray"}`}>
              {lastMessageTime()}
            </span>
          </div>

          <div class="flex items-center justify-between gap-2 mt-1">
            <span class={`font-pixel text-[8px] truncate ${props.isActive ? "text-black/80" : "text-gray"}`}>
              {lastMessagePreview()}
            </span>
            <div class="flex items-center gap-1 flex-shrink-0">
              <Show when={props.room.is_encrypted}>
                <EncryptionBadge isEncrypted size="sm" />
              </Show>
              <Show when={props.room.unread_count > 0}>
                <div class="min-w-[18px] h-[18px] bg-orange flex items-center justify-center">
                  <span class="font-pixel text-[8px] text-black">
                    {props.room.unread_count > 99 ? "99+" : props.room.unread_count}
                  </span>
                </div>
              </Show>
            </div>
          </div>
        </div>
      </div>
    </button>
  )
}
