// ===================
// © AngelaMos | 2025
// ChatHeader.tsx
// ===================
import { Show } from "solid-js"
import type { JSX } from "solid-js"
import type { Room, Participant } from "../../types"
import { OnlineStatus } from "./OnlineStatus"
import { EncryptionBadge } from "./EncryptionBadge"
import { getUserStatus } from "../../stores"
import { IconButton } from "../UI/IconButton"

interface ChatHeaderProps {
  room: Room | null
  onSettingsClick?: () => void
  onInfoClick?: () => void
  class?: string
}

export function ChatHeader(props: ChatHeaderProps): JSX.Element {
  const otherParticipant = (): Participant | null => {
    if (props.room?.type !== "direct") return null
    return props.room.participants[0] ?? null
  }

  const displayName = (): string => {
    const room = props.room
    if (room === null) return "CHAT"
    if (room.name !== undefined && room.name !== null) return room.name
    const other = otherParticipant()
    return other?.display_name ?? other?.username ?? "CHAT"
  }

  const initials = (): string => {
    const name = displayName()
    return name.slice(0, 2).toUpperCase()
  }

  return (
    <div class={`flex-shrink-0 px-4 py-3 border-b-2 border-orange ${props.class ?? ""}`}>
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="relative">
            <div class="w-10 h-10 bg-black border-2 border-orange flex items-center justify-center">
              <span class="font-pixel text-[10px] text-orange">
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

          <div>
            <h2 class="font-pixel text-xs text-white">
              {displayName()}
            </h2>
            <div class="flex items-center gap-2 mt-0.5">
              <Show when={props.room?.is_encrypted}>
                <EncryptionBadge isEncrypted showLabel size="sm" />
              </Show>
              <Show when={props.room?.type === "group"}>
                <span class="font-pixel text-[8px] text-gray">
                  {props.room?.participants.length ?? 0} MEMBERS
                </span>
              </Show>
              <Show when={otherParticipant()} keyed>
                {(participant) => (
                  <span class="font-pixel text-[8px] text-gray uppercase">
                    {getUserStatus(participant.user_id)}
                  </span>
                )}
              </Show>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <Show when={props.onInfoClick}>
            <IconButton
              icon={<InfoIcon />}
              onClick={props.onInfoClick}
              ariaLabel="Room info"
              size="sm"
            />
          </Show>
          <Show when={props.onSettingsClick}>
            <IconButton
              icon={<SettingsIcon />}
              onClick={props.onSettingsClick}
              ariaLabel="Room settings"
              size="sm"
            />
          </Show>
        </div>
      </div>
    </div>
  )
}

function InfoIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="7" y="3" width="2" height="2" />
      <rect x="7" y="7" width="2" height="6" />
    </svg>
  )
}

function SettingsIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <rect x="7" y="1" width="2" height="3" />
      <rect x="7" y="12" width="2" height="3" />
      <rect x="1" y="7" width="3" height="2" />
      <rect x="12" y="7" width="3" height="2" />
      <rect x="5" y="5" width="6" height="6" />
    </svg>
  )
}
