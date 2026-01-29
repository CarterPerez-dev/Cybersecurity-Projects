// ===================
// © AngelaMos | 2025
// OnlineStatus.tsx
// ===================
import { Show } from "solid-js"
import type { JSX } from "solid-js"
import type { PresenceStatus } from "../../types"

interface OnlineStatusProps {
  status: PresenceStatus
  size?: "sm" | "md" | "lg"
  showLabel?: boolean
  class?: string
}

const SIZE_MAP = {
  sm: "w-2 h-2",
  md: "w-3 h-3",
  lg: "w-4 h-4",
}

export function OnlineStatus(props: OnlineStatusProps): JSX.Element {
  const sizeClass = (): string => SIZE_MAP[props.size ?? "md"]

  const statusColor = (): string => {
    switch (props.status) {
      case "online":
        return "bg-success"
      case "away":
        return "bg-away"
      case "offline":
        return "bg-offline"
      default:
        return "bg-gray"
    }
  }

  const statusLabel = (): string => {
    switch (props.status) {
      case "online":
        return "ONLINE"
      case "away":
        return "AWAY"
      case "offline":
        return "OFFLINE"
      default:
        return "UNKNOWN"
    }
  }

  return (
    <div class={`flex items-center gap-2 ${props.class ?? ""}`}>
      <div
        class={`${sizeClass()} ${statusColor()}`}
        role="status"
        aria-label={statusLabel()}
      />
      <Show when={props.showLabel === true}>
        <span class="font-pixel text-[8px] text-gray uppercase">
          {statusLabel()}
        </span>
      </Show>
    </div>
  )
}
