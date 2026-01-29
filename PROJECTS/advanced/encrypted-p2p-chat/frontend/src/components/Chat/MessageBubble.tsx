// ===================
// © AngelaMos | 2025
// MessageBubble.tsx
// ===================
import { Show, Switch, Match } from "solid-js"
import type { JSX } from "solid-js"
import type { Message, MessageStatus } from "../../types"
import { EncryptionBadge } from "./EncryptionBadge"
import { formatTime } from "../../lib/date"

interface MessageBubbleProps {
  message: Message
  isOwnMessage: boolean
  showSender?: boolean
  class?: string
}

export function MessageBubble(props: MessageBubbleProps): JSX.Element {
  const bubbleClasses = (): string => {
    const base = "max-w-[70%] p-4"
    if (props.isOwnMessage) {
      return `${base} bg-orange text-black`
    }
    return `${base} bg-black border-2 border-orange text-white`
  }

  return (
    <div class={`flex px-4 ${props.isOwnMessage ? "justify-end" : "justify-start"} ${props.class ?? ""}`}>
      <div class={bubbleClasses()}>
        <Show when={props.showSender === true && !props.isOwnMessage}>
          <div class="font-pixel text-[10px] text-orange mb-2">
            {props.message.sender_username}
          </div>
        </Show>

        <div class="font-placeholder break-words whitespace-pre-wrap" style="font-size: 32px; line-height: 1.4;">
          {props.message.content}
        </div>

        <div class="flex items-center justify-end gap-2 mt-2">
          <Show when={props.message.is_encrypted}>
            <EncryptionBadge isEncrypted size="sm" />
          </Show>
          <span class={`font-pixel text-[8px] ${props.isOwnMessage ? "text-black/60" : "text-gray"}`}>
            {formatTime(props.message.created_at)}
          </span>
          <Show when={props.isOwnMessage}>
            <MessageStatusIcon status={props.message.status} />
          </Show>
        </div>
      </div>
    </div>
  )
}

interface MessageStatusIconProps {
  status: MessageStatus
}

function MessageStatusIcon(props: MessageStatusIconProps): JSX.Element {
  return (
    <Switch fallback={<></>}>
      <Match when={props.status === "sending"}>
        <ClockIcon class="w-3 h-3 text-black/40" />
      </Match>
      <Match when={props.status === "sent"}>
        <CheckIcon class="w-3 h-3 text-black/60" />
      </Match>
      <Match when={props.status === "delivered"}>
        <DoubleCheckIcon class="w-3 h-3 text-black/60" />
      </Match>
      <Match when={props.status === "read"}>
        <DoubleCheckIcon class="w-3 h-3 text-success" />
      </Match>
      <Match when={props.status === "failed"}>
        <ErrorIcon class="w-3 h-3 text-error" />
      </Match>
    </Switch>
  )
}

interface IconProps {
  class?: string
}

function ClockIcon(props: IconProps): JSX.Element {
  return (
    <svg viewBox="0 0 12 12" fill="currentColor" class={props.class}>
      <rect x="5" y="1" width="2" height="1" />
      <rect x="3" y="2" width="2" height="1" />
      <rect x="7" y="2" width="2" height="1" />
      <rect x="2" y="3" width="1" height="2" />
      <rect x="9" y="3" width="1" height="2" />
      <rect x="1" y="5" width="1" height="2" />
      <rect x="10" y="5" width="1" height="2" />
      <rect x="2" y="7" width="1" height="2" />
      <rect x="9" y="7" width="1" height="2" />
      <rect x="3" y="9" width="2" height="1" />
      <rect x="7" y="9" width="2" height="1" />
      <rect x="5" y="10" width="2" height="1" />
      <rect x="5" y="3" width="2" height="3" />
      <rect x="5" y="5" width="3" height="2" />
    </svg>
  )
}

function CheckIcon(props: IconProps): JSX.Element {
  return (
    <svg viewBox="0 0 12 12" fill="currentColor" class={props.class}>
      <rect x="2" y="6" width="2" height="2" />
      <rect x="4" y="8" width="2" height="2" />
      <rect x="6" y="6" width="2" height="2" />
      <rect x="8" y="4" width="2" height="2" />
      <rect x="10" y="2" width="2" height="2" />
    </svg>
  )
}

function DoubleCheckIcon(props: IconProps): JSX.Element {
  return (
    <svg viewBox="0 0 16 12" fill="currentColor" class={props.class}>
      <rect x="0" y="6" width="2" height="2" />
      <rect x="2" y="8" width="2" height="2" />
      <rect x="4" y="6" width="2" height="2" />
      <rect x="6" y="4" width="2" height="2" />
      <rect x="8" y="2" width="2" height="2" />
      <rect x="4" y="6" width="2" height="2" />
      <rect x="6" y="8" width="2" height="2" />
      <rect x="8" y="6" width="2" height="2" />
      <rect x="10" y="4" width="2" height="2" />
      <rect x="12" y="2" width="2" height="2" />
    </svg>
  )
}

function ErrorIcon(props: IconProps): JSX.Element {
  return (
    <svg viewBox="0 0 12 12" fill="currentColor" class={props.class}>
      <rect x="5" y="1" width="2" height="1" />
      <rect x="3" y="2" width="2" height="1" />
      <rect x="7" y="2" width="2" height="1" />
      <rect x="2" y="3" width="1" height="2" />
      <rect x="9" y="3" width="1" height="2" />
      <rect x="1" y="5" width="1" height="2" />
      <rect x="10" y="5" width="1" height="2" />
      <rect x="2" y="7" width="1" height="2" />
      <rect x="9" y="7" width="1" height="2" />
      <rect x="3" y="9" width="2" height="1" />
      <rect x="7" y="9" width="2" height="1" />
      <rect x="5" y="10" width="2" height="1" />
      <rect x="5" y="3" width="2" height="4" />
      <rect x="5" y="8" width="2" height="1" />
    </svg>
  )
}
