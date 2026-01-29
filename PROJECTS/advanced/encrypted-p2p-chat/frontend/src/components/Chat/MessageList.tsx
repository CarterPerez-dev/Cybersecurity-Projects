// ===================
// © AngelaMos | 2025
// MessageList.tsx
// ===================
import { Show, For, createEffect, createSignal, onMount } from "solid-js"
import type { JSX } from "solid-js"
import { useStore } from "@nanostores/solid"
import { $activeRoomMessages, $activeRoomPendingMessages } from "../../stores"
import { $userId } from "../../stores"
import { MessageBubble } from "./MessageBubble"
import { TypingIndicator } from "./TypingIndicator"
import { Spinner } from "../UI/Spinner"
import type { Message } from "../../types"

interface MessageListProps {
  roomId: string
  onLoadMore?: () => void
  hasMore?: boolean
  loading?: boolean
  class?: string
}

export function MessageList(props: MessageListProps): JSX.Element {
  let containerRef: HTMLDivElement | undefined
  const [autoScroll, setAutoScroll] = createSignal(true)

  const messages = useStore($activeRoomMessages)
  const pendingMessages = useStore($activeRoomPendingMessages)
  const userId = useStore($userId)

  const allMessages = (): Message[] => {
    return [...messages(), ...pendingMessages()]
  }

  const handleScroll = (): void => {
    if (containerRef === undefined) return

    const { scrollTop, scrollHeight, clientHeight } = containerRef
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50
    setAutoScroll(isAtBottom)

    if (scrollTop < 100 && props.hasMore === true && props.loading !== true && props.onLoadMore !== undefined) {
      props.onLoadMore()
    }
  }

  createEffect(() => {
    allMessages()
    if (autoScroll() && containerRef !== undefined) {
      containerRef.scrollTop = containerRef.scrollHeight
    }
  })

  onMount(() => {
    if (containerRef !== undefined) {
      containerRef.scrollTop = containerRef.scrollHeight
    }
  })

  const groupMessagesByDate = (msgs: Message[]): Map<string, Message[]> => {
    const groups = new Map<string, Message[]>()

    for (const msg of msgs) {
      const date = new Date(msg.created_at).toLocaleDateString("en-US", {
        weekday: "short",
        month: "short",
        day: "numeric",
      })

      const existing = groups.get(date) ?? []
      groups.set(date, [...existing, msg])
    }

    return groups
  }

  return (
    <div
      ref={containerRef}
      class={`flex-1 overflow-y-auto scrollbar-pixel p-4 ${props.class ?? ""}`}
      onScroll={handleScroll}
    >
      <Show when={props.loading}>
        <div class="flex justify-center py-4">
          <Spinner size="sm" />
        </div>
      </Show>

      <Show
        when={allMessages().length > 0}
        fallback={<EmptyMessages />}
      >
        <For each={Array.from(groupMessagesByDate(allMessages()).entries())}>
          {([date, dateMessages]) => (
            <div class="mb-6">
              <DateSeparator date={date} />
              <div class="space-y-3">
                <For each={dateMessages}>
                  {(message, index) => {
                    const prevMessage = (): Message | undefined =>
                      index() > 0 ? dateMessages[index() - 1] : undefined
                    const showSender = (): boolean => {
                      const prev = prevMessage()
                      return prev === undefined || prev.sender_id !== message.sender_id
                    }

                    return (
                      <MessageBubble
                        message={message}
                        isOwnMessage={message.sender_id === userId()}
                        showSender={showSender()}
                      />
                    )
                  }}
                </For>
              </div>
            </div>
          )}
        </For>
      </Show>

      <div class="h-6">
        <TypingIndicator />
      </div>
    </div>
  )
}

function EmptyMessages(): JSX.Element {
  return (
    <div class="h-full flex flex-col items-center justify-center py-12">
      <MessageIcon />
      <p class="font-pixel text-[10px] text-gray mt-4">
        NO MESSAGES YET
      </p>
      <p class="font-pixel text-[8px] text-gray mt-1">
        START THE CONVERSATION
      </p>
    </div>
  )
}

interface DateSeparatorProps {
  date: string
}

function DateSeparator(props: DateSeparatorProps): JSX.Element {
  return (
    <div class="flex items-center gap-4 my-4">
      <div class="flex-1 h-px bg-dark-gray" />
      <span class="font-pixel text-[8px] text-gray uppercase">
        {props.date}
      </span>
      <div class="flex-1 h-px bg-dark-gray" />
    </div>
  )
}

function MessageIcon(): JSX.Element {
  return (
    <svg width="48" height="48" viewBox="0 0 48 48" fill="currentColor" class="text-dark-gray">
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
