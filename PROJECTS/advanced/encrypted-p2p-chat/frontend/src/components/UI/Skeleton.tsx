/**
 * 8-bit styled skeleton loading component
 */

import { For } from "solid-js"
import type { JSX } from "solid-js"
import type { SkeletonProps } from "../../types"

type SkeletonVariant = "text" | "circular" | "rectangular"

export function Skeleton(props: SkeletonProps): JSX.Element {
  const variant = (): SkeletonVariant => props.variant ?? "text"
  const lines = (): number => props.lines ?? 1

  const getVariantClasses = (): string => {
    switch (variant()) {
      case "circular":
        return "rounded-none aspect-square"
      case "rectangular":
        return ""
      case "text":
      default:
        return "h-4"
    }
  }

  const getStyle = (): JSX.CSSProperties => {
    const style: JSX.CSSProperties = {}

    if (props.width) {
      style.width = props.width
    }

    if (props.height) {
      style.height = props.height
    }

    return style
  }

  return (
    <div class={`flex flex-col gap-2 ${props.class ?? ""}`}>
      <For each={Array(lines()).fill(0)}>
        {(_, index) => (
          <div
            class={`
              bg-dark-gray
              animate-pixel-pulse
              ${getVariantClasses()}
              ${index() === lines() - 1 && variant() === "text" ? "w-3/4" : "w-full"}
            `}
            style={getStyle()}
          />
        )}
      </For>
    </div>
  )
}

export function MessageSkeleton(): JSX.Element {
  return (
    <div class="flex gap-3 p-3">
      <Skeleton variant="circular" width="40px" height="40px" />
      <div class="flex-1">
        <Skeleton variant="text" width="120px" />
        <div class="mt-2">
          <Skeleton variant="text" lines={2} />
        </div>
      </div>
    </div>
  )
}

export function ConversationSkeleton(): JSX.Element {
  return (
    <div class="flex gap-3 p-3 border-b border-dark-gray">
      <Skeleton variant="circular" width="48px" height="48px" />
      <div class="flex-1">
        <Skeleton variant="text" width="140px" />
        <div class="mt-1">
          <Skeleton variant="text" width="200px" />
        </div>
      </div>
    </div>
  )
}

export function AvatarSkeleton(): JSX.Element {
  return <Skeleton variant="circular" width="40px" height="40px" />
}
