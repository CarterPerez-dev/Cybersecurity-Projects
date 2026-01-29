/**
 * 8-bit styled avatar component
 */

import { Show, createSignal, onMount } from "solid-js"
import type { JSX } from "solid-js"
import type { AvatarProps, Size, PresenceStatus } from "../../types"

const SIZE_CLASSES: Record<Size, string> = {
  xs: "w-6 h-6 text-[8px]",
  sm: "w-8 h-8 text-[10px]",
  md: "w-10 h-10 text-xs",
  lg: "w-12 h-12 text-sm",
  xl: "w-16 h-16 text-base",
}

const STATUS_COLORS: Record<PresenceStatus, string> = {
  online: "bg-success",
  away: "bg-orange",
  offline: "bg-gray",
}

const STATUS_SIZE: Record<Size, string> = {
  xs: "w-2 h-2",
  sm: "w-2.5 h-2.5",
  md: "w-3 h-3",
  lg: "w-3.5 h-3.5",
  xl: "w-4 h-4",
}

export function Avatar(props: AvatarProps): JSX.Element {
  const [imageError, setImageError] = createSignal(false)
  let imgRef: HTMLImageElement | undefined

  const size = (): Size => props.size ?? "md"
  const showStatus = (): boolean => props.showStatus ?? false

  const getFallbackInitials = (): string => {
    if (props.fallback) {
      return props.fallback.slice(0, 2).toUpperCase()
    }
    return props.alt.slice(0, 2).toUpperCase()
  }

  onMount(() => {
    if (imgRef !== undefined) {
      imgRef.addEventListener("error", () => setImageError(true))
    }
  })

  const shouldShowImage = (): boolean => {
    return Boolean(props.src) && !imageError()
  }

  return (
    <div
      class={`
        relative inline-flex items-center justify-center
        bg-black border-2 border-orange
        ${SIZE_CLASSES[size()]}
        ${props.class ?? ""}
      `}
    >
      <Show
        when={shouldShowImage()}
        fallback={
          <span class="font-pixel text-orange select-none">
            {getFallbackInitials()}
          </span>
        }
      >
        <img
          ref={imgRef}
          src={props.src}
          alt={props.alt}
          class="w-full h-full object-cover"
          style={{ "image-rendering": "pixelated" }}
        />
      </Show>

      <Show when={showStatus() ? props.status : undefined} keyed>
        {(status) => (
          <span
            class={`
              absolute -bottom-0.5 -right-0.5
              border-2 border-black
              ${STATUS_SIZE[size()]}
              ${STATUS_COLORS[status]}
            `}
          />
        )}
      </Show>
    </div>
  )
}
