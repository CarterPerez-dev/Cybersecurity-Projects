/**
 * 8-bit styled spinner component
 */

import type { JSX } from "solid-js"
import type { SpinnerProps, Size } from "../../types"

const SIZE_CLASSES: Record<Size, string> = {
  xs: "w-3 h-3",
  sm: "w-4 h-4",
  md: "w-6 h-6",
  lg: "w-8 h-8",
  xl: "w-12 h-12",
}

export function Spinner(props: SpinnerProps): JSX.Element {
  const size = (): Size => props.size ?? "md"

  return (
    <div
      class={`
        inline-block animate-pixel-spin
        ${SIZE_CLASSES[size()]}
        ${props.class ?? ""}
      `}
      role="status"
      aria-label="Loading"
    >
      <svg
        viewBox="0 0 16 16"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        class="w-full h-full"
      >
        <rect x="6" y="0" width="4" height="4" fill="currentColor" class="text-orange" />
        <rect x="10" y="2" width="4" height="4" fill="currentColor" class="text-orange/80" />
        <rect x="12" y="6" width="4" height="4" fill="currentColor" class="text-orange/60" />
        <rect x="10" y="10" width="4" height="4" fill="currentColor" class="text-orange/40" />
        <rect x="6" y="12" width="4" height="4" fill="currentColor" class="text-orange/30" />
        <rect x="2" y="10" width="4" height="4" fill="currentColor" class="text-orange/20" />
        <rect x="0" y="6" width="4" height="4" fill="currentColor" class="text-orange/10" />
        <rect x="2" y="2" width="4" height="4" fill="currentColor" class="text-orange/90" />
      </svg>
    </div>
  )
}

export function LoadingOverlay(): JSX.Element {
  return (
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/90">
      <div class="flex flex-col items-center gap-4">
        <Spinner size="xl" />
        <span class="font-pixel text-xs text-orange animate-pulse">
          LOADING...
        </span>
      </div>
    </div>
  )
}
