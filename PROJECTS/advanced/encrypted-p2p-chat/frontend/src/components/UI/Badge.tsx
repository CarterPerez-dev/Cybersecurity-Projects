/**
 * 8-bit styled badge component
 */

import { Show } from "solid-js"
import type { JSX } from "solid-js"
import type { BadgeProps, Size, BadgeVariant } from "../../types"

const SIZE_CLASSES: Record<Size, string> = {
  xs: "px-1 py-0.5 text-[6px]",
  sm: "px-1.5 py-0.5 text-[8px]",
  md: "px-2 py-1 text-[10px]",
  lg: "px-3 py-1 text-xs",
  xl: "px-4 py-1.5 text-sm",
}

const VARIANT_CLASSES: Record<BadgeVariant, string> = {
  default: "bg-dark-gray text-white border-gray",
  primary: "bg-black text-orange border-orange",
  success: "bg-black text-success border-success",
  warning: "bg-black text-orange border-orange",
  error: "bg-black text-error border-error",
}

const DOT_COLORS: Record<BadgeVariant, string> = {
  default: "bg-gray",
  primary: "bg-orange",
  success: "bg-success",
  warning: "bg-orange",
  error: "bg-error",
}

export function Badge(props: BadgeProps): JSX.Element {
  const variant = (): BadgeVariant => props.variant ?? "default"
  const size = (): Size => props.size ?? "md"
  const showDot = (): boolean => props.dot ?? false

  return (
    <span
      class={`
        inline-flex items-center gap-1
        font-pixel border-2 uppercase
        ${SIZE_CLASSES[size()]}
        ${VARIANT_CLASSES[variant()]}
        ${props.class ?? ""}
      `}
    >
      <Show when={showDot()}>
        <span class={`w-1.5 h-1.5 ${DOT_COLORS[variant()]}`} />
      </Show>
      {props.children}
    </span>
  )
}
