/**
 * 8-bit styled icon button component
 */

import { Show, splitProps } from "solid-js"
import type { JSX } from "solid-js"
import type { IconButtonProps, Size } from "../../types"
import { Spinner } from "./Spinner"

type IconButtonVariant = "ghost" | "subtle"

const SIZE_CLASSES: Record<Size, string> = {
  xs: "w-6 h-6",
  sm: "w-8 h-8",
  md: "w-10 h-10",
  lg: "w-12 h-12",
  xl: "w-14 h-14",
}

const ICON_SIZE_CLASSES: Record<Size, string> = {
  xs: "w-3 h-3",
  sm: "w-4 h-4",
  md: "w-5 h-5",
  lg: "w-6 h-6",
  xl: "w-7 h-7",
}

const VARIANT_CLASSES: Record<IconButtonVariant, string> = {
  ghost: `
    bg-transparent text-orange
    hover:bg-orange/10 hover:text-orange
    active:bg-orange/20
  `,
  subtle: `
    bg-dark-gray text-white
    hover:bg-orange hover:text-black
    active:bg-orange/80
  `,
}

const DISABLED_CLASSES = "opacity-50 cursor-not-allowed hover:bg-transparent"

export function IconButton(props: IconButtonProps): JSX.Element {
  const [local, rest] = splitProps(props, [
    "icon",
    "onClick",
    "size",
    "variant",
    "ariaLabel",
    "disabled",
    "loading",
    "class",
  ])

  const size = (): Size => local.size ?? "md"
  const variant = (): IconButtonVariant => local.variant ?? "ghost"
  const isDisabled = (): boolean => local.disabled ?? false
  const isLoading = (): boolean => local.loading ?? false

  const handleClick = (): void => {
    if (!isDisabled() && !isLoading() && local.onClick !== undefined) {
      local.onClick()
    }
  }

  return (
    <button
      type="button"
      aria-label={local.ariaLabel}
      disabled={isDisabled() || isLoading()}
      onClick={handleClick}
      class={`
        inline-flex items-center justify-center
        transition-all duration-100
        focus:outline-none focus:ring-2 focus:ring-orange focus:ring-offset-1 focus:ring-offset-black
        ${SIZE_CLASSES[size()]}
        ${VARIANT_CLASSES[variant()]}
        ${(isDisabled() || isLoading()) ? DISABLED_CLASSES : ""}
        ${local.class ?? ""}
      `}
      {...rest}
    >
      <Show
        when={!isLoading()}
        fallback={<Spinner size={size() === "xs" ? "xs" : "sm"} />}
      >
        <span class={ICON_SIZE_CLASSES[size()]}>
          {local.icon}
        </span>
      </Show>
    </button>
  )
}
