// ===================
// © AngelaMos | 2025
// components.ts
// ===================
import type { JSX } from "solid-js"
import type { MessageStatus, PresenceStatus } from "./chat"

export type Size = "xs" | "sm" | "md" | "lg" | "xl"

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger"

export type BadgeVariant = "default" | "primary" | "success" | "warning" | "error"

export interface ButtonProps {
  variant?: ButtonVariant
  size?: Size
  fullWidth?: boolean
  disabled?: boolean
  loading?: boolean
  leftIcon?: JSX.Element
  rightIcon?: JSX.Element
  type?: "button" | "submit" | "reset"
  onClick?: () => void
  class?: string
  children: JSX.Element
}

export interface InputProps {
  type?: "text" | "email" | "password" | "search"
  name?: string
  placeholder?: string
  value?: string
  onInput?: (value: string) => void
  onChange?: (value: string) => void
  onFocus?: () => void
  onBlur?: () => void
  disabled?: boolean
  error?: string
  label?: string
  hint?: string
  leftIcon?: JSX.Element
  rightIcon?: JSX.Element
  fullWidth?: boolean
  maxLength?: number
  minLength?: number
  required?: boolean
  autofocus?: boolean
  class?: string
}

export interface TextAreaProps {
  name?: string
  placeholder?: string
  value?: string
  onInput?: (value: string) => void
  disabled?: boolean
  error?: string
  label?: string
  rows?: number
  maxLength?: number
  autoResize?: boolean
  class?: string
}

export interface AvatarProps {
  src?: string
  alt: string
  size?: Size
  fallback?: string
  status?: PresenceStatus
  showStatus?: boolean
  class?: string
}

export interface BadgeProps {
  variant?: BadgeVariant
  size?: Size
  children: JSX.Element
  dot?: boolean
  class?: string
}

export interface ModalProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  description?: string
  size?: Size
  closeOnOverlayClick?: boolean
  showCloseButton?: boolean
  children: JSX.Element
}

export interface ToastProps {
  id: string
  variant: "info" | "success" | "warning" | "error"
  title: string
  description?: string
  duration?: number
  action?: {
    label: string
    onClick: () => void
  }
}

export interface SpinnerProps {
  size?: Size
  class?: string
}

export interface SkeletonProps {
  variant?: "text" | "circular" | "rectangular"
  width?: string
  height?: string
  lines?: number
  class?: string
}

export interface TooltipProps {
  content: string
  position?: "top" | "bottom" | "left" | "right"
  delay?: number
  children: JSX.Element
}

export interface DropdownItem {
  label: string
  value: string
  icon?: JSX.Element
  disabled?: boolean
  danger?: boolean
}

export interface DropdownProps {
  items: DropdownItem[]
  onSelect: (value: string) => void
  trigger: JSX.Element
  align?: "left" | "right"
  class?: string
}

export interface IconButtonProps {
  icon: JSX.Element
  onClick?: () => void
  size?: Size
  variant?: "ghost" | "subtle"
  ariaLabel: string
  disabled?: boolean
  loading?: boolean
  class?: string
}

export interface MessageBubbleProps {
  content: string
  timestamp: string
  isSent: boolean
  status?: MessageStatus
  senderName?: string
  senderAvatar?: string
  isEncrypted?: boolean
  showTail?: boolean
  isGrouped?: boolean
}

export interface ConversationItemProps {
  id: string
  name: string
  avatar?: string
  lastMessage?: string
  lastMessageTime?: string
  unreadCount?: number
  isOnline?: boolean
  isSelected?: boolean
  isTyping?: boolean
  isGroup?: boolean
  onClick?: () => void
}

export interface OnlineStatusProps {
  status: PresenceStatus
  showLabel?: boolean
  size?: Size
}

export interface TypingIndicatorProps {
  users: string[]
}
