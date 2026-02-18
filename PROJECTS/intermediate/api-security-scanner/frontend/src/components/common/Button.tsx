// ===========================
// Button.tsx
// ©AngelaMos | 2025
// ===========================

import type { ButtonHTMLAttributes } from 'react'
import './Button.css'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  isLoading?: boolean
  children: React.ReactNode
}

export const Button = ({
  variant = 'primary',
  size = 'md',
  isLoading = false,
  disabled,
  children,
  ...props
}: ButtonProps): React.ReactElement => {
  return (
    <button
      className={`button button--${variant} button--${size}`}
      disabled={disabled ?? isLoading}
      aria-busy={isLoading}
      {...props}
    >
      {isLoading ? 'Loading...' : children}
    </button>
  )
}
