// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import type { ButtonHTMLAttributes, PropsWithChildren } from 'react'
import { forwardRef } from 'react'
import styles from './Button.module.scss'

type ButtonVariant = 'primary' | 'ghost' | 'alarm'
type ButtonSize = 'sm' | 'md' | 'lg'

type ButtonProps = PropsWithChildren<
  Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className'> & {
    variant?: ButtonVariant
    size?: ButtonSize
    fullWidth?: boolean
    busy?: boolean
  }
>

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  function Button(props, ref) {
    const {
      variant = 'primary',
      size = 'md',
      fullWidth = false,
      busy = false,
      type = 'button',
      children,
      disabled,
      ...rest
    } = props
    return (
      <button
        {...rest}
        ref={ref}
        type={type}
        disabled={disabled || busy}
        className={styles.button}
        data-variant={variant}
        data-size={size}
        data-full={fullWidth}
        data-busy={busy}
      >
        <span className={styles.label}>{children}</span>
      </button>
    )
  }
)
