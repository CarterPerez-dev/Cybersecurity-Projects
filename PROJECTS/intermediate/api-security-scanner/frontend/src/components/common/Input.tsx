// ===========================
// Input.tsx
// ©AngelaMos | 2025
// ===========================

import { forwardRef, type InputHTMLAttributes } from 'react'
import './Input.css'

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  error?: string | undefined
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, id, ...props }, ref) => {
    const inputId = id ?? `input-${label.toLowerCase().replace(/\s+/g, '-')}`
    const errorId = `${inputId}-error`

    return (
      <div className="input-wrapper">
        <label htmlFor={inputId} className="input-label">
          {label}
        </label>
        <input
          ref={ref}
          id={inputId}
          className={`input ${error !== null && error !== undefined ? 'input--error' : ''}`}
          aria-invalid={!!(error !== null && error !== undefined)}
          aria-describedby={
            error !== null && error !== undefined ? errorId : undefined
          }
          {...props}
        />
        {error !== null && error !== undefined ? (
          <p id={errorId} className="input-error" role="alert">
            {error}
          </p>
        ) : null}
      </div>
    )
  }
)

Input.displayName = 'Input'
