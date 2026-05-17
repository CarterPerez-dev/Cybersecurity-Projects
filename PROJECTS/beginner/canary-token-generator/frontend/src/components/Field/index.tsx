// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import type {
  InputHTMLAttributes,
  PropsWithChildren,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react'
import { forwardRef, useId } from 'react'
import styles from './Field.module.scss'

type FieldWrapProps = PropsWithChildren<{
  label: ReactNode
  hint?: ReactNode
  error?: ReactNode
  index?: string
  required?: boolean
  htmlFor?: string
}>

export function FieldWrap({
  label,
  hint,
  error,
  index,
  required,
  htmlFor,
  children,
}: FieldWrapProps): React.ReactElement {
  return (
    <div className={styles.field} data-invalid={error ? 'true' : 'false'}>
      <div className={styles.head}>
        {index ? <span className={styles.index}>{index}</span> : null}
        <label className={styles.label} htmlFor={htmlFor}>
          {label}
          {required ? <span className={styles.required}> *</span> : null}
        </label>
        <span className={styles.rule} aria-hidden="true" />
      </div>
      {children}
      {hint && !error ? <p className={styles.hint}>{hint}</p> : null}
      {error ? (
        <p className={styles.error} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}

type TextFieldProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  'className' | 'id'
> & {
  label: ReactNode
  hint?: ReactNode
  error?: ReactNode
  index?: string
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(
  function TextField(props, ref) {
    const { label, hint, error, index, required, ...rest } = props
    const fallbackId = useId()
    const id = rest.name ? `f-${rest.name}` : fallbackId
    return (
      <FieldWrap
        label={label}
        hint={hint}
        error={error}
        index={index}
        required={required}
        htmlFor={id}
      >
        <input
          {...rest}
          id={id}
          required={required}
          ref={ref}
          className={styles.input}
        />
      </FieldWrap>
    )
  }
)

type TextareaFieldProps = Omit<
  TextareaHTMLAttributes<HTMLTextAreaElement>,
  'className' | 'id'
> & {
  label: ReactNode
  hint?: ReactNode
  error?: ReactNode
  index?: string
}

export const TextareaField = forwardRef<HTMLTextAreaElement, TextareaFieldProps>(
  function TextareaField(props, ref) {
    const { label, hint, error, index, required, ...rest } = props
    const fallbackId = useId()
    const id = rest.name ? `f-${rest.name}` : fallbackId
    return (
      <FieldWrap
        label={label}
        hint={hint}
        error={error}
        index={index}
        required={required}
        htmlFor={id}
      >
        <textarea
          {...rest}
          id={id}
          required={required}
          ref={ref}
          className={styles.textarea}
        />
      </FieldWrap>
    )
  }
)

type SelectFieldProps = Omit<
  SelectHTMLAttributes<HTMLSelectElement>,
  'className' | 'id'
> & {
  label: ReactNode
  hint?: ReactNode
  error?: ReactNode
  index?: string
}

export const SelectField = forwardRef<HTMLSelectElement, SelectFieldProps>(
  function SelectField(props, ref) {
    const { label, hint, error, index, required, children, ...rest } = props
    const fallbackId = useId()
    const id = rest.name ? `f-${rest.name}` : fallbackId
    return (
      <FieldWrap
        label={label}
        hint={hint}
        error={error}
        index={index}
        required={required}
        htmlFor={id}
      >
        <select
          {...rest}
          id={id}
          required={required}
          ref={ref}
          className={styles.select}
        >
          {children}
        </select>
      </FieldWrap>
    )
  }
)
