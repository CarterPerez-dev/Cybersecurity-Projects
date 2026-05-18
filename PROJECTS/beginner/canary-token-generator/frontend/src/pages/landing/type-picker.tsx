// ===================
// ©AngelaMos | 2026
// type-picker.tsx
// ===================

import type { TokenType, TypeDescriptor } from '@/api'
import { Glyph } from '@/components'
import { TOKEN_BLURB } from './copy'
import styles from './landing.module.scss'

type TypePickerProps = {
  descriptors: TypeDescriptor[]
  value: TokenType | ''
  onChange: (next: TokenType) => void
  invalid?: boolean
  name?: string
}

export function TypePicker({
  descriptors,
  value,
  onChange,
  invalid = false,
  name = 'token-type',
}: TypePickerProps): React.ReactElement {
  return (
    <fieldset className={styles.typeGrid} data-invalid={invalid}>
      <legend className={styles.srOnly}>Token species</legend>
      {descriptors.map((d, idx) => (
        <TypeCard
          key={d.type}
          name={name}
          descriptor={d}
          index={idx + 1}
          selected={value === d.type}
          onSelect={() => onChange(d.type)}
        />
      ))}
    </fieldset>
  )
}

type TypeCardProps = {
  name: string
  descriptor: TypeDescriptor
  index: number
  selected: boolean
  onSelect: () => void
}

function TypeCard({
  name,
  descriptor,
  index,
  selected,
  onSelect,
}: TypeCardProps): React.ReactElement {
  const indexStr = String(index).padStart(2, '0')
  const disabled = !descriptor.enabled
  return (
    <label
      className={styles.typeCard}
      data-selected={selected}
      data-disabled={disabled}
    >
      <input
        className={styles.srOnly}
        type="radio"
        name={name}
        value={descriptor.type}
        checked={selected}
        disabled={disabled}
        onChange={onSelect}
      />
      <span className={styles.typeIndex}>{indexStr}</span>
      <span className={styles.typeGlyph} aria-hidden="true">
        <Glyph type={descriptor.type} size={36} />
      </span>
      <span className={styles.typeName}>{descriptor.name}</span>
      <span className={styles.typeCode}>{descriptor.type}</span>
      <span className={styles.typeBlurb}>
        {disabled && descriptor.disabled_reason
          ? descriptor.disabled_reason
          : TOKEN_BLURB[descriptor.type]}
      </span>
      {disabled ? <span className={styles.typeDisabledTag}>disabled</span> : null}
    </label>
  )
}
