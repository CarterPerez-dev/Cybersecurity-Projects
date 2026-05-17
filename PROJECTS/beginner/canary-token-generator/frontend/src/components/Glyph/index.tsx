// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import type { TokenType } from '@/api'
import styles from './Glyph.module.scss'

type GlyphProps = {
  type: TokenType
  size?: number
  title?: string
}

export function Glyph({
  type,
  size = 28,
  title,
}: GlyphProps): React.ReactElement {
  return (
    <svg
      className={styles.glyph}
      viewBox="0 0 24 24"
      width={size}
      height={size}
      role={title ? 'img' : 'presentation'}
      aria-label={title}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="square"
      strokeLinejoin="miter"
    >
      {renderGlyph(type)}
    </svg>
  )
}

function renderGlyph(type: TokenType): React.ReactElement {
  switch (type) {
    case 'webbug':
      return <WebbugGlyph />
    case 'slowredirect':
      return <SlowRedirectGlyph />
    case 'docx':
      return <DocxGlyph />
    case 'pdf':
      return <PdfGlyph />
    case 'kubeconfig':
      return <KubeconfigGlyph />
    case 'envfile':
      return <EnvfileGlyph />
    case 'mysql':
      return <MysqlGlyph />
    default:
      return <WebbugGlyph />
  }
}

function WebbugGlyph(): React.ReactElement {
  return (
    <>
      <rect x="3" y="3" width="4" height="4" fill="currentColor" stroke="none" />
      <rect x="9" y="3" width="4" height="4" />
      <rect x="15" y="3" width="4" height="4" />
      <rect x="3" y="9" width="4" height="4" />
      <rect x="9" y="9" width="4" height="4" />
      <rect x="15" y="9" width="4" height="4" />
      <rect x="3" y="15" width="4" height="4" />
      <rect x="9" y="15" width="4" height="4" />
      <rect x="15" y="15" width="4" height="4" />
    </>
  )
}

function SlowRedirectGlyph(): React.ReactElement {
  return (
    <>
      <circle cx="3.5" cy="12" r="1" fill="currentColor" stroke="none" />
      <circle cx="6.5" cy="12" r="1" fill="currentColor" stroke="none" />
      <circle cx="9.5" cy="12" r="1" fill="currentColor" stroke="none" />
      <line x1="12" y1="12" x2="20" y2="12" />
      <polyline points="17,8 21,12 17,16" />
    </>
  )
}

function DocxGlyph(): React.ReactElement {
  return (
    <>
      <path d="M5 3 L15 3 L19 7 L19 21 L5 21 Z" />
      <line x1="15" y1="3" x2="15" y2="7" />
      <line x1="15" y1="7" x2="19" y2="7" />
      <line x1="8" y1="11" x2="16" y2="11" />
      <line x1="8" y1="14" x2="16" y2="14" />
      <line x1="8" y1="17" x2="13" y2="17" />
    </>
  )
}

function PdfGlyph(): React.ReactElement {
  return (
    <>
      <path d="M5 3 L15 3 L19 7 L19 21 L5 21 Z" />
      <line x1="15" y1="3" x2="15" y2="7" />
      <line x1="15" y1="7" x2="19" y2="7" />
      <text
        x="12"
        y="17"
        fontFamily="ui-monospace, monospace"
        fontSize="6"
        fontWeight="700"
        textAnchor="middle"
        fill="currentColor"
        stroke="none"
      >
        PDF
      </text>
    </>
  )
}

function KubeconfigGlyph(): React.ReactElement {
  return (
    <>
      <polygon points="12,3 19.5,7.5 19.5,16.5 12,21 4.5,16.5 4.5,7.5" />
      <circle cx="12" cy="12" r="2.5" fill="currentColor" stroke="none" />
      <line x1="12" y1="3" x2="12" y2="9.5" />
      <line x1="19.5" y1="7.5" x2="14.2" y2="11" />
      <line x1="19.5" y1="16.5" x2="14.2" y2="13" />
      <line x1="12" y1="21" x2="12" y2="14.5" />
      <line x1="4.5" y1="16.5" x2="9.8" y2="13" />
      <line x1="4.5" y1="7.5" x2="9.8" y2="11" />
    </>
  )
}

function EnvfileGlyph(): React.ReactElement {
  return (
    <>
      <path d="M8 4 C5 4 5 8 5 12 C5 16 5 20 8 20" />
      <path d="M16 4 C19 4 19 8 19 12 C19 16 19 20 16 20" />
      <line x1="8" y1="11.5" x2="16" y2="11.5" />
      <line x1="8" y1="13.5" x2="16" y2="13.5" />
      <circle cx="12" cy="8.5" r="0.7" fill="currentColor" stroke="none" />
      <circle cx="12" cy="16.5" r="0.7" fill="currentColor" stroke="none" />
    </>
  )
}

function MysqlGlyph(): React.ReactElement {
  return (
    <>
      <ellipse cx="12" cy="5.5" rx="7" ry="2.5" />
      <path d="M5 5.5 L5 11 C5 12.4 8.1 13.5 12 13.5 C15.9 13.5 19 12.4 19 11 L19 5.5" />
      <path d="M5 11 L5 16.5 C5 17.9 8.1 19 12 19 C15.9 19 19 17.9 19 16.5 L19 11" />
    </>
  )
}
