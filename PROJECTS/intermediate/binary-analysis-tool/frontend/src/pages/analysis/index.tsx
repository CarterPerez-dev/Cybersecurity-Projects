// ===================
// © AngelaMos | 2026
// index.tsx
//
// Analysis results page with threat score card, tab
// navigation, and six analysis tab panels
//
// Fetches the full analysis via useAnalysis(slug) from
// the URL params and renders three main sections: a
// header with file name, format/architecture/size
// badges, SHA-256 copy-to-clipboard button, and entry
// point hex display; a threat score card with numeric
// score colored by RISK_LEVEL_COLORS, risk label, and
// per-category ScoreBar components showing score/max
// fill percentages; and a six-tab navigation bar
// (overview, headers, imports, strings, entropy,
// disassembly) that switches between TabOverview,
// TabHeaders, TabImports, TabStrings, TabEntropy, and
// TabDisassembly via renderTab dispatch. Shows loading
// and 404 states with a back link to ROUTES.HOME.
// Lazy-loaded via react-router with displayName
// "Analysis"
//
// Connects to:
//   api/hooks           - useAnalysis query
//   api/types           - AnalysisResponse
//   config.ts           - RISK_LEVEL_COLORS, ROUTES
//   core/lib            - copyToClipboard, formatBytes,
//                          formatHex, truncateHash
//   tab-overview.tsx    - TabOverview component
//   tab-headers.tsx     - TabHeaders component
//   tab-imports.tsx     - TabImports component
//   tab-strings.tsx     - TabStrings component
//   tab-entropy.tsx     - TabEntropy component
//   tab-disassembly.tsx - TabDisassembly component
//   analysis.module
//     .scss             - all layout styles
//   routers.tsx         - lazy-loaded at ROUTES.ANALYSIS
// ===================

import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import type { AnalysisResponse } from '@/api'
import { useAnalysis } from '@/api'
import { RISK_LEVEL_COLORS, ROUTES } from '@/config'
import { copyToClipboard, formatBytes, formatHex, truncateHash } from '@/core/lib'
import styles from './analysis.module.scss'
import { TabDisassembly } from './tab-disassembly'
import { TabEntropy } from './tab-entropy'
import { TabHeaders } from './tab-headers'
import { TabImports } from './tab-imports'
import { TabOverview } from './tab-overview'
import { TabStrings } from './tab-strings'

type TabId =
  | 'overview'
  | 'headers'
  | 'imports'
  | 'strings'
  | 'entropy'
  | 'disassembly'

const TABS: readonly { id: TabId; label: string }[] = [
  { id: 'overview', label: 'OVERVIEW' },
  { id: 'headers', label: 'HEADERS' },
  { id: 'imports', label: 'IMPORTS' },
  { id: 'strings', label: 'STRINGS' },
  { id: 'entropy', label: 'ENTROPY' },
  { id: 'disassembly', label: 'DISASM' },
] as const

function renderTab(tab: TabId, data: AnalysisResponse): React.ReactElement {
  switch (tab) {
    case 'overview':
      return <TabOverview data={data} />
    case 'headers':
      return <TabHeaders data={data} />
    case 'imports':
      return <TabImports data={data} />
    case 'strings':
      return <TabStrings data={data} />
    case 'entropy':
      return <TabEntropy data={data} />
    case 'disassembly':
      return <TabDisassembly data={data} />
  }
}

function ScoreBar({
  name,
  score,
  maxScore,
}: {
  name: string
  score: number
  maxScore: number
}): React.ReactElement {
  const pct = maxScore > 0 ? (score / maxScore) * 100 : 0
  return (
    <div className={styles.scoreBar}>
      <div className={styles.scoreBarHeader}>
        <span className={styles.scoreBarName}>{name}</span>
        <span className={styles.scoreBarValue}>
          {score}/{maxScore}
        </span>
      </div>
      <div className={styles.scoreBarTrack}>
        <div className={styles.scoreBarFill} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

export function Component(): React.ReactElement {
  const { slug = '' } = useParams<{ slug: string }>()
  const { data, isLoading, isError } = useAnalysis(slug)
  const [activeTab, setActiveTab] = useState<TabId>('overview')

  if (isLoading) {
    return (
      <div className={styles.state}>
        <span className={styles.stateLabel}>ANALYZING SPECIMEN\u2026</span>
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className={styles.state}>
        <span className={styles.stateCode}>404</span>
        <span className={styles.stateLabel}>SPECIMEN NOT FOUND</span>
        <Link to={ROUTES.HOME} className={styles.stateBack}>
          NEW ANALYSIS
        </Link>
      </div>
    )
  }

  const riskColor = data.risk_level
    ? (RISK_LEVEL_COLORS[data.risk_level] ?? '#888')
    : '#888'

  const handleCopyHash = async () => {
    const ok = await copyToClipboard(data.sha256)
    if (ok) toast.success('SHA-256 copied')
  }

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <Link to={ROUTES.HOME} className={styles.backLink}>
          AXUMORTEM
        </Link>
        <div className={styles.headerTop}>
          <h1 className={styles.fileName}>{data.file_name}</h1>
          <div className={styles.badges}>
            <span className={styles.badge}>{data.format}</span>
            <span className={styles.badge}>{data.architecture}</span>
            <span className={styles.badge}>{formatBytes(data.file_size)}</span>
          </div>
        </div>
        <div className={styles.headerMeta}>
          <button
            type="button"
            className={styles.hashBtn}
            onClick={handleCopyHash}
            title={data.sha256}
          >
            <span className={styles.hashLabel}>SHA-256</span>
            <span className={styles.hashValue}>{truncateHash(data.sha256)}</span>
          </button>
          {data.entry_point !== null && (
            <span className={styles.metaItem}>
              <span className={styles.metaLabel}>ENTRY</span>
              <span className={styles.metaValue}>
                {formatHex(data.entry_point)}
              </span>
            </span>
          )}
        </div>
      </header>

      {data.passes.threat && (
        <section className={styles.scoreCard}>
          <div className={styles.scoreMain}>
            <span className={styles.scoreNumber} style={{ color: riskColor }}>
              {data.threat_score ?? 0}
            </span>
            <div className={styles.scoreInfo}>
              <span className={styles.riskLabel} style={{ color: riskColor }}>
                {data.risk_level ?? 'UNKNOWN'}
              </span>
              <span className={styles.scoreSuffix}>/ 100 THREAT SCORE</span>
            </div>
          </div>
          {data.passes.threat.categories.length > 0 && (
            <div className={styles.scoreBars}>
              {data.passes.threat.categories.map((cat) => (
                <ScoreBar
                  key={cat.name}
                  name={cat.name}
                  score={cat.score}
                  maxScore={cat.max_score}
                />
              ))}
            </div>
          )}
        </section>
      )}

      <nav className={styles.tabBar}>
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`${styles.tab} ${activeTab === tab.id ? styles.tabActive : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className={styles.tabContent}>{renderTab(activeTab, data)}</div>
    </div>
  )
}

Component.displayName = 'Analysis'
