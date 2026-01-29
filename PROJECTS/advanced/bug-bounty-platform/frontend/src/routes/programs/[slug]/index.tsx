/**
 * AngelaMos | 2026
 * index.tsx
 */

import { Link, useParams } from 'react-router-dom'
import { useProgram } from '@/api/hooks'
import {
  ASSET_TYPE_LABELS,
  type ProgramDetail,
  SEVERITY_LABELS,
  STATUS_LABELS,
} from '@/api/types'
import { ROUTES } from '@/config'
import styles from './detail.module.scss'

function formatCurrency(cents: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(cents / 100)
}

function AssetsSection({
  program,
}: {
  program: ProgramDetail
}): React.ReactElement {
  const inScope = program.assets.filter((a) => a.in_scope)
  const outOfScope = program.assets.filter((a) => !a.in_scope)

  return (
    <section className={styles.section}>
      <h2 className={styles.sectionTitle}>Scope</h2>

      {inScope.length > 0 && (
        <div className={styles.scopeGroup}>
          <h3 className={styles.scopeLabel}>In Scope</h3>
          <div className={styles.assetList}>
            {inScope.map((asset) => (
              <div key={asset.id} className={styles.asset}>
                <span className={styles.assetType}>
                  {ASSET_TYPE_LABELS[asset.asset_type]}
                </span>
                <span className={styles.assetIdentifier}>{asset.identifier}</span>
                {asset.description && (
                  <span className={styles.assetDescription}>
                    {asset.description}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {outOfScope.length > 0 && (
        <div className={styles.scopeGroup}>
          <h3 className={styles.scopeLabelOut}>Out of Scope</h3>
          <div className={styles.assetList}>
            {outOfScope.map((asset) => (
              <div key={asset.id} className={styles.assetOut}>
                <span className={styles.assetType}>
                  {ASSET_TYPE_LABELS[asset.asset_type]}
                </span>
                <span className={styles.assetIdentifier}>{asset.identifier}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {program.assets.length === 0 && (
        <p className={styles.emptyText}>No assets defined yet</p>
      )}
    </section>
  )
}

function RewardsSection({
  program,
}: {
  program: ProgramDetail
}): React.ReactElement {
  const sortedTiers = [...program.reward_tiers].sort((a, b) => {
    const order = ['critical', 'high', 'medium', 'low', 'informational']
    return order.indexOf(a.severity) - order.indexOf(b.severity)
  })

  return (
    <section className={styles.section}>
      <h2 className={styles.sectionTitle}>Rewards</h2>

      {sortedTiers.length > 0 ? (
        <div className={styles.rewardTable}>
          {sortedTiers.map((tier) => (
            <div key={tier.id} className={styles.rewardRow}>
              <span className={styles.severity} data-severity={tier.severity}>
                {SEVERITY_LABELS[tier.severity]}
              </span>
              <span className={styles.rewardRange}>
                {formatCurrency(tier.min_bounty)} -{' '}
                {formatCurrency(tier.max_bounty)}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <p className={styles.emptyText}>No reward tiers defined</p>
      )}
    </section>
  )
}

export function Component(): React.ReactElement {
  const { slug } = useParams<{ slug: string }>()
  const { data: program, isLoading, error } = useProgram(slug ?? '')

  if (isLoading) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.loading}>Loading program...</div>
        </div>
      </div>
    )
  }

  if (error || !program) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.error}>Program not found</div>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <Link to={ROUTES.PROGRAMS.LIST} className={styles.backLink}>
            Back to Programs
          </Link>
          <div className={styles.titleRow}>
            <h1 className={styles.title}>{program.name}</h1>
            <span className={styles.status} data-status={program.status}>
              {STATUS_LABELS[program.status]}
            </span>
          </div>
          {program.description && (
            <p className={styles.description}>{program.description}</p>
          )}
          <div className={styles.meta}>
            <span className={styles.metaItem}>
              Response SLA: {program.response_sla_hours}h
            </span>
          </div>
        </div>

        <div className={styles.content}>
          <div className={styles.main}>
            <AssetsSection program={program} />
            <RewardsSection program={program} />

            {program.rules && (
              <section className={styles.section}>
                <h2 className={styles.sectionTitle}>Rules</h2>
                <div className={styles.rules}>{program.rules}</div>
              </section>
            )}
          </div>

          <aside className={styles.sidebar}>
            <div className={styles.submitCard}>
              <h3 className={styles.submitTitle}>Submit a Report</h3>
              <p className={styles.submitText}>
                Found a vulnerability? Submit your report and help improve
                security.
              </p>
              <Link
                to={ROUTES.PROGRAMS.SUBMIT(program.slug)}
                className={styles.submitButton}
              >
                Submit Report
              </Link>
            </div>
          </aside>
        </div>
      </div>
    </div>
  )
}

Component.displayName = 'ProgramDetail'
