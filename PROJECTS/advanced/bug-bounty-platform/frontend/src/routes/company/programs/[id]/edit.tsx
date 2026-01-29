/**
 * AngelaMos | 2026
 * edit.tsx
 */

import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  useAddAsset,
  useDeleteAsset,
  useProgram,
  useSetRewardTiers,
  useUpdateProgram,
} from '@/api/hooks'
import {
  ASSET_TYPE_LABELS,
  type Asset,
  AssetType,
  type ProgramDetail,
  type ProgramStatus,
  ProgramVisibility,
  SEVERITY_LABELS,
  Severity,
  STATUS_LABELS,
} from '@/api/types'
import { ROUTES } from '@/config'
import styles from './edit.module.scss'

function ProgramDetails({
  program,
}: {
  program: ProgramDetail
}): React.ReactElement {
  const updateProgram = useUpdateProgram()
  const [name, setName] = useState(program.name)
  const [description, setDescription] = useState(program.description ?? '')
  const [rules, setRules] = useState(program.rules ?? '')
  const [sla, setSla] = useState(program.response_sla_hours)
  const [status, setStatus] = useState(program.status)
  const [visibility, setVisibility] = useState(program.visibility)

  const handleSave = async (): Promise<void> => {
    await updateProgram.mutateAsync({
      id: program.id,
      data: {
        name,
        description: description || undefined,
        rules: rules || undefined,
        response_sla_hours: sla,
        status,
        visibility,
      },
    })
  }

  return (
    <div className={styles.section}>
      <h2 className={styles.sectionTitle}>Program Details</h2>
      <div className={styles.fields}>
        <label className={styles.field}>
          <span className={styles.label}>Name</span>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className={styles.input}
          />
        </label>
        <div className={styles.row}>
          <label className={styles.field}>
            <span className={styles.label}>Status</span>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as ProgramStatus)}
              className={styles.select}
            >
              {Object.entries(STATUS_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className={styles.field}>
            <span className={styles.label}>Visibility</span>
            <select
              value={visibility}
              onChange={(e) => setVisibility(e.target.value as ProgramVisibility)}
              className={styles.select}
            >
              <option value={ProgramVisibility.PUBLIC}>Public</option>
              <option value={ProgramVisibility.PRIVATE}>Private</option>
              <option value={ProgramVisibility.INVITE_ONLY}>Invite Only</option>
            </select>
          </label>
          <label className={styles.field}>
            <span className={styles.label}>Response SLA</span>
            <input
              type="number"
              value={sla}
              onChange={(e) => setSla(Number(e.target.value))}
              className={styles.input}
              min={1}
              max={720}
            />
          </label>
        </div>
        <label className={styles.field}>
          <span className={styles.label}>Description</span>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className={styles.textarea}
            rows={3}
          />
        </label>
        <label className={styles.field}>
          <span className={styles.label}>Rules</span>
          <textarea
            value={rules}
            onChange={(e) => setRules(e.target.value)}
            className={styles.textarea}
            rows={5}
          />
        </label>
        <button
          type="button"
          onClick={handleSave}
          className={styles.saveBtn}
          disabled={updateProgram.isPending}
        >
          {updateProgram.isPending ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  )
}

function AssetsSection({
  program,
}: {
  program: ProgramDetail
}): React.ReactElement {
  const addAsset = useAddAsset()
  const deleteAsset = useDeleteAsset()
  const [showForm, setShowForm] = useState(false)
  const [assetType, setAssetType] = useState<AssetType>(AssetType.DOMAIN)
  const [identifier, setIdentifier] = useState('')
  const [inScope, setInScope] = useState(true)
  const [assetDescription, setAssetDescription] = useState('')

  const handleAdd = async (): Promise<void> => {
    await addAsset.mutateAsync({
      programId: program.id,
      data: {
        asset_type: assetType,
        identifier,
        in_scope: inScope,
        description: assetDescription || undefined,
      },
    })
    setIdentifier('')
    setAssetDescription('')
    setShowForm(false)
  }

  const handleDelete = async (assetId: string): Promise<void> => {
    await deleteAsset.mutateAsync({ programId: program.id, assetId })
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle}>Assets (Scope)</h2>
        <button
          type="button"
          onClick={() => setShowForm(!showForm)}
          className={styles.addBtn}
        >
          {showForm ? 'Cancel' : 'Add Asset'}
        </button>
      </div>

      {showForm && (
        <div className={styles.addForm}>
          <div className={styles.row}>
            <label className={styles.field}>
              <span className={styles.label}>Type</span>
              <select
                value={assetType}
                onChange={(e) => setAssetType(e.target.value as AssetType)}
                className={styles.select}
              >
                {Object.entries(ASSET_TYPE_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.field}>
              <span className={styles.label}>Identifier</span>
              <input
                type="text"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                className={styles.input}
                placeholder="*.example.com"
              />
            </label>
          </div>
          <div className={styles.row}>
            <div className={styles.field}>
              <label className={styles.checkLabel}>
                <input
                  type="checkbox"
                  checked={inScope}
                  onChange={(e) => setInScope(e.target.checked)}
                />
                In Scope
              </label>
            </div>
          </div>
          <label className={styles.field}>
            <span className={styles.label}>Description (optional)</span>
            <input
              type="text"
              value={assetDescription}
              onChange={(e) => setAssetDescription(e.target.value)}
              className={styles.input}
            />
          </label>
          <button
            type="button"
            onClick={handleAdd}
            className={styles.saveBtn}
            disabled={addAsset.isPending || !identifier}
          >
            {addAsset.isPending ? 'Adding...' : 'Add Asset'}
          </button>
        </div>
      )}

      <div className={styles.assetList}>
        {program.assets.length === 0 ? (
          <p className={styles.emptyText}>No assets defined</p>
        ) : (
          program.assets.map((asset: Asset) => (
            <div key={asset.id} className={styles.assetItem}>
              <div className={styles.assetInfo}>
                <span className={styles.assetType}>
                  {ASSET_TYPE_LABELS[asset.asset_type]}
                </span>
                <span className={styles.assetId}>{asset.identifier}</span>
                <span
                  className={styles.scopeBadge}
                  data-scope={asset.in_scope ? 'in' : 'out'}
                >
                  {asset.in_scope ? 'In Scope' : 'Out of Scope'}
                </span>
              </div>
              <button
                type="button"
                onClick={() => handleDelete(asset.id)}
                className={styles.deleteBtn}
              >
                Delete
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function RewardsSection({
  program,
}: {
  program: ProgramDetail
}): React.ReactElement {
  const setRewardTiers = useSetRewardTiers()
  const severities: Severity[] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
  ]

  const storageKey = `reward-tiers-${program.id}`

  const [tiers, setTiers] = useState<
    Record<Severity, { min: string; max: string }>
  >(() => {
    const stored = localStorage.getItem(storageKey)
    if (stored) {
      try {
        return JSON.parse(stored)
      } catch {}
    }

    const initial: Record<Severity, { min: string; max: string }> = {
      critical: { min: '0', max: '0' },
      high: { min: '0', max: '0' },
      medium: { min: '0', max: '0' },
      low: { min: '0', max: '0' },
      informational: { min: '0', max: '0' },
    }
    for (const tier of program.reward_tiers) {
      initial[tier.severity] = {
        min: String(tier.min_bounty / 100),
        max: String(tier.max_bounty / 100),
      }
    }
    return initial
  })

  useEffect(() => {
    localStorage.setItem(storageKey, JSON.stringify(tiers))
  }, [tiers, storageKey])

  const handleSave = async (): Promise<void> => {
    const tierData = severities
      .filter((s) => Number(tiers[s].max) > 0)
      .map((severity) => ({
        severity,
        min_bounty: Math.round(Number(tiers[severity].min) * 100),
        max_bounty: Math.round(Number(tiers[severity].max) * 100),
        currency: 'USD',
      }))
    await setRewardTiers.mutateAsync({ programId: program.id, tiers: tierData })
    localStorage.removeItem(storageKey)
  }

  const handleInputChange = (
    severity: Severity,
    field: 'min' | 'max',
    value: string
  ): void => {
    const sanitized = value.replace(/[^0-9]/g, '')
    setTiers((t) => ({
      ...t,
      [severity]: { ...t[severity], [field]: sanitized },
    }))
  }

  return (
    <div className={styles.section}>
      <h2 className={styles.sectionTitle}>Reward Tiers</h2>
      <div className={styles.rewardGrid}>
        {severities.map((severity) => (
          <div key={severity} className={styles.rewardRow}>
            <span className={styles.severityLabel}>
              {SEVERITY_LABELS[severity]}
            </span>
            <div className={styles.rewardInputs}>
              <span className={styles.currency}>$</span>
              <input
                type="text"
                inputMode="numeric"
                value={tiers[severity].min}
                onChange={(e) =>
                  handleInputChange(severity, 'min', e.target.value)
                }
                className={styles.rewardInput}
                placeholder="Min"
              />
              <span className={styles.rewardSep}>-</span>
              <span className={styles.currency}>$</span>
              <input
                type="text"
                inputMode="numeric"
                value={tiers[severity].max}
                onChange={(e) =>
                  handleInputChange(severity, 'max', e.target.value)
                }
                className={styles.rewardInput}
                placeholder="Max"
              />
            </div>
          </div>
        ))}
      </div>
      <button
        type="button"
        onClick={handleSave}
        className={styles.saveBtn}
        disabled={setRewardTiers.isPending}
      >
        {setRewardTiers.isPending ? 'Saving...' : 'Save Rewards'}
      </button>
    </div>
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
          <Link to={ROUTES.COMPANY.PROGRAMS} className={styles.backLink}>
            Back to My Programs
          </Link>
          <h1 className={styles.title}>Edit: {program.name}</h1>
        </div>

        <ProgramDetails program={program} />
        <AssetsSection program={program} />
        <RewardsSection program={program} />
      </div>
    </div>
  )
}

Component.displayName = 'EditProgram'
