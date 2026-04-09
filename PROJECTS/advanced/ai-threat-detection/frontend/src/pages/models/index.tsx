// ===================
// © AngelaMos | 2026
// index.tsx
//
// Models page with status banner, retrain button, and model
// cards
//
// Exports a lazy-loaded Component (displayName ModelsPage)
// that fetches useModelStatus and provides useRetrain. Shows
// a status banner indicating whether models are loaded and
// the current detection mode. A retrain button triggers the
// mutation with a spinning icon while pending. ModelCard
// renders each ActiveModel entry with model_type, version,
// training_samples, optional threshold to 4 decimals, and
// a metrics section listing all numeric metric key-value
// pairs. Empty state prompts retraining. Connects to
// api/hooks/useModels, api/types/models.types
// ===================

import { LuRefreshCw } from 'react-icons/lu'
import { useModelStatus, useRetrain } from '@/api/hooks'
import type { ActiveModel } from '@/api/types'
import styles from './models.module.scss'

function ModelCard({ model }: { model: ActiveModel }): React.ReactElement {
  return (
    <div className={styles.modelCard}>
      <div className={styles.modelHeader}>
        <span className={styles.modelType}>{model.model_type}</span>
        <span className={styles.modelVersion}>v{model.version}</span>
      </div>

      <div className={styles.modelStats}>
        <div className={styles.stat}>
          <span className={styles.statLabel}>Training Samples</span>
          <span className={styles.statValue}>
            {model.training_samples.toLocaleString()}
          </span>
        </div>
        {model.threshold !== null && (
          <div className={styles.stat}>
            <span className={styles.statLabel}>Threshold</span>
            <span className={styles.statValue}>{model.threshold.toFixed(4)}</span>
          </div>
        )}
      </div>

      {Object.keys(model.metrics).length > 0 && (
        <div className={styles.metrics}>
          <span className={styles.metricsTitle}>Metrics</span>
          {Object.entries(model.metrics)
            .filter(([, val]) => typeof val === 'number')
            .map(([key, val]) => (
              <div key={key} className={styles.metricRow}>
                <span className={styles.metricKey}>{key}</span>
                <span className={styles.metricVal}>
                  {(val as number).toFixed(4)}
                </span>
              </div>
            ))}
        </div>
      )}
    </div>
  )
}

export function Component(): React.ReactElement {
  const { data: status, isLoading } = useModelStatus()
  const retrain = useRetrain()

  if (isLoading || !status) {
    return <div className={styles.loading}>Loading model status...</div>
  }

  const loaded = status.models_loaded

  return (
    <div className={styles.page}>
      <div
        className={`${styles.banner} ${loaded ? styles.bannerLoaded : styles.bannerNotLoaded}`}
      >
        <span className={styles.bannerText}>
          {loaded
            ? `Models Loaded — ${status.detection_mode} mode`
            : `Models Not Loaded — ${status.detection_mode} mode`}
        </span>
      </div>

      <div className={styles.actions}>
        <button
          type="button"
          className={styles.retrainBtn}
          disabled={retrain.isPending}
          onClick={() => retrain.mutate()}
        >
          <LuRefreshCw className={retrain.isPending ? styles.spinning : ''} />
          {retrain.isPending ? 'Retraining...' : 'Retrain Models'}
        </button>
      </div>

      {status.active_models.length === 0 ? (
        <div className={styles.empty}>
          No trained models found. Click Retrain to start training.
        </div>
      ) : (
        <div className={styles.grid}>
          {status.active_models.map((model) => (
            <ModelCard key={model.model_type} model={model} />
          ))}
        </div>
      )}
    </div>
  )
}

Component.displayName = 'ModelsPage'
