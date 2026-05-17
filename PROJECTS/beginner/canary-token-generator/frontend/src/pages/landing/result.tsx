// ===================
// ©AngelaMos | 2026
// result.tsx
// ===================

import { Link } from 'react-router-dom'
import type { CreateTokenResponse } from '@/api'
import {
  Button,
  CopyField,
  DataRow,
  Pill,
  SerialBar,
  SpecimenCard,
  SpecimenCardSection,
} from '@/components'
import { manageRoute } from '@/config'
import { ArtifactDisplay } from './artifact'
import { ARTIFACT_LABEL, PAGE_COPY } from './copy'
import styles from './landing.module.scss'

type ResultViewProps = {
  data: CreateTokenResponse
  onAnother: () => void
  filenameFallback: string
}

export function ResultView({
  data,
  onAnother,
  filenameFallback,
}: ResultViewProps): React.ReactElement {
  const { token, artifact } = data
  const managePath = manageRoute(token.manage_id)
  return (
    <div className={styles.result}>
      <header className={styles.resultHead}>
        <span className={styles.resultMarker}>★</span>
        <h2 className={styles.resultHeadline}>{PAGE_COPY.RESULT_HEADLINE}</h2>
        <p className={styles.resultBody}>{PAGE_COPY.RESULT_BODY}</p>
      </header>

      <SpecimenCard
        tag={`SPECIES // ${token.type.toUpperCase()}`}
        serial={<SerialBar value={token.id} prefix="SN" />}
      >
        <SpecimenCardSection label="DOSSIER">
          <DataRow label="memo">{token.memo || '—'}</DataRow>
          <DataRow label="filename" mono>
            {token.filename ?? '—'}
          </DataRow>
          <DataRow label="alert" emphasize>
            {token.alert_channel}
          </DataRow>
          <DataRow label="created" mono>
            {formatIso(token.created_at)}
          </DataRow>
          <DataRow label="status">
            <Pill tone={token.enabled ? 'signal' : 'alarm'} size="sm">
              {token.enabled ? 'armed' : 'disabled'}
            </Pill>
          </DataRow>
        </SpecimenCardSection>

        <SpecimenCardSection label={ARTIFACT_LABEL[artifact.kind]}>
          <ArtifactDisplay
            artifact={artifact}
            filenameFallback={filenameFallback}
          />
        </SpecimenCardSection>

        <SpecimenCardSection label="ENDPOINTS">
          <CopyField label="MANAGE" value={token.manage_url} fullWidth />
          <CopyField label="TRIGGER" value={token.trigger_url} fullWidth />
        </SpecimenCardSection>
      </SpecimenCard>

      <footer className={styles.resultFoot}>
        <Link to={managePath} className={styles.resultLink}>
          open dossier →
        </Link>
        <Button variant="ghost" onClick={onAnother}>
          {PAGE_COPY.ISSUE_ANOTHER_LABEL}
        </Button>
      </footer>
    </div>
  )
}

function formatIso(iso: string): string {
  try {
    const dt = new Date(iso)
    return dt
      .toISOString()
      .replace('T', ' ')
      .replace(/\.\d+Z$/, ' Z')
  } catch (_err) {
    return iso
  }
}
