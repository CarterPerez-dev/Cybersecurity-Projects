// ===================
// ©AngelaMos | 2026
// index.tsx
// ===================

import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import {
  type ManageResponse,
  type ManageTokenView,
  useDeleteToken,
  useManageToken,
} from '@/api'
import {
  Button,
  CopyField,
  DataRow,
  Halftone,
  Pill,
  SerialBar,
  SpecimenCard,
  SpecimenCardSection,
  Strip,
  StripItem,
} from '@/components'
import { ApiError, ApiErrorCode } from '@/core/api'
import { MANAGE_COPY } from './copy'
import { EventRow } from './event-row'
import styles from './manage.module.scss'

const PAGE_SIZE = 20

export function Component(): React.ReactElement {
  const params = useParams()
  const manageId = params.manageId ?? ''
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const query = useManageToken(manageId, { cursor, limit: PAGE_SIZE })

  if (manageId.length === 0) {
    return <ManageNotFound />
  }
  if (query.isLoading) {
    return <ManageLoading />
  }
  if (query.error) {
    if (
      query.error instanceof ApiError &&
      query.error.code === ApiErrorCode.NOT_FOUND
    ) {
      return <ManageNotFound />
    }
    return <ManageError onRetry={() => query.refetch()} />
  }
  if (!query.data) {
    return <ManageNotFound />
  }

  return (
    <ManageView
      manageId={manageId}
      data={query.data}
      cursor={cursor}
      isFetchingNextPage={query.isFetching && cursor !== undefined}
      onLoadOlder={() => setCursor(query.data?.page.next_cursor)}
      onResetCursor={() => setCursor(undefined)}
    />
  )
}

Component.displayName = 'Manage'

type ManageViewProps = {
  manageId: string
  data: ManageResponse
  cursor: string | undefined
  isFetchingNextPage: boolean
  onLoadOlder: () => void
  onResetCursor: () => void
}

function ManageView({
  manageId,
  data,
  cursor,
  isFetchingNextPage,
  onLoadOlder,
  onResetCursor,
}: ManageViewProps): React.ReactElement {
  const { token, events, events_total, events_silenced_active, page } = data
  return (
    <div className={styles.page}>
      <Strip>
        <StripItem label="FIELD STATION">canary</StripItem>
        <StripItem label="SECTION">dossier</StripItem>
        <StripItem label="SPECIES" inverted>
          {token.type}
        </StripItem>
      </Strip>

      <DossierHero token={token} eventsTotal={events_total} />

      <Halftone density="sparse" height={18} />

      <DossierCard
        token={token}
        eventsTotal={events_total}
        silenced={events_silenced_active}
      />

      <EventLogSection
        events={events}
        cursor={cursor}
        hasMore={page.has_more}
        isFetchingNextPage={isFetchingNextPage}
        onLoadOlder={onLoadOlder}
        onResetCursor={onResetCursor}
      />

      <DeleteSection manageId={manageId} memo={token.memo} />

      <Strip align="left" border="top">
        <StripItem label="LINK">
          <Link to="/" className={styles.footerLink}>
            new specimen ↗
          </Link>
        </StripItem>
        <StripItem label="LICENSE">©AngelaMos 2026</StripItem>
      </Strip>
    </div>
  )
}

type DossierHeroProps = {
  token: ManageTokenView
  eventsTotal: number
}

function DossierHero({
  token,
  eventsTotal,
}: DossierHeroProps): React.ReactElement {
  const state = resolveState(token, eventsTotal)
  const headline =
    state === 'live'
      ? MANAGE_COPY.HEADLINE_LIVE
      : state === 'disabled'
        ? MANAGE_COPY.HEADLINE_DISABLED
        : MANAGE_COPY.HEADLINE_QUIET
  const purpose =
    state === 'live'
      ? MANAGE_COPY.PURPOSE_LIVE
      : state === 'disabled'
        ? MANAGE_COPY.PURPOSE_DISABLED
        : MANAGE_COPY.PURPOSE_QUIET
  return (
    <header className={styles.hero}>
      <p className={styles.heroIndex}>DOSSIER · {token.type.toUpperCase()}</p>
      <h1 className={styles.headline} data-state={state}>
        {headline}
      </h1>
      <p className={styles.purpose}>{purpose}</p>
      <p className={styles.memo}>{token.memo || 'no memo recorded'}</p>
    </header>
  )
}

type DossierCardProps = {
  token: ManageTokenView
  eventsTotal: number
  silenced: number
}

function DossierCard({
  token,
  eventsTotal,
  silenced,
}: DossierCardProps): React.ReactElement {
  return (
    <SpecimenCard
      tag={`SN · ${token.id}`}
      serial={<SerialBar value={token.id} prefix="SN" />}
    >
      <SpecimenCardSection label="STATUS">
        <DataRow label="armed">
          <Pill tone={token.enabled ? 'signal' : 'alarm'}>
            {token.enabled ? 'live' : 'disabled'}
          </Pill>
        </DataRow>
        <DataRow label="triggers" emphasize alarm={eventsTotal > 0}>
          {eventsTotal}
        </DataRow>
        <DataRow label="silenced (15m window)" mono>
          {silenced}
        </DataRow>
        <DataRow label="last seen" mono>
          {token.last_triggered ? formatTs(token.last_triggered) : 'never'}
        </DataRow>
        <DataRow label="created" mono>
          {formatTs(token.created_at)}
        </DataRow>
        <DataRow label="alert" emphasize>
          {token.alert_channel}
        </DataRow>
        {token.filename ? (
          <DataRow label="filename" mono>
            {token.filename}
          </DataRow>
        ) : null}
      </SpecimenCardSection>

      <SpecimenCardSection label="ENDPOINT">
        <CopyField label="TRIGGER" value={token.trigger_url} fullWidth />
      </SpecimenCardSection>
    </SpecimenCard>
  )
}

type EventLogSectionProps = {
  events: ManageResponse['events']
  cursor: string | undefined
  hasMore: boolean
  isFetchingNextPage: boolean
  onLoadOlder: () => void
  onResetCursor: () => void
}

function EventLogSection({
  events,
  cursor,
  hasMore,
  isFetchingNextPage,
  onLoadOlder,
  onResetCursor,
}: EventLogSectionProps): React.ReactElement {
  return (
    <section className={styles.eventLog}>
      <header className={styles.eventLogHead}>
        <span className={styles.eventLogIndex}>06 / EVENT LOG</span>
        <span className={styles.eventLogRule} aria-hidden="true" />
        <span className={styles.eventLogCount}>
          {events.length} {events.length === 1 ? 'entry' : 'entries'}
        </span>
      </header>
      {events.length === 0 ? (
        <p className={styles.eventEmpty}>{MANAGE_COPY.EVENT_LOG_EMPTY}</p>
      ) : (
        <div className={styles.eventList}>
          {events.map((event, idx) => (
            <EventRow
              key={event.id}
              event={event}
              index={cursor === undefined ? idx + 1 : idx + 1}
            />
          ))}
        </div>
      )}
      <footer className={styles.eventLogFoot}>
        {cursor !== undefined ? (
          <Button variant="ghost" size="sm" onClick={onResetCursor}>
            ← back to most recent
          </Button>
        ) : (
          <span />
        )}
        {hasMore ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={onLoadOlder}
            busy={isFetchingNextPage}
          >
            {MANAGE_COPY.EVENT_LOAD_MORE} →
          </Button>
        ) : (
          <span className={styles.eventEnd}>end of log</span>
        )}
      </footer>
    </section>
  )
}

type DeleteSectionProps = {
  manageId: string
  memo: string
}

function DeleteSection({
  manageId,
  memo,
}: DeleteSectionProps): React.ReactElement {
  const [armed, setArmed] = useState(false)
  const del = useDeleteToken()
  const navigate = useNavigate()

  function confirm(): void {
    del.mutate(manageId, {
      onSuccess: () => {
        toast.success(`Terminated ${memo || 'unnamed specimen'}`)
        navigate('/')
      },
    })
  }

  return (
    <section className={styles.deleteSection}>
      <header className={styles.deleteHead}>
        <span className={styles.deleteIndex}>07 / TERMINATION</span>
        <span className={styles.deleteRule} aria-hidden="true" />
      </header>
      <h2 className={styles.deleteTitle}>{MANAGE_COPY.DELETE_TITLE}</h2>
      <p className={styles.deleteBody}>{MANAGE_COPY.DELETE_BODY}</p>
      {armed ? (
        <div className={styles.deleteArmed}>
          <Button
            variant="alarm"
            onClick={confirm}
            busy={del.isPending}
            size="md"
          >
            {MANAGE_COPY.DELETE_CONFIRM}
          </Button>
          <Button
            variant="ghost"
            onClick={() => setArmed(false)}
            disabled={del.isPending}
            size="md"
          >
            {MANAGE_COPY.DELETE_CANCEL}
          </Button>
        </div>
      ) : (
        <Button variant="ghost" onClick={() => setArmed(true)}>
          {MANAGE_COPY.DELETE_ARM}
        </Button>
      )}
    </section>
  )
}

function ManageLoading(): React.ReactElement {
  return (
    <div className={styles.page}>
      <Strip>
        <StripItem label="FIELD STATION">canary</StripItem>
        <StripItem label="STATUS">loading dossier…</StripItem>
      </Strip>
      <div className={styles.statusBlock}>fetching specimen record…</div>
    </div>
  )
}

function ManageNotFound(): React.ReactElement {
  return (
    <div className={styles.page}>
      <Strip>
        <StripItem label="FIELD STATION">canary</StripItem>
        <StripItem label="STATUS" inverted>
          unfound
        </StripItem>
      </Strip>
      <header className={styles.hero}>
        <p className={styles.heroIndex}>404 · DOSSIER</p>
        <h1 className={styles.headline}>{MANAGE_COPY.NOT_FOUND_HEADLINE}</h1>
        <p className={styles.purpose}>{MANAGE_COPY.NOT_FOUND_BODY}</p>
      </header>
      <Link to="/" className={styles.heroLink}>
        ← {MANAGE_COPY.BACK_TO_INTAKE}
      </Link>
    </div>
  )
}

type ManageErrorProps = {
  onRetry: () => void
}

function ManageError({ onRetry }: ManageErrorProps): React.ReactElement {
  return (
    <div className={styles.page}>
      <Strip>
        <StripItem label="FIELD STATION">canary</StripItem>
        <StripItem label="STATUS" inverted>
          archive offline
        </StripItem>
      </Strip>
      <header className={styles.hero}>
        <p className={styles.heroIndex}>5xx · ARCHIVE</p>
        <h1 className={styles.headline}>{MANAGE_COPY.ERROR_HEADLINE}</h1>
        <p className={styles.purpose}>{MANAGE_COPY.ERROR_BODY}</p>
      </header>
      <div className={styles.heroActions}>
        <Button onClick={onRetry}>Try again</Button>
        <Link to="/" className={styles.heroLink}>
          new specimen
        </Link>
      </div>
    </div>
  )
}

function resolveState(
  token: ManageTokenView,
  eventsTotal: number
): 'quiet' | 'live' | 'disabled' {
  if (!token.enabled) {
    return 'disabled'
  }
  if (eventsTotal > 0) {
    return 'live'
  }
  return 'quiet'
}

function formatTs(iso: string): string {
  try {
    const dt = new Date(iso)
    return dt
      .toISOString()
      .replace('T', ' ')
      .replace(/\.\d+Z$/, 'Z')
  } catch (_err) {
    return iso
  }
}
