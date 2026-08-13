// ===================
// © AngelaMos | 2026
// index.tsx
// ===================

import { useMemo, useState } from 'react'

import { useAttempt, useLevels, useSession } from '@/api/hooks'
import type { AttemptResponse, Finding, Level } from '@/api/types'
import {
  ARENA,
  CENSUS_MARKS,
  COPY,
  DECISION,
  LAYER_ORDER,
  NUMERAL_PAD,
  RULE_LAYER_DISABLED,
  SESSION_ID_HEAD,
  SEVERITY_MAX_WEIGHT,
  SEVERITY_SCALE_OFFSET,
  SEVERITY_WEIGHT,
} from '@/config'
import { ApiError } from '@/core/api/errors'
import { census, hiddenTotal, segments } from '@/core/lib'

import styles from './arena.module.scss'

function numeral(value: number): string {
  return String(value).padStart(NUMERAL_PAD, '0')
}

function severityWidth(severity: string): string {
  const weight = SEVERITY_WEIGHT[severity as keyof typeof SEVERITY_WEIGHT] ?? 0
  const span = SEVERITY_MAX_WEIGHT + SEVERITY_SCALE_OFFSET
  return `${((weight + SEVERITY_SCALE_OFFSET) / span) * 100}%`
}

function attemptMessage(error: Error | null): string {
  const status = error instanceof ApiError ? error.statusCode : 0
  return COPY.ERRORS[status as keyof typeof COPY.ERRORS] ?? COPY.ERRORS.DEFAULT
}

function firedFindings(result: AttemptResponse): Finding[] {
  return result.findings.filter((finding) => finding.rule !== RULE_LAYER_DISABLED)
}

function LevelPlate({
  level,
  selected,
  onSelect,
}: {
  level: Level
  selected: boolean
  onSelect: (value: number) => void
}): React.ReactElement {
  return (
    <button
      type="button"
      className={styles.levelPlate}
      data-selected={selected}
      onClick={() => onSelect(level.number)}
    >
      <span className={styles.levelNumber}>{numeral(level.number)}</span>
      <span className={styles.levelTitle}>{level.title}</span>
      <span className={styles.levelBars} aria-hidden="true">
        {LAYER_ORDER.map((layer) => (
          <span
            key={layer}
            className={styles.levelBar}
            data-on={level.active_layers.includes(layer)}
          />
        ))}
      </span>
    </button>
  )
}

function LayerRail({ level }: { level: Level }): React.ReactElement {
  const off = LAYER_ORDER.filter((layer) => !level.active_layers.includes(layer))

  return (
    <section className={styles.rail}>
      <h2 className={styles.railHeading}>{COPY.ACTIVE_LAYERS}</h2>
      <ul className={styles.railList}>
        {LAYER_ORDER.map((layer, index) => (
          <li
            key={layer}
            className={styles.railItem}
            data-active={level.active_layers.includes(layer)}
          >
            <span className={styles.railIndex}>{numeral(index + 1)}</span>
            <span className={styles.railName}>{layer}</span>
          </li>
        ))}
      </ul>
      {level.active_layers.length === 0 && (
        <p className={styles.note} data-tone="loud">
          {COPY.NO_ACTIVE_LAYERS}
        </p>
      )}
      {off.length > 0 && level.active_layers.length > 0 && (
        <p className={styles.note}>{COPY.DISABLED_NOTICE}</p>
      )}
      {level.number === ARENA.BOUNTY_LEVEL && (
        <p className={styles.note} data-tone="loud">
          {COPY.BOUNTY_NOTE}
        </p>
      )}
    </section>
  )
}

function CensusCell({
  label,
  value,
  hot,
}: {
  label: string
  value: number
  hot: boolean
}): React.ReactElement {
  return (
    <div className={styles.censusCell} data-hot={hot}>
      <span className={styles.censusValue}>{value}</span>
      <span className={styles.censusLabel}>{label}</span>
    </div>
  )
}

function Specimen({ ticket }: { ticket: string }): React.ReactElement {
  const [revealed, setRevealed] = useState<boolean>(false)
  const counts = useMemo(() => census(ticket), [ticket])
  const hidden = hiddenTotal(counts)
  const parts = useMemo(
    () => (revealed ? segments(ticket) : []),
    [revealed, ticket]
  )

  return (
    <section className={styles.specimen}>
      <div className={styles.specimenHead}>
        <h2 className={styles.plateHeading}>{COPY.SPECIMEN_HEADING}</h2>
        <button
          type="button"
          className={styles.ghostButton}
          data-on={revealed}
          onClick={() => setRevealed((value) => !value)}
        >
          {revealed ? COPY.REVEAL_OFF : COPY.REVEAL_ON}
        </button>
      </div>

      <div className={styles.censusGrid}>
        <CensusCell
          label={COPY.CENSUS.GLYPHS}
          value={counts.glyphs}
          hot={false}
        />
        <CensusCell label={COPY.CENSUS.BYTES} value={counts.bytes} hot={false} />
        <CensusCell
          label={COPY.CENSUS.NON_ASCII}
          value={counts.nonAscii}
          hot={false}
        />
        <CensusCell
          label={COPY.CENSUS.TAG}
          value={counts.tag}
          hot={counts.tag > 0}
        />
        <CensusCell
          label={COPY.CENSUS.BIDI}
          value={counts.bidi}
          hot={counts.bidi > 0}
        />
        <CensusCell
          label={COPY.CENSUS.ZERO_WIDTH}
          value={counts.zeroWidth}
          hot={counts.zeroWidth > 0}
        />
      </div>

      {ticket.length === 0 ? (
        <p className={styles.note}>{COPY.SPECIMEN_EMPTY}</p>
      ) : (
        <p className={styles.note} data-tone={hidden > 0 ? 'loud' : 'calm'}>
          {hidden > 0 ? COPY.CENSUS_DIRTY : COPY.CENSUS_CLEAN}
        </p>
      )}

      {revealed && ticket.length > 0 && (
        <pre className={styles.reveal}>
          {parts.map((part) =>
            part.mark === null ? (
              <span key={part.start}>{part.text}</span>
            ) : (
              <mark
                key={part.start}
                className={styles.revealMark}
                data-mark={part.mark}
              >
                {part.mark === CENSUS_MARKS.TAG
                  ? part.text.codePointAt(0)?.toString(16)
                  : part.mark}
              </mark>
            )
          )}
        </pre>
      )}
    </section>
  )
}

function Findings({ findings }: { findings: Finding[] }): React.ReactElement {
  if (findings.length === 0) {
    return <p className={styles.note}>{COPY.NO_RULES}</p>
  }

  return (
    <ul className={styles.findings}>
      {findings.map((finding) => (
        <li
          key={`${finding.layer}-${finding.rule}`}
          className={styles.finding}
          data-invariant={finding.invariant}
        >
          <span className={styles.findingLayer}>{finding.layer}</span>
          <span className={styles.findingRule}>{finding.rule}</span>
          <span className={styles.findingTrack}>
            <span
              className={styles.findingFill}
              style={{ width: severityWidth(finding.severity) }}
            />
          </span>
          <span className={styles.findingSeverity}>{finding.severity}</span>
          <span className={styles.findingFlag}>
            {finding.invariant ? COPY.INVARIANT_MARK : ''}
          </span>
        </li>
      ))}
    </ul>
  )
}

function Verdict({ result }: { result: AttemptResponse }): React.ReactElement {
  const fired = firedFindings(result)

  return (
    <section className={styles.verdict}>
      <div className={styles.verdictHead}>
        <h2 className={styles.plateHeading}>{COPY.VERDICT_HEADING}</h2>
        <span className={styles.attempts}>
          {COPY.ATTEMPTS_LABEL} {numeral(result.attempts)}
        </span>
      </div>

      <dl className={styles.decisions}>
        <div className={styles.decision}>
          <dt className={styles.decisionKey}>{COPY.REQUEST_LABEL}</dt>
          <dd
            className={styles.decisionValue}
            data-decision={result.request_decision}
          >
            {result.request_decision}
          </dd>
        </div>
        <div className={styles.decision}>
          <dt className={styles.decisionKey}>{COPY.EGRESS_LABEL}</dt>
          <dd
            className={styles.decisionValue}
            data-decision={result.egress_decision ?? DECISION.ALLOW}
            data-unreached={result.egress_decision === null}
          >
            {result.egress_decision ?? COPY.EGRESS_UNREACHED}
          </dd>
        </div>
      </dl>

      <h3 className={styles.subHeading}>{COPY.FINDINGS_HEADING}</h3>
      <Findings findings={fired} />

      <div className={styles.seal} data-escaped={result.secret_escaped}>
        <span className={styles.sealLabel}>{COPY.SECRET_LABEL}</span>
        <span className={styles.sealText}>
          {result.secret_escaped ? COPY.SECRET_ESCAPED : COPY.SECRET_CONTAINED}
        </span>
      </div>

      <section className={styles.agent}>
        <h3 className={styles.subHeading}>{COPY.AGENT_HEADING}</h3>
        <pre className={styles.agentText}>
          {result.agent_text || COPY.AGENT_EMPTY}
        </pre>
      </section>
    </section>
  )
}

export function Component(): React.ReactElement {
  const [level, setLevel] = useState<number>(ARENA.FIRST_LEVEL)
  const [ticket, setTicket] = useState<string>('')

  const levels = useLevels()
  const session = useSession()
  const attempt = useAttempt()

  const current = useMemo(
    () => levels.data?.levels.find((entry) => entry.number === level),
    [levels.data, level]
  )

  const canSubmit =
    session.data !== undefined &&
    ticket.length > 0 &&
    ticket.length <= ARENA.MAX_TICKET_CHARS &&
    !attempt.isPending

  const submit = (event: React.FormEvent): void => {
    event.preventDefault()
    if (session.data === undefined) {
      return
    }
    attempt.mutate({
      session_id: session.data.session_id,
      level,
      ticket,
    })
  }

  return (
    <div className={styles.page}>
      <header className={styles.masthead}>
        <div className={styles.mastheadMain}>
          <h1 className={styles.title}>{COPY.TITLE}</h1>
          <p className={styles.tagline}>{COPY.TAGLINE}</p>
        </div>
        <dl className={styles.mastheadMeta}>
          <div className={styles.metaRow}>
            <dt className={styles.metaKey}>{COPY.SESSION_LABEL}</dt>
            <dd className={styles.metaValue}>
              {session.data?.session_id.slice(0, SESSION_ID_HEAD) ??
                COPY.SESSION_PENDING}
            </dd>
          </div>
          <div className={styles.metaRow}>
            <dt className={styles.metaKey}>{COPY.SECRET_LABEL_SHORT}</dt>
            <dd className={styles.metaValue}>
              {session.data === undefined
                ? COPY.SESSION_PENDING
                : `${session.data.secret_length} ${COPY.SECRET_UNIT}`}
            </dd>
          </div>
          <div className={styles.metaRow}>
            <dt className={styles.metaKey}>{COPY.CONFIG_LABEL}</dt>
            <dd className={styles.metaValue}>
              {numeral(levels.data?.levels.length ?? 0)}
            </dd>
          </div>
        </dl>
        <div className={styles.mastheadRule} />
      </header>

      <section className={styles.config}>
        <h2 className={styles.plateHeading}>{COPY.LEVEL_HEADING}</h2>
        <nav className={styles.levels}>
          {levels.data?.levels.map((entry) => (
            <LevelPlate
              key={entry.number}
              level={entry}
              selected={entry.number === level}
              onSelect={setLevel}
            />
          ))}
        </nav>

        {current && (
          <div className={styles.detail}>
            <div className={styles.teaches}>
              <span className={styles.teachesLabel}>{COPY.TEACHES_LABEL}</span>
              <p className={styles.teachesText}>{current.teaches}</p>
            </div>
            <LayerRail level={current} />
          </div>
        )}
      </section>

      <form className={styles.form} onSubmit={submit}>
        <div className={styles.formHead}>
          <label className={styles.label} htmlFor="ticket">
            {COPY.TICKET_LABEL}
          </label>
          <span className={styles.counter}>
            {ticket.length} / {ARENA.MAX_TICKET_CHARS}
          </span>
        </div>
        <p className={styles.hint}>{COPY.TICKET_HINT}</p>
        <textarea
          id="ticket"
          className={styles.textarea}
          value={ticket}
          maxLength={ARENA.MAX_TICKET_CHARS}
          spellCheck={false}
          onChange={(event) => setTicket(event.target.value)}
        />
        <button type="submit" className={styles.submit} disabled={!canSubmit}>
          {attempt.isPending ? COPY.SUBMITTING : COPY.SUBMIT}
        </button>
      </form>

      <Specimen ticket={ticket} />

      {attempt.isError && (
        <p className={styles.error}>{attemptMessage(attempt.error)}</p>
      )}

      {attempt.data ? (
        <Verdict result={attempt.data} />
      ) : (
        <p className={styles.awaiting}>{COPY.AWAITING}</p>
      )}
    </div>
  )
}

Component.displayName = 'Arena'
