// ===================
// © AngelaMos | 2026
// index.tsx
// ===================

import { useMemo, useState } from 'react'

import { useAttempt, useLevels, useSession } from '@/api/hooks'
import type { AttemptResponse, Finding, Level } from '@/api/types'
import { ARENA, COPY, DECISION, LAYER_ORDER, RULE_LAYER_DISABLED } from '@/config'

import styles from './arena.module.scss'

function firedFindings(result: AttemptResponse): Finding[] {
  return result.findings.filter((finding) => finding.rule !== RULE_LAYER_DISABLED)
}

function disabledLayers(level: Level): string[] {
  return LAYER_ORDER.filter((layer) => !level.active_layers.includes(layer))
}

function LayerList({ level }: { level: Level }): React.ReactElement {
  const off = disabledLayers(level)

  return (
    <section className={styles.layers}>
      <h2 className={styles.layersHeading}>{COPY.ACTIVE_LAYERS}</h2>
      <ul className={styles.layerList}>
        {LAYER_ORDER.map((layer) => (
          <li
            key={layer}
            className={styles.layer}
            data-active={level.active_layers.includes(layer)}
          >
            {layer}
          </li>
        ))}
      </ul>
      {level.active_layers.length === 0 && (
        <p className={styles.note}>{COPY.NO_ACTIVE_LAYERS}</p>
      )}
      {off.length > 0 && level.active_layers.length > 0 && (
        <p className={styles.note}>{COPY.DISABLED_NOTICE}</p>
      )}
      {level.number === ARENA.BOUNTY_LEVEL && (
        <p className={styles.note}>{COPY.BOUNTY_NOTE}</p>
      )}
    </section>
  )
}

function Verdict({ result }: { result: AttemptResponse }): React.ReactElement {
  const fired = firedFindings(result)

  return (
    <section className={styles.verdict}>
      <h2 className={styles.verdictHeading}>{COPY.VERDICT_HEADING}</h2>

      <dl className={styles.decisions}>
        <dt>request</dt>
        <dd data-decision={result.request_decision}>{result.request_decision}</dd>
        <dt>egress</dt>
        <dd data-decision={result.egress_decision ?? DECISION.ALLOW}>
          {result.egress_decision ?? '—'}
        </dd>
      </dl>

      {fired.length === 0 ? (
        <p className={styles.note}>{COPY.NO_RULES}</p>
      ) : (
        <ul className={styles.findings}>
          {fired.map((finding) => (
            <li
              key={`${finding.layer}-${finding.rule}`}
              className={styles.finding}
              data-invariant={finding.invariant}
            >
              <span className={styles.findingLayer}>{finding.layer}</span>
              <span className={styles.findingRule}>{finding.rule}</span>
              <span className={styles.findingSeverity}>{finding.severity}</span>
            </li>
          ))}
        </ul>
      )}

      <p className={styles.outcome} data-escaped={result.secret_escaped}>
        {result.secret_escaped ? COPY.SECRET_ESCAPED : COPY.SECRET_CONTAINED}
      </p>
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
    <main className={styles.page}>
      <header className={styles.header}>
        <h1 className={styles.title}>{COPY.TITLE}</h1>
        <p className={styles.tagline}>{COPY.TAGLINE}</p>
      </header>

      <nav className={styles.levels}>
        {levels.data?.levels.map((entry) => (
          <button
            key={entry.number}
            type="button"
            className={styles.levelButton}
            data-selected={entry.number === level}
            onClick={() => setLevel(entry.number)}
          >
            <span className={styles.levelNumber}>{entry.number}</span>
            <span className={styles.levelTitle}>{entry.title}</span>
          </button>
        ))}
      </nav>

      {current && (
        <>
          <p className={styles.teaches}>{current.teaches}</p>
          <LayerList level={current} />
        </>
      )}

      <form className={styles.form} onSubmit={submit}>
        <label className={styles.label} htmlFor="ticket">
          {COPY.TICKET_LABEL}
        </label>
        <p className={styles.hint}>{COPY.TICKET_HINT}</p>
        <textarea
          id="ticket"
          className={styles.textarea}
          value={ticket}
          maxLength={ARENA.MAX_TICKET_CHARS}
          onChange={(event) => setTicket(event.target.value)}
        />
        <div className={styles.counter}>
          {ticket.length} / {ARENA.MAX_TICKET_CHARS}
        </div>
        <button type="submit" className={styles.submit} disabled={!canSubmit}>
          {attempt.isPending ? COPY.SUBMITTING : COPY.SUBMIT}
        </button>
      </form>

      {attempt.isError && <p className={styles.error}>{COPY.ERRORS.DEFAULT}</p>}

      {attempt.data && (
        <>
          <Verdict result={attempt.data} />
          <section className={styles.agent}>
            <h2 className={styles.agentHeading}>{COPY.AGENT_HEADING}</h2>
            <pre className={styles.agentText}>
              {attempt.data.agent_text || COPY.AGENT_EMPTY}
            </pre>
          </section>
        </>
      )}
    </main>
  )
}

Component.displayName = 'Arena'
