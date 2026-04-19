// ©AngelaMos | 2026
// session-player.tsx

import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import { useCallback, useEffect, useRef, useState } from 'react'
import '@xterm/xterm/css/xterm.css'
import styles from './session-player.module.scss'

const PLAYBACK_SPEEDS = [0.5, 1, 2, 4] as const
const TERMINAL_FONT_SIZE = 14
const TERMINAL_FONT_FAMILY = 'JetBrains Mono, Fira Code, monospace'

interface CastHeader {
  version: number
  width: number
  height: number
}

type CastFrame = [number, string, string]

interface SessionPlayerProps {
  castData: string
}

function parseCast(raw: string): { header: CastHeader; frames: CastFrame[] } {
  const lines = raw.trim().split('\n')
  const header = JSON.parse(lines[0] ?? '{}') as CastHeader
  const frames = lines.slice(1).map((line) => JSON.parse(line) as CastFrame)
  return { header, frames }
}

export function SessionPlayer({ castData }: SessionPlayerProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState<(typeof PLAYBACK_SPEEDS)[number]>(1)
  const [frameIdx, setFrameIdx] = useState(0)

  const { header, frames } = parseCast(castData)

  useEffect(() => {
    if (!containerRef.current) return

    const term = new Terminal({
      fontSize: TERMINAL_FONT_SIZE,
      fontFamily: TERMINAL_FONT_FAMILY,
      theme: {
        background: '#1a1a2e',
        foreground: '#e0e0e0',
        cursor: '#e0e0e0',
      },
      cols: header.width,
      rows: header.height,
      disableStdin: true,
      cursorBlink: false,
    })

    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)
    fit.fit()

    terminalRef.current = term
    fitAddonRef.current = fit

    return () => {
      term.dispose()
    }
  }, [header.width, header.height])

  const playFrom = useCallback(
    (startIdx: number) => {
      const term = terminalRef.current
      if (!term || startIdx >= frames.length) {
        setPlaying(false)
        return
      }

      const frame = frames[startIdx]
      if (!frame) {
        setPlaying(false)
        return
      }

      const [time, type, data] = frame
      const prevTime = startIdx > 0 ? (frames[startIdx - 1]?.[0] ?? 0) : 0
      const delay = ((time - prevTime) * 1000) / speed

      timerRef.current = setTimeout(() => {
        if (type === 'o') {
          term.write(data)
        }
        setFrameIdx(startIdx + 1)
        playFrom(startIdx + 1)
      }, delay)
    },
    [frames, speed]
  )

  useEffect(() => {
    if (playing) {
      playFrom(frameIdx)
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [playing, playFrom, frameIdx])

  function handlePlayPause() {
    if (playing) {
      setPlaying(false)
      if (timerRef.current) clearTimeout(timerRef.current)
    } else {
      if (frameIdx >= frames.length) {
        terminalRef.current?.reset()
        setFrameIdx(0)
      }
      setPlaying(true)
    }
  }

  function handleReset() {
    setPlaying(false)
    if (timerRef.current) clearTimeout(timerRef.current)
    terminalRef.current?.reset()
    setFrameIdx(0)
  }

  const progress = frames.length > 0 ? (frameIdx / frames.length) * 100 : 0

  return (
    <div className={styles.player}>
      <div ref={containerRef} className={styles.terminal} />

      <div className={styles.controls}>
        <button type="button" className={styles.btn} onClick={handlePlayPause}>
          {playing ? 'Pause' : 'Play'}
        </button>

        <button type="button" className={styles.btn} onClick={handleReset}>
          Reset
        </button>

        <div className={styles.speedGroup}>
          {PLAYBACK_SPEEDS.map((s) => (
            <button
              key={s}
              type="button"
              className={`${styles.speedBtn} ${s === speed ? styles.speedBtnActive : ''}`}
              onClick={() => setSpeed(s)}
            >
              {s}x
            </button>
          ))}
        </div>

        <div className={styles.progress}>
          <div className={styles.progressBar} style={{ width: `${progress}%` }} />
        </div>

        <span className={styles.counter}>
          {frameIdx}/{frames.length}
        </span>
      </div>
    </div>
  )
}
