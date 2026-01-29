/**
 * AngelaMos | 2026
 * submit.tsx
 */

import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useProgram, useSubmitReport } from '@/api/hooks'
import { SEVERITY_LABELS, Severity } from '@/api/types'
import { ROUTES } from '@/config'
import styles from './submit.module.scss'

export function Component(): React.ReactElement {
  const { slug } = useParams<{ slug: string }>()
  const navigate = useNavigate()
  const { data: program, isLoading: programLoading } = useProgram(slug ?? '')
  const submitReport = useSubmitReport()

  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [stepsToReproduce, setStepsToReproduce] = useState('')
  const [impact, setImpact] = useState('')
  const [severity, setSeverity] = useState<Severity>(Severity.MEDIUM)

  const handleSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()

    if (!program) return

    try {
      await submitReport.mutateAsync({
        program_id: program.id,
        title,
        description,
        steps_to_reproduce: stepsToReproduce || undefined,
        impact: impact || undefined,
        severity_submitted: severity,
      })
      navigate(ROUTES.REPORTS.LIST)
    } catch {
      // Error handled by mutation
    }
  }

  if (programLoading) {
    return (
      <div className={styles.page}>
        <div className={styles.container}>
          <div className={styles.loading}>Loading...</div>
        </div>
      </div>
    )
  }

  if (!program) {
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
          <Link
            to={ROUTES.PROGRAMS.DETAIL(program.slug)}
            className={styles.backLink}
          >
            Back to {program.name}
          </Link>
          <h1 className={styles.title}>Submit Vulnerability Report</h1>
          <p className={styles.subtitle}>
            Report a security vulnerability to {program.name}
          </p>
        </div>

        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.field}>
            <label htmlFor="title" className={styles.label}>
              Title
            </label>
            <input
              id="title"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className={styles.input}
              placeholder="Brief, descriptive title"
              required
              maxLength={500}
            />
          </div>

          <div className={styles.field}>
            <label htmlFor="severity" className={styles.label}>
              Severity Assessment
            </label>
            <select
              id="severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity)}
              className={styles.select}
            >
              {Object.entries(SEVERITY_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <span className={styles.hint}>
              Your initial assessment. The program may adjust this after review.
            </span>
          </div>

          <div className={styles.field}>
            <label htmlFor="description" className={styles.label}>
              Description
            </label>
            <textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className={styles.textarea}
              placeholder="Detailed description of the vulnerability..."
              required
              rows={6}
            />
          </div>

          <div className={styles.field}>
            <label htmlFor="steps" className={styles.label}>
              Steps to Reproduce
            </label>
            <textarea
              id="steps"
              value={stepsToReproduce}
              onChange={(e) => setStepsToReproduce(e.target.value)}
              className={styles.textarea}
              placeholder="1. Go to...&#10;2. Click on...&#10;3. Observe that..."
              rows={6}
            />
            <span className={styles.hint}>
              Clear, numbered steps to reproduce the issue
            </span>
          </div>

          <div className={styles.field}>
            <label htmlFor="impact" className={styles.label}>
              Impact
            </label>
            <textarea
              id="impact"
              value={impact}
              onChange={(e) => setImpact(e.target.value)}
              className={styles.textarea}
              placeholder="What is the security impact? What can an attacker do?"
              rows={4}
            />
            <span className={styles.hint}>
              Explain the potential damage or risk this vulnerability poses
            </span>
          </div>

          <div className={styles.actions}>
            <Link
              to={ROUTES.PROGRAMS.DETAIL(program.slug)}
              className={styles.cancelButton}
            >
              Cancel
            </Link>
            <button
              type="submit"
              className={styles.submitButton}
              disabled={submitReport.isPending || !title || !description}
            >
              {submitReport.isPending ? 'Submitting...' : 'Submit Report'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

Component.displayName = 'SubmitReport'
