/**
 * AngelaMos | 2026
 * new.tsx
 */

import { Link, useNavigate } from 'react-router-dom'
import { useCreateProgram } from '@/api/hooks'
import { ProgramVisibility } from '@/api/types'
import { ROUTES } from '@/config'
import { useProgramFormStore } from '@/core/lib'
import styles from './new.module.scss'

function generateSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 100)
}

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const createProgram = useCreateProgram()

  const {
    name,
    slug,
    description,
    rules,
    responseSlaHours,
    visibility,
    setName,
    setSlug,
    setDescription,
    setRules,
    setResponseSlaHours,
    setVisibility,
    clearForm,
  } = useProgramFormStore()

  const handleNameChange = (value: string): void => {
    setName(value)
    if (!slug || slug === generateSlug(name)) {
      setSlug(generateSlug(value))
    }
  }

  const handleSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()

    try {
      const program = await createProgram.mutateAsync({
        name,
        slug,
        description: description || undefined,
        rules: rules || undefined,
        response_sla_hours: responseSlaHours,
        visibility,
      })
      clearForm()
      navigate(ROUTES.COMPANY.EDIT_PROGRAM(program.slug))
    } catch {}
  }

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <Link to={ROUTES.COMPANY.PROGRAMS} className={styles.backLink}>
            Back to My Programs
          </Link>
          <h1 className={styles.title}>Create New Program</h1>
          <p className={styles.subtitle}>
            Set up your bug bounty program. You can add assets and rewards after
            creating.
          </p>
        </div>

        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.field}>
            <label htmlFor="name" className={styles.label}>
              Program Name
            </label>
            <input
              id="name"
              type="text"
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              className={styles.input}
              placeholder="My Company Security"
              required
              maxLength={255}
              autoComplete="off"
            />
          </div>

          <div className={styles.field}>
            <label htmlFor="slug" className={styles.label}>
              URL Slug
            </label>
            <div className={styles.slugWrapper}>
              <span className={styles.slugPrefix}>/programs/</span>
              <input
                id="slug"
                type="text"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                className={styles.slugInput}
                placeholder="my-company"
                required
                maxLength={100}
                pattern="^[a-z0-9-]+$"
              />
            </div>
            <span className={styles.hint}>
              Only lowercase letters, numbers, and hyphens
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
              placeholder="Brief description of your program..."
              rows={4}
              maxLength={10000}
            />
          </div>

          <div className={styles.field}>
            <label htmlFor="rules" className={styles.label}>
              Program Rules
            </label>
            <textarea
              id="rules"
              value={rules}
              onChange={(e) => setRules(e.target.value)}
              className={styles.textarea}
              placeholder="Disclosure policy, testing guidelines, out of bounds activities..."
              rows={6}
              maxLength={50000}
            />
            <span className={styles.hint}>
              Define what researchers can and cannot do
            </span>
          </div>

          <div className={styles.row}>
            <div className={styles.field}>
              <label htmlFor="sla" className={styles.label}>
                Response SLA (hours)
              </label>
              <input
                id="sla"
                type="text"
                inputMode="numeric"
                value={responseSlaHours}
                onChange={(e) => {
                  const val = e.target.value.replace(/[^0-9]/g, '')
                  if (val) {
                    const num = Number(val)
                    if (num >= 1 && num <= 720) {
                      setResponseSlaHours(num)
                    }
                  }
                }}
                className={styles.input}
                placeholder="72"
              />
              <span className={styles.hint}>Expected time to first response</span>
            </div>

            <div className={styles.field}>
              <label htmlFor="visibility" className={styles.label}>
                Visibility
              </label>
              <select
                id="visibility"
                value={visibility}
                onChange={(e) =>
                  setVisibility(e.target.value as ProgramVisibility)
                }
                className={styles.select}
              >
                <option value={ProgramVisibility.PUBLIC}>
                  Public - Anyone can see and submit
                </option>
                <option value={ProgramVisibility.PRIVATE}>
                  Private - Hidden from listing
                </option>
                <option value={ProgramVisibility.INVITE_ONLY}>
                  Invite Only - Requires invitation
                </option>
              </select>
            </div>
          </div>

          <div className={styles.actions}>
            <Link to={ROUTES.COMPANY.PROGRAMS} className={styles.cancelBtn}>
              Cancel
            </Link>
            <button
              type="submit"
              className={styles.submitBtn}
              disabled={createProgram.isPending || !name || !slug}
            >
              {createProgram.isPending ? 'Creating...' : 'Create Program'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

Component.displayName = 'NewProgram'
