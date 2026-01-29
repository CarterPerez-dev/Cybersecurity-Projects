/**
 * AngelaMos | 2026
 * index.tsx
 */

import { LuBug, LuShield, LuTarget, LuTrophy } from 'react-icons/lu'
import { Link } from 'react-router-dom'
import { ROUTES } from '@/config'
import styles from './landing.module.scss'

export function Component(): React.ReactElement {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <h1 className={styles.title}>Bug Bounty Platform</h1>
        <p className={styles.subtitle}>Find vulnerabilities. Get rewarded.</p>
      </header>

      <div className={styles.content}>
        <p className={styles.description}>
          A platform connecting security researchers with organizations. Report
          vulnerabilities responsibly and earn bounties for your discoveries.
        </p>

        <div className={styles.sections}>
          <section className={styles.section}>
            <div className={styles.sectionIcon}>
              <LuTarget />
            </div>
            <h2 className={styles.sectionTitle}>Browse Programs</h2>
            <p className={styles.sectionText}>
              Explore active bug bounty programs from various organizations. Each
              program defines its scope, rules, and reward tiers.
            </p>
          </section>

          <section className={styles.section}>
            <div className={styles.sectionIcon}>
              <LuBug />
            </div>
            <h2 className={styles.sectionTitle}>Submit Reports</h2>
            <p className={styles.sectionText}>
              Found a vulnerability? Submit detailed reports with steps to
              reproduce, impact assessment, and severity rating.
            </p>
          </section>

          <section className={styles.section}>
            <div className={styles.sectionIcon}>
              <LuShield />
            </div>
            <h2 className={styles.sectionTitle}>Responsible Disclosure</h2>
            <p className={styles.sectionText}>
              Work directly with security teams through our secure platform. All
              communications are tracked and encrypted.
            </p>
          </section>

          <section className={styles.section}>
            <div className={styles.sectionIcon}>
              <LuTrophy />
            </div>
            <h2 className={styles.sectionTitle}>Earn Rewards</h2>
            <p className={styles.sectionText}>
              Get paid for valid security findings. Build your reputation and
              climb the leaderboard as you discover more bugs.
            </p>
          </section>
        </div>

        <div className={styles.actions}>
          <Link to={ROUTES.PROGRAMS.LIST} className={styles.button}>
            Browse Programs
          </Link>
          <Link to={ROUTES.REGISTER} className={styles.buttonOutline}>
            Create Account
          </Link>
        </div>
      </div>
    </div>
  )
}

Component.displayName = 'Landing'
