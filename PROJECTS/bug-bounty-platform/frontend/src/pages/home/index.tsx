/**
 * ©AngelaMos | 2025
 * index.tsx
 */

import styles from './home.module.scss'

export function Component(): React.ReactElement {
  return (
    <div className={styles.home}>
      <h1>Home</h1>
      <p>Welcome to the template.</p>
    </div>
  )
}

Component.displayName = 'Home'
