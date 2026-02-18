// ===========================
// DashboardPage.tsx
// ©AngelaMos | 2025
// ===========================

import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/common/Button'
import { NewScanForm } from '@/components/scan/NewScanForm'
import { ScansList } from '@/components/scan/ScansList'
import { useAuthStore } from '@/store/authStore'
import './DashboardPage.css'

export const DashboardPage = (): React.ReactElement => {
  const navigate = useNavigate()
  const clearAuth = useAuthStore((state) => state.clearAuth)
  const user = useAuthStore((state) => state.user)

  const handleLogout = (): void => {
    clearAuth()
    void navigate('/login')
  }

  return (
    <div className="dashboard">
      <div className="dashboard__container">
        <header className="dashboard__header">
          <div className="dashboard__header-content">
            <div className="dashboard__header-text">
              <h1 className="dashboard__title">API Security Scanner</h1>
              <p className="dashboard__subtitle">
                Test your APIs for security vulnerabilities
              </p>
            </div>
            <div className="dashboard__header-actions">
              <span className="dashboard__user-email">{user?.email}</span>
              <Button onClick={handleLogout} variant="secondary">
                Logout
              </Button>
            </div>
          </div>
        </header>

        <div className="dashboard__content">
          <section className="dashboard__section">
            <h2 className="dashboard__section-title">New Scan</h2>
            <NewScanForm />
          </section>

          <section className="dashboard__section">
            <h2 className="dashboard__section-title">Recent Scans</h2>
            <ScansList />
          </section>
        </div>
      </div>
    </div>
  )
}
