/**
 * AngelaMos | 2026
 * shell.tsx
 */

import { Suspense } from 'react'
import { ErrorBoundary } from 'react-error-boundary'
import {
  LuBuilding2,
  LuChartNetwork,
  LuChevronLeft,
  LuChevronRight,
  LuFileText,
  LuInbox,
  LuLayoutDashboard,
  LuLogOut,
  LuMenu,
  LuSettings,
  LuTarget,
  LuUsers,
} from 'react-icons/lu'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { useLogout } from '@/api/hooks'
import { ROUTES } from '@/config'
import { useIsAdmin, useUIStore, useUser } from '@/core/lib'
import styles from './shell.module.scss'

const NAV_ITEMS = [
  { path: ROUTES.DASHBOARD, label: 'Dashboard', icon: LuLayoutDashboard },
  { path: ROUTES.PROGRAMS.LIST, label: 'Programs', icon: LuTarget },
  { path: ROUTES.REPORTS.LIST, label: 'My Reports', icon: LuFileText },
  { path: ROUTES.SETTINGS, label: 'Settings', icon: LuSettings },
]

const COMPANY_NAV_ITEMS = [
  { path: ROUTES.COMPANY.PROGRAMS, label: 'My Programs', icon: LuBuilding2 },
  { path: ROUTES.COMPANY.INBOX, label: 'Inbox', icon: LuInbox },
]

const ADMIN_NAV_ITEMS = [
  { path: ROUTES.ADMIN.DASHBOARD, label: 'Statistics', icon: LuChartNetwork },
  { path: ROUTES.ADMIN.USERS, label: 'Users', icon: LuUsers },
  { path: ROUTES.ADMIN.PROGRAMS, label: 'Programs', icon: LuTarget },
  { path: ROUTES.ADMIN.REPORTS, label: 'Reports', icon: LuFileText },
]

function ShellErrorFallback({ error }: { error: Error }): React.ReactElement {
  return (
    <div className={styles.error}>
      <h2>Something went wrong</h2>
      <pre>{error.message}</pre>
    </div>
  )
}

function ShellLoading(): React.ReactElement {
  return <div className={styles.loading}>Loading...</div>
}

function getPageTitle(pathname: string, isAdmin: boolean): string {
  if (isAdmin) {
    const adminItem = ADMIN_NAV_ITEMS.find((i) => i.path === pathname)
    if (adminItem) {
      return `Admin: ${adminItem.label}`
    }
  }
  if (pathname.startsWith('/programs/') && pathname.includes('/submit')) {
    return 'Submit Report'
  }
  if (pathname.startsWith('/programs/')) {
    return 'Program'
  }
  if (pathname.startsWith('/reports/')) {
    return 'Report'
  }
  if (pathname === ROUTES.COMPANY.NEW_PROGRAM) {
    return 'New Program'
  }
  if (pathname.startsWith('/company/programs/') && pathname.endsWith('/edit')) {
    return 'Edit Program'
  }
  if (pathname.startsWith('/company/reports/')) {
    return 'Triage Report'
  }
  const companyItem = COMPANY_NAV_ITEMS.find((i) => i.path === pathname)
  if (companyItem) {
    return companyItem.label
  }
  const item = NAV_ITEMS.find((i) => i.path === pathname)
  return item?.label ?? 'Dashboard'
}

export function Shell(): React.ReactElement {
  const location = useLocation()
  const { sidebarOpen, sidebarCollapsed, toggleSidebar, toggleSidebarCollapsed } =
    useUIStore()
  const { mutate: logout } = useLogout()
  const isAdmin = useIsAdmin()
  const user = useUser()

  const pageTitle = getPageTitle(location.pathname, isAdmin)
  const avatarLetter =
    user?.full_name?.[0]?.toUpperCase() ?? user?.email?.[0]?.toUpperCase() ?? 'U'

  return (
    <div className={styles.shell}>
      <aside
        className={`${styles.sidebar} ${sidebarOpen ? styles.open : ''} ${sidebarCollapsed ? styles.collapsed : ''}`}
      >
        <div className={styles.sidebarHeader}>
          <span className={styles.logo}>BugBounty</span>
          <button
            type="button"
            className={styles.collapseBtn}
            onClick={toggleSidebarCollapsed}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? <LuChevronRight /> : <LuChevronLeft />}
          </button>
        </div>

        <nav className={styles.nav}>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `${styles.navItem} ${isActive ? styles.active : ''}`
              }
              onClick={() => sidebarOpen && toggleSidebar()}
            >
              <item.icon className={styles.navIcon} />
              <span className={styles.navLabel}>{item.label}</span>
            </NavLink>
          ))}
          <div className={styles.navDivider} />
          <span className={styles.navSection}>Company</span>
          {COMPANY_NAV_ITEMS.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `${styles.navItem} ${isActive ? styles.active : ''}`
              }
              onClick={() => sidebarOpen && toggleSidebar()}
            >
              <item.icon className={styles.navIcon} />
              <span className={styles.navLabel}>{item.label}</span>
            </NavLink>
          ))}
          {isAdmin && (
            <>
              <div className={styles.navDivider} />
              <span className={styles.navSection}>Admin</span>
              {ADMIN_NAV_ITEMS.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) =>
                    `${styles.navItem} ${isActive ? styles.active : ''}`
                  }
                  onClick={() => sidebarOpen && toggleSidebar()}
                >
                  <item.icon className={styles.navIcon} />
                  <span className={styles.navLabel}>{item.label}</span>
                </NavLink>
              ))}
            </>
          )}
        </nav>

        <div className={styles.sidebarFooter}>
          <button
            type="button"
            className={styles.logoutBtn}
            onClick={() => logout()}
          >
            <LuLogOut className={styles.logoutIcon} />
            <span className={styles.logoutText}>Logout</span>
          </button>
        </div>
      </aside>

      {sidebarOpen && (
        <button
          type="button"
          className={styles.overlay}
          onClick={toggleSidebar}
          onKeyDown={(e) => e.key === 'Escape' && toggleSidebar()}
          aria-label="Close sidebar"
        />
      )}

      <div
        className={`${styles.main} ${sidebarCollapsed ? styles.collapsed : ''}`}
      >
        <header className={styles.header}>
          <div className={styles.headerLeft}>
            <button
              type="button"
              className={styles.menuBtn}
              onClick={toggleSidebar}
              aria-label="Toggle menu"
            >
              <LuMenu />
            </button>
            <h1 className={styles.pageTitle}>{pageTitle}</h1>
          </div>

          <div className={styles.headerRight}>
            <Link to={ROUTES.SETTINGS} className={styles.avatar}>
              {avatarLetter}
            </Link>
          </div>
        </header>

        <main className={styles.content}>
          <ErrorBoundary FallbackComponent={ShellErrorFallback}>
            <Suspense fallback={<ShellLoading />}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
