// ©AngelaMos | 2026
// router.tsx

import { createBrowserRouter } from 'react-router-dom'
import { AttackersPage } from '@/pages/attackers'
import { AttackerDetailPage } from '@/pages/attackers/detail'
import { DashboardPage } from '@/pages/dashboard'
import { EventsPage } from '@/pages/events'
import { IntelPage } from '@/pages/intel'
import { MitrePage } from '@/pages/mitre'
import { SessionsPage } from '@/pages/sessions'
import { SessionDetailPage } from '@/pages/sessions/detail'
import { Shell } from './shell'

export const router = createBrowserRouter([
  {
    element: <Shell />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'events', element: <EventsPage /> },
      { path: 'sessions', element: <SessionsPage /> },
      { path: 'sessions/:id', element: <SessionDetailPage /> },
      { path: 'attackers', element: <AttackersPage /> },
      { path: 'attackers/:id', element: <AttackerDetailPage /> },
      { path: 'mitre', element: <MitrePage /> },
      { path: 'intel', element: <IntelPage /> },
    ],
  },
])
