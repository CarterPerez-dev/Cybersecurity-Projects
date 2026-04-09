// ===========================
// ©AngelaMos | 2026
// main.tsx
//
// Application entry point that mounts the React root
// into the #root DOM element with StrictMode enabled
// and imports the global SCSS stylesheet
//
// Connects to:
//   App.tsx      - root component
//   styles.scss  - global styles
// ===========================

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles.scss'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>
)
