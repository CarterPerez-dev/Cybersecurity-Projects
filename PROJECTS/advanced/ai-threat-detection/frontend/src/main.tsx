// ===========================
// ©AngelaMos | 2026
// main.tsx
//
// React application entry point
//
// Mounts the App component inside React.StrictMode onto the
// #root DOM element via createRoot. Imports the global SCSS
// stylesheet for Tailwind-free custom theming
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
