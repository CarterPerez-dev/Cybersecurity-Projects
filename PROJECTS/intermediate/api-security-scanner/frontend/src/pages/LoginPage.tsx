// ===========================
// LoginPage.tsx
// ©AngelaMos | 2025
// ===========================

import { LoginForm } from '@/components/auth/LoginForm'
import './AuthPage.css'

export const LoginPage = (): React.ReactElement => {
  return (
    <div className="auth-page">
      <div className="auth-page__container">
        <LoginForm />
      </div>
    </div>
  )
}
