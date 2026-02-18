// ===========================
// RegisterPage.tsx
// ©AngelaMos | 2025
// ===========================

import { RegisterForm } from '@/components/auth/RegisterForm'
import './AuthPage.css'

export const RegisterPage = (): React.ReactElement => {
  return (
    <div className="auth-page">
      <div className="auth-page__container">
        <RegisterForm />
      </div>
    </div>
  )
}
