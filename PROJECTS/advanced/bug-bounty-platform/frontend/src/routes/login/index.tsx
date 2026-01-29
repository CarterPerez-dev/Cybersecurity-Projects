/**
 * ©AngelaMos | 2025
 * index.tsx
 */

import { useState } from 'react'
import { LuArrowLeft, LuEye, LuEyeOff } from 'react-icons/lu'
import { Link, useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useLogin } from '@/api/hooks'
import { loginRequestSchema } from '@/api/types'
import { ROUTES } from '@/config'
import { useAuthFormStore } from '@/core/lib'
import styles from './login.module.scss'

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const login = useLogin()

  const { loginEmail, setLoginEmail, clearLoginForm } = useAuthFormStore()
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  const handleSubmit = (e: React.FormEvent): void => {
    e.preventDefault()

    const result = loginRequestSchema.safeParse({
      username: loginEmail,
      password,
    })

    if (!result.success) {
      const firstError = result.error.issues[0]
      toast.error(firstError.message)
      return
    }

    login.mutate(result.data, {
      onSuccess: () => {
        clearLoginForm()
        navigate(ROUTES.DASHBOARD)
      },
    })
  }

  return (
    <div className={styles.page}>
      <Link to={ROUTES.HOME} className={styles.homeLink}>
        <LuArrowLeft />
        Home
      </Link>
      <div className={styles.card}>
        <div className={styles.header}>
          <h1 className={styles.title}>Login</h1>
          <p className={styles.subtitle}>Welcome back</p>
        </div>

        <form className={styles.form} onSubmit={handleSubmit}>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="email">
              Email
            </label>
            <input
              id="email"
              type="email"
              className={styles.input}
              placeholder="xxx@example.com"
              value={loginEmail}
              onChange={(e) => setLoginEmail(e.target.value)}
              autoComplete="email"
            />
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="password">
              Password
            </label>
            <div className={styles.inputWrapper}>
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                className={styles.input}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
              <button
                type="button"
                className={styles.eyeButton}
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <LuEyeOff /> : <LuEye />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className={styles.submit}
            disabled={login.isPending}
          >
            {login.isPending ? 'Logging in...' : 'Login'}
          </button>
        </form>

        <p className={styles.footer}>
          Don&apos;t have an account?{' '}
          <Link to={ROUTES.REGISTER} className={styles.link}>
            Sign up
          </Link>
        </p>
      </div>
    </div>
  )
}

Component.displayName = 'Login'
