/**
 * ©AngelaMos | 2026
 * index.tsx
 */

import { useEffect, useState } from 'react'
import { LuEye, LuEyeOff } from 'react-icons/lu'
import { toast } from 'sonner'
import { useChangePassword, useLogoutAll } from '@/api/hooks/useAuth'
import { useUpdateProfile } from '@/api/hooks/useUsers'
import { passwordChangeRequestSchema, userUpdateRequestSchema } from '@/api/types'
import { useSettingsFormStore, useUser } from '@/core/lib'
import styles from './settings.module.scss'

export function Component(): React.ReactElement {
  const user = useUser()
  const updateProfile = useUpdateProfile()
  const changePassword = useChangePassword()
  const logoutAll = useLogoutAll()

  const { fullName, setFullName } = useSettingsFormStore()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  useEffect(() => {
    if (user?.full_name && !fullName) {
      setFullName(user.full_name)
    }
  }, [user?.full_name, fullName, setFullName])

  const handleProfileUpdate = (e: React.FormEvent): void => {
    e.preventDefault()

    const result = userUpdateRequestSchema.safeParse({
      full_name: fullName || null,
    })

    if (!result.success) {
      const firstError = result.error.issues[0]
      toast.error(firstError.message)
      return
    }

    updateProfile.mutate(result.data, {
      onSuccess: () => {
        toast.success('Profile updated successfully')
      },
    })
  }

  const handlePasswordChange = (e: React.FormEvent): void => {
    e.preventDefault()

    if (newPassword !== confirmPassword) {
      toast.error('Passwords do not match')
      return
    }

    const result = passwordChangeRequestSchema.safeParse({
      current_password: currentPassword,
      new_password: newPassword,
    })

    if (!result.success) {
      const firstError = result.error.issues[0]
      toast.error(firstError.message)
      return
    }

    changePassword.mutate(result.data, {
      onSuccess: () => {
        setCurrentPassword('')
        setNewPassword('')
        setConfirmPassword('')
        toast.success('Password changed successfully')
      },
    })
  }

  const handleLogoutAll = (): void => {
    if (
      !confirm(
        'This will log you out from all devices. Are you sure you want to continue?'
      )
    ) {
      return
    }

    logoutAll.mutate()
  }

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>Settings</h1>
          <p className={styles.subtitle}>
            Manage your account settings and preferences
          </p>
        </div>

        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>Profile</h2>
            <p className={styles.sectionSubtitle}>
              Update your personal information
            </p>
          </div>

          <form className={styles.form} onSubmit={handleProfileUpdate}>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="email">
                Email
              </label>
              <input
                id="email"
                type="email"
                className={styles.input}
                value={user?.email ?? ''}
                disabled
              />
              <p className={styles.hint}>Email cannot be changed</p>
            </div>

            <div className={styles.field}>
              <label className={styles.label} htmlFor="fullName">
                Full Name
              </label>
              <input
                id="fullName"
                type="text"
                className={styles.input}
                placeholder="Enter your full name"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                maxLength={255}
              />
            </div>

            <button
              type="submit"
              className={styles.button}
              disabled={updateProfile.isPending}
            >
              {updateProfile.isPending ? 'Saving...' : 'Save Changes'}
            </button>
          </form>
        </section>

        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>Change Password</h2>
            <p className={styles.sectionSubtitle}>
              Update your password to keep your account secure
            </p>
          </div>

          <form className={styles.form} onSubmit={handlePasswordChange}>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="currentPassword">
                Current Password
              </label>
              <div className={styles.inputWrapper}>
                <input
                  id="currentPassword"
                  type={showCurrentPassword ? 'text' : 'password'}
                  className={styles.input}
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className={styles.eyeButton}
                  onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                  aria-label={
                    showCurrentPassword ? 'Hide password' : 'Show password'
                  }
                >
                  {showCurrentPassword ? <LuEyeOff /> : <LuEye />}
                </button>
              </div>
            </div>

            <div className={styles.field}>
              <label className={styles.label} htmlFor="newPassword">
                New Password
              </label>
              <div className={styles.inputWrapper}>
                <input
                  id="newPassword"
                  type={showNewPassword ? 'text' : 'password'}
                  className={styles.input}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className={styles.eyeButton}
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  aria-label={showNewPassword ? 'Hide password' : 'Show password'}
                >
                  {showNewPassword ? <LuEyeOff /> : <LuEye />}
                </button>
              </div>
              <p className={styles.hint}>Minimum 8 characters</p>
            </div>

            <div className={styles.field}>
              <label className={styles.label} htmlFor="confirmPassword">
                Confirm New Password
              </label>
              <div className={styles.inputWrapper}>
                <input
                  id="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  className={styles.input}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className={styles.eyeButton}
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  aria-label={
                    showConfirmPassword ? 'Hide password' : 'Show password'
                  }
                >
                  {showConfirmPassword ? <LuEyeOff /> : <LuEye />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className={styles.button}
              disabled={changePassword.isPending}
            >
              {changePassword.isPending ? 'Changing...' : 'Change Password'}
            </button>
          </form>
        </section>

        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>Account Management</h2>
            <p className={styles.sectionSubtitle}>
              Manage your account security and sessions
            </p>
          </div>

          <div className={styles.dangerZone}>
            <div className={styles.dangerItem}>
              <div className={styles.dangerContent}>
                <h3 className={styles.dangerTitle}>Logout All Devices</h3>
                <p className={styles.dangerDescription}>
                  Sign out from all active sessions on all devices
                </p>
              </div>
              <button
                type="button"
                className={styles.dangerButton}
                onClick={handleLogoutAll}
                disabled={logoutAll.isPending}
              >
                {logoutAll.isPending ? 'Logging out...' : 'Logout All'}
              </button>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}

Component.displayName = 'Settings'
