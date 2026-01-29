/**
 * ©AngelaMos | 2025
 * index.tsx
 */

import { useState } from 'react'
import { LuPencil, LuTrash2, LuX } from 'react-icons/lu'
import {
  useAdminCreateUser,
  useAdminDeleteUser,
  useAdminUpdateUser,
  useAdminUsers,
} from '@/api/hooks'
import type { UserResponse } from '@/api/types'
import { UserRole } from '@/api/types'
import { PAGINATION } from '@/config'
import styles from './admin.module.scss'

type ModalState =
  | { type: 'closed' }
  | { type: 'create' }
  | { type: 'edit'; user: UserResponse }
  | { type: 'delete'; user: UserResponse }

export function Component(): React.ReactElement {
  const [page, setPage] = useState<number>(PAGINATION.DEFAULT_PAGE)
  const [modal, setModal] = useState<ModalState>({ type: 'closed' })

  const { data, isLoading } = useAdminUsers({
    page,
    size: PAGINATION.DEFAULT_SIZE,
  })
  const createUser = useAdminCreateUser()
  const updateUser = useAdminUpdateUser()
  const deleteUser = useAdminDeleteUser()

  const handleCreate = (formData: FormData): void => {
    const email = formData.get('email') as string
    const password = formData.get('password') as string
    const fullName = (formData.get('fullName') as string) || undefined
    const role = formData.get('role') as UserRole
    const isActive = formData.get('isActive') === 'on'

    createUser.mutate(
      { email, password, full_name: fullName, role, is_active: isActive },
      { onSuccess: () => setModal({ type: 'closed' }) }
    )
  }

  const handleUpdate = (userId: string, formData: FormData): void => {
    const email = formData.get('email') as string
    const fullName = (formData.get('fullName') as string) || undefined
    const role = formData.get('role') as UserRole
    const isActive = formData.get('isActive') === 'on'

    updateUser.mutate(
      {
        id: userId,
        data: { email, full_name: fullName, role, is_active: isActive },
      },
      { onSuccess: () => setModal({ type: 'closed' }) }
    )
  }

  const handleDelete = (userId: string): void => {
    deleteUser.mutate(userId, { onSuccess: () => setModal({ type: 'closed' }) })
  }

  const totalPages = data ? Math.ceil(data.total / PAGINATION.DEFAULT_SIZE) : 0

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Users</h1>
        <button
          type="button"
          className={styles.createBtn}
          onClick={() => setModal({ type: 'create' })}
        >
          Create User
        </button>
      </div>

      <div className={styles.table}>
        <div className={styles.tableHeader}>
          <div className={styles.tableHeaderCell}>Email</div>
          <div className={styles.tableHeaderCell}>Name</div>
          <div className={styles.tableHeaderCell}>Role</div>
          <div className={styles.tableHeaderCell}>Status</div>
          <div className={styles.tableHeaderCell}>Actions</div>
        </div>

        <div className={styles.tableBody}>
          {isLoading && <div className={styles.loading}>Loading...</div>}

          {!isLoading && data?.items.length === 0 && (
            <div className={styles.empty}>No users found</div>
          )}

          {data?.items.map((user) => (
            <div key={user.id} className={styles.tableRow}>
              <div className={styles.tableCell} data-label="Email">
                <span className={styles.email}>{user.email}</span>
              </div>
              <div className={styles.tableCell} data-label="Name">
                {user.full_name ?? '—'}
              </div>
              <div className={styles.tableCell} data-label="Role">
                <span
                  className={`${styles.badge} ${user.role === UserRole.ADMIN ? styles.admin : styles.user}`}
                >
                  {user.role}
                </span>
              </div>
              <div className={styles.tableCell} data-label="Status">
                <span
                  className={`${styles.badge} ${user.is_active ? styles.active : styles.inactive}`}
                >
                  {user.is_active ? 'Active' : 'Inactive'}
                </span>
              </div>
              <div className={styles.actions}>
                <button
                  type="button"
                  className={styles.actionBtn}
                  onClick={() => setModal({ type: 'edit', user })}
                  aria-label="Edit user"
                >
                  <LuPencil />
                </button>
                <button
                  type="button"
                  className={`${styles.actionBtn} ${styles.delete}`}
                  onClick={() => setModal({ type: 'delete', user })}
                  aria-label="Delete user"
                >
                  <LuTrash2 />
                </button>
              </div>
            </div>
          ))}
        </div>

        {data && data.total > PAGINATION.DEFAULT_SIZE && (
          <div className={styles.pagination}>
            <span className={styles.paginationInfo}>
              Page {page} of {totalPages} ({data.total} users)
            </span>
            <div className={styles.paginationBtns}>
              <button
                type="button"
                className={styles.paginationBtn}
                onClick={() => setPage((p) => p - 1)}
                disabled={page <= 1}
              >
                Previous
              </button>
              <button
                type="button"
                className={styles.paginationBtn}
                onClick={() => setPage((p) => p + 1)}
                disabled={page >= totalPages}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {modal.type === 'create' && (
        <div className={styles.modal}>
          <button
            type="button"
            className={styles.modalOverlay}
            onClick={() => setModal({ type: 'closed' })}
            onKeyDown={(e) => e.key === 'Escape' && setModal({ type: 'closed' })}
            aria-label="Close modal"
          />
          <div className={styles.modalContent}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>Create User</h2>
              <button
                type="button"
                className={styles.modalClose}
                onClick={() => setModal({ type: 'closed' })}
              >
                <LuX />
              </button>
            </div>
            <form
              className={styles.form}
              onSubmit={(e) => {
                e.preventDefault()
                handleCreate(new FormData(e.currentTarget))
              }}
            >
              <div className={styles.field}>
                <label className={styles.label} htmlFor="email">
                  Email
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  className={styles.input}
                  required
                />
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="password">
                  Password
                </label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  className={styles.input}
                  required
                  minLength={8}
                />
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="fullName">
                  Full Name
                </label>
                <input
                  id="fullName"
                  name="fullName"
                  type="text"
                  className={styles.input}
                />
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="role">
                  Role
                </label>
                <select id="role" name="role" className={styles.select}>
                  <option value={UserRole.USER}>User</option>
                  <option value={UserRole.ADMIN}>Admin</option>
                </select>
              </div>
              <label className={styles.checkbox}>
                <input type="checkbox" name="isActive" defaultChecked />
                <span>Active</span>
              </label>
              <div className={styles.formActions}>
                <button
                  type="button"
                  className={styles.cancelBtn}
                  onClick={() => setModal({ type: 'closed' })}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className={styles.submitBtn}
                  disabled={createUser.isPending}
                >
                  {createUser.isPending ? 'Creating...' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {modal.type === 'edit' && (
        <div className={styles.modal}>
          <button
            type="button"
            className={styles.modalOverlay}
            onClick={() => setModal({ type: 'closed' })}
            onKeyDown={(e) => e.key === 'Escape' && setModal({ type: 'closed' })}
            aria-label="Close modal"
          />
          <div className={styles.modalContent}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>Edit User</h2>
              <button
                type="button"
                className={styles.modalClose}
                onClick={() => setModal({ type: 'closed' })}
              >
                <LuX />
              </button>
            </div>
            <form
              className={styles.form}
              onSubmit={(e) => {
                e.preventDefault()
                handleUpdate(modal.user.id, new FormData(e.currentTarget))
              }}
            >
              <div className={styles.field}>
                <label className={styles.label} htmlFor="editEmail">
                  Email
                </label>
                <input
                  id="editEmail"
                  name="email"
                  type="email"
                  className={styles.input}
                  defaultValue={modal.user.email}
                  required
                />
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="editFullName">
                  Full Name
                </label>
                <input
                  id="editFullName"
                  name="fullName"
                  type="text"
                  className={styles.input}
                  defaultValue={modal.user.full_name ?? ''}
                />
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor="editRole">
                  Role
                </label>
                <select
                  id="editRole"
                  name="role"
                  className={styles.select}
                  defaultValue={modal.user.role}
                >
                  <option value={UserRole.USER}>User</option>
                  <option value={UserRole.ADMIN}>Admin</option>
                </select>
              </div>
              <label className={styles.checkbox}>
                <input
                  type="checkbox"
                  name="isActive"
                  defaultChecked={modal.user.is_active}
                />
                <span>Active</span>
              </label>
              <div className={styles.formActions}>
                <button
                  type="button"
                  className={styles.cancelBtn}
                  onClick={() => setModal({ type: 'closed' })}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className={styles.submitBtn}
                  disabled={updateUser.isPending}
                >
                  {updateUser.isPending ? 'Saving...' : 'Save'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {modal.type === 'delete' && (
        <div className={styles.modal}>
          <button
            type="button"
            className={styles.modalOverlay}
            onClick={() => setModal({ type: 'closed' })}
            onKeyDown={(e) => e.key === 'Escape' && setModal({ type: 'closed' })}
            aria-label="Close modal"
          />
          <div className={styles.modalContent}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>Delete User</h2>
              <button
                type="button"
                className={styles.modalClose}
                onClick={() => setModal({ type: 'closed' })}
              >
                <LuX />
              </button>
            </div>
            <div className={styles.deleteConfirm}>
              <p className={styles.deleteText}>
                Are you sure you want to delete{' '}
                <span className={styles.deleteEmail}>{modal.user.email}</span>?
                This action cannot be undone.
              </p>
              <div className={styles.formActions}>
                <button
                  type="button"
                  className={styles.cancelBtn}
                  onClick={() => setModal({ type: 'closed' })}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className={styles.deleteBtn}
                  onClick={() => handleDelete(modal.user.id)}
                  disabled={deleteUser.isPending}
                >
                  {deleteUser.isPending ? 'Deleting...' : 'Delete'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

Component.displayName = 'AdminUsers'
