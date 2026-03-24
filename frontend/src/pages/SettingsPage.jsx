import { useState, useEffect } from 'react'
import './SettingsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function authHeaders(token) {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
}

function formatDate(dateStr) {
  if (!dateStr) return 'Never'
  return new Date(dateStr).toLocaleString()
}

// ─── Profile Section ─────────────────────────────────────────────────
function ProfileSection({ user, loading }) {
  if (loading) return <div className="settings-card"><p className="settings-muted">Loading profile...</p></div>
  if (!user) return <div className="settings-card"><p className="settings-muted">Unable to load profile.</p></div>

  return (
    <div className="settings-card">
      <h2 className="settings-card-title">Profile</h2>
      <div className="settings-field-grid">
        <div className="settings-field">
          <label>Email</label>
          <span>{user.email}</span>
        </div>
        <div className="settings-field">
          <label>Plan</label>
          <span className="settings-badge">{user.plan}</span>
        </div>
        <div className="settings-field">
          <label>Account Created</label>
          <span>{formatDate(user.created_at)}</span>
        </div>
        <div className="settings-field">
          <label>Last Login</label>
          <span>{formatDate(user.last_login)}</span>
        </div>
        <div className="settings-field">
          <label>2FA Status</label>
          <span className={user.totp_enabled ? 'settings-badge-green' : 'settings-badge-dim'}>
            {user.totp_enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        <div className="settings-field">
          <label>Account Status</label>
          <span className={user.is_active ? 'settings-badge-green' : 'settings-badge-red'}>
            {user.is_active ? 'Active' : 'Inactive'}
          </span>
        </div>
      </div>
    </div>
  )
}

// ─── Change Password Section ─────────────────────────────────────────
function PasswordSection({ token }) {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [message, setMessage] = useState({ type: '', text: '' })
  const [submitting, setSubmitting] = useState(false)

  function validate() {
    if (!currentPassword) return 'Current password is required.'
    if (newPassword.length < 8) return 'New password must be at least 8 characters.'
    if (newPassword !== confirmPassword) return 'Passwords do not match.'
    if (currentPassword === newPassword) return 'New password must be different from current password.'
    return null
  }

  async function handleSubmit(e) {
    e.preventDefault()
    const err = validate()
    if (err) {
      setMessage({ type: 'error', text: err })
      return
    }

    setSubmitting(true)
    setMessage({ type: '', text: '' })
    try {
      const resp = await fetch(`${API_BASE}/api/auth/change-password`, {
        method: 'POST',
        headers: authHeaders(token),
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      })
      const data = await resp.json()
      if (!resp.ok) throw new Error(data.detail || 'Failed to change password')
      setMessage({ type: 'success', text: 'Password changed successfully.' })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (fetchErr) {
      setMessage({ type: 'error', text: fetchErr.message })
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="settings-card">
      <h2 className="settings-card-title">Change Password</h2>
      <form onSubmit={handleSubmit} className="settings-form">
        <div className="settings-form-field">
          <label>Current Password</label>
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="Enter current password"
            autoComplete="current-password"
          />
        </div>
        <div className="settings-form-field">
          <label>New Password</label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="Min 8 characters"
            autoComplete="new-password"
          />
        </div>
        <div className="settings-form-field">
          <label>Confirm New Password</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Repeat new password"
            autoComplete="new-password"
          />
        </div>
        {message.text && (
          <div className={`settings-message settings-message-${message.type}`}>{message.text}</div>
        )}
        <button type="submit" className="settings-btn" disabled={submitting}>
          {submitting ? 'Changing...' : 'Change Password'}
        </button>
      </form>
    </div>
  )
}

// ─── Notification Channels Section ───────────────────────────────────
function NotificationsSection({ token }) {
  const [channels, setChannels] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [confirmingDelete, setConfirmingDelete] = useState(null)

  useEffect(() => {
    async function load() {
      try {
        const resp = await fetch(`${API_BASE}/api/notifications`, {
          headers: authHeaders(token),
        })
        if (!resp.ok) throw new Error('Failed to fetch channels')
        setChannels(await resp.json())
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [token])

  async function toggleChannel(id, currentActive) {
    try {
      const resp = await fetch(`${API_BASE}/api/notifications/${id}`, {
        method: 'PATCH',
        headers: authHeaders(token),
        body: JSON.stringify({ is_active: !currentActive }),
      })
      if (!resp.ok) throw new Error('Failed to update channel')
      setChannels(prev => prev.map(ch => ch.id === id ? { ...ch, is_active: !currentActive } : ch))
    } catch (err) {
      setError(err.message)
    }
  }

  async function deleteChannel(id) {
    if (confirmingDelete !== id) {
      setConfirmingDelete(id)
      return
    }
    setConfirmingDelete(null)
    try {
      const resp = await fetch(`${API_BASE}/api/notifications/${id}`, {
        method: 'DELETE',
        headers: authHeaders(token),
      })
      if (!resp.ok) throw new Error('Failed to delete channel')
      setChannels(prev => prev.filter(ch => ch.id !== id))
    } catch (err) {
      setError(err.message)
    }
  }

  const typeLabels = {
    email: 'Email',
    slack: 'Slack',
    discord: 'Discord',
    webhook: 'Webhook',
    jira: 'Jira',
    linear: 'Linear',
    github_issues: 'GitHub Issues',
  }

  return (
    <div className="settings-card">
      <div className="settings-card-header">
        <h2 className="settings-card-title">Notification Channels</h2>
      </div>
      {error && <div className="settings-message settings-message-error">{error}</div>}
      {loading ? (
        <p className="settings-muted">Loading channels...</p>
      ) : channels.length === 0 ? (
        <p className="settings-muted">No notification channels configured.</p>
      ) : (
        <div className="settings-table-wrap">
          <table className="settings-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Min Severity</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {channels.map(ch => (
                <tr key={ch.id}>
                  <td>{ch.name}</td>
                  <td>{typeLabels[ch.channel_type] || ch.channel_type}</td>
                  <td className="settings-muted">{ch.min_severity}</td>
                  <td>
                    <span className={ch.is_active ? 'settings-badge-green' : 'settings-badge-dim'}>
                      {ch.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="settings-actions">
                    <button
                      className="settings-btn-sm"
                      onClick={() => toggleChannel(ch.id, ch.is_active)}
                    >
                      {ch.is_active ? 'Disable' : 'Enable'}
                    </button>
                    {confirmingDelete === ch.id ? (
                      <>
                        <button
                          className="settings-btn-sm settings-btn-danger"
                          onClick={() => deleteChannel(ch.id)}
                        >
                          Confirm
                        </button>
                        <button
                          className="settings-btn-sm"
                          onClick={() => setConfirmingDelete(null)}
                        >
                          Cancel
                        </button>
                      </>
                    ) : (
                      <button
                        className="settings-btn-sm settings-btn-danger"
                        onClick={() => deleteChannel(ch.id)}
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── API Keys / Webhooks Section ─────────────────────────────────────
function ApiKeysSection({ token }) {
  const [webhooks, setWebhooks] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [newKeyName, setNewKeyName] = useState('')
  const [createdKey, setCreatedKey] = useState(null)
  const [creating, setCreating] = useState(false)
  const [copied, setCopied] = useState(false)
  const [confirmingRevoke, setConfirmingRevoke] = useState(null)

  useEffect(() => {
    async function load() {
      try {
        const resp = await fetch(`${API_BASE}/api/webhooks`, {
          headers: authHeaders(token),
        })
        if (!resp.ok) throw new Error('Failed to fetch API keys')
        setWebhooks(await resp.json())
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [token])

  async function refreshWebhooks() {
    try {
      const resp = await fetch(`${API_BASE}/api/webhooks`, {
        headers: authHeaders(token),
      })
      if (resp.ok) setWebhooks(await resp.json())
    } catch {
      // silent refresh
    }
  }

  async function createKey(e) {
    e.preventDefault()
    if (!newKeyName.trim()) return
    setCreating(true)
    setError('')
    setCreatedKey(null)
    try {
      const resp = await fetch(`${API_BASE}/api/webhooks`, {
        method: 'POST',
        headers: authHeaders(token),
        body: JSON.stringify({ name: newKeyName.trim() }),
      })
      const data = await resp.json()
      if (!resp.ok) throw new Error(data.detail || 'Failed to create key')
      setCreatedKey(data.api_key)
      setNewKeyName('')
      refreshWebhooks()
    } catch (err) {
      setError(err.message)
    } finally {
      setCreating(false)
    }
  }

  async function revokeKey(id) {
    if (confirmingRevoke !== id) {
      setConfirmingRevoke(id)
      return
    }
    setConfirmingRevoke(null)
    try {
      const resp = await fetch(`${API_BASE}/api/webhooks/${id}`, {
        method: 'DELETE',
        headers: authHeaders(token),
      })
      if (!resp.ok) throw new Error('Failed to revoke key')
      setWebhooks(prev => prev.filter(w => w.id !== id))
    } catch (err) {
      setError(err.message)
    }
  }

  function copyKey() {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className="settings-card">
      <h2 className="settings-card-title">API Keys</h2>
      <p className="settings-muted" style={{ marginBottom: '16px' }}>
        API keys are used for CI/CD webhook integrations. Keys are shown only once at creation.
      </p>

      {createdKey && (
        <div className="settings-created-key">
          <p className="settings-created-key-label">New API key created. Copy it now -- it will not be shown again.</p>
          <div className="settings-key-display">
            <code>{createdKey}</code>
            <button className="settings-btn-sm" onClick={copyKey}>
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      <form onSubmit={createKey} className="settings-inline-form">
        <input
          type="text"
          value={newKeyName}
          onChange={(e) => setNewKeyName(e.target.value)}
          placeholder="Key name (e.g. CI pipeline)"
          className="settings-inline-input"
        />
        <button type="submit" className="settings-btn" disabled={creating || !newKeyName.trim()}>
          {creating ? 'Creating...' : 'Generate New Key'}
        </button>
      </form>

      {error && <div className="settings-message settings-message-error" style={{ marginTop: '12px' }}>{error}</div>}

      {loading ? (
        <p className="settings-muted" style={{ marginTop: '16px' }}>Loading keys...</p>
      ) : webhooks.length === 0 ? (
        <p className="settings-muted" style={{ marginTop: '16px' }}>No API keys configured.</p>
      ) : (
        <div className="settings-table-wrap" style={{ marginTop: '16px' }}>
          <table className="settings-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Key Prefix</th>
                <th>Scan Type</th>
                <th>Status</th>
                <th>Created</th>
                <th>Last Used</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map(wh => (
                <tr key={wh.id}>
                  <td>{wh.name}</td>
                  <td><code className="settings-code">{wh.key_prefix}...</code></td>
                  <td className="settings-muted">{wh.scan_type}</td>
                  <td>
                    <span className={wh.is_active ? 'settings-badge-green' : 'settings-badge-dim'}>
                      {wh.is_active ? 'Active' : 'Revoked'}
                    </span>
                  </td>
                  <td className="settings-muted">{formatDate(wh.created_at)}</td>
                  <td className="settings-muted">{formatDate(wh.last_used_at)}</td>
                  <td>
                    {confirmingRevoke === wh.id ? (
                      <>
                        <button
                          className="settings-btn-sm settings-btn-danger"
                          onClick={() => revokeKey(wh.id)}
                        >
                          Confirm
                        </button>
                        <button
                          className="settings-btn-sm"
                          onClick={() => setConfirmingRevoke(null)}
                        >
                          Cancel
                        </button>
                      </>
                    ) : (
                      <button
                        className="settings-btn-sm settings-btn-danger"
                        onClick={() => revokeKey(wh.id)}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Scan Defaults Section ───────────────────────────────────────────
function ScanDefaultsSection() {
  const [scanType, setScanType] = useState(() => localStorage.getItem('default_scan_type') || 'security')
  const [saved, setSaved] = useState(false)

  const scanTypes = [
    { value: 'security', label: 'Security (Full)' },
    { value: 'quick', label: 'Quick Scan' },
    { value: 'deep', label: 'Deep Scan' },
    { value: 'api', label: 'API Scan' },
    { value: 'web', label: 'Web Application' },
    { value: 'infrastructure', label: 'Infrastructure' },
  ]

  function handleSave() {
    localStorage.setItem('default_scan_type', scanType)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="settings-card">
      <h2 className="settings-card-title">Scan Defaults</h2>
      <p className="settings-muted" style={{ marginBottom: '16px' }}>
        Default settings applied when creating new scans.
      </p>
      <div className="settings-form-field">
        <label>Default Scan Type</label>
        <select value={scanType} onChange={(e) => setScanType(e.target.value)} className="settings-select">
          {scanTypes.map(t => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
      </div>
      <div style={{ marginTop: '16px' }}>
        <button className="settings-btn" onClick={handleSave}>
          {saved ? 'Saved' : 'Save Defaults'}
        </button>
      </div>
    </div>
  )
}

// ─── Main Settings Page ──────────────────────────────────────────────
function SettingsPage({ token }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('profile')

  useEffect(() => {
    async function fetchUser() {
      try {
        const resp = await fetch(`${API_BASE}/api/auth/me`, {
          headers: authHeaders(token),
        })
        if (resp.ok) {
          setUser(await resp.json())
        }
      } catch (err) {
        console.error('Failed to fetch user:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchUser()
  }, [token])

  const tabs = [
    { id: 'profile', label: 'Profile' },
    { id: 'security', label: 'Security' },
    { id: 'notifications', label: 'Notifications' },
    { id: 'apikeys', label: 'API Keys' },
    { id: 'defaults', label: 'Scan Defaults' },
  ]

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Settings</h1>
        <p>Manage your account, security, and preferences</p>
      </div>

      <div className="settings-tabs">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`settings-tab ${activeTab === tab.id ? 'settings-tab-active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="settings-content">
        {activeTab === 'profile' && <ProfileSection user={user} loading={loading} />}
        {activeTab === 'security' && <PasswordSection token={token} />}
        {activeTab === 'notifications' && <NotificationsSection token={token} />}
        {activeTab === 'apikeys' && <ApiKeysSection token={token} />}
        {activeTab === 'defaults' && <ScanDefaultsSection />}
      </div>
    </div>
  )
}

export default SettingsPage
