import { useState, useEffect } from 'react'

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
  if (loading) return <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6"><p className="text-sm text-gray-500">Loading profile...</p></div>
  if (!user) return <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6"><p className="text-sm text-gray-500">Unable to load profile.</p></div>

  return (
    <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-4">Profile</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">Email</label>
          <span className="block text-sm text-white">{user.email}</span>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">Plan</label>
          <span className="inline-block px-2 py-0.5 bg-cyan-500/20 text-cyan-400 rounded text-xs font-medium">{user.plan}</span>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">Account Created</label>
          <span className="block text-sm text-white">{formatDate(user.created_at)}</span>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">Last Login</label>
          <span className="block text-sm text-white">{formatDate(user.last_login)}</span>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">2FA Status</label>
          <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${user.totp_enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-700 text-gray-400'}`}>
            {user.totp_enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">Account Status</label>
          <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${user.is_active ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
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
    <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-4">Change Password</h2>
      <form onSubmit={handleSubmit} className="space-y-4 max-w-md">
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">Current Password</label>
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="Enter current password"
            autoComplete="current-password"
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">New Password</label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="Min 8 characters"
            autoComplete="new-password"
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-gray-500 uppercase tracking-wider">Confirm New Password</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Repeat new password"
            autoComplete="new-password"
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        {message.text && (
          <div className={`px-3 py-2 rounded-lg text-sm ${message.type === 'error' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{message.text}</div>
        )}
        <button type="submit" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-medium rounded-lg transition disabled:opacity-50" disabled={submitting}>
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
        const resp = await fetch(`${API_BASE}/api/notifications/?limit=500`, {
          headers: authHeaders(token),
        })
        if (!resp.ok) throw new Error('Failed to fetch channels')
        const data = await resp.json()
        setChannels(Array.isArray(data) ? data : (data.items || []))
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
    <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-4">Notification Channels</h2>
      {error && <div className="px-3 py-2 rounded-lg text-sm bg-red-500/20 text-red-400 mb-4">{error}</div>}
      {loading ? (
        <p className="text-sm text-gray-500">Loading channels...</p>
      ) : channels.length === 0 ? (
        <p className="text-sm text-gray-500">No notification channels configured.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Name</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Type</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Min Severity</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Status</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {channels.map(ch => (
                <tr key={ch.id} className="border-b border-gray-700/50 hover:bg-gray-800/40">
                  <td className="py-2 px-3 text-white">{ch.name}</td>
                  <td className="py-2 px-3 text-white">{typeLabels[ch.channel_type] || ch.channel_type}</td>
                  <td className="py-2 px-3 text-gray-400">{ch.min_severity}</td>
                  <td className="py-2 px-3">
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${ch.is_active ? 'bg-green-500/20 text-green-400' : 'bg-gray-700 text-gray-400'}`}>
                      {ch.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex gap-2">
                      <button
                        className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition"
                        onClick={() => toggleChannel(ch.id, ch.is_active)}
                      >
                        {ch.is_active ? 'Disable' : 'Enable'}
                      </button>
                      {confirmingDelete === ch.id ? (
                        <>
                          <button
                            className="px-2 py-1 text-xs bg-red-600 hover:bg-red-700 text-white rounded transition"
                            onClick={() => deleteChannel(ch.id)}
                          >
                            Confirm
                          </button>
                          <button
                            className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition"
                            onClick={() => setConfirmingDelete(null)}
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <button
                          className="px-2 py-1 text-xs bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded transition"
                          onClick={() => deleteChannel(ch.id)}
                        >
                          Delete
                        </button>
                      )}
                    </div>
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
        const resp = await fetch(`${API_BASE}/api/webhooks/`, {
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
      const resp = await fetch(`${API_BASE}/api/webhooks/`, {
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
      const resp = await fetch(`${API_BASE}/api/webhooks/`, {
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
    <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-2">API Keys</h2>
      <p className="text-sm text-gray-500 mb-4">
        API keys are used for CI/CD webhook integrations. Keys are shown only once at creation.
      </p>

      {createdKey && (
        <div className="mb-4 p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
          <p className="text-sm text-green-400 mb-2">New API key created. Copy it now -- it will not be shown again.</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 px-2 py-1 bg-gray-900 rounded text-xs text-cyan-400 font-mono overflow-x-auto">{createdKey}</code>
            <button className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition" onClick={copyKey}>
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      <form onSubmit={createKey} className="flex gap-2 mb-4">
        <input
          type="text"
          value={newKeyName}
          onChange={(e) => setNewKeyName(e.target.value)}
          placeholder="Key name (e.g. CI pipeline)"
          className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
        />
        <button type="submit" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-medium rounded-lg transition disabled:opacity-50" disabled={creating || !newKeyName.trim()}>
          {creating ? 'Creating...' : 'Generate New Key'}
        </button>
      </form>

      {error && <div className="px-3 py-2 rounded-lg text-sm bg-red-500/20 text-red-400 mb-4">{error}</div>}

      {loading ? (
        <p className="text-sm text-gray-500">Loading keys...</p>
      ) : webhooks.length === 0 ? (
        <p className="text-sm text-gray-500">No API keys configured.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Name</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Key Prefix</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Scan Type</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Status</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Created</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Last Used</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map(wh => (
                <tr key={wh.id} className="border-b border-gray-700/50 hover:bg-gray-800/40">
                  <td className="py-2 px-3 text-white">{wh.name}</td>
                  <td className="py-2 px-3"><code className="text-xs text-cyan-400 font-mono">{wh.key_prefix}...</code></td>
                  <td className="py-2 px-3 text-gray-400">{wh.scan_type}</td>
                  <td className="py-2 px-3">
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${wh.is_active ? 'bg-green-500/20 text-green-400' : 'bg-gray-700 text-gray-400'}`}>
                      {wh.is_active ? 'Active' : 'Revoked'}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-gray-400">{formatDate(wh.created_at)}</td>
                  <td className="py-2 px-3 text-gray-400">{formatDate(wh.last_used_at)}</td>
                  <td className="py-2 px-3">
                    <div className="flex gap-2">
                      {confirmingRevoke === wh.id ? (
                        <>
                          <button
                            className="px-2 py-1 text-xs bg-red-600 hover:bg-red-700 text-white rounded transition"
                            onClick={() => revokeKey(wh.id)}
                          >
                            Confirm
                          </button>
                          <button
                            className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition"
                            onClick={() => setConfirmingRevoke(null)}
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <button
                          className="px-2 py-1 text-xs bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded transition"
                          onClick={() => revokeKey(wh.id)}
                        >
                          Revoke
                        </button>
                      )}
                    </div>
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
    <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-2">Scan Defaults</h2>
      <p className="text-sm text-gray-500 mb-4">
        Default settings applied when creating new scans.
      </p>
      <div className="space-y-1 max-w-md">
        <label className="text-xs text-gray-500 uppercase tracking-wider">Default Scan Type</label>
        <select
          value={scanType}
          onChange={(e) => setScanType(e.target.value)}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
        >
          {scanTypes.map(t => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
      </div>
      <div className="mt-4">
        <button className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-medium rounded-lg transition" onClick={handleSave}>
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
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-sm text-gray-400 mt-1">Manage your account, security, and preferences</p>
      </div>

      <div className="flex gap-0 border-b border-gray-700 mb-6">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`px-4 py-2 text-sm transition ${activeTab === tab.id ? 'border-b-2 border-cyan-400 text-cyan-400 font-medium' : 'text-gray-500 hover:text-gray-300'}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="space-y-6">
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
