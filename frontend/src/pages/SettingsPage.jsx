import { useState, useEffect } from 'react'
import './StubPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function SettingsPage({ token }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // In a real app, fetch current user info
    setUser({ email: 'user@example.com', name: 'Security Administrator' })
    setLoading(false)
  }, [])

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Settings</h1>
        <p>Manage account and application settings</p>
      </div>

      <div className="stub-content">
        <div className="feature-card">
          <h2>👤 Account Settings</h2>
          <p>Manage your account:</p>
          <ul>
            <li>Update profile information</li>
            <li>Change password</li>
            <li>Enable two-factor authentication</li>
            <li>API key management</li>
          </ul>
        </div>

        <div className="feature-card">
          <h2>🔔 Notification Preferences</h2>
          <p>Configure how you receive alerts:</p>
          <ul>
            <li>Email notification settings</li>
            <li>Alert severity thresholds</li>
            <li>Slack/webhook integration</li>
            <li>Quiet hours configuration</li>
          </ul>
        </div>

        <div className="feature-card">
          <h2>⚙️ Application Settings</h2>
          <p>Configure application behavior:</p>
          <ul>
            <li>Scanning preferences</li>
            <li>Default report formats</li>
            <li>Timezone and language</li>
            <li>Data retention policies</li>
          </ul>
        </div>

        <div className="feature-card">
          <h2>🔐 Security</h2>
          <p>Security and privacy options:</p>
          <ul>
            <li>Session management</li>
            <li>Login activity log</li>
            <li>Connected devices</li>
            <li>Privacy settings</li>
          </ul>
        </div>
      </div>

      {user && (
        <div style={{ marginTop: '40px', padding: '20px', background: '#1a1d27', borderRadius: '8px', border: '1px solid #2a2d3a' }}>
          <h2 style={{ margin: '0 0 16px', color: '#fff' }}>Current User</h2>
          <div style={{ color: '#aaa', fontSize: '13px' }}>
            <p style={{ margin: '8px 0' }}>
              <strong style={{ color: '#e8eaed' }}>Name:</strong> {user.name}
            </p>
            <p style={{ margin: '8px 0' }}>
              <strong style={{ color: '#e8eaed' }}>Email:</strong> {user.email}
            </p>
            <p style={{ margin: '8px 0' }}>
              <strong style={{ color: '#e8eaed' }}>Role:</strong> Administrator
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

export default SettingsPage
