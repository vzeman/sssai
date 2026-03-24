import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { SecurityAdvisorChat } from './components/SecurityAdvisorChat'
import { ToastProvider } from './components/ToastContext'
import Toast from './components/Toast'
import Dashboard from './pages/Dashboard'
import FindingsPage from './pages/FindingsPage'
import ScanDetailsPage from './pages/ScanDetailsPage'
import ReportsPage from './pages/ReportsPage'
import CompliancePage from './pages/CompliancePage'
import RemediationPage from './pages/RemediationPage'
import SchedulesPage from './pages/SchedulesPage'
import WebhooksPage from './pages/WebhooksPage'
import CampaignsPage from './pages/CampaignsPage'
import QueuePage from './pages/QueuePage'
import AlertHistoryPage from './pages/AlertHistoryPage'
import AssetsPage from './pages/AssetsPage'
import InventoryPage from './pages/InventoryPage'
import SettingsPage from './pages/SettingsPage'
import PosturePage from './pages/PosturePage'
import AuditLogsPage from './pages/AuditLogsPage'
import ScansPage from './pages/ScansPage'
import ScanWizard from './components/ScanWizard'
import Navigation from './components/Navigation'
import './App.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function LoginForm({ onLogin }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const form = new URLSearchParams()
      form.append('username', email)
      form.append('password', password)
      const resp = await fetch(`${API_BASE}/api/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
        credentials: 'include', // receive refresh_token cookie from backend
      })
      const data = await resp.json()
      if (!resp.ok) throw new Error(data.detail || 'Login failed')
      onLogin(data.access_token)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <span className="login-icon">🛡️</span>
          <h1>SSSAI Security Advisor</h1>
          <p>Sign in to access your AI security dashboard</p>
        </div>
        <form onSubmit={handleSubmit} className="login-form">
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="login-input"
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="login-input"
          />
          {error && <div className="login-error">{error}</div>}
          <button type="submit" className="login-btn" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}

function AppLayout({ token, onLogout }) {
  return (
    <div className="app-layout">
      <Navigation token={token} onLogout={onLogout} />
      <main className="app-main">
        <Routes>
          <Route path="/" element={<Dashboard token={token} />} />
          <Route path="/scans" element={<ScansPage token={token} />} />
          <Route path="/scans/new" element={<ScanWizard token={token} />} />
          <Route path="/scans/:scanId" element={<ScanDetailsPage token={token} />} />
          <Route path="/findings" element={<FindingsPage token={token} />} />
          <Route path="/reports" element={<ReportsPage token={token} />} />
          <Route path="/compliance" element={<CompliancePage token={token} />} />
          <Route path="/remediation" element={<RemediationPage token={token} />} />
          <Route path="/schedules" element={<SchedulesPage token={token} />} />
          <Route path="/webhooks" element={<WebhooksPage token={token} />} />
          <Route path="/campaigns" element={<CampaignsPage token={token} />} />
          <Route path="/queue" element={<QueuePage token={token} />} />
          <Route path="/alerts" element={<AlertHistoryPage token={token} />} />
          <Route path="/assets" element={<AssetsPage token={token} />} />
          <Route path="/inventory" element={<InventoryPage token={token} />} />
          <Route path="/posture" element={<PosturePage token={token} />} />
          <Route path="/audit-logs" element={<AuditLogsPage token={token} />} />
          <Route path="/settings" element={<SettingsPage token={token} />} />
          <Route path="/advisor" element={<SecurityAdvisorChat token={token} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

function App() {
  const [token, setToken] = useState(() => localStorage.getItem('auth_token') || '')

  function handleLogin(newToken) {
    localStorage.setItem('auth_token', newToken)
    setToken(newToken)
  }

  function handleLogout() {
    localStorage.removeItem('auth_token')
    // Also call backend logout to clear cookies/blacklist refresh token
    fetch(`${API_BASE}/api/auth/logout`, {
      method: 'POST',
      credentials: 'include',
    }).catch(() => {})
    setToken('')
  }

  // Auto-refresh token before it expires (every 25 minutes)
  useEffect(() => {
    if (!token) return

    async function refreshToken() {
      try {
        const resp = await fetch(`${API_BASE}/api/auth/refresh`, {
          method: 'POST',
          credentials: 'include', // send refresh_token cookie
        })
        if (resp.ok) {
          const data = await resp.json()
          if (data.access_token) {
            localStorage.setItem('auth_token', data.access_token)
            setToken(data.access_token)
          }
        } else if (resp.status === 401) {
          // Refresh token also expired — force re-login
          localStorage.removeItem('auth_token')
          setToken('')
        }
      } catch {
        // Network error — don't logout, will retry next interval
      }
    }

    // Refresh every 25 minutes (token expires at 30)
    const interval = setInterval(refreshToken, 25 * 60 * 1000)
    return () => clearInterval(interval)
  }, [token])

  // Listen for 401 responses globally to handle expired tokens
  useEffect(() => {
    if (!token) return

    const originalFetch = window.fetch
    window.fetch = async (...args) => {
      const resp = await originalFetch(...args)
      if (resp.status === 401) {
        const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || ''
        // Don't intercept auth endpoints themselves
        if (!url.includes('/api/auth/')) {
          localStorage.removeItem('auth_token')
          setToken('')
        }
      }
      return resp
    }
    return () => { window.fetch = originalFetch }
  }, [token])

  return (
    <ToastProvider>
      <Router>
        {!token ? (
          <Routes>
            <Route path="/login" element={<LoginForm onLogin={handleLogin} />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </Routes>
        ) : (
          <AppLayout token={token} onLogout={handleLogout} />
        )}
      </Router>
      <Toast />
    </ToastProvider>
  )
}

export default App
