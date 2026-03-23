import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { SecurityAdvisorChat } from './components/SecurityAdvisorChat'
import Dashboard from './pages/Dashboard'
import FindingsPage from './pages/FindingsPage'
import ScanDetailsPage from './pages/ScanDetailsPage'
import ReportsPage from './pages/ReportsPage'
import CompliancePage from './pages/CompliancePage'
import RemediationPage from './pages/RemediationPage'
import SchedulesPage from './pages/SchedulesPage'
import WebhooksPage from './pages/WebhooksPage'
import QueuePage from './pages/QueuePage'
import AlertHistoryPage from './pages/AlertHistoryPage'
import SettingsPage from './pages/SettingsPage'
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
          <Route path="/findings" element={<FindingsPage token={token} />} />
          <Route path="/scans/:scanId" element={<ScanDetailsPage token={token} />} />
          <Route path="/reports" element={<ReportsPage token={token} />} />
          <Route path="/compliance" element={<CompliancePage token={token} />} />
          <Route path="/remediation" element={<RemediationPage token={token} />} />
          <Route path="/schedules" element={<SchedulesPage token={token} />} />
          <Route path="/webhooks" element={<WebhooksPage token={token} />} />
          <Route path="/queue" element={<QueuePage token={token} />} />
          <Route path="/alerts" element={<AlertHistoryPage token={token} />} />
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
    setToken('')
  }

  if (!token) {
    return <LoginForm onLogin={handleLogin} />
  }

  return (
    <Router>
      <AppLayout token={token} onLogout={handleLogout} />
    </Router>
  )
}

export default App
