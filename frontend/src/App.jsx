import { useState } from 'react'
import { SecurityAdvisorChat } from './components/SecurityAdvisorChat'
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
    <div className="app-layout">
      <nav className="app-nav">
        <span className="nav-brand">🛡️ SSSAI</span>
        <button className="logout-btn" onClick={handleLogout}>
          Sign Out
        </button>
      </nav>
      <main className="app-main">
        <SecurityAdvisorChat token={token} />
      </main>
    </div>
  )
}

export default App
