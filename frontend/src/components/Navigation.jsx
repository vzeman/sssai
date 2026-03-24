import { Link, useLocation } from 'react-router-dom'
import { useTheme } from '../contexts/useTheme'
import './Navigation.css'

function Navigation({ onLogout }) {
  const location = useLocation()
  const { theme, toggleTheme } = useTheme()

  const navItems = [
    { label: 'Dashboard', path: '/', icon: '📊' },
    { label: 'Scans', path: '/scans', icon: '🔍' },
    { label: 'Findings', path: '/findings', icon: '🐛' },
    { label: 'Assets', path: '/assets', icon: '🖥' },
    { label: 'Inventory', path: '/inventory', icon: '📡' },
    { label: 'Reports', path: '/reports', icon: '📋' },
    { label: 'Campaigns', path: '/campaigns', icon: '🎯' },
    { label: 'Compliance', path: '/compliance', icon: '✓' },
    { label: 'Remediation', path: '/remediation', icon: '🔧' },
    { label: 'Schedules', path: '/schedules', icon: '⏰' },
    { label: 'Webhooks', path: '/webhooks', icon: '🔗' },
    { label: 'Queue', path: '/queue', icon: '📦' },
    { label: 'Posture', path: '/posture', icon: '🛡' },
    { label: 'Alerts', path: '/alerts', icon: '🚨' },
    { label: 'Audit Logs', path: '/audit-logs', icon: '📜' },
    { label: 'Advisor', path: '/advisor', icon: '💡' },
    { label: 'Settings', path: '/settings', icon: '⚙️' },
  ]

  return (
    <nav className="sidebar-nav">
      <div className="nav-header">
        <div className="nav-brand">🛡️ SSSAI</div>
        <div className="nav-subtitle">Security Scanner</div>
      </div>

      <div className="nav-new-scan">
        <Link to="/scans/new" className="new-scan-btn">+ New Scan</Link>
      </div>

      <ul className="nav-menu">
        {navItems.map((item) => (
          <li key={item.label}>
            <Link
              to={item.path}
              className={`nav-link ${location.pathname === item.path ? 'active' : ''}`}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </Link>
          </li>
        ))}
      </ul>

      <div className="nav-footer">
        <button onClick={toggleTheme} className="theme-toggle-btn" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
          {theme === 'dark' ? '\u2600\uFE0F Light Mode' : '\uD83C\uDF19 Dark Mode'}
        </button>
        <button onClick={onLogout} className="logout-btn">
          Sign Out
        </button>
      </div>
    </nav>
  )
}

export default Navigation
