import { Link, useLocation } from 'react-router-dom'
import { useTheme } from '../contexts/useTheme'
import './Navigation.css'

function Navigation({ onLogout }) {
  const location = useLocation()
  const { theme, toggleTheme } = useTheme()

  const navGroups = [
    {
      items: [
        { label: 'Dashboard', path: '/', icon: '📊' },
      ],
    },
    {
      title: 'Scanning',
      items: [
        { label: 'Scans', path: '/scans', icon: '🔍' },
        { label: 'Queue', path: '/queue', icon: '📦' },
        { label: 'Schedules', path: '/schedules', icon: '⏰' },
        { label: 'Campaigns', path: '/campaigns', icon: '🎯' },
      ],
    },
    {
      title: 'Results',
      items: [
        { label: 'Findings', path: '/findings', icon: '🐛' },
        { label: 'Reports', path: '/reports', icon: '📋' },
        { label: 'Remediation', path: '/remediation', icon: '🔧' },
        { label: 'Compliance', path: '/compliance', icon: '✓' },
      ],
    },
    {
      title: 'Assets',
      items: [
        { label: 'Assets', path: '/assets', icon: '🖥' },
        { label: 'Inventory', path: '/inventory', icon: '📡' },
        { label: 'Posture', path: '/posture', icon: '🛡' },
      ],
    },
    {
      title: 'Monitoring',
      items: [
        { label: 'Alerts', path: '/alerts', icon: '🚨' },
        { label: 'Webhooks', path: '/webhooks', icon: '🔗' },
        { label: 'Audit Logs', path: '/audit-logs', icon: '📜' },
      ],
    },
    {
      title: 'Tools',
      items: [
        { label: 'Advisor', path: '/advisor', icon: '💡' },
        { label: 'Settings', path: '/settings', icon: '⚙️' },
      ],
    },
  ]

  return (
    <nav className="sidebar-nav" aria-label="Main navigation">
      <div className="nav-header">
        <div className="nav-brand"><span aria-hidden="true">🛡️</span> SSSAI</div>
        <div className="nav-subtitle">Security Scanner</div>
      </div>

      <div className="nav-new-scan">
        <Link to="/scans/new" className="new-scan-btn" aria-label="Create new scan">+ New Scan</Link>
      </div>

      <div className="nav-menu" role="list">
        {navGroups.map((group, gi) => (
          <div key={group.title || gi} className="nav-group">
            {group.title && (
              <div className="nav-group-title">{group.title}</div>
            )}
            <ul className="nav-group-items" role="list">
              {group.items.map((item) => (
                <li key={item.label}>
                  <Link
                    to={item.path}
                    className={`nav-link ${location.pathname === item.path ? 'active' : ''}`}
                    {...(location.pathname === item.path ? { 'aria-current': 'page' } : {})}
                  >
                    <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                    <span className="nav-label">{item.label}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="nav-footer">
        <button onClick={toggleTheme} className="theme-toggle-btn" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
          {theme === 'dark' ? '\u2600\uFE0F Light Mode' : '\uD83C\uDF19 Dark Mode'}
        </button>
        <button onClick={onLogout} className="logout-btn" aria-label="Sign out">
          Sign Out
        </button>
      </div>
    </nav>
  )
}

export default Navigation
