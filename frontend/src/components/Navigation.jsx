import { Link, useLocation } from 'react-router-dom'
import { useTheme } from '../contexts/useTheme'


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
    <nav className="w-60 bg-gray-950 border-r border-gray-800 h-screen flex flex-col fixed left-0 top-0 z-50 overflow-y-auto" aria-label="Main navigation">
      <div className="p-5 border-b border-gray-800">
        <div className="text-lg font-bold text-white"><span aria-hidden="true">🛡️</span> SSSAI</div>
        <div className="text-xs text-gray-500 mt-0.5">Security Scanner</div>
      </div>

      <div className="px-3 py-3">
        <Link to="/scans/new" className="block w-full text-center py-2.5 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold text-sm rounded-lg transition" aria-label="Create new scan">
          + New Scan
        </Link>
      </div>

      <div className="flex-1 px-2 pb-4">
        {navGroups.map((group, gi) => (
          <div key={group.title || gi} className="mb-1">
            {group.title && (
              <div className="px-3 pt-4 pb-1 text-[10px] font-bold uppercase tracking-widest text-gray-500">
                {group.title}
              </div>
            )}
            <ul role="list">
              {group.items.map((item) => {
                const isActive = location.pathname === item.path
                return (
                  <li key={item.label}>
                    <Link
                      to={item.path}
                      className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition ${
                        isActive
                          ? 'bg-cyan-500/10 text-cyan-400 font-medium'
                          : 'text-gray-400 hover:bg-gray-800/50 hover:text-gray-200'
                      }`}
                      {...(isActive ? { 'aria-current': 'page' } : {})}
                    >
                      <span className="text-base w-5 text-center" aria-hidden="true">{item.icon}</span>
                      <span>{item.label}</span>
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </div>

      <div className="p-3 border-t border-gray-800 space-y-2">
        <button
          onClick={toggleTheme}
          className="w-full px-3 py-2 text-sm text-gray-400 hover:text-gray-200 border border-gray-800 rounded-lg hover:bg-gray-800/50 transition"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode'}
        </button>
        <button
          onClick={onLogout}
          className="w-full px-3 py-2 text-sm text-gray-400 hover:text-red-400 border border-gray-800 rounded-lg hover:bg-gray-800/50 hover:border-red-900 transition"
          aria-label="Sign out"
        >
          Sign Out
        </button>
      </div>
    </nav>
  )
}

export default Navigation
