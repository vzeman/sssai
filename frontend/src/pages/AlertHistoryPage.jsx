import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import DetailModal from '../components/DetailModal'

const API_BASE = import.meta.env.VITE_API_URL || ''

function AlertHistoryPage({ token }) {
  const [alerts, setAlerts] = useState([])
  const [filter, setFilter] = useState('all')
  const [selectedAlert, setSelectedAlert] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        let url = `${API_BASE}/api/notifications/`
        if (filter !== 'all') {
          url += `?status=${filter}`
        }
        const resp = await fetch(url, {
          headers: { Authorization: `Bearer ${token}` },
        })
        if (resp.ok && !cancelled) {
          const data = await resp.json()
          setAlerts(Array.isArray(data) ? data : [])
        }
      } catch (err) {
        if (!cancelled) console.error('Failed to fetch alerts:', err)
      }
    }
    load()
    return () => { cancelled = true }
  }, [filter, token])

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Alert History</h1>
        <p className="text-sm text-gray-400 mt-1">View all security alerts and notifications</p>
      </div>

      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setFilter('all')}
          className={`px-3 py-1.5 text-sm rounded-lg transition ${filter === 'all' ? 'bg-cyan-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'}`}
        >
          All
        </button>
        <button
          onClick={() => setFilter('unread')}
          className={`px-3 py-1.5 text-sm rounded-lg transition ${filter === 'unread' ? 'bg-cyan-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'}`}
        >
          Unread
        </button>
        <button
          onClick={() => setFilter('critical')}
          className={`px-3 py-1.5 text-sm rounded-lg transition ${filter === 'critical' ? 'bg-red-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'}`}
        >
          Critical
        </button>
      </div>

      {alerts.length === 0 ? (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-8 text-center">
          <div className="mb-3">
            <svg className="mx-auto" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
              <path d="M13.73 21a2 2 0 0 1-3.46 0" />
            </svg>
          </div>
          <h3 className="text-base font-semibold text-white mb-1">No alerts yet</h3>
          <p className="text-sm text-gray-400 mb-4">
            Alerts are generated when scans detect security issues. Run a scan to start receiving alerts.
          </p>
          <Link to="/scans/new" className="inline-block px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg transition">Start a New Scan</Link>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              onClick={() => setSelectedAlert(alert)}
              className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 cursor-pointer hover:bg-gray-800/50 transition flex items-center justify-between"
            >
              <div>
                <h3 className="text-sm font-semibold text-white">
                  {alert.title || 'Alert'}
                </h3>
                <p className="text-sm text-gray-400 mt-0.5">
                  {alert.message || 'No description'}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  {new Date(alert.created_at).toLocaleString()}
                </p>
              </div>
              <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                alert.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                alert.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                alert.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-gray-700 text-gray-400'
              }`}>
                {alert.severity || 'info'}
              </span>
            </div>
          ))}
        </div>
      )}

      {selectedAlert && (
        <DetailModal
          title={selectedAlert.title || 'Alert Details'}
          data={selectedAlert}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </div>
  )
}

export default AlertHistoryPage
