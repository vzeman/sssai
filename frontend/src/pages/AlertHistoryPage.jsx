import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import DetailModal from '../components/DetailModal'
import './StubPage.css'
import './AlertHistoryPage.css'

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
    <div className="page-container">
      <div className="page-header">
        <h1>Alert History</h1>
        <p>View all security alerts and notifications</p>
      </div>

      <div className="alert-filter-bar">
        <button
          onClick={() => setFilter('all')}
          className={`alert-filter-btn${filter === 'all' ? ' active' : ''}`}
        >
          All
        </button>
        <button
          onClick={() => setFilter('unread')}
          className={`alert-filter-btn${filter === 'unread' ? ' active' : ''}`}
        >
          Unread
        </button>
        <button
          onClick={() => setFilter('critical')}
          className={`alert-filter-btn${filter === 'critical' ? ' active-critical' : ''}`}
        >
          Critical
        </button>
      </div>

      {alerts.length === 0 ? (
        <div className="empty-state-card">
          <div className="empty-state-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
              <path d="M13.73 21a2 2 0 0 1-3.46 0" />
            </svg>
          </div>
          <h3 className="empty-state-title">No alerts yet</h3>
          <p className="empty-state-text">
            Alerts are generated when scans detect security issues. Run a scan to start receiving alerts.
          </p>
          <Link to="/scans/new" className="empty-state-cta">Start a New Scan</Link>
        </div>
      ) : (
        <div className="alert-list">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              onClick={() => setSelectedAlert(alert)}
              className="alert-card"
            >
              <div>
                <h3 className="alert-card-title">
                  {alert.title || 'Alert'}
                </h3>
                <p className="alert-card-message">
                  {alert.message || 'No description'}
                </p>
                <p className="alert-card-time">
                  {new Date(alert.created_at).toLocaleString()}
                </p>
              </div>
              <span className="alert-severity-badge">
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
