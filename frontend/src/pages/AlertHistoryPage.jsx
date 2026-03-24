import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import DetailModal from '../components/DetailModal'
import './StubPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function AlertHistoryPage({ token }) {
  const [alerts, setAlerts] = useState([])
  const [filter, setFilter] = useState('all')
  const [selectedAlert, setSelectedAlert] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        let url = `${API_BASE}/api/notifications`
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

      <div style={{ marginBottom: '20px', display: 'flex', gap: '12px' }}>
        <button
          onClick={() => setFilter('all')}
          style={{
            padding: '6px 12px',
            border: '1px solid #3a3d4a',
            background: filter === 'all' ? '#2a3d50' : 'transparent',
            color: filter === 'all' ? '#4a9eff' : '#aaa',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
          }}
        >
          All
        </button>
        <button
          onClick={() => setFilter('unread')}
          style={{
            padding: '6px 12px',
            border: '1px solid #3a3d4a',
            background: filter === 'unread' ? '#2a3d50' : 'transparent',
            color: filter === 'unread' ? '#4a9eff' : '#aaa',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
          }}
        >
          Unread
        </button>
        <button
          onClick={() => setFilter('critical')}
          style={{
            padding: '6px 12px',
            border: '1px solid #3a3d4a',
            background: filter === 'critical' ? '#4a2a2a' : 'transparent',
            color: filter === 'critical' ? '#ff4444' : '#aaa',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
          }}
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {alerts.map((alert) => (
            <div
              key={alert.id}
              onClick={() => setSelectedAlert(alert)}
              style={{
                background: '#1a1d27',
                border: '1px solid #2a2d3a',
                borderRadius: '8px',
                padding: '16px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                cursor: 'pointer',
              }}
            >
              <div>
                <h3 style={{ margin: '0 0 4px', color: '#fff', fontSize: '14px' }}>
                  {alert.title || 'Alert'}
                </h3>
                <p style={{ margin: 0, color: '#888', fontSize: '12px' }}>
                  {alert.message || 'No description'}
                </p>
                <p style={{ margin: '4px 0 0', color: '#666', fontSize: '11px' }}>
                  {new Date(alert.created_at).toLocaleString()}
                </p>
              </div>
              <span
                style={{
                  padding: '4px 10px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: '#4a2a2a',
                  color: '#ff4444',
                }}
              >
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
