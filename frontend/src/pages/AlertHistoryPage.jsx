import { useState, useEffect } from 'react'
import './StubPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function AlertHistoryPage({ token }) {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    fetchAlerts()
  }, [filter])

  async function fetchAlerts() {
    try {
      let url = `${API_BASE}/api/notifications`
      if (filter !== 'all') {
        url += `?status=${filter}`
      }
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (resp.ok) {
        const data = await resp.json()
        setAlerts(Array.isArray(data) ? data : [])
      }
    } catch (err) {
      console.error('Failed to fetch alerts:', err)
    } finally {
      setLoading(false)
    }
  }

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
        <div className="empty-state">
          <p>No alerts in history</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {alerts.map((alert) => (
            <div
              key={alert.id}
              style={{
                background: '#1a1d27',
                border: '1px solid #2a2d3a',
                borderRadius: '8px',
                padding: '16px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
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
    </div>
  )
}

export default AlertHistoryPage
