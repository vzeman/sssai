import { useState, useEffect } from 'react'
import './StubPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function SchedulesPage({ token }) {
  const [schedules, setSchedules] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchSchedules()
  }, [])

  async function fetchSchedules() {
    try {
      const resp = await fetch(`${API_BASE}/api/schedules`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (resp.ok) {
        const data = await resp.json()
        setSchedules(data)
      }
    } catch (err) {
      console.error('Failed to fetch schedules:', err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Schedules Manager</h1>
        <p>Create and manage recurring security scans</p>
      </div>

      <div className="stub-content">
        <div className="feature-card">
          <h2>⏰ Scheduled Scans</h2>
          <p>Manage recurring security scan schedules:</p>
          <ul>
            <li>Create recurring scan schedules</li>
            <li>Daily, weekly, monthly frequencies</li>
            <li>Custom cron expressions</li>
            <li>Timezone-aware scheduling</li>
          </ul>
        </div>

        <div className="feature-card">
          <h2>📅 Calendar View</h2>
          <p>View scheduled scans in calendar format</p>
        </div>

        <div className="feature-card">
          <h2>⚙️ Advanced Settings</h2>
          <p>Configure scan parameters and notifications for each schedule</p>
        </div>
      </div>

      {schedules.length > 0 && (
        <div className="schedules-list">
          <h2>Active Schedules</h2>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#111420', borderBottom: '1px solid #2a2d3a' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>Target</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>Frequency</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>Last Run</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map(sched => (
                <tr key={sched.id} style={{ borderBottom: '1px solid #2a2d3a' }}>
                  <td style={{ padding: '12px 16px', color: '#e8eaed' }}>{sched.target_url || 'N/A'}</td>
                  <td style={{ padding: '12px 16px', color: '#e8eaed' }}>{sched.frequency || 'N/A'}</td>
                  <td style={{ padding: '12px 16px', color: '#888' }}>
                    {sched.last_run ? new Date(sched.last_run).toLocaleDateString() : 'Never'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default SchedulesPage
