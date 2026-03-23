import React, { useState, useEffect } from 'react'
import DashboardStats from './dashboard/DashboardStats'
import VulnerabilityFeed from './dashboard/VulnerabilityFeed'
import RiskHeatmap from './dashboard/RiskHeatmap'
import RiskTrendChart from './dashboard/RiskTrendChart'
import WebSocketManager from './dashboard/WebSocketManager'
import '../styles/Dashboard.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

export default function Dashboard({ token, userId }) {
  const [stats, setStats] = useState(null)
  const [heatmap, setHeatmap] = useState(null)
  const [trends, setTrends] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [wsConnected, setWsConnected] = useState(false)

  // Initialize WebSocket connection
  useEffect(() => {
    if (!userId || !token) return

    const ws = new WebSocketManager(userId, API_BASE)
    
    ws.on('connected', () => setWsConnected(true))
    ws.on('disconnected', () => setWsConnected(false))
    ws.on('stats_update', (data) => setStats(data.data))
    ws.on('heatmap_update', (data) => setHeatmap(data.data))
    ws.on('trends_update', (data) => setTrends(data.data))
    ws.on('error', (msg) => setError(msg))

    ws.connect()

    return () => ws.disconnect()
  }, [userId, token])

  // Load initial data
  useEffect(() => {
    if (!token) return

    const loadDashboard = async () => {
      try {
        setLoading(true)
        setError('')

        const [statsRes, heatmapRes, trendsRes] = await Promise.all([
          fetch(`${API_BASE}/api/dashboard/stats`, {
            headers: { Authorization: `Bearer ${token}` }
          }),
          fetch(`${API_BASE}/api/dashboard/heatmap`, {
            headers: { Authorization: `Bearer ${token}` }
          }),
          fetch(`${API_BASE}/api/dashboard/trends?days=30`, {
            headers: { Authorization: `Bearer ${token}` }
          })
        ])

        if (statsRes.ok) setStats(await statsRes.json())
        if (heatmapRes.ok) setHeatmap(await heatmapRes.json())
        if (trendsRes.ok) setTrends(await trendsRes.json())
      } catch (err) {
        setError(`Failed to load dashboard: ${err.message}`)
      } finally {
        setLoading(false)
      }
    }

    loadDashboard()
    // Refresh every 30 seconds if no WebSocket
    const interval = setInterval(loadDashboard, 30000)
    return () => clearInterval(interval)
  }, [token])

  if (loading && !stats) {
    return (
      <div className="dashboard-loading">
        <div className="loading-spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    )
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>🔍 Security Dashboard</h1>
        <div className="dashboard-status">
          <span className={`ws-indicator ${wsConnected ? 'connected' : 'disconnected'}`}>
            {wsConnected ? '●' : '◯'} Real-time
          </span>
        </div>
      </div>

      {error && (
        <div className="dashboard-error">
          <span>{error}</span>
          <button onClick={() => setError('')}>✕</button>
        </div>
      )}

      {/* Summary Stats */}
      {stats && <DashboardStats data={stats.summary} />}

      <div className="dashboard-grid">
        {/* Recent Scans Feed */}
        <div className="dashboard-section">
          <VulnerabilityFeed scans={stats?.recent_scans || []} />
        </div>

        {/* Risk Heatmap */}
        <div className="dashboard-section">
          {heatmap && <RiskHeatmap data={heatmap.data} />}
        </div>

        {/* Risk Trend Chart */}
        <div className="dashboard-section full-width">
          {trends && <RiskTrendChart data={trends.trend} />}
        </div>

        {/* Uptime Status */}
        {stats && stats.uptime_status && (
          <div className="dashboard-section">
            <div className="uptime-card">
              <h3>Monitor Status</h3>
              <div className="uptime-stats">
                <div className="stat-box up">
                  <div className="stat-value">{stats.uptime_status.up}</div>
                  <div className="stat-label">Up</div>
                </div>
                <div className="stat-box down">
                  <div className="stat-value">{stats.uptime_status.down}</div>
                  <div className="stat-label">Down</div>
                </div>
                <div className="stat-box degraded">
                  <div className="stat-value">{stats.uptime_status.degraded}</div>
                  <div className="stat-label">Degraded</div>
                </div>
                <div className="uptime-percentage">
                  <div className="percentage">{stats.uptime_status.uptime_percentage}%</div>
                  <div className="percentage-label">Uptime</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Risk Distribution */}
        {stats && stats.risk_distribution && (
          <div className="dashboard-section">
            <div className="risk-distribution-card">
              <h3>Risk Breakdown</h3>
              <div className="risk-bars">
                {Object.entries(stats.risk_distribution).map(([level, count]) => (
                  <div key={level} className={`risk-bar ${level}`}>
                    <div className="risk-bar-label">{level}</div>
                    <div className="risk-bar-container">
                      <div 
                        className={`risk-bar-fill ${level}`}
                        style={{ width: `${Math.min((count / 10) * 100, 100)}%` }}
                      ></div>
                    </div>
                    <div className="risk-bar-count">{count}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Activity Timeline */}
      {stats && stats.activity_timeline && stats.activity_timeline.length > 0 && (
        <div className="dashboard-section full-width">
          <div className="activity-timeline">
            <h3>Recent Activity</h3>
            <div className="timeline-list">
              {stats.activity_timeline.slice(0, 5).map((item, idx) => (
                <div key={idx} className="timeline-item">
                  <div className="timeline-time">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-action">{item.action}</div>
                    <div className="timeline-target">{item.target}</div>
                    {item.duration_seconds && (
                      <div className="timeline-meta">
                        {(item.duration_seconds / 60).toFixed(1)}m duration
                      </div>
                    )}
                  </div>
                  <div className={`timeline-status ${item.status}`}>
                    {item.status}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
