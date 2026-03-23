import React from 'react'

export default function DashboardStats({ data }) {
  if (!data) return null

  const stats = [
    { label: 'Total Scans', value: data.total_scans, icon: '📊', color: '#3b82f6' },
    { label: 'Active Monitors', value: data.active_monitors, icon: '📡', color: '#10b981' },
    { label: 'Avg Risk Score', value: data.average_risk_score, icon: '⚠️', color: '#f59e0b' },
    { label: 'Total Findings', value: data.total_findings, icon: '🚨', color: '#ef4444' },
    { label: 'Active Assets', value: data.active_assets, icon: '🎯', color: '#8b5cf6' },
    { label: 'Running Scans', value: data.running_scans, icon: '⚡', color: '#06b6d4' },
  ]

  return (
    <div className="stats-grid">
      {stats.map((stat, idx) => (
        <div key={idx} className="stat-card" style={{ borderLeftColor: stat.color }}>
          <div className="stat-icon">{stat.icon}</div>
          <div className="stat-info">
            <div className="stat-label">{stat.label}</div>
            <div className="stat-value">{stat.value}</div>
          </div>
        </div>
      ))}
    </div>
  )
}
