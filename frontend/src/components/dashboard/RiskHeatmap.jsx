import React from 'react'

export default function RiskHeatmap({ data }) {
  if (!data || data.length === 0) {
    return (
      <div className="heatmap-card">
        <h3>Risk Heatmap</h3>
        <div className="empty-state">No scan data available</div>
      </div>
    )
  }

  const getRiskColor = (risk) => {
    if (risk >= 8) return '#ef4444'
    if (risk >= 6) return '#f59e0b'
    if (risk >= 4) return '#3b82f6'
    return '#10b981'
  }

  const getRiskIntensity = (risk) => {
    return Math.min(risk / 10, 1)
  }

  // Sort by risk score
  const sortedData = [...data].sort((a, b) => (b.latest_risk || 0) - (a.latest_risk || 0)).slice(0, 10)

  return (
    <div className="heatmap-card">
      <h3>Risk Heatmap (Top 10)</h3>
      <div className="heatmap-grid">
        {sortedData.map((item, idx) => (
          <div
            key={idx}
            className="heatmap-cell"
            style={{
              backgroundColor: getRiskColor(item.latest_risk || 0),
              opacity: 0.5 + getRiskIntensity(item.latest_risk || 0) * 0.5,
            }}
            title={`${item.target} (${item.scan_type}) - Risk: ${item.latest_risk || 0}, Findings: ${item.findings}`}
          >
            <div className="heatmap-label">
              <div className="label-target">{item.target.substring(0, 20)}</div>
              <div className="label-type">{item.scan_type}</div>
            </div>
            <div className="heatmap-risk">{item.latest_risk || 0}</div>
          </div>
        ))}
      </div>
      <div className="heatmap-legend">
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: '#10b981' }}></div>
          <span>Low (0-3.9)</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: '#3b82f6' }}></div>
          <span>Medium (4-5.9)</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: '#f59e0b' }}></div>
          <span>High (6-7.9)</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: '#ef4444' }}></div>
          <span>Critical (8+)</span>
        </div>
      </div>
    </div>
  )
}
