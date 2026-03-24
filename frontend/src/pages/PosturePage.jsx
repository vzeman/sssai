import { useState, useEffect } from 'react'
import './PosturePage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function PosturePage({ token }) {
  const [posture, setPosture] = useState(null)
  const [targets, setTargets] = useState([])
  const [brief, setBrief] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchPosture()
  }, [])

  async function fetchPosture() {
    try {
      setLoading(true)
      setError('')

      const headers = { Authorization: `Bearer ${token}` }

      const [summaryResp, briefResp] = await Promise.all([
        fetch(`${API_BASE}/api/posture`, { headers }),
        fetch(`${API_BASE}/api/posture/brief`, { headers }),
      ])

      if (!summaryResp.ok) throw new Error('Failed to fetch posture summary')
      const summaryData = await summaryResp.json()
      setPosture(summaryData)

      // Extract per-target data from summary if available
      if (summaryData.targets) {
        setTargets(summaryData.targets)
      }

      if (briefResp.ok) {
        const briefData = await briefResp.json()
        setBrief(briefData.brief || briefData.message || '')
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function getScoreColor(score) {
    if (score < 40) return 'score-green'
    if (score <= 70) return 'score-yellow'
    return 'score-red'
  }

  function getTrendLabel(trend) {
    if (trend === 'improving') return 'Improving'
    if (trend === 'degrading') return 'Degrading'
    return 'Stable'
  }

  function getTrendIcon(trend) {
    if (trend === 'improving') return '\u2193'
    if (trend === 'degrading') return '\u2191'
    return '\u2194'
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading posture data...</div></div>
  }

  const score = posture?.risk_score ?? 0
  const trend = posture?.trend || 'stable'
  const severities = posture?.severity_counts || {}

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Security Posture</h1>
        <p>Overall security posture and risk assessment</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="posture-top">
        <div className={`posture-score-card ${getScoreColor(score)}`}>
          <div className="posture-score-label">Risk Score</div>
          <div className="posture-score-value">{score}</div>
          <div className="posture-score-range">out of 100</div>
          <div className={`posture-trend trend-${trend}`}>
            <span className="trend-icon">{getTrendIcon(trend)}</span>
            <span className="trend-label">{getTrendLabel(trend)}</span>
          </div>
        </div>

        <button className="refresh-btn" onClick={fetchPosture}>
          Refresh
        </button>
      </div>

      <div className="severity-cards">
        <div className="stat-card critical">
          <div className="stat-label">Critical</div>
          <div className="stat-value">{severities.critical || 0}</div>
        </div>
        <div className="stat-card high">
          <div className="stat-label">High</div>
          <div className="stat-value">{severities.high || 0}</div>
        </div>
        <div className="stat-card medium">
          <div className="stat-label">Medium</div>
          <div className="stat-value">{severities.medium || 0}</div>
        </div>
        <div className="stat-card low">
          <div className="stat-label">Low</div>
          <div className="stat-value">{severities.low || 0}</div>
        </div>
      </div>

      {targets.length > 0 && (
        <div className="targets-section">
          <h2>Per-Target Posture</h2>
          <div className="targets-grid">
            {targets.map((t, idx) => (
              <div key={idx} className="target-card">
                <div className="target-name">{t.target || t.target_url || 'Unknown'}</div>
                <div className={`target-score ${getScoreColor(t.risk_score ?? 0)}`}>
                  {t.risk_score ?? 'N/A'}
                </div>
                <div className="target-findings">
                  {t.finding_count ?? 0} finding{(t.finding_count ?? 0) !== 1 ? 's' : ''}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {brief && (
        <div className="brief-section">
          <h2>AI Security Brief</h2>
          <div className="brief-content">
            {brief.split('\n').map((line, idx) => (
              <p key={idx}>{line}</p>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default PosturePage
