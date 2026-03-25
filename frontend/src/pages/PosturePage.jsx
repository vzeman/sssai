import { useState, useEffect } from 'react'

const API_BASE = import.meta.env.VITE_API_URL || ''

function PosturePage({ token }) {
  const [posture, setPosture] = useState(null)
  const [targets, setTargets] = useState([])
  const [brief, setBrief] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchPosture()
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    if (score < 40) return 'text-green-400'
    if (score <= 70) return 'text-yellow-400'
    return 'text-red-400'
  }

  function getScoreBg(score) {
    if (score < 40) return 'border-green-500/30'
    if (score <= 70) return 'border-yellow-500/30'
    return 'border-red-500/30'
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

  function getTrendColor(trend) {
    if (trend === 'improving') return 'text-green-400'
    if (trend === 'degrading') return 'text-red-400'
    return 'text-gray-400'
  }

  if (loading) {
    return <div className="p-6 max-w-6xl mx-auto"><p className="text-sm text-gray-400">Loading posture data...</p></div>
  }

  const score = posture?.risk_score ?? 0
  const trend = posture?.trend || 'stable'
  const severities = posture?.severity_counts || {}

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Security Posture</h1>
        <p className="text-sm text-gray-400 mt-1">Overall security posture and risk assessment</p>
      </div>

      {error && <div className="px-3 py-2 rounded-lg text-sm bg-red-500/20 text-red-400 mb-4">{error}</div>}

      <div className="flex items-start gap-4 mb-6">
        <div className={`bg-gray-800/30 border ${getScoreBg(score)} rounded-xl p-6 text-center`}>
          <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Risk Score</div>
          <div className={`text-4xl font-bold ${getScoreColor(score)}`}>{score}</div>
          <div className="text-xs text-gray-500 mt-1">out of 100</div>
          <div className={`flex items-center justify-center gap-1 mt-2 text-sm ${getTrendColor(trend)}`}>
            <span>{getTrendIcon(trend)}</span>
            <span>{getTrendLabel(trend)}</span>
          </div>
        </div>

        <button
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm rounded-lg transition"
          onClick={fetchPosture}
        >
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        <div className="bg-gray-800/30 border border-red-500/30 rounded-xl p-4 text-center">
          <div className="text-xs text-gray-500 uppercase tracking-wider">Critical</div>
          <div className="text-2xl font-bold text-red-400 mt-1">{severities.critical || 0}</div>
        </div>
        <div className="bg-gray-800/30 border border-orange-500/30 rounded-xl p-4 text-center">
          <div className="text-xs text-gray-500 uppercase tracking-wider">High</div>
          <div className="text-2xl font-bold text-orange-400 mt-1">{severities.high || 0}</div>
        </div>
        <div className="bg-gray-800/30 border border-yellow-500/30 rounded-xl p-4 text-center">
          <div className="text-xs text-gray-500 uppercase tracking-wider">Medium</div>
          <div className="text-2xl font-bold text-yellow-400 mt-1">{severities.medium || 0}</div>
        </div>
        <div className="bg-gray-800/30 border border-blue-500/30 rounded-xl p-4 text-center">
          <div className="text-xs text-gray-500 uppercase tracking-wider">Low</div>
          <div className="text-2xl font-bold text-blue-400 mt-1">{severities.low || 0}</div>
        </div>
      </div>

      {targets.length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-white mb-3">Per-Target Posture</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {targets.map((t, idx) => (
              <div key={idx} className="bg-gray-800/30 border border-gray-700 rounded-xl p-4">
                <div className="text-sm text-white font-medium truncate">{t.target || t.target_url || 'Unknown'}</div>
                <div className={`text-2xl font-bold mt-1 ${getScoreColor(t.risk_score ?? 0)}`}>
                  {t.risk_score ?? 'N/A'}
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  {t.finding_count ?? 0} finding{(t.finding_count ?? 0) !== 1 ? 's' : ''}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {brief && (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-3">AI Security Brief</h2>
          <div className="text-sm text-gray-300 space-y-2">
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
