import { useState, useEffect } from 'react'

const API_BASE = import.meta.env.VITE_API_URL || ''

function InventoryPage({ token }) {
  const [activeTab, setActiveTab] = useState('technologies')
  const [technologies, setTechnologies] = useState([])
  const [cveAlerts, setCveAlerts] = useState([])
  const [filteredAlerts, setFilteredAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [rescanningIds, setRescanningIds] = useState(new Set())

  useEffect(() => {
    if (activeTab === 'technologies') {
      fetchTechnologies()
    } else {
      fetchCveAlerts()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab])

  useEffect(() => {
    applyAlertFilters()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cveAlerts, severityFilter])

  async function fetchTechnologies() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/inventory/`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch technologies')
      const data = await resp.json()
      setTechnologies(Array.isArray(data) ? data : data.technologies || [])
      setError('')
    } catch (err) {
      setError(err.message)
      setTechnologies([])
    } finally {
      setLoading(false)
    }
  }

  async function fetchCveAlerts() {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      if (severityFilter !== 'all') params.append('severity', severityFilter)
      const qs = params.toString() ? `?${params.toString()}` : ''
      const resp = await fetch(`${API_BASE}/api/inventory/cve-alerts${qs}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch CVE alerts')
      const data = await resp.json()
      setCveAlerts(Array.isArray(data) ? data : data.alerts || [])
      setError('')
    } catch (err) {
      setError(err.message)
      setCveAlerts([])
    } finally {
      setLoading(false)
    }
  }

  function applyAlertFilters() {
    if (severityFilter === 'all') {
      setFilteredAlerts(cveAlerts)
    } else {
      setFilteredAlerts(cveAlerts.filter(a => a.severity === severityFilter))
    }
  }

  async function handleTriggerRescan(alertId) {
    try {
      setRescanningIds(prev => new Set([...prev, alertId]))
      const resp = await fetch(`${API_BASE}/api/inventory/cve-alerts/${alertId}/trigger-rescan`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to trigger rescan')
    } catch (err) {
      setError(err.message)
    } finally {
      setRescanningIds(prev => {
        const next = new Set(prev)
        next.delete(alertId)
        return next
      })
    }
  }

  function severityBadgeClass(severity) {
    const s = severity?.toLowerCase()
    if (s === 'critical') return 'bg-red-500/20 text-red-400'
    if (s === 'high') return 'bg-orange-500/20 text-orange-400'
    if (s === 'medium') return 'bg-yellow-500/20 text-yellow-400'
    if (s === 'low') return 'bg-blue-500/20 text-blue-400'
    return 'bg-gray-700 text-gray-400'
  }

  if (loading) {
    return <div className="p-6 max-w-6xl mx-auto"><p className="text-sm text-gray-400">Loading inventory...</p></div>
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Inventory</h1>
        <p className="text-sm text-gray-400 mt-1">Detected technologies and CVE vulnerability alerts</p>
      </div>

      {error && <div className="px-3 py-2 rounded-lg text-sm bg-red-500/20 text-red-400 mb-4">{error}</div>}

      <div className="flex gap-0 border-b border-gray-700 mb-6">
        <button
          className={`px-4 py-2 text-sm transition ${activeTab === 'technologies' ? 'border-b-2 border-cyan-400 text-cyan-400 font-medium' : 'text-gray-500 hover:text-gray-300'}`}
          onClick={() => setActiveTab('technologies')}
        >
          Technologies
        </button>
        <button
          className={`px-4 py-2 text-sm transition ${activeTab === 'cve-alerts' ? 'border-b-2 border-cyan-400 text-cyan-400 font-medium' : 'text-gray-500 hover:text-gray-300'}`}
          onClick={() => setActiveTab('cve-alerts')}
        >
          CVE Alerts
        </button>
      </div>

      {activeTab === 'technologies' && (
        <div>
          <p className="text-sm text-gray-400 mb-3">
            Found {technologies.length} technolog{technologies.length !== 1 ? 'ies' : 'y'}
          </p>

          <div className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Name</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Version</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Vendor</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Assets</th>
                  </tr>
                </thead>
                <tbody>
                  {technologies.length === 0 ? (
                    <tr><td colSpan="4" className="py-6 px-3 text-gray-500 text-center">No technologies detected</td></tr>
                  ) : (
                    technologies.map((tech, idx) => (
                      <tr key={idx} className="border-b border-gray-700/50 hover:bg-gray-800/40">
                        <td className="py-2 px-3 text-white font-medium">{tech.name || '-'}</td>
                        <td className="py-2 px-3 text-gray-400 font-mono text-xs">{tech.version || '-'}</td>
                        <td className="py-2 px-3 text-gray-300">{tech.vendor || '-'}</td>
                        <td className="py-2 px-3 text-gray-400">{tech.asset_count ?? tech.count ?? '-'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'cve-alerts' && (
        <div>
          <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 mb-4">
            <div className="space-y-1">
              <label className="text-xs text-gray-500 uppercase tracking-wider">Severity</label>
              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="w-full max-w-xs px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <p className="text-sm text-gray-400 mb-3">
            Found {filteredAlerts.length} CVE alert{filteredAlerts.length !== 1 ? 's' : ''}
          </p>

          <div className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">CVE ID</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Technology</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">CVSS Score</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Severity</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Affected Version</th>
                    <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAlerts.length === 0 ? (
                    <tr><td colSpan="6" className="py-6 px-3 text-gray-500 text-center">No CVE alerts match your filters</td></tr>
                  ) : (
                    filteredAlerts.map((alert, idx) => (
                      <tr key={idx} className="border-b border-gray-700/50 hover:bg-gray-800/40">
                        <td className="py-2 px-3 text-cyan-400 font-mono text-xs">{alert.cve_id || '-'}</td>
                        <td className="py-2 px-3 text-white">{alert.technology || '-'}</td>
                        <td className="py-2 px-3">
                          <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${severityBadgeClass(alert.severity)}`}>
                            {alert.cvss_score ?? '-'}
                          </span>
                        </td>
                        <td className="py-2 px-3">
                          <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${severityBadgeClass(alert.severity)}`}>
                            {alert.severity || 'unknown'}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-gray-400 font-mono text-xs">{alert.affected_version || '-'}</td>
                        <td className="py-2 px-3">
                          <button
                            className="px-2 py-1 text-xs bg-indigo-600 hover:bg-indigo-700 text-white rounded transition disabled:opacity-50"
                            onClick={() => handleTriggerRescan(alert.id)}
                            disabled={rescanningIds.has(alert.id)}
                          >
                            {rescanningIds.has(alert.id) ? 'Rescanning...' : 'Trigger Rescan'}
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default InventoryPage
