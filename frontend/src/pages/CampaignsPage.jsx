import { useState, useEffect } from 'react'

const API_BASE = import.meta.env.VITE_API_URL || ''

function CampaignsPage({ token }) {
  const [campaigns, setCampaigns] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const [expandedData, setExpandedData] = useState(null)
  const [showForm, setShowForm] = useState(false)
  const [creating, setCreating] = useState(false)
  const [reportData, setReportData] = useState(null)
  const [reportLoading, setReportLoading] = useState(false)

  const [formData, setFormData] = useState({
    name: '',
    targets: '',
    scan_type: 'full',
  })

  useEffect(() => {
    fetchCampaigns()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function fetchCampaigns() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/campaigns/`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch campaigns')
      const data = await resp.json()
      setCampaigns(data)
      setError('')
    } catch (err) {
      setError(err.message)
      setCampaigns([])
    } finally {
      setLoading(false)
    }
  }

  async function handleCreate(e) {
    e.preventDefault()
    const targets = formData.targets
      .split('\n')
      .map(t => t.trim())
      .filter(Boolean)
    if (!formData.name || targets.length === 0) {
      setError('Name and at least one target are required')
      return
    }
    try {
      setCreating(true)
      const resp = await fetch(`${API_BASE}/api/campaigns/`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: formData.name,
          targets,
          scan_type: formData.scan_type,
          config: {},
        }),
      })
      if (!resp.ok) throw new Error('Failed to create campaign')
      setFormData({ name: '', targets: '', scan_type: 'full' })
      setShowForm(false)
      setError('')
      fetchCampaigns()
    } catch (err) {
      setError(err.message)
    } finally {
      setCreating(false)
    }
  }

  async function handleExpand(id) {
    if (expandedId === id) {
      setExpandedId(null)
      setExpandedData(null)
      return
    }
    try {
      setExpandedId(id)
      setExpandedData(null)
      const resp = await fetch(`${API_BASE}/api/campaigns/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch campaign details')
      const data = await resp.json()
      setExpandedData(data)
    } catch (err) {
      setError(err.message)
      setExpandedId(null)
    }
  }

  async function handleViewReport(id) {
    try {
      setReportLoading(true)
      setReportData(null)
      const resp = await fetch(`${API_BASE}/api/campaigns/${id}/report`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch campaign report')
      const data = await resp.json()
      setReportData(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setReportLoading(false)
    }
  }

  function statusColor(status) {
    if (status === 'running') return 'bg-blue-500/20 text-blue-400'
    if (status === 'completed') return 'bg-green-500/20 text-green-400'
    if (status === 'failed') return 'bg-red-500/20 text-red-400'
    return 'bg-gray-700 text-gray-400'
  }

  if (loading) {
    return <div className="p-6 max-w-6xl mx-auto"><p className="text-sm text-gray-400">Loading campaigns...</p></div>
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Campaigns</h1>
        <p className="text-sm text-gray-400 mt-1">Multi-target scan campaigns and cross-target analysis</p>
      </div>

      {error && <div className="px-3 py-2 rounded-lg text-sm bg-red-500/20 text-red-400 mb-4">{error}</div>}

      <div className="mb-4">
        <button
          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg transition"
          onClick={() => setShowForm(!showForm)}
        >
          {showForm ? 'Cancel' : '+ New Campaign'}
        </button>
      </div>

      {showForm && (
        <form className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 mb-6 space-y-4 max-w-xl" onSubmit={handleCreate}>
          <div className="space-y-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">Campaign Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={e => setFormData(prev => ({ ...prev, name: e.target.value }))}
              placeholder="e.g. Q1 External Pentest"
              required
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">Targets (one URL per line)</label>
            <textarea
              value={formData.targets}
              onChange={e => setFormData(prev => ({ ...prev, targets: e.target.value }))}
              placeholder={"https://example.com\nhttps://api.example.com\nhttps://admin.example.com"}
              rows={5}
              required
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 resize-y"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">Scan Type</label>
            <select
              value={formData.scan_type}
              onChange={e => setFormData(prev => ({ ...prev, scan_type: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="full">Full Scan</option>
              <option value="quick">Quick Scan</option>
              <option value="api">API Scan</option>
              <option value="web">Web Application</option>
              <option value="infrastructure">Infrastructure</option>
            </select>
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg transition disabled:opacity-50"
            disabled={creating}
          >
            {creating ? 'Creating...' : 'Create Campaign'}
          </button>
        </form>
      )}

      {reportData && (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Cross-Target Analysis</h3>
            <button
              className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm rounded-lg transition"
              onClick={() => setReportData(null)}
            >
              Close
            </button>
          </div>
          <div className="space-y-4">
            {reportData.summary && <p className="text-sm text-gray-300">{reportData.summary}</p>}
            {reportData.common_findings && reportData.common_findings.length > 0 && (
              <div>
                <h4 className="text-sm font-semibold text-white mb-2">Common Findings</h4>
                <ul className="list-disc list-inside text-sm text-gray-400 space-y-1">
                  {reportData.common_findings.map((f, idx) => (
                    <li key={idx}>{f.title || f}</li>
                  ))}
                </ul>
              </div>
            )}
            {reportData.risk_scores && (
              <div>
                <h4 className="text-sm font-semibold text-white mb-2">Risk Scores by Target</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {Object.entries(reportData.risk_scores).map(([target, riskScore]) => (
                    <div key={target} className="flex justify-between items-center bg-gray-900/50 rounded-lg px-3 py-2">
                      <span className="text-sm text-gray-400 truncate mr-2">{target}</span>
                      <span className="text-sm font-semibold text-white">{riskScore}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {!reportData.summary && !reportData.common_findings && (
              <pre className="text-xs text-gray-400 bg-gray-900/50 rounded-lg p-3 overflow-x-auto">{JSON.stringify(reportData, null, 2)}</pre>
            )}
          </div>
        </div>
      )}

      <div className="space-y-3">
        {campaigns.length === 0 ? (
          <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-8 text-center">
            <p className="text-sm text-gray-400">No campaigns yet. Create one to scan multiple targets together.</p>
          </div>
        ) : (
          campaigns.map(campaign => (
            <div key={campaign.id} className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
              <div
                className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-800/50 transition"
                onClick={() => handleExpand(campaign.id)}
              >
                <div>
                  <h3 className="text-sm font-semibold text-white">{campaign.name}</h3>
                  <div className="flex items-center gap-3 mt-1">
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${statusColor(campaign.status)}`}>
                      {campaign.status}
                    </span>
                    <span className="text-xs text-gray-500">
                      {campaign.target_count || campaign.targets?.length || 0} targets
                    </span>
                    {campaign.aggregate_risk_score != null && (
                      <span className="text-xs text-gray-500">
                        Risk: {campaign.aggregate_risk_score}
                      </span>
                    )}
                    <span className="text-xs text-gray-500">
                      {new Date(campaign.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {campaign.status === 'completed' && (
                    <button
                      className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded-lg transition"
                      onClick={e => {
                        e.stopPropagation()
                        handleViewReport(campaign.id)
                      }}
                    >
                      View Report
                    </button>
                  )}
                  <span className="text-gray-500 text-sm">
                    {expandedId === campaign.id ? '\u25BE' : '\u25B8'}
                  </span>
                </div>
              </div>

              {expandedId === campaign.id && (
                <div className="border-t border-gray-700 p-4">
                  {!expandedData ? (
                    <p className="text-sm text-gray-400">Loading scan details...</p>
                  ) : (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">Scans</h4>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-gray-700">
                              <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Target</th>
                              <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Status</th>
                              <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Findings</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(expandedData.scans || []).map((scan, idx) => (
                              <tr key={idx} className="border-b border-gray-700/50">
                                <td className="py-2 px-3 text-gray-300 font-mono text-xs">{scan.target_url || scan.target}</td>
                                <td className="py-2 px-3">
                                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${statusColor(scan.status)}`}>
                                    {scan.status}
                                  </span>
                                </td>
                                <td className="py-2 px-3 text-white">{scan.findings_count ?? scan.findings?.length ?? 0}</td>
                              </tr>
                            ))}
                            {(!expandedData.scans || expandedData.scans.length === 0) && (
                              <tr>
                                <td colSpan="3" className="py-2 px-3 text-gray-500 text-center">No scans found</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {reportLoading && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <p className="text-sm text-gray-300">Loading cross-target analysis...</p>
        </div>
      )}
    </div>
  )
}

export default CampaignsPage
