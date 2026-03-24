import { useState, useEffect } from 'react'
import './CampaignsPage.css'

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

  function statusClass(status) {
    if (status === 'running') return 'running'
    if (status === 'completed') return 'completed'
    if (status === 'failed') return 'failed'
    return 'queued'
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading campaigns...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Campaigns</h1>
        <p>Multi-target scan campaigns and cross-target analysis</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="campaigns-actions">
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : '+ New Campaign'}
        </button>
      </div>

      {showForm && (
        <form className="campaign-form" onSubmit={handleCreate}>
          <div className="form-group">
            <label>Campaign Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={e => setFormData(prev => ({ ...prev, name: e.target.value }))}
              placeholder="e.g. Q1 External Pentest"
              required
            />
          </div>
          <div className="form-group">
            <label>Targets (one URL per line)</label>
            <textarea
              value={formData.targets}
              onChange={e => setFormData(prev => ({ ...prev, targets: e.target.value }))}
              placeholder={"https://example.com\nhttps://api.example.com\nhttps://admin.example.com"}
              rows={5}
              required
            />
          </div>
          <div className="form-group">
            <label>Scan Type</label>
            <select
              value={formData.scan_type}
              onChange={e => setFormData(prev => ({ ...prev, scan_type: e.target.value }))}
            >
              <option value="full">Full Scan</option>
              <option value="quick">Quick Scan</option>
              <option value="api">API Scan</option>
              <option value="web">Web Application</option>
              <option value="infrastructure">Infrastructure</option>
            </select>
          </div>
          <button type="submit" className="btn btn-primary" disabled={creating}>
            {creating ? 'Creating...' : 'Create Campaign'}
          </button>
        </form>
      )}

      {reportData && (
        <div className="campaign-report">
          <div className="report-header-bar">
            <h3>Cross-Target Analysis</h3>
            <button className="btn btn-secondary" onClick={() => setReportData(null)}>Close</button>
          </div>
          <div className="report-body">
            {reportData.summary && <p className="report-summary">{reportData.summary}</p>}
            {reportData.common_findings && reportData.common_findings.length > 0 && (
              <div className="report-section">
                <h4>Common Findings</h4>
                <ul className="report-findings-list">
                  {reportData.common_findings.map((f, idx) => (
                    <li key={idx}>{f.title || f}</li>
                  ))}
                </ul>
              </div>
            )}
            {reportData.risk_scores && (
              <div className="report-section">
                <h4>Risk Scores by Target</h4>
                <div className="risk-scores-grid">
                  {Object.entries(reportData.risk_scores).map(([target, score]) => (
                    <div key={target} className="risk-score-item">
                      <span className="risk-target">{target}</span>
                      <span className="risk-value">{score}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {!reportData.summary && !reportData.common_findings && (
              <pre className="report-raw">{JSON.stringify(reportData, null, 2)}</pre>
            )}
          </div>
        </div>
      )}

      <div className="campaigns-list">
        {campaigns.length === 0 ? (
          <div className="empty-state">
            <p>No campaigns yet. Create one to scan multiple targets together.</p>
          </div>
        ) : (
          campaigns.map(campaign => (
            <div key={campaign.id} className="campaign-card">
              <div
                className="campaign-header"
                onClick={() => handleExpand(campaign.id)}
              >
                <div className="campaign-info">
                  <h3>{campaign.name}</h3>
                  <div className="campaign-meta">
                    <span className={`status-badge ${statusClass(campaign.status)}`}>
                      {campaign.status}
                    </span>
                    <span className="meta-text">
                      {campaign.target_count || campaign.targets?.length || 0} targets
                    </span>
                    {campaign.aggregate_risk_score != null && (
                      <span className="meta-text">
                        Risk: {campaign.aggregate_risk_score}
                      </span>
                    )}
                    <span className="meta-text">
                      {new Date(campaign.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
                <div className="campaign-actions">
                  {campaign.status === 'completed' && (
                    <button
                      className="btn btn-secondary"
                      onClick={e => {
                        e.stopPropagation()
                        handleViewReport(campaign.id)
                      }}
                    >
                      View Report
                    </button>
                  )}
                  <span className="expand-icon">
                    {expandedId === campaign.id ? '▾' : '▸'}
                  </span>
                </div>
              </div>

              {expandedId === campaign.id && (
                <div className="campaign-details">
                  {!expandedData ? (
                    <div className="loading">Loading scan details...</div>
                  ) : (
                    <div className="scans-list">
                      <h4>Scans</h4>
                      <table>
                        <thead>
                          <tr>
                            <th>Target</th>
                            <th>Status</th>
                            <th>Findings</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(expandedData.scans || []).map((scan, idx) => (
                            <tr key={idx}>
                              <td className="target-cell">{scan.target_url || scan.target}</td>
                              <td>
                                <span className={`status-badge ${statusClass(scan.status)}`}>
                                  {scan.status}
                                </span>
                              </td>
                              <td>{scan.findings_count ?? scan.findings?.length ?? 0}</td>
                            </tr>
                          ))}
                          {(!expandedData.scans || expandedData.scans.length === 0) && (
                            <tr>
                              <td colSpan="3" className="empty-cell">No scans found</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {reportLoading && (
        <div className="report-loading-overlay">
          <div className="loading">Loading cross-target analysis...</div>
        </div>
      )}
    </div>
  )
}

export default CampaignsPage
