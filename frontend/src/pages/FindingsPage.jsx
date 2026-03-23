import { useState, useEffect } from 'react'
import './FindingsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function FindingDetailsModal({ finding, onClose }) {
  if (!finding) return null

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{finding.title || 'Finding Details'}</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className="detail-section">
            <h3>CVSS Score</h3>
            <div className="cvss-display">
              <div className={`cvss-score severity-${finding.severity}`}>
                {finding.cvss_score || 'N/A'}
              </div>
              <div className="cvss-vector">{finding.cvss_vector || 'N/A'}</div>
            </div>
          </div>

          <div className="detail-section">
            <h3>Severity</h3>
            <span className={`severity-badge ${finding.severity}`}>
              {finding.severity || 'Unknown'}
            </span>
          </div>

          <div className="detail-section">
            <h3>Description</h3>
            <p>{finding.description || 'No description available'}</p>
          </div>

          <div className="detail-section">
            <h3>Remediation</h3>
            <p>{finding.remediation || 'No remediation steps available'}</p>
          </div>

          {finding.history && finding.history.length > 0 && (
            <div className="detail-section">
              <h3>History</h3>
              <div className="history-list">
                {finding.history.map((entry, idx) => (
                  <div key={idx} className="history-item">
                    <span className="history-date">
                      {new Date(entry.timestamp).toLocaleDateString()}
                    </span>
                    <span className="history-status">{entry.status}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
          <button className="btn btn-success">Mark as Resolved</button>
          <button className="btn btn-warning">Mark as False Positive</button>
        </div>
      </div>
    </div>
  )
}

function FindingsPage({ token }) {
  const [findings, setFindings] = useState([])
  const [filteredFindings, setFilteredFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedFinding, setSelectedFinding] = useState(null)

  const [filters, setFilters] = useState({
    severity: 'all',
    cvssMin: 0,
    cvssMax: 10,
    status: 'all',
  })

  useEffect(() => {
    fetchFindings()
  }, [])

  useEffect(() => {
    applyFilters()
  }, [findings, filters])

  async function fetchFindings() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/search?q=severity:*`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch findings')
      const data = await resp.json()
      setFindings(data.findings || [])
      setError('')
    } catch (err) {
      setError(err.message)
      setFindings([])
    } finally {
      setLoading(false)
    }
  }

  function applyFilters() {
    let filtered = findings.filter(f => {
      if (filters.severity !== 'all' && f.severity !== filters.severity) return false
      if (filters.status !== 'all' && f.status !== filters.status) return false
      const cvss = parseFloat(f.cvss_score) || 0
      if (cvss < filters.cvssMin || cvss > filters.cvssMax) return false
      return true
    })
    setFilteredFindings(filtered)
  }

  function handleFilterChange(e) {
    const { name, value } = e.target
    setFilters(prev => ({ ...prev, [name]: value }))
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading findings...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Findings</h1>
        <p>Security findings and vulnerabilities across all scans</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="filters-section">
        <div className="filter-group">
          <label>Severity</label>
          <select name="severity" value={filters.severity} onChange={handleFilterChange}>
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="filter-group">
          <label>CVSS Score</label>
          <div className="cvss-range">
            <input
              type="number"
              min="0"
              max="10"
              step="0.5"
              name="cvssMin"
              value={filters.cvssMin}
              onChange={handleFilterChange}
              placeholder="Min"
            />
            <span>-</span>
            <input
              type="number"
              min="0"
              max="10"
              step="0.5"
              name="cvssMax"
              value={filters.cvssMax}
              onChange={handleFilterChange}
              placeholder="Max"
            />
          </div>
        </div>

        <div className="filter-group">
          <label>Status</label>
          <select name="status" value={filters.status} onChange={handleFilterChange}>
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="false-positive">False Positive</option>
          </select>
        </div>
      </div>

      <div className="findings-summary">
        Found {filteredFindings.length} finding{filteredFindings.length !== 1 ? 's' : ''}
      </div>

      <div className="findings-table">
        <table>
          <thead>
            <tr>
              <th>Title</th>
              <th>Severity</th>
              <th>CVSS</th>
              <th>Status</th>
              <th>Scan</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredFindings.length === 0 ? (
              <tr><td colSpan="6" className="empty-cell">No findings match your filters</td></tr>
            ) : (
              filteredFindings.map((finding, idx) => (
                <tr key={idx} className="finding-row">
                  <td className="title-cell">
                    <span className="finding-title">{finding.title || 'Unknown'}</span>
                  </td>
                  <td>
                    <span className={`severity-badge ${finding.severity}`}>
                      {finding.severity || 'unknown'}
                    </span>
                  </td>
                  <td>
                    <span className={`cvss-badge ${finding.severity}`}>
                      {finding.cvss_score || 'N/A'}
                    </span>
                  </td>
                  <td>
                    <span className={`status-badge ${finding.status || 'open'}`}>
                      {finding.status || 'open'}
                    </span>
                  </td>
                  <td className="scan-ref">{finding.scan_id?.substring(0, 8) || 'N/A'}</td>
                  <td>
                    <button
                      className="action-btn"
                      onClick={() => setSelectedFinding(finding)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <FindingDetailsModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  )
}

export default FindingsPage
