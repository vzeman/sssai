import { useState, useEffect } from 'react'
import './InventoryPage.css'

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

  function getSeverityClass(severity) {
    return severity?.toLowerCase() || 'unknown'
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading inventory...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Inventory</h1>
        <p>Detected technologies and CVE vulnerability alerts</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="inventory-tabs">
        <button
          className={`tab-btn ${activeTab === 'technologies' ? 'active' : ''}`}
          onClick={() => setActiveTab('technologies')}
        >
          Technologies
        </button>
        <button
          className={`tab-btn ${activeTab === 'cve-alerts' ? 'active' : ''}`}
          onClick={() => setActiveTab('cve-alerts')}
        >
          CVE Alerts
        </button>
      </div>

      {activeTab === 'technologies' && (
        <div className="inventory-panel">
          <div className="inventory-summary">
            Found {technologies.length} technolog{technologies.length !== 1 ? 'ies' : 'y'}
          </div>

          <div className="inventory-table">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Version</th>
                  <th>Vendor</th>
                  <th>Assets</th>
                </tr>
              </thead>
              <tbody>
                {technologies.length === 0 ? (
                  <tr><td colSpan="4" className="empty-cell">No technologies detected</td></tr>
                ) : (
                  technologies.map((tech, idx) => (
                    <tr key={idx} className="tech-row">
                      <td className="tech-name">{tech.name || '-'}</td>
                      <td className="mono-cell">{tech.version || '-'}</td>
                      <td>{tech.vendor || '-'}</td>
                      <td className="count-cell">{tech.asset_count ?? tech.count ?? '-'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'cve-alerts' && (
        <div className="inventory-panel">
          <div className="filters-section">
            <div className="filter-group">
              <label>Severity</label>
              <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div className="inventory-summary">
            Found {filteredAlerts.length} CVE alert{filteredAlerts.length !== 1 ? 's' : ''}
          </div>

          <div className="inventory-table">
            <table>
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Technology</th>
                  <th>CVSS Score</th>
                  <th>Severity</th>
                  <th>Affected Version</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.length === 0 ? (
                  <tr><td colSpan="6" className="empty-cell">No CVE alerts match your filters</td></tr>
                ) : (
                  filteredAlerts.map((alert, idx) => (
                    <tr key={idx} className="cve-row">
                      <td className="cve-id">{alert.cve_id || '-'}</td>
                      <td>{alert.technology || '-'}</td>
                      <td>
                        <span className={`cvss-badge ${getSeverityClass(alert.severity)}`}>
                          {alert.cvss_score ?? '-'}
                        </span>
                      </td>
                      <td>
                        <span className={`severity-badge ${getSeverityClass(alert.severity)}`}>
                          {alert.severity || 'unknown'}
                        </span>
                      </td>
                      <td className="mono-cell">{alert.affected_version || '-'}</td>
                      <td>
                        <button
                          className="action-btn rescan-btn"
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
      )}
    </div>
  )
}

export default InventoryPage
