import { useState, useEffect } from 'react'
import './AssetsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function AssetDiffModal({ target, token, onClose }) {
  const [diff, setDiff] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchDiff()
  }, [target])

  async function fetchDiff() {
    try {
      setLoading(true)
      const resp = await fetch(`${API_BASE}/api/assets/${encodeURIComponent(target)}/diff`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch asset diff')
      const data = await resp.json()
      setDiff(data)
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content asset-diff-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Asset Changes: {target}</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          {loading && <div className="loading">Loading diff...</div>}
          {error && <div className="error-message">{error}</div>}

          {diff && !loading && (
            <>
              {diff.new && diff.new.length > 0 && (
                <div className="diff-section">
                  <h3 className="diff-label diff-new">New Assets ({diff.new.length})</h3>
                  <ul className="diff-list">
                    {diff.new.map((asset, idx) => (
                      <li key={idx} className="diff-item diff-item-new">
                        {asset.hostname || asset.ip || asset.value || JSON.stringify(asset)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {diff.changed && diff.changed.length > 0 && (
                <div className="diff-section">
                  <h3 className="diff-label diff-changed">Changed Assets ({diff.changed.length})</h3>
                  <ul className="diff-list">
                    {diff.changed.map((asset, idx) => (
                      <li key={idx} className="diff-item diff-item-changed">
                        {asset.hostname || asset.ip || asset.value || JSON.stringify(asset)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {diff.removed && diff.removed.length > 0 && (
                <div className="diff-section">
                  <h3 className="diff-label diff-removed">Removed Assets ({diff.removed.length})</h3>
                  <ul className="diff-list">
                    {diff.removed.map((asset, idx) => (
                      <li key={idx} className="diff-item diff-item-removed">
                        {asset.hostname || asset.ip || asset.value || JSON.stringify(asset)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {(!diff.new || diff.new.length === 0) &&
               (!diff.changed || diff.changed.length === 0) &&
               (!diff.removed || diff.removed.length === 0) && (
                <div className="empty-state">No changes detected since last scan</div>
              )}
            </>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  )
}

function AssetsPage({ token }) {
  const [assets, setAssets] = useState([])
  const [filteredAssets, setFilteredAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [diffTarget, setDiffTarget] = useState(null)

  const [filters, setFilters] = useState({
    asset_type: 'all',
    target: '',
  })

  useEffect(() => {
    fetchAssets()
  }, [])

  useEffect(() => {
    applyFilters()
  }, [assets, filters])

  async function fetchAssets() {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      if (filters.asset_type !== 'all') params.append('asset_type', filters.asset_type)
      if (filters.target) params.append('target', filters.target)
      const qs = params.toString() ? `?${params.toString()}` : ''
      const resp = await fetch(`${API_BASE}/api/assets/${qs}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) throw new Error('Failed to fetch assets')
      const data = await resp.json()
      setAssets(Array.isArray(data) ? data : data.assets || [])
      setError('')
    } catch (err) {
      setError(err.message)
      setAssets([])
    } finally {
      setLoading(false)
    }
  }

  function applyFilters() {
    let filtered = assets.filter(a => {
      if (filters.asset_type !== 'all' && a.asset_type !== filters.asset_type) return false
      if (filters.target && !a.target?.toLowerCase().includes(filters.target.toLowerCase())) return false
      return true
    })
    setFilteredAssets(filtered)
  }

  function handleFilterChange(e) {
    const { name, value } = e.target
    setFilters(prev => ({ ...prev, [name]: value }))
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading assets...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Assets</h1>
        <p>Discovered assets across all scan targets</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="filters-section">
        <div className="filter-group">
          <label>Asset Type</label>
          <select name="asset_type" value={filters.asset_type} onChange={handleFilterChange}>
            <option value="all">All Types</option>
            <option value="domain">Domain</option>
            <option value="subdomain">Subdomain</option>
            <option value="ip">IP</option>
            <option value="api_endpoint">API Endpoint</option>
            <option value="service">Service</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Target</label>
          <input
            type="text"
            name="target"
            value={filters.target}
            onChange={handleFilterChange}
            placeholder="Filter by target..."
          />
        </div>
      </div>

      <div className="assets-summary">
        Found {filteredAssets.length} asset{filteredAssets.length !== 1 ? 's' : ''}
      </div>

      <div className="assets-table">
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>IP</th>
              <th>Port</th>
              <th>Service</th>
              <th>Technology</th>
              <th>Version</th>
              <th>First Seen</th>
              <th>Last Seen</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredAssets.length === 0 ? (
              <tr><td colSpan="9" className="empty-cell">No assets match your filters</td></tr>
            ) : (
              filteredAssets.map((asset, idx) => (
                <tr key={idx} className={`asset-row ${asset.is_new ? 'asset-new' : ''} ${asset.is_removed ? 'asset-removed' : ''}`}>
                  <td className="hostname-cell">{asset.hostname || '-'}</td>
                  <td className="mono-cell">{asset.ip || '-'}</td>
                  <td className="mono-cell">{asset.port || '-'}</td>
                  <td>{asset.service || '-'}</td>
                  <td>{asset.technology || '-'}</td>
                  <td className="mono-cell">{asset.version || '-'}</td>
                  <td className="date-cell">
                    {asset.first_seen ? new Date(asset.first_seen).toLocaleDateString() : '-'}
                  </td>
                  <td className="date-cell">
                    {asset.last_seen ? new Date(asset.last_seen).toLocaleDateString() : '-'}
                  </td>
                  <td>
                    {asset.target && (
                      <button
                        className="action-btn"
                        onClick={() => setDiffTarget(asset.target)}
                      >
                        View Changes
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {diffTarget && (
        <AssetDiffModal target={diffTarget} token={token} onClose={() => setDiffTarget(null)} />
      )}
    </div>
  )
}

export default AssetsPage
