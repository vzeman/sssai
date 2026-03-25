import { useState, useEffect } from 'react'

const API_BASE = import.meta.env.VITE_API_URL || ''

function AssetDiffModal({ target, token, onClose }) {
  const [diff, setDiff] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchDiff()
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-2xl w-full max-h-[80vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-base font-semibold text-white">Asset Changes: {target}</h2>
          <button className="text-gray-400 hover:text-white transition" onClick={onClose}>&#10005;</button>
        </div>

        <div className="p-4 overflow-y-auto flex-1">
          {loading && <p className="text-sm text-gray-400">Loading diff...</p>}
          {error && <div className="px-3 py-2 rounded-lg text-sm bg-red-500/20 text-red-400">{error}</div>}

          {diff && !loading && (
            <div className="space-y-4">
              {diff.new && diff.new.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-green-400 mb-2">New Assets ({diff.new.length})</h3>
                  <ul className="space-y-1">
                    {diff.new.map((asset, idx) => (
                      <li key={idx} className="text-sm text-green-300 bg-green-500/10 rounded px-2 py-1">
                        {asset.hostname || asset.ip || asset.value || JSON.stringify(asset)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {diff.changed && diff.changed.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-yellow-400 mb-2">Changed Assets ({diff.changed.length})</h3>
                  <ul className="space-y-1">
                    {diff.changed.map((asset, idx) => (
                      <li key={idx} className="text-sm text-yellow-300 bg-yellow-500/10 rounded px-2 py-1">
                        {asset.hostname || asset.ip || asset.value || JSON.stringify(asset)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {diff.removed && diff.removed.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-red-400 mb-2">Removed Assets ({diff.removed.length})</h3>
                  <ul className="space-y-1">
                    {diff.removed.map((asset, idx) => (
                      <li key={idx} className="text-sm text-red-300 bg-red-500/10 rounded px-2 py-1">
                        {asset.hostname || asset.ip || asset.value || JSON.stringify(asset)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {(!diff.new || diff.new.length === 0) &&
               (!diff.changed || diff.changed.length === 0) &&
               (!diff.removed || diff.removed.length === 0) && (
                <p className="text-sm text-gray-500">No changes detected since last scan</p>
              )}
            </div>
          )}
        </div>

        <div className="p-4 border-t border-gray-700 flex justify-end">
          <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm rounded-lg transition" onClick={onClose}>Close</button>
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    applyFilters()
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    return <div className="p-6 max-w-6xl mx-auto"><p className="text-sm text-gray-400">Loading assets...</p></div>
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Assets</h1>
        <p className="text-sm text-gray-400 mt-1">Discovered assets across all scan targets</p>
      </div>

      {error && <div className="px-3 py-2 rounded-lg text-sm bg-red-500/20 text-red-400 mb-4">{error}</div>}

      <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-4 mb-4">
        <div className="flex flex-wrap gap-4">
          <div className="space-y-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">Asset Type</label>
            <select
              name="asset_type"
              value={filters.asset_type}
              onChange={handleFilterChange}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Types</option>
              <option value="domain">Domain</option>
              <option value="subdomain">Subdomain</option>
              <option value="ip">IP</option>
              <option value="api_endpoint">API Endpoint</option>
              <option value="service">Service</option>
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-xs text-gray-500 uppercase tracking-wider">Target</label>
            <input
              type="text"
              name="target"
              value={filters.target}
              onChange={handleFilterChange}
              placeholder="Filter by target..."
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      </div>

      <p className="text-sm text-gray-400 mb-3">
        Found {filteredAssets.length} asset{filteredAssets.length !== 1 ? 's' : ''}
      </p>

      <div className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Hostname</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">IP</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Port</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Service</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Technology</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Version</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">First Seen</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Last Seen</th>
                <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.length === 0 ? (
                <tr><td colSpan="9" className="py-6 px-3 text-gray-500 text-center">No assets match your filters</td></tr>
              ) : (
                filteredAssets.map((asset, idx) => (
                  <tr
                    key={idx}
                    className={`border-b border-gray-700/50 hover:bg-gray-800/40 ${asset.is_new ? 'bg-green-500/5' : ''} ${asset.is_removed ? 'bg-red-500/5 opacity-60' : ''}`}
                  >
                    <td className="py-2 px-3 text-white">{asset.hostname || '-'}</td>
                    <td className="py-2 px-3 text-gray-400 font-mono text-xs">{asset.ip || '-'}</td>
                    <td className="py-2 px-3 text-gray-400 font-mono text-xs">{asset.port || '-'}</td>
                    <td className="py-2 px-3 text-gray-300">{asset.service || '-'}</td>
                    <td className="py-2 px-3 text-gray-300">{asset.technology || '-'}</td>
                    <td className="py-2 px-3 text-gray-400 font-mono text-xs">{asset.version || '-'}</td>
                    <td className="py-2 px-3 text-gray-500 text-xs">
                      {asset.first_seen ? new Date(asset.first_seen).toLocaleDateString() : '-'}
                    </td>
                    <td className="py-2 px-3 text-gray-500 text-xs">
                      {asset.last_seen ? new Date(asset.last_seen).toLocaleDateString() : '-'}
                    </td>
                    <td className="py-2 px-3">
                      {asset.target && (
                        <button
                          className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition"
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
      </div>

      {diffTarget && (
        <AssetDiffModal target={diffTarget} token={token} onClose={() => setDiffTarget(null)} />
      )}
    </div>
  )
}

export default AssetsPage
