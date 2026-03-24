import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import './SearchModal.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

export function SearchModal({ open, onClose, token }) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)
  const inputRef = useRef(null)
  const debounceRef = useRef(null)
  const navigate = useNavigate()

  // Focus input when modal opens
  useEffect(() => {
    if (open) {
      setQuery('')
      setResults(null)
      setActiveIndex(0)
      // Small delay to let modal render
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [open])

  const performSearch = useCallback(async (q) => {
    if (!q.trim()) {
      setResults(null)
      return
    }
    setLoading(true)
    try {
      const resp = await fetch(
        `${API_BASE}/api/search/global?q=${encodeURIComponent(q.trim())}&size=20`,
        { headers: { Authorization: `Bearer ${token}` } }
      )
      if (!resp.ok) throw new Error('Search failed')
      const data = await resp.json()
      setResults(data)
      setActiveIndex(0)
    } catch {
      setResults(null)
    } finally {
      setLoading(false)
    }
  }, [token])

  function handleInputChange(e) {
    const value = e.target.value
    setQuery(value)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => performSearch(value), 300)
  }

  // Build a flat list of navigable results for keyboard navigation
  function getFlatResults() {
    if (!results) return []
    const items = []
    const findings = results.findings?.items || []
    for (const f of findings) {
      items.push({ type: 'finding', data: f })
    }
    const activities = results.activity?.items || []
    for (const a of activities) {
      items.push({ type: 'scan', data: a })
    }
    return items
  }

  function navigateToResult(item) {
    if (item.type === 'finding') {
      navigate('/findings')
    } else if (item.type === 'scan' && item.data.scan_id) {
      navigate(`/scans/${item.data.scan_id}`)
    }
    onClose()
  }

  function handleKeyDown(e) {
    const flat = getFlatResults()
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActiveIndex(prev => Math.min(prev + 1, flat.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActiveIndex(prev => Math.max(prev - 1, 0))
    } else if (e.key === 'Enter' && flat.length > 0) {
      e.preventDefault()
      navigateToResult(flat[activeIndex])
    } else if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    }
  }

  function handleOverlayClick(e) {
    if (e.target === e.currentTarget) {
      onClose()
    }
  }

  if (!open) return null

  const flat = getFlatResults()
  const findings = results?.findings?.items || []
  const activities = results?.activity?.items || []
  const findingsTotal = results?.findings?.total || 0
  const activitiesTotal = results?.activity?.total || 0

  let globalIdx = 0

  return (
    <div className="search-modal-overlay" onClick={handleOverlayClick}>
      <div className="search-modal" onKeyDown={handleKeyDown}>
        <div className="search-modal-input-wrapper">
          <svg className="search-modal-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            ref={inputRef}
            className="search-modal-input"
            type="text"
            placeholder="Search findings, scans, activity..."
            value={query}
            onChange={handleInputChange}
          />
          <span className="search-modal-kbd">ESC</span>
        </div>

        <div className="search-modal-body">
          {loading && (
            <div className="search-modal-loading">Searching...</div>
          )}

          {!loading && query.trim() && results && flat.length === 0 && (
            <div className="search-modal-empty">
              <span>No results found for &quot;{query}&quot;</span>
              <span className="search-modal-empty-hint">
                Try different keywords or check your spelling
              </span>
            </div>
          )}

          {!loading && !query.trim() && (
            <div className="search-modal-empty">
              <span>Type to search across findings, scans, and activity</span>
              <span className="search-modal-empty-hint">
                Use keywords like severity names, vulnerability types, or target URLs
              </span>
            </div>
          )}

          {!loading && findings.length > 0 && (
            <div className="search-modal-section">
              <div className="search-modal-section-title">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                Findings
                <span className="search-modal-section-count">({findingsTotal})</span>
              </div>
              {findings.map((f) => {
                const idx = globalIdx++
                return (
                  <div
                    key={`finding-${f.id || idx}`}
                    className={`search-modal-result ${idx === activeIndex ? 'active' : ''}`}
                    onClick={() => navigateToResult({ type: 'finding', data: f })}
                  >
                    <div className="search-modal-result-icon finding">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      </svg>
                    </div>
                    <div className="search-modal-result-text">
                      <div className="search-modal-result-title">{f.title || 'Untitled Finding'}</div>
                      <div className="search-modal-result-meta">
                        {f.category && `${f.category} - `}{f.target || 'Unknown target'}
                      </div>
                    </div>
                    {f.severity && (
                      <span className={`search-modal-result-badge ${f.severity}`}>
                        {f.severity}
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {!loading && activities.length > 0 && (
            <div className="search-modal-section">
              <div className="search-modal-section-title">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                </svg>
                Scans / Activity
                <span className="search-modal-section-count">({activitiesTotal})</span>
              </div>
              {activities.map((a) => {
                const idx = globalIdx++
                return (
                  <div
                    key={`activity-${a.scan_id || idx}-${idx}`}
                    className={`search-modal-result ${idx === activeIndex ? 'active' : ''}`}
                    onClick={() => navigateToResult({ type: 'scan', data: a })}
                  >
                    <div className="search-modal-result-icon scan">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                      </svg>
                    </div>
                    <div className="search-modal-result-text">
                      <div className="search-modal-result-title">{a.message || a.tool || 'Scan Activity'}</div>
                      <div className="search-modal-result-meta">
                        {a.tool && `Tool: ${a.tool} - `}Scan: {a.scan_id?.substring(0, 8) || 'N/A'}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div className="search-modal-footer">
          <div className="search-modal-footer-keys">
            <span className="search-modal-footer-key"><kbd>&#8593;&#8595;</kbd> Navigate</span>
            <span className="search-modal-footer-key"><kbd>Enter</kbd> Open</span>
            <span className="search-modal-footer-key"><kbd>Esc</kbd> Close</span>
          </div>
          <span>Global Search</span>
        </div>
      </div>
    </div>
  )
}
