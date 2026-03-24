import { useEffect, useRef } from 'react'
import { useFocusTrap } from '../hooks/useFocusTrap'
import './DetailModal.css'

export default function DetailModal({ title, data, onClose }) {
  const modalRef = useRef(null)
  useFocusTrap(modalRef, !!data)

  useEffect(() => {
    function handleEsc(e) { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handleEsc)
    return () => document.removeEventListener('keydown', handleEsc)
  }, [onClose])

  if (!data) return null

  function renderValue(val) {
    if (val === null || val === undefined) return <span className="detail-null">—</span>
    if (typeof val === 'boolean') return <span className={`detail-bool ${val ? 'true' : 'false'}`}>{val ? 'Yes' : 'No'}</span>
    if (Array.isArray(val)) {
      if (val.length === 0) return <span className="detail-null">None</span>
      return (
        <ul className="detail-list">
          {val.map((item, i) => (
            <li key={i}>{typeof item === 'object' ? <pre className="detail-json">{JSON.stringify(item, null, 2)}</pre> : String(item)}</li>
          ))}
        </ul>
      )
    }
    if (typeof val === 'object') return <pre className="detail-json">{JSON.stringify(val, null, 2)}</pre>
    return <span>{String(val)}</span>
  }

  function formatKey(key) {
    return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
  }

  const entries = typeof data === 'object' && !Array.isArray(data) ? Object.entries(data) : []

  return (
    <div className="detail-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="detail-modal" onClick={e => e.stopPropagation()} ref={modalRef} aria-labelledby="detail-modal-title">
        <div className="detail-header">
          <h2 id="detail-modal-title">{title || 'Details'}</h2>
          <button className="detail-close" onClick={onClose} aria-label="Close dialog">&times;</button>
        </div>
        <div className="detail-body">
          {entries.length > 0 ? (
            <table className="detail-table">
              <tbody>
                {entries.map(([key, val]) => (
                  <tr key={key}>
                    <th>{formatKey(key)}</th>
                    <td>{renderValue(val)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <pre className="detail-json">{JSON.stringify(data, null, 2)}</pre>
          )}
        </div>
      </div>
    </div>
  )
}
