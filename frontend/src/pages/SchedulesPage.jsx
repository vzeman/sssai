import { useState, useEffect } from 'react'
import ConfirmDialog from '../components/ConfirmDialog'
import DetailModal from '../components/DetailModal'
import '../styles/tables.css'
import './StubPage.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

const FREQUENCY_OPTIONS = [
  { value: 'hourly', label: 'Every hour' },
  { value: '6h', label: 'Every 6 hours' },
  { value: '12h', label: 'Every 12 hours' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
]

const SCAN_TYPES = ['full', 'quick', 'api', 'ssl', 'headers', 'recon', 'vulnerability']

function SchedulesPage({ token }) {
  const [schedules, setSchedules] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState(null)
  const [confirmingDelete, setConfirmingDelete] = useState(null)
  const [selectedSchedule, setSelectedSchedule] = useState(null)
  const [actionMsg, setActionMsg] = useState('')

  const [form, setForm] = useState({
    target: '',
    scan_type: 'full',
    cron_expression: 'daily',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    max_runs: 0,
  })

  useEffect(() => {
    fetchSchedules()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (actionMsg) {
      const t = setTimeout(() => setActionMsg(''), 3000)
      return () => clearTimeout(t)
    }
  }, [actionMsg])

  async function apiFetch(path, opts = {}) {
    const resp = await fetch(`${API_BASE}/api/schedules${path}`, {
      ...opts,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        ...(opts.headers || {}),
      },
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `Request failed (${resp.status})`)
    }
    return resp.json()
  }

  async function fetchSchedules() {
    try {
      setLoading(true)
      const data = await apiFetch('/?limit=500')
      setSchedules(Array.isArray(data) ? data : (data.items || []))
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function resetForm() {
    setForm({ target: '', scan_type: 'full', cron_expression: 'daily', timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC', max_runs: 0 })
    setEditingId(null)
    setShowForm(false)
  }

  async function handleSubmit(e) {
    e.preventDefault()
    try {
      if (editingId) {
        await apiFetch(`/${editingId}`, { method: 'PATCH', body: JSON.stringify(form) })
        setActionMsg('Schedule updated')
      } else {
        await apiFetch('/', { method: 'POST', body: JSON.stringify(form) })
        setActionMsg('Schedule created')
      }
      resetForm()
      fetchSchedules()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleToggle(id) {
    try {
      await apiFetch(`/${id}/toggle`, { method: 'POST' })
      fetchSchedules()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleDelete(id) {
    try {
      await apiFetch(`/${id}`, { method: 'DELETE' })
      setConfirmingDelete(null)
      setActionMsg('Schedule deleted')
      fetchSchedules()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleRunNow(id) {
    try {
      const result = await apiFetch(`/${id}/run`, { method: 'POST' })
      setActionMsg(`Scan triggered: ${result.scan_id?.slice(0, 8)}...`)
    } catch (err) {
      setError(err.message)
    }
  }

  function startEdit(sched) {
    setForm({
      target: sched.target,
      scan_type: sched.scan_type,
      cron_expression: sched.cron_expression,
      timezone: sched.timezone || 'UTC',
      max_runs: sched.max_runs || 0,
    })
    setEditingId(sched.id)
    setShowForm(true)
  }

  function formatDate(d) {
    if (!d) return 'N/A'
    return new Date(d).toLocaleString()
  }

  function frequencyLabel(expr) {
    const opt = FREQUENCY_OPTIONS.find(f => f.value === expr)
    return opt ? opt.label : expr
  }

  if (loading) {
    return <div className="page-container"><div className="loading">Loading schedules...</div></div>
  }

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1>Scheduled Scans</h1>
          <p>Create and manage recurring security scans</p>
        </div>
        <button
          onClick={() => { resetForm(); setShowForm(!showForm) }}
          style={btnStyle}
        >
          {showForm ? 'Cancel' : '+ New Schedule'}
        </button>
      </div>

      {actionMsg && (
        <div style={{ padding: '10px 16px', background: '#1a3a2a', border: '1px solid #2a5a3a', borderRadius: 8, color: '#6fdf8f', marginBottom: 16, fontSize: 13 }}>
          {actionMsg}
        </div>
      )}

      {error && (
        <div style={{ padding: '10px 16px', background: '#3a1a1a', border: '1px solid #5a2a2a', borderRadius: 8, color: '#ff6b6b', marginBottom: 16, fontSize: 13 }}>
          {error}
          <button onClick={() => setError('')} style={{ marginLeft: 12, background: 'none', border: 'none', color: '#ff6b6b', cursor: 'pointer' }}>dismiss</button>
        </div>
      )}

      {showForm && (
        <form onSubmit={handleSubmit} style={formContainerStyle}>
          <h3 style={{ margin: '0 0 16px', color: '#e8eaed' }}>{editingId ? 'Edit Schedule' : 'Create New Schedule'}</h3>
          <div style={formGridStyle}>
            <div style={fieldStyle}>
              <label style={labelStyle}>Target URL *</label>
              <input
                type="url"
                required
                placeholder="https://example.com"
                value={form.target}
                onChange={e => setForm({ ...form, target: e.target.value })}
                disabled={!!editingId}
                style={inputStyle}
              />
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Scan Type</label>
              <select value={form.scan_type} onChange={e => setForm({ ...form, scan_type: e.target.value })} style={inputStyle}>
                {SCAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Frequency</label>
              <select value={form.cron_expression} onChange={e => setForm({ ...form, cron_expression: e.target.value })} style={inputStyle}>
                {FREQUENCY_OPTIONS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
              </select>
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Timezone</label>
              <input
                type="text"
                value={form.timezone}
                onChange={e => setForm({ ...form, timezone: e.target.value })}
                style={inputStyle}
                placeholder="UTC"
              />
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Max Runs (0 = unlimited)</label>
              <input
                type="number"
                min="0"
                value={form.max_runs}
                onChange={e => setForm({ ...form, max_runs: parseInt(e.target.value) || 0 })}
                style={inputStyle}
              />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
            <button type="submit" style={btnStyle}>{editingId ? 'Update Schedule' : 'Create Schedule'}</button>
            <button type="button" onClick={resetForm} style={btnSecondaryStyle}>Cancel</button>
          </div>
        </form>
      )}

      {schedules.length === 0 ? (
        <div className="empty-state-card">
          <div className="empty-state-icon" style={{ fontSize: 48 }}>&#128197;</div>
          <h3 className="empty-state-title">No scheduled scans</h3>
          <p className="empty-state-text">Create your first recurring scan to automatically monitor your targets on a schedule.</p>
          <button onClick={() => setShowForm(true)} className="empty-state-cta">Create Schedule</button>
        </div>
      ) : (
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Type</th>
                <th>Frequency</th>
                <th>Status</th>
                <th>Next Run</th>
                <th>Last Run</th>
                <th>Runs</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map(sched => (
                <tr key={sched.id} onClick={() => setSelectedSchedule(sched)}>
                  <td>
                    <span style={{ color: '#4a9eff' }}>{sched.target}</span>
                  </td>
                  <td>
                    <span className="badge">{sched.scan_type}</span>
                  </td>
                  <td>{frequencyLabel(sched.cron_expression)}</td>
                  <td>
                    <span className={`badge ${sched.is_active ? 'active' : 'paused'}`}>
                      {sched.is_active ? 'Active' : 'Paused'}
                    </span>
                  </td>
                  <td className="cell-muted">{formatDate(sched.next_run_at)}</td>
                  <td className="cell-muted">{formatDate(sched.last_run_at)}</td>
                  <td>
                    {sched.run_count || 0}
                    {sched.max_runs ? ` / ${sched.max_runs}` : ''}
                  </td>
                  <td style={{ textAlign: 'right' }} onClick={e => e.stopPropagation()}>
                    <div className="table-actions">
                      <button
                        onClick={() => handleToggle(sched.id)}
                        className="table-action-btn"
                        title={sched.is_active ? 'Pause' : 'Resume'}
                      >
                        {sched.is_active ? 'Pause' : 'Resume'}
                      </button>
                      <button
                        onClick={() => handleRunNow(sched.id)}
                        className="table-action-btn success"
                        title="Run scan now"
                      >
                        Run Now
                      </button>
                      <button
                        onClick={() => startEdit(sched)}
                        className="table-action-btn"
                        title="Edit schedule"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => setConfirmingDelete(sched.id)}
                        className="table-action-btn danger"
                        title="Delete schedule"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedSchedule && (
        <DetailModal
          data={selectedSchedule}
          title={`Schedule: ${selectedSchedule.target}`}
          onClose={() => setSelectedSchedule(null)}
        />
      )}

      <ConfirmDialog
        open={confirmingDelete !== null}
        title="Delete Schedule?"
        description="This will permanently delete the scheduled scan. This action cannot be undone."
        confirmLabel="Delete"
        confirmVariant="danger"
        onConfirm={() => handleDelete(confirmingDelete)}
        onCancel={() => setConfirmingDelete(null)}
      />
    </div>
  )
}

/* Form styles (kept as inline style objects — table styles moved to tables.css) */
const btnStyle = {
  padding: '8px 20px',
  background: '#2a3d50',
  color: '#4a9eff',
  border: '1px solid #3a5070',
  borderRadius: 6,
  fontSize: 13,
  fontWeight: 600,
  cursor: 'pointer',
}

const btnSecondaryStyle = {
  ...btnStyle,
  background: 'transparent',
  borderColor: '#2a2d3a',
  color: '#b0b4c0',
}

const formContainerStyle = {
  background: '#1a1d27',
  border: '1px solid #2a2d3a',
  borderRadius: 8,
  padding: 24,
  marginBottom: 20,
}

const formGridStyle = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
  gap: 16,
}

const fieldStyle = {
  display: 'flex',
  flexDirection: 'column',
  gap: 6,
}

const labelStyle = {
  fontSize: 12,
  color: '#b0b4c0',
  fontWeight: 600,
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
}

const inputStyle = {
  padding: '8px 12px',
  background: '#111420',
  border: '1px solid #2a2d3a',
  borderRadius: 6,
  color: '#e8eaed',
  fontSize: 13,
  outline: 'none',
}

export default SchedulesPage
