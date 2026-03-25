import { useState, useEffect } from 'react'
import ConfirmDialog from '../components/ConfirmDialog'
import DetailModal from '../components/DetailModal'

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
    return <div className="p-6 max-w-6xl mx-auto"><div className="text-gray-400 text-sm">Loading schedules...</div></div>
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Scheduled Scans</h1>
          <p className="text-sm text-gray-400">Create and manage recurring security scans</p>
        </div>
        <button
          onClick={() => { resetForm(); setShowForm(!showForm) }}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition"
        >
          {showForm ? 'Cancel' : '+ New Schedule'}
        </button>
      </div>

      {actionMsg && (
        <div className="px-4 py-2.5 bg-green-900/30 border border-green-800 rounded-lg text-green-400 mb-4 text-sm">
          {actionMsg}
        </div>
      )}

      {error && (
        <div className="px-4 py-2.5 bg-red-900/30 border border-red-800 rounded-lg text-red-400 mb-4 text-sm flex items-center">
          {error}
          <button onClick={() => setError('')} className="ml-3 bg-transparent border-none text-red-400 cursor-pointer text-sm hover:text-red-300">dismiss</button>
        </div>
      )}

      {showForm && (
        <form onSubmit={handleSubmit} className="bg-gray-800/30 border border-gray-700 rounded-xl p-5 mb-5">
          <h3 className="text-white font-semibold mb-4">{editingId ? 'Edit Schedule' : 'Create New Schedule'}</h3>
          <div className="grid grid-cols-[repeat(auto-fit,minmax(220px,1fr))] gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Target URL *</label>
              <input
                type="url"
                required
                placeholder="https://example.com"
                value={form.target}
                onChange={e => setForm({ ...form, target: e.target.value })}
                disabled={!!editingId}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:border-gray-500"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Scan Type</label>
              <select value={form.scan_type} onChange={e => setForm({ ...form, scan_type: e.target.value })} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:border-gray-500">
                {SCAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Frequency</label>
              <select value={form.cron_expression} onChange={e => setForm({ ...form, cron_expression: e.target.value })} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:border-gray-500">
                {FREQUENCY_OPTIONS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Timezone</label>
              <input
                type="text"
                value={form.timezone}
                onChange={e => setForm({ ...form, timezone: e.target.value })}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:border-gray-500"
                placeholder="UTC"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Max Runs (0 = unlimited)</label>
              <input
                type="number"
                min="0"
                value={form.max_runs}
                onChange={e => setForm({ ...form, max_runs: parseInt(e.target.value) || 0 })}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:border-gray-500"
              />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button type="submit" className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition">{editingId ? 'Update Schedule' : 'Create Schedule'}</button>
            <button type="button" onClick={resetForm} className="px-4 py-2 bg-transparent hover:bg-gray-800 text-gray-400 font-semibold rounded-lg text-sm transition border border-gray-700">Cancel</button>
          </div>
        </form>
      )}

      {schedules.length === 0 ? (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-10 text-center">
          <div className="text-5xl mb-4">&#128197;</div>
          <h3 className="text-white font-semibold mb-2">No scheduled scans</h3>
          <p className="text-gray-400 text-sm mb-4">Create your first recurring scan to automatically monitor your targets on a schedule.</p>
          <button onClick={() => setShowForm(true)} className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white font-semibold rounded-lg text-sm transition">Create Schedule</button>
        </div>
      ) : (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Target</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Type</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Frequency</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Status</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Next Run</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Last Run</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Runs</th>
                <th className="bg-gray-900/50 border-b border-gray-700 px-4 py-3 text-right text-xs font-semibold text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map(sched => (
                <tr key={sched.id} onClick={() => setSelectedSchedule(sched)} className="cursor-pointer hover:bg-gray-800/50 transition">
                  <td className="border-b border-gray-700/50 px-4 py-3 text-sm text-cyan-400">{sched.target}</td>
                  <td className="border-b border-gray-700/50 px-4 py-3">
                    <span className="inline-block px-2 py-0.5 rounded text-xs font-medium bg-gray-700/50 text-gray-300">{sched.scan_type}</span>
                  </td>
                  <td className="border-b border-gray-700/50 px-4 py-3 text-sm text-gray-300">{frequencyLabel(sched.cron_expression)}</td>
                  <td className="border-b border-gray-700/50 px-4 py-3">
                    <span className={`inline-block px-2.5 py-1 rounded text-xs font-semibold ${sched.is_active ? 'bg-green-900/50 text-green-400' : 'bg-gray-700/50 text-gray-400'}`}>
                      {sched.is_active ? 'Active' : 'Paused'}
                    </span>
                  </td>
                  <td className="border-b border-gray-700/50 px-4 py-3 text-sm text-gray-500">{formatDate(sched.next_run_at)}</td>
                  <td className="border-b border-gray-700/50 px-4 py-3 text-sm text-gray-500">{formatDate(sched.last_run_at)}</td>
                  <td className="border-b border-gray-700/50 px-4 py-3 text-sm text-gray-300">
                    {sched.run_count || 0}
                    {sched.max_runs ? ` / ${sched.max_runs}` : ''}
                  </td>
                  <td className="border-b border-gray-700/50 px-4 py-3 text-right" onClick={e => e.stopPropagation()}>
                    <div className="flex gap-1 justify-end">
                      <button
                        onClick={() => handleToggle(sched.id)}
                        className="px-2 py-1 text-xs font-medium text-gray-400 hover:text-white bg-gray-700/50 hover:bg-gray-600/50 rounded transition"
                        title={sched.is_active ? 'Pause' : 'Resume'}
                      >
                        {sched.is_active ? 'Pause' : 'Resume'}
                      </button>
                      <button
                        onClick={() => handleRunNow(sched.id)}
                        className="px-2 py-1 text-xs font-medium text-green-400 hover:text-green-300 bg-green-900/30 hover:bg-green-900/50 rounded transition"
                        title="Run scan now"
                      >
                        Run Now
                      </button>
                      <button
                        onClick={() => startEdit(sched)}
                        className="px-2 py-1 text-xs font-medium text-gray-400 hover:text-white bg-gray-700/50 hover:bg-gray-600/50 rounded transition"
                        title="Edit schedule"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => setConfirmingDelete(sched.id)}
                        className="px-2 py-1 text-xs font-medium text-red-400 hover:text-red-300 bg-red-900/30 hover:bg-red-900/50 rounded transition"
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

export default SchedulesPage
