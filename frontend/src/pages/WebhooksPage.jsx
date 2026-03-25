import { useState, useEffect } from 'react'

const API_BASE = import.meta.env.VITE_API_URL || ''

function WebhooksPage({ token }) {
  const [webhooks, setWebhooks] = useState([])

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const resp = await fetch(`${API_BASE}/api/webhooks`, {
          headers: { Authorization: `Bearer ${token}` },
        })
        if (resp.ok && !cancelled) {
          setWebhooks(await resp.json())
        }
      } catch (err) {
        if (!cancelled) console.error('Failed to fetch webhooks:', err)
      }
    }
    load()
    return () => { cancelled = true }
  }, [token])

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Webhooks & Integrations</h1>
        <p className="text-sm text-gray-400 mt-1">Configure webhooks and external integrations</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5">
          <h2 className="text-base font-semibold text-white mb-2">Webhook Management</h2>
          <p className="text-sm text-gray-400 mb-2">Create and manage webhook endpoints:</p>
          <ul className="text-sm text-gray-400 list-disc list-inside space-y-1">
            <li>Receive scan completion notifications</li>
            <li>Post findings to external systems</li>
            <li>Custom payload configuration</li>
            <li>Retry and timeout settings</li>
          </ul>
        </div>

        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5">
          <h2 className="text-base font-semibold text-white mb-2">Integration Providers</h2>
          <p className="text-sm text-gray-400 mb-2">Pre-built integrations with popular tools:</p>
          <ul className="text-sm text-gray-400 list-disc list-inside space-y-1">
            <li>Slack notifications</li>
            <li>Jira issue creation</li>
            <li>GitHub issue posting</li>
            <li>Email notifications</li>
          </ul>
        </div>

        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5">
          <h2 className="text-base font-semibold text-white mb-2">Webhook Logs</h2>
          <p className="text-sm text-gray-400">Monitor webhook delivery and retry history</p>
        </div>
      </div>

      {webhooks.length > 0 && (
        <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-5">
          <h2 className="text-lg font-semibold text-white mb-4">Configured Webhooks</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">URL</th>
                  <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Event</th>
                  <th className="text-left py-2 px-3 text-xs text-gray-500 uppercase tracking-wider font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {webhooks.map(wh => (
                  <tr key={wh.id} className="border-b border-gray-700/50 hover:bg-gray-800/40">
                    <td className="py-2 px-3 text-gray-300 font-mono text-xs truncate max-w-xs">
                      {wh.url?.substring(0, 50)}...
                    </td>
                    <td className="py-2 px-3 text-white">{wh.event || 'N/A'}</td>
                    <td className="py-2 px-3">
                      <span className="inline-block px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-medium">Active</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default WebhooksPage
