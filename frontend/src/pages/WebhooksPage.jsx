import { useState, useEffect } from 'react'
import './StubPage.css'

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
    <div className="page-container">
      <div className="page-header">
        <h1>Webhooks & Integrations</h1>
        <p>Configure webhooks and external integrations</p>
      </div>

      <div className="stub-content">
        <div className="feature-card">
          <h2>Webhook Management</h2>
          <p>Create and manage webhook endpoints:</p>
          <ul>
            <li>Receive scan completion notifications</li>
            <li>Post findings to external systems</li>
            <li>Custom payload configuration</li>
            <li>Retry and timeout settings</li>
          </ul>
        </div>

        <div className="feature-card">
          <h2>Integration Providers</h2>
          <p>Pre-built integrations with popular tools:</p>
          <ul>
            <li>Slack notifications</li>
            <li>Jira issue creation</li>
            <li>GitHub issue posting</li>
            <li>Email notifications</li>
          </ul>
        </div>

        <div className="feature-card">
          <h2>Webhook Logs</h2>
          <p>Monitor webhook delivery and retry history</p>
        </div>
      </div>

      {webhooks.length > 0 && (
        <div className="webhooks-list">
          <h2>Configured Webhooks</h2>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#111420', borderBottom: '1px solid #2a2d3a' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>URL</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>Event</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', color: '#888' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map(wh => (
                <tr key={wh.id} style={{ borderBottom: '1px solid #2a2d3a' }}>
                  <td style={{ padding: '12px 16px', color: '#e8eaed', fontSize: '12px' }}>
                    {wh.url?.substring(0, 50)}...
                  </td>
                  <td style={{ padding: '12px 16px', color: '#e8eaed' }}>{wh.event || 'N/A'}</td>
                  <td style={{ padding: '12px 16px', color: '#44ff44' }}>Active</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default WebhooksPage
