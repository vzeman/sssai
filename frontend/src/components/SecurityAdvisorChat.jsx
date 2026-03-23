import { useState, useEffect, useRef, useCallback } from 'react'
import './SecurityAdvisorChat.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

const SUGGESTED_QUESTIONS = [
  "What's our biggest security risk right now?",
  "Compare our security posture to last month",
  "Generate a remediation plan for all critical findings",
  "Which targets need scanning most urgently?",
  "Show me all SQL injection findings across all targets",
  "Check for CVEs in our detected tech stack",
]

function parseActionBlocks(text) {
  const actionRegex = /```action\s*([\s\S]*?)```/g
  const actions = []
  let match
  while ((match = actionRegex.exec(text)) !== null) {
    try {
      actions.push(JSON.parse(match[1].trim()))
    } catch {
      // ignore malformed action blocks
    }
  }
  return actions
}

function stripActionBlocks(text) {
  return text.replace(/```action[\s\S]*?```/g, '').trim()
}

function ActionBlock({ action, token, onExecuted }) {
  const [status, setStatus] = useState('idle')
  const [result, setResult] = useState(null)

  async function execute() {
    setStatus('loading')
    try {
      const resp = await fetch(`${API_BASE}/api/chat/actions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(action),
      })
      const data = await resp.json()
      if (!resp.ok) throw new Error(data.detail || 'Action failed')
      setResult(data)
      setStatus('done')
      if (onExecuted) onExecuted(data)
    } catch (err) {
      setResult({ error: err.message })
      setStatus('error')
    }
  }

  const actionLabels = {
    create_scan: `Scan ${action.target} (${action.scan_type})`,
    generate_report: `Generate report: ${action.title || 'Ad-hoc Report'}`,
    validate_finding: `Validate: ${(action.finding || '').slice(0, 50)}`,
    cve_check: `Check CVEs for ${(action.technologies || []).length} technologies`,
  }

  const label = actionLabels[action.action] || `Execute: ${action.action}`

  return (
    <div className={`action-block action-${status}`}>
      <div className="action-label">
        <span className="action-icon">⚡</span>
        {label}
      </div>
      {status === 'idle' && (
        <button className="action-btn" onClick={execute}>
          Run
        </button>
      )}
      {status === 'loading' && <span className="action-status">Running…</span>}
      {status === 'done' && (
        <span className="action-status success">
          {action.action === 'create_scan'
            ? `Scan started (${(result?.scan_id || '').slice(0, 8)}…)`
            : action.action === 'generate_report'
            ? `Found ${result?.total ?? 0} findings`
            : 'Done'}
        </span>
      )}
      {status === 'error' && (
        <span className="action-status error">{result?.error}</span>
      )}
    </div>
  )
}

function Message({ msg, token, onActionExecuted }) {
  const isAgent = msg.role === 'agent'
  const actions = isAgent ? parseActionBlocks(msg.message || '') : []
  const displayText = isAgent ? stripActionBlocks(msg.message || '') : (msg.message || '')
  const isCveAlert = msg.type === 'cve_alert'

  return (
    <div className={`message message-${isAgent ? 'agent' : 'user'} ${isCveAlert ? 'message-alert' : ''}`}>
      <div className="message-avatar">{isAgent ? '🤖' : '👤'}</div>
      <div className="message-body">
        <div className="message-text">{displayText}</div>
        {actions.length > 0 && (
          <div className="action-list">
            {actions.map((act, i) => (
              <ActionBlock
                key={i}
                action={act}
                token={token}
                onExecuted={onActionExecuted}
              />
            ))}
          </div>
        )}
        <div className="message-time">{msg.timestamp || ''}</div>
      </div>
    </div>
  )
}

async function fetchChatHistory(token) {
  const resp = await fetch(`${API_BASE}/api/chat`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error('fetch failed')
  return resp.json()
}

export function SecurityAdvisorChat({ token }) {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [lastTs, setLastTs] = useState(0)
  const bottomRef = useRef(null)
  const pollTimer = useRef(null)

  // Load history on mount
  useEffect(() => {
    let cancelled = false
    fetchChatHistory(token).then((data) => {
      if (cancelled) return
      const msgs = data.messages || []
      setMessages(msgs)
      if (msgs.length) setLastTs(msgs[msgs.length - 1].ts || 0)
    }).catch(() => {})
    return () => { cancelled = true }
  }, [token])

  // Auto-scroll on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Poll for agent replies while loading
  useEffect(() => {
    if (!loading) {
      clearInterval(pollTimer.current)
      return
    }
    pollTimer.current = setInterval(() => {
      fetchChatHistory(token).then((data) => {
        const msgs = data.messages || []
        if (msgs.length > 0) {
          const newest = msgs[msgs.length - 1]
          if (newest.ts > lastTs && newest.role === 'agent') {
            setMessages(msgs)
            setLastTs(newest.ts)
            setLoading(false)
          }
        }
      }).catch(() => {})
    }, 1500)
    return () => clearInterval(pollTimer.current)
  }, [loading, lastTs, token])

  const refreshHistory = useCallback(() => {
    fetchChatHistory(token).then((data) => {
      const msgs = data.messages || []
      setMessages(msgs)
      if (msgs.length) setLastTs(msgs[msgs.length - 1].ts || 0)
    }).catch(() => {})
  }, [token])

  async function sendMessage(text) {
    const msg = text.trim()
    if (!msg) return
    setInput('')
    setLoading(true)
    setMessages((prev) => [...prev, { role: 'human', message: msg, timestamp: '', ts: 0 }])

    try {
      await fetch(`${API_BASE}/api/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ message: msg }),
      })
    } catch {
      setLoading(false)
    }
  }

  async function clearChat() {
    await fetch(`${API_BASE}/api/chat`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    })
    setMessages([])
    setLastTs(0)
  }

  function handleKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage(input)
    }
  }

  return (
    <div className="advisor-chat">
      <div className="advisor-header">
        <div className="advisor-title">
          <span className="advisor-icon">🛡️</span>
          <div>
            <h2>AI Security Advisor</h2>
            <p>Powered by Claude — full access to your scan history, findings, and analytics</p>
          </div>
        </div>
        <button className="clear-btn" onClick={clearChat} title="Clear conversation">
          ✕ Clear
        </button>
      </div>

      <div className="messages-container">
        {messages.length === 0 && (
          <div className="empty-state">
            <div className="empty-icon">🔍</div>
            <h3>Ask me anything about your security posture</h3>
            <p>I have access to all your scan history, findings, and security analytics.</p>
            <div className="suggestions">
              {SUGGESTED_QUESTIONS.map((q, i) => (
                <button key={i} className="suggestion-btn" onClick={() => sendMessage(q)}>
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <Message
            key={i}
            msg={msg}
            token={token}
            onActionExecuted={refreshHistory}
          />
        ))}

        {loading && (
          <div className="message message-agent">
            <div className="message-avatar">🤖</div>
            <div className="message-body">
              <div className="typing-indicator">
                <span /><span /><span />
              </div>
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      <div className="input-area">
        <textarea
          className="chat-input"
          placeholder="Ask about risks, request reports, trigger scans… (Enter to send)"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          rows={2}
          disabled={loading}
        />
        <button
          className="send-btn"
          onClick={() => sendMessage(input)}
          disabled={loading || !input.trim()}
        >
          {loading ? '…' : '➤'}
        </button>
      </div>
    </div>
  )
}

export default SecurityAdvisorChat
