/**
 * WebSocketManager — singleton managing the WebSocket connection to the
 * backend for real-time scan updates.
 *
 * Usage:
 *   import wsManager from '../services/WebSocketManager'
 *   wsManager.connect(token)
 *   wsManager.on('scan_update', (data) => { ... })
 *   wsManager.off('scan_update', handler)
 *   wsManager.disconnect()
 */

const WS_RECONNECT_DELAY_MS = 3000
const WS_PING_INTERVAL_MS = 25000

class WebSocketManager {
  constructor() {
    this._ws = null
    this._token = null
    this._listeners = {}
    this._reconnectTimer = null
    this._pingTimer = null
    this._intentionalClose = false
    this._status = 'disconnected' // disconnected | connecting | connected
  }

  /** Current connection status. */
  get status() {
    return this._status
  }

  /** Connect (or reconnect) to the WebSocket server. */
  connect(token) {
    if (!token) return
    this._token = token
    this._intentionalClose = false
    this._open()
  }

  /** Gracefully disconnect. */
  disconnect() {
    this._intentionalClose = true
    this._clearTimers()
    if (this._ws) {
      this._ws.close()
      this._ws = null
    }
    this._setStatus('disconnected')
  }

  /** Subscribe to a message type. Returns unsubscribe function. */
  on(type, handler) {
    if (!this._listeners[type]) {
      this._listeners[type] = new Set()
    }
    this._listeners[type].add(handler)
    return () => this.off(type, handler)
  }

  /** Unsubscribe a handler. */
  off(type, handler) {
    if (this._listeners[type]) {
      this._listeners[type].delete(handler)
    }
  }

  /** Send a JSON message to the server. */
  send(data) {
    if (this._ws && this._ws.readyState === WebSocket.OPEN) {
      this._ws.send(JSON.stringify(data))
    }
  }

  // ── Internal ──────────────────────────────────────────────────────

  _open() {
    this._clearTimers()
    if (this._ws) {
      this._ws.close()
      this._ws = null
    }

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const apiBase = import.meta.env.VITE_API_URL || ''
    let wsUrl

    if (apiBase) {
      // Replace http(s) with ws(s)
      wsUrl = apiBase.replace(/^http/, 'ws') + '/ws'
    } else {
      wsUrl = `${protocol}://${window.location.host}/ws`
    }

    this._setStatus('connecting')
    this._ws = new WebSocket(wsUrl)

    this._ws.onopen = () => {
      // Authenticate immediately after connecting
      this._ws.send(JSON.stringify({ type: 'auth', token: this._token }))
    }

    this._ws.onmessage = (event) => {
      let msg
      try {
        msg = JSON.parse(event.data)
      } catch {
        return
      }

      if (msg.type === 'connected') {
        this._setStatus('connected')
        this._startPing()
        this._emit('connected', msg)
        return
      }

      if (msg.type === 'error') {
        this._emit('error', msg)
        // Auth error — don't reconnect
        if (msg.message === 'Invalid token' || msg.message === 'Authentication required') {
          this._intentionalClose = true
          this._setStatus('disconnected')
        }
        return
      }

      if (msg.type === 'pong') {
        return // heartbeat response, ignore
      }

      // Dispatch to listeners
      this._emit(msg.type, msg)
    }

    this._ws.onclose = () => {
      this._setStatus('disconnected')
      this._clearTimers()
      if (!this._intentionalClose) {
        this._scheduleReconnect()
      }
    }

    this._ws.onerror = () => {
      // onclose will fire after onerror, which handles reconnect
    }
  }

  _setStatus(newStatus) {
    if (this._status !== newStatus) {
      this._status = newStatus
      this._emit('status_change', { status: newStatus })
    }
  }

  _emit(type, data) {
    const handlers = this._listeners[type]
    if (handlers) {
      handlers.forEach((fn) => {
        try {
          fn(data)
        } catch (err) {
          console.error(`WebSocket listener error (${type}):`, err)
        }
      })
    }
  }

  _startPing() {
    this._pingTimer = setInterval(() => {
      this.send({ type: 'ping' })
    }, WS_PING_INTERVAL_MS)
  }

  _scheduleReconnect() {
    this._reconnectTimer = setTimeout(() => {
      if (this._token && !this._intentionalClose) {
        this._open()
      }
    }, WS_RECONNECT_DELAY_MS)
  }

  _clearTimers() {
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer)
      this._reconnectTimer = null
    }
    if (this._pingTimer) {
      clearInterval(this._pingTimer)
      this._pingTimer = null
    }
  }
}

const wsManager = new WebSocketManager()
export default wsManager
