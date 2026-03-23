/**
 * WebSocket Manager for real-time dashboard updates
 * Handles connection, reconnection, and message handling
 */

class WebSocketManager {
  constructor(userId, apiBase) {
    this.userId = userId
    this.apiBase = apiBase
    this.ws = null
    this.listeners = {}
    this.reconnectAttempts = 0
    this.maxReconnectAttempts = 5
    this.reconnectDelay = 3000
  }

  /**
   * Establish WebSocket connection
   */
  connect() {
    if (this.ws) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/api/dashboard/ws`

    try {
      this.ws = new WebSocket(wsUrl)

      this.ws.onopen = () => {
        console.log('WebSocket connected')
        this.reconnectAttempts = 0
        
        // Send user_id for identification
        this.send({ type: 'identify', user_id: this.userId })
        this.emit('connected')
      }

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          this.handleMessage(data)
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err)
        }
      }

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error)
        this.emit('error', 'Connection error')
      }

      this.ws.onclose = () => {
        console.log('WebSocket disconnected')
        this.ws = null
        this.emit('disconnected')
        this.attemptReconnect()
      }
    } catch (err) {
      console.error('Failed to create WebSocket:', err)
      this.attemptReconnect()
    }
  }

  /**
   * Attempt to reconnect with exponential backoff
   */
  attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached')
      this.emit('error', 'Connection failed')
      return
    }

    this.reconnectAttempts++
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1)
    
    console.log(`Attempting reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`)
    setTimeout(() => this.connect(), delay)
  }

  /**
   * Send message through WebSocket
   */
  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify(message))
      } catch (err) {
        console.error('Failed to send WebSocket message:', err)
      }
    } else {
      console.warn('WebSocket not connected, cannot send message')
    }
  }

  /**
   * Handle incoming messages
   */
  handleMessage(data) {
    const { type } = data

    if (type === 'pong') {
      // Pong response to ping
      return
    }

    // Emit type-specific event
    this.emit(type, data)
  }

  /**
   * Register event listener
   */
  on(event, callback) {
    if (!this.listeners[event]) {
      this.listeners[event] = []
    }
    this.listeners[event].push(callback)
  }

  /**
   * Unregister event listener
   */
  off(event, callback) {
    if (!this.listeners[event]) return
    
    this.listeners[event] = this.listeners[event].filter(cb => cb !== callback)
  }

  /**
   * Emit event to listeners
   */
  emit(event, data) {
    if (!this.listeners[event]) return

    this.listeners[event].forEach(callback => {
      try {
        callback(data)
      } catch (err) {
        console.error(`Error in listener for event '${event}':`, err)
      }
    })
  }

  /**
   * Send a ping message
   */
  ping() {
    this.send({
      type: 'ping',
      timestamp: new Date().toISOString(),
    })
  }

  /**
   * Subscribe to a specific update channel
   */
  subscribe(channel) {
    this.send({
      type: 'subscribe',
      channel,
    })
  }

  /**
   * Disconnect WebSocket
   */
  disconnect() {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this.reconnectAttempts = 0
  }

  /**
   * Check if connected
   */
  isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN
  }
}

export default WebSocketManager
