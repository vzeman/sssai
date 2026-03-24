import { useEffect, useCallback, useSyncExternalStore } from 'react'
import wsManager from '../services/WebSocketManager'

/** Subscribe to wsManager status via useSyncExternalStore (no setState in effect). */
function subscribeToStatus(callback) {
  return wsManager.on('status_change', callback)
}

function getStatus() {
  return wsManager.status
}

/**
 * Hook to manage WebSocket connection lifecycle and status.
 * Connects on mount (when token is truthy), disconnects on unmount.
 *
 * @param {string} token - JWT auth token
 * @returns {{ status: string, subscribe: function }}
 */
export function useWebSocket(token) {
  const status = useSyncExternalStore(subscribeToStatus, getStatus)

  useEffect(() => {
    if (!token) return

    // Connect if not already connected
    if (wsManager.status === 'disconnected') {
      wsManager.connect(token)
    }
  }, [token])

  const subscribe = useCallback((eventType, handler) => {
    return wsManager.on(eventType, handler)
  }, [])

  return { status, subscribe }
}

/**
 * Hook to subscribe to scan update events.
 *
 * @param {string} token - JWT auth token
 * @param {function} onScanUpdate - Called with scan update data
 * @returns {{ wsStatus: string }}
 */
export function useScanUpdates(token, onScanUpdate) {
  const { status, subscribe } = useWebSocket(token)

  useEffect(() => {
    if (!onScanUpdate) return
    return subscribe('scan_update', onScanUpdate)
  }, [subscribe, onScanUpdate])

  return { wsStatus: status }
}
