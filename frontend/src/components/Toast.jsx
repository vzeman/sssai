import { useToast } from './ToastContext'
import '../styles/Toast.css'

const ICONS = {
  success: '\u2713',
  error: '\u2717',
  warning: '\u26A0',
  info: '\u2139',
}

function Toast() {
  const { toasts, removeToast } = useToast()

  if (toasts.length === 0) return null

  return (
    <div className="toast-container">
      {toasts.map(toast => (
        <div
          key={toast.id}
          className={`toast toast-${toast.type}${toast.removing ? ' removing' : ''}`}
        >
          <span className="toast-icon">{ICONS[toast.type] || ICONS.info}</span>
          <span className="toast-message">{toast.message}</span>
          <button
            className="toast-dismiss"
            onClick={() => removeToast(toast.id)}
            aria-label="Dismiss"
          >
            &times;
          </button>
        </div>
      ))}
    </div>
  )
}

export default Toast
