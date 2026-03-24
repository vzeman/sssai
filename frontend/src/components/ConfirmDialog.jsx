import { useEffect, useRef } from 'react'
import { useFocusTrap } from '../hooks/useFocusTrap'
import './ConfirmDialog.css'

export default function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  confirmVariant = 'danger',
  onConfirm,
  onCancel,
  isLoading = false,
}) {
  useEffect(() => {
    if (!open) return
    function handleEsc(e) {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handleEsc)
    return () => document.removeEventListener('keydown', handleEsc)
  }, [open, onCancel])

  const dialogRef = useRef(null)
  useFocusTrap(dialogRef, open)

  if (!open) return null

  return (
    <div className="confirm-dialog-overlay" onClick={onCancel} role="dialog" aria-modal="true">
      <div className="confirm-dialog" onClick={e => e.stopPropagation()} ref={dialogRef} aria-labelledby="confirm-dialog-title">
        <h3 className="confirm-dialog-title" id="confirm-dialog-title">{title}</h3>
        <p className="confirm-dialog-description">{description}</p>
        <div className="confirm-dialog-footer">
          <button
            className="confirm-btn confirm-btn-cancel"
            onClick={onCancel}
            disabled={isLoading}
          >
            {cancelLabel}
          </button>
          <button
            className={`confirm-btn confirm-btn-${confirmVariant}`}
            onClick={onConfirm}
            disabled={isLoading}
          >
            {isLoading ? 'Processing...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
