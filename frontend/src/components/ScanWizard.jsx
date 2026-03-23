import React, { useState, useEffect } from 'react';
import axios from 'axios';
import '../styles/ScanWizard.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:8000/api';

export default function ScanWizard() {
  const [currentStep, setCurrentStep] = useState(0);
  const [target, setTarget] = useState('');
  const [targetDetection, setTargetDetection] = useState(null);
  const [selectedTemplate, setSelectedTemplate] = useState('quick');
  const [templates, setTemplates] = useState([]);
  const [customConfig, setCustomConfig] = useState({});
  const [validationErrors, setValidationErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [createdScan, setCreatedScan] = useState(null);

  const STEPS = [
    { id: 0, name: 'Target', description: 'Enter target to scan' },
    { id: 1, name: 'Template', description: 'Choose scan template' },
    { id: 2, name: 'Advanced', description: 'Custom configuration (optional)' },
    { id: 3, name: 'Review', description: 'Review and confirm' },
  ];

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      const response = await axios.get(`${API_BASE}/wizard/templates`);
      setTemplates(response.data);
    } catch (error) {
      console.error('Failed to load templates:', error);
    }
  };

  const detectTarget = async (value) => {
    setTarget(value);
    if (value.length < 3) {
      setTargetDetection(null);
      return;
    }

    try {
      setLoading(true);
      const response = await axios.post(`${API_BASE}/wizard/detect-target`, {
        target: value,
      });
      setTargetDetection(response.data);

      // Auto-recommend template
      const recommendResponse = await axios.post(
        `${API_BASE}/wizard/recommend-template`,
        { target: value }
      );
      setSelectedTemplate(recommendResponse.data.recommended_template);
    } catch (error) {
      console.error('Detection failed:', error);
      setTargetDetection(null);
    } finally {
      setLoading(false);
    }
  };

  const validateStep = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API_BASE}/wizard/validate`, {
        target,
        template: selectedTemplate,
        custom_config: customConfig,
      });

      if (!response.data.is_valid) {
        setValidationErrors(response.data.errors);
        return false;
      }

      setValidationErrors({});
      return true;
    } catch (error) {
      console.error('Validation failed:', error);
      setValidationErrors({ general: 'Validation failed' });
      return false;
    } finally {
      setLoading(false);
    }
  };

  const handleNext = async () => {
    if (await validateStep()) {
      if (currentStep < STEPS.length - 1) {
        setCurrentStep(currentStep + 1);
      }
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleCreateScan = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API_BASE}/wizard/create`, {
        target,
        template: selectedTemplate,
        custom_config: customConfig,
      });

      setCreatedScan(response.data);
      // Could redirect to scan details here
    } catch (error) {
      console.error('Failed to create scan:', error);
      setValidationErrors({
        general: error.response?.data?.detail || 'Failed to create scan',
      });
    } finally {
      setLoading(false);
    }
  };

  if (createdScan) {
    return (
      <div className="scan-wizard-success">
        <div className="success-card">
          <h2>✓ Scan Created Successfully</h2>
          <p>Scan ID: <code>{createdScan.scan_id}</code></p>
          <p>Target: {createdScan.target}</p>
          <p>Template: {createdScan.template}</p>
          <p>Status: <span className="status-badge">{createdScan.status}</span></p>

          <div className="action-buttons">
            <button
              onClick={() => window.location.href = `/scans/${createdScan.scan_id}`}
              className="btn btn-primary"
            >
              View Scan Details
            </button>
            <button
              onClick={() => {
                setCurrentStep(0);
                setTarget('');
                setSelectedTemplate('quick');
                setCustomConfig({});
                setCreatedScan(null);
              }}
              className="btn btn-secondary"
            >
              Create Another Scan
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="scan-wizard">
      <div className="wizard-container">
        {/* Progress Bar */}
        <div className="progress-bar">
          {STEPS.map((step, idx) => (
            <div
              key={step.id}
              className={`progress-step ${idx <= currentStep ? 'active' : ''} ${
                idx === currentStep ? 'current' : ''
              }`}
              onClick={() => setCurrentStep(idx)}
            >
              <div className="step-number">{step.id + 1}</div>
              <div className="step-info">
                <div className="step-name">{step.name}</div>
                <div className="step-desc">{step.description}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Step Content */}
        <div className="wizard-content">
          {/* Step 0: Target */}
          {currentStep === 0 && (
            <div className="wizard-step">
              <h2>What do you want to scan?</h2>
              <p>Enter a domain, IP address, URL, or email address</p>

              <div className="input-group">
                <input
                  type="text"
                  placeholder="example.com, 192.168.1.1, https://example.com, or user@example.com"
                  value={target}
                  onChange={(e) => detectTarget(e.target.value)}
                  className="input-large"
                  disabled={loading}
                />
                {loading && <div className="spinner"></div>}
              </div>

              {targetDetection && (
                <div className={`detection-result ${targetDetection.confidence > 0.7 ? 'success' : 'warning'}`}>
                  <h4>Detected Target</h4>
                  <p>
                    <strong>Type:</strong> {targetDetection.type}
                  </p>
                  <p>
                    <strong>Normalized:</strong> <code>{targetDetection.normalized}</code>
                  </p>
                  <p>
                    <strong>Confidence:</strong> {(targetDetection.confidence * 100).toFixed(0)}%
                  </p>
                </div>
              )}

              {validationErrors.target && (
                <div className="error-message">{validationErrors.target}</div>
              )}

              <div className="wizard-actions">
                <button className="btn btn-secondary" disabled>
                  Back
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleNext}
                  disabled={!target || loading}
                >
                  Next: Choose Template
                </button>
              </div>
            </div>
          )}

          {/* Step 1: Template Selection */}
          {currentStep === 1 && (
            <div className="wizard-step">
              <h2>Choose a Scan Template</h2>
              <p>Select the type of scan based on your needs</p>

              <div className="template-grid">
                {templates.map((template) => (
                  <div
                    key={template.id}
                    className={`template-card ${selectedTemplate === template.id ? 'selected' : ''}`}
                    onClick={() => setSelectedTemplate(template.id)}
                  >
                    <div className="template-header">
                      <h4>{template.name}</h4>
                      <span className="template-duration">{template.duration}</span>
                    </div>
                    <p className="template-description">{template.description}</p>
                    <div className="template-meta">
                      <span>{template.modules_count} modules</span>
                      <span className="depth-badge">{template.depth}</span>
                    </div>
                  </div>
                ))}
              </div>

              {validationErrors.template && (
                <div className="error-message">{validationErrors.template}</div>
              )}

              <div className="wizard-actions">
                <button className="btn btn-secondary" onClick={handlePrevious}>
                  Back
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleNext}
                  disabled={loading}
                >
                  Next: Advanced Options
                </button>
              </div>
            </div>
          )}

          {/* Step 2: Advanced Options */}
          {currentStep === 2 && (
            <div className="wizard-step">
              <h2>Advanced Configuration (Optional)</h2>
              <p>Customize scan settings (leave empty for defaults)</p>

              <div className="config-section">
                <label>Custom Configuration (JSON)</label>
                <textarea
                  placeholder='{"timeout": 30, "aggressive": true}'
                  value={JSON.stringify(customConfig, null, 2)}
                  onChange={(e) => {
                    try {
                      setCustomConfig(JSON.parse(e.target.value || '{}'));
                    } catch {
                      // Invalid JSON, ignore
                    }
                  }}
                  className="config-textarea"
                  rows={6}
                />
              </div>

              <div className="wizard-actions">
                <button className="btn btn-secondary" onClick={handlePrevious}>
                  Back
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleNext}
                  disabled={loading}
                >
                  Next: Review
                </button>
              </div>
            </div>
          )}

          {/* Step 3: Review */}
          {currentStep === 3 && (
            <div className="wizard-step">
              <h2>Review Your Scan</h2>
              <p>Confirm settings before creating scan</p>

              <div className="review-section">
                <div className="review-item">
                  <strong>Target:</strong>
                  <span className="review-value">{target}</span>
                </div>
                <div className="review-item">
                  <strong>Target Type:</strong>
                  <span className="review-value">{targetDetection?.type}</span>
                </div>
                <div className="review-item">
                  <strong>Normalized:</strong>
                  <span className="review-value">{targetDetection?.normalized}</span>
                </div>
                <div className="review-item">
                  <strong>Template:</strong>
                  <span className="review-value">
                    {templates.find((t) => t.id === selectedTemplate)?.name}
                  </span>
                </div>
                <div className="review-item">
                  <strong>Estimated Duration:</strong>
                  <span className="review-value">
                    {templates.find((t) => t.id === selectedTemplate)?.duration}
                  </span>
                </div>
                {Object.keys(customConfig).length > 0 && (
                  <div className="review-item">
                    <strong>Custom Config:</strong>
                    <span className="review-value">
                      <code>{JSON.stringify(customConfig)}</code>
                    </span>
                  </div>
                )}
              </div>

              {validationErrors.general && (
                <div className="error-message">{validationErrors.general}</div>
              )}

              <div className="wizard-actions">
                <button
                  className="btn btn-secondary"
                  onClick={handlePrevious}
                  disabled={loading}
                >
                  Back
                </button>
                <button
                  className="btn btn-success"
                  onClick={handleCreateScan}
                  disabled={loading}
                >
                  {loading ? 'Creating Scan...' : 'Create Scan'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
