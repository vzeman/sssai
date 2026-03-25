import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_URL || '';

const DEFAULT_TEMPLATES = [
  { id: 'quick', name: 'Quick Scan', description: 'Fast surface-level check — headers, SSL, ports', icon: '\u26A1', duration: '~2 min' },
  { id: 'security', name: 'Security Scan', description: 'Full vulnerability assessment with AI analysis', icon: '\uD83D\uDEE1\uFE0F', duration: '~5 min' },
  { id: 'adaptive', name: 'Adaptive (AI-First)', description: 'AI plans and executes the optimal scan strategy', icon: '\uD83E\uDD16', duration: '~5 min' },
  { id: 'api', name: 'API Scan', description: 'Test API endpoints for auth, injection, rate limits', icon: '\uD83D\uDD0C', duration: '~3 min' },
  { id: 'ssl', name: 'SSL/TLS Audit', description: 'Certificate chain, cipher suites, protocols', icon: '\uD83D\uDD12', duration: '~1 min' },
  { id: 'recon', name: 'Reconnaissance', description: 'Subdomain discovery, tech stack, open ports', icon: '\uD83D\uDD0D', duration: '~3 min' },
];

const STEPS = [
  { id: 0, name: 'Target', description: 'Enter target to scan' },
  { id: 1, name: 'Template', description: 'Choose scan template' },
  { id: 2, name: 'Advanced', description: 'Custom configuration (optional)' },
  { id: 3, name: 'Review', description: 'Review and confirm' },
];

const FREQUENCY_LABELS = {
  hourly: 'Every hour',
  '6h': 'Every 6 hours',
  '12h': 'Every 12 hours',
  daily: 'Daily',
  weekly: 'Weekly',
  monthly: 'Monthly',
};

export default function ScanWizard({ token }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [target, setTarget] = useState('');
  const [targetDetection, setTargetDetection] = useState(null);
  const [selectedTemplate, setSelectedTemplate] = useState('quick');
  const [templates, setTemplates] = useState(DEFAULT_TEMPLATES);
  const [customConfig, setCustomConfig] = useState({});
  const [validationErrors, setValidationErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [createdScan, setCreatedScan] = useState(null);
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [scheduleFrequency, setScheduleFrequency] = useState('daily');

  const authHeaders = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  };

  useEffect(() => {
    loadTemplates();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const loadTemplates = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/wizard/templates`, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error('Failed');
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        setTemplates(data);
      }
    } catch {
      // Use default templates
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
      const res = await fetch(`${API_BASE}/api/wizard/detect-target`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ target: value }),
      });
      if (res.ok) {
        const data = await res.json();
        setTargetDetection(data);

        // Auto-recommend template
        const recRes = await fetch(`${API_BASE}/api/wizard/recommend-template`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ target: value }),
        });
        if (recRes.ok) {
          const recData = await recRes.json();
          if (recData.recommended_template) {
            setSelectedTemplate(recData.recommended_template);
          }
        }
      }
    } catch {
      setTargetDetection(null);
    } finally {
      setLoading(false);
    }
  };

  const validateStep = () => {
    const errors = {};
    if (currentStep === 0 && !target.trim()) {
      errors.target = 'Target is required';
    }
    if (Object.keys(errors).length > 0) {
      setValidationErrors(errors);
      return false;
    }
    setValidationErrors({});
    return true;
  };

  const nextStep = () => {
    if (validateStep() && currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const submitScan = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/api/scans/`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          target,
          scan_type: selectedTemplate,
          config: Object.keys(customConfig).length > 0 ? customConfig : undefined,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Failed to create scan');
      }

      const data = await res.json();

      // Create schedule if recurring scan is enabled
      if (scheduleEnabled) {
        try {
          await fetch(`${API_BASE}/api/schedules/`, {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({
              target,
              scan_type: selectedTemplate,
              cron_expression: scheduleFrequency,
              timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
              max_runs: 0,
            }),
          });
        } catch {
          // Schedule creation failed silently
        }
      }

      setCreatedScan({ ...data, scheduled: scheduleEnabled });
    } catch (error) {
      setValidationErrors({ general: error.message || 'Failed to create scan' });
    } finally {
      setLoading(false);
    }
  };

  const selectedTemplateMeta = templates.find((t) => t.id === selectedTemplate);

  // ── Success state ──────────────────────────────────────────────────
  if (createdScan) {
    return (
      <div className="theme-page">
        <div className="max-w-xl mx-auto">
          <div className="text-center py-8">
            <div className="text-5xl mb-4">{'\u2705'}</div>
            <h3 className="text-xl font-bold text-white mb-2">Scan Created!</h3>
            <p className="text-gray-400 text-sm mb-1">
              Scan ID: {createdScan?.id?.slice(0, 8) || createdScan?.scan_id?.slice(0, 8)}
            </p>
            <p className="text-gray-400 text-sm mb-1">Target: {target}</p>
            <p className="text-gray-400 text-sm mb-1">Template: {selectedTemplateMeta?.name}</p>
            {createdScan.scheduled && (
              <p className="text-cyan-400 text-sm mb-1">Recurring scan scheduled</p>
            )}
            <div className="flex items-center justify-center gap-3 mt-6">
              <Link
                to={`/scans/${createdScan?.id || createdScan?.scan_id}`}
                className="theme-btn-primary"
              >
                View Scan
              </Link>
              <button
                onClick={() => {
                  setCurrentStep(0);
                  setTarget('');
                  setSelectedTemplate('quick');
                  setCustomConfig({});
                  setCreatedScan(null);
                  setTargetDetection(null);
                  setScheduleEnabled(false);
                  setValidationErrors({});
                }}
                className="theme-btn-secondary"
              >
                Create Another
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ── Wizard ─────────────────────────────────────────────────────────
  return (
    <div className="theme-page">
      <div className="max-w-2xl mx-auto">
        {/* Step indicator */}
        <div className="flex items-center justify-center gap-2 mb-8">
          {STEPS.map((step, idx) => (
            <div key={step.id} className="flex items-center gap-2">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${
                idx < currentStep ? 'bg-cyan-700 text-white' :
                idx === currentStep ? 'bg-cyan-500 text-white' :
                'bg-gray-700 text-gray-400'
              }`}>{idx + 1}</div>
              <span className={`text-xs hidden sm:inline ${idx === currentStep ? 'text-white font-medium' : 'text-gray-500'}`}>{step.name}</span>
              {idx < STEPS.length - 1 && <div className="w-8 h-px bg-gray-700" />}
            </div>
          ))}
        </div>

        {/* Step 0: Target */}
        {currentStep === 0 && (
          <div className="theme-card-padded">
            <h2 className="text-lg font-bold text-white mb-1">What do you want to scan?</h2>
            <p className="text-sm text-gray-400 mb-5">Enter a domain, IP address, URL, or email address</p>

            <div className="relative">
              <input
                type="text"
                placeholder="example.com, 192.168.1.1, https://example.com"
                value={target}
                onChange={(e) => detectTarget(e.target.value)}
                className="theme-input-lg"
                disabled={loading}
              />
              {loading && (
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  <div className="w-5 h-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                </div>
              )}
            </div>

            {targetDetection && (
              <div className={`mt-4 ${targetDetection.confidence > 0.7 ? 'theme-alert-success' : 'theme-alert-info'}`}>
                <p className="font-medium mb-1">Detected: {targetDetection.type}</p>
                <p className="text-xs opacity-80">
                  Normalized: <code className="bg-black/20 px-1 rounded">{targetDetection.normalized}</code>
                  {' \u2014 '}{(targetDetection.confidence * 100).toFixed(0)}% confidence
                </p>
              </div>
            )}

            {validationErrors.target && (
              <div className="theme-alert-error mt-3">{validationErrors.target}</div>
            )}

            <div className="flex justify-between mt-6">
              <div />
              <button
                onClick={nextStep}
                disabled={!target || loading}
                className="theme-btn-primary"
              >
                Next
              </button>
            </div>
          </div>
        )}

        {/* Step 1: Template selection */}
        {currentStep === 1 && (
          <div>
            <h2 className="text-lg font-bold text-white mb-1">Choose a Scan Template</h2>
            <p className="text-sm text-gray-400 mb-5">Select the type of scan based on your needs</p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {templates.map((t) => (
                <div
                  key={t.id}
                  onClick={() => setSelectedTemplate(t.id)}
                  className={`theme-card-padded cursor-pointer transition ${
                    selectedTemplate === t.id ? 'ring-2 ring-cyan-500 bg-gray-800/60' : 'hover:bg-gray-800/60'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl">{t.icon}</span>
                    {t.duration && <span className="text-xs text-gray-500">{t.duration}</span>}
                  </div>
                  <h4 className="text-sm font-semibold text-white mb-1">{t.name}</h4>
                  <p className="text-xs text-gray-400 leading-relaxed">{t.description}</p>
                </div>
              ))}
            </div>

            {validationErrors.template && (
              <div className="theme-alert-error mt-3">{validationErrors.template}</div>
            )}

            <div className="flex justify-between mt-6">
              <button onClick={prevStep} className="theme-btn-secondary">Back</button>
              <button onClick={nextStep} className="theme-btn-primary">Next</button>
            </div>
          </div>
        )}

        {/* Step 2: Advanced config */}
        {currentStep === 2 && (
          <div>
            <h2 className="text-lg font-bold text-white mb-1">Advanced Configuration</h2>
            <p className="text-sm text-gray-400 mb-5">Customize scan settings and scheduling (optional)</p>

            {/* Schedule toggle */}
            <div className="theme-card-padded mb-4">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={scheduleEnabled}
                  onChange={(e) => setScheduleEnabled(e.target.checked)}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500"
                />
                <div>
                  <span className="text-sm font-medium text-white">Schedule recurring scans</span>
                  <p className="text-xs text-gray-500 mt-0.5">Automatically run this scan on a regular schedule</p>
                </div>
              </label>

              {scheduleEnabled && (
                <div className="mt-4 pl-7">
                  <label className="theme-label">Frequency</label>
                  <select
                    value={scheduleFrequency}
                    onChange={(e) => setScheduleFrequency(e.target.value)}
                    className="theme-select"
                  >
                    <option value="hourly">Every hour</option>
                    <option value="6h">Every 6 hours</option>
                    <option value="12h">Every 12 hours</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
              )}
            </div>

            {/* Custom JSON config */}
            <div className="theme-card-padded">
              <label className="theme-label">Custom Configuration (JSON)</label>
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
                className="theme-textarea mt-2"
                rows={5}
              />
            </div>

            <div className="flex justify-between mt-6">
              <button onClick={prevStep} className="theme-btn-secondary">Back</button>
              <button onClick={nextStep} className="theme-btn-primary">Next</button>
            </div>
          </div>
        )}

        {/* Step 3: Review */}
        {currentStep === 3 && (
          <div>
            <h2 className="text-lg font-bold text-white mb-1">Review Your Scan</h2>
            <p className="text-sm text-gray-400 mb-5">Confirm settings before starting</p>

            <div className="theme-card-padded">
              <div className="space-y-3">
                <div className="flex justify-between py-2 border-b border-gray-700">
                  <span className="text-gray-400 text-sm">Target</span>
                  <span className="text-white text-sm font-medium">{target}</span>
                </div>
                {targetDetection?.type && (
                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400 text-sm">Target Type</span>
                    <span className="text-white text-sm font-medium">{targetDetection.type}</span>
                  </div>
                )}
                {targetDetection?.normalized && (
                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400 text-sm">Normalized</span>
                    <span className="text-white text-sm font-medium font-mono">{targetDetection.normalized}</span>
                  </div>
                )}
                <div className="flex justify-between py-2 border-b border-gray-700">
                  <span className="text-gray-400 text-sm">Template</span>
                  <span className="text-white text-sm font-medium">{selectedTemplateMeta?.name}</span>
                </div>
                {selectedTemplateMeta?.duration && (
                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400 text-sm">Estimated Duration</span>
                    <span className="text-white text-sm font-medium">{selectedTemplateMeta.duration}</span>
                  </div>
                )}
                <div className="flex justify-between py-2 border-b border-gray-700">
                  <span className="text-gray-400 text-sm">Schedule</span>
                  <span className="text-white text-sm font-medium">
                    {scheduleEnabled ? (
                      <span className="text-cyan-400">{FREQUENCY_LABELS[scheduleFrequency] || scheduleFrequency}</span>
                    ) : 'One-time scan'}
                  </span>
                </div>
                {Object.keys(customConfig).length > 0 && (
                  <div className="flex justify-between py-2">
                    <span className="text-gray-400 text-sm">Custom Config</span>
                    <code className="text-xs text-gray-300 bg-gray-900 px-2 py-1 rounded">
                      {JSON.stringify(customConfig)}
                    </code>
                  </div>
                )}
              </div>
            </div>

            {validationErrors.general && (
              <div className="theme-alert-error mt-3">{validationErrors.general}</div>
            )}

            <div className="flex justify-between mt-6">
              <button onClick={prevStep} disabled={loading} className="theme-btn-secondary">Back</button>
              <button onClick={submitScan} disabled={loading} className="theme-btn-primary">
                {loading ? 'Creating Scan...' : 'Start Scan'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
