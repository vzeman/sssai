# Scan Workflow Wizard (#44)

## Overview

Guided multi-step workflow for creating security scans. Includes automatic target type detection, template-based configuration, and progressive disclosure of advanced options.

## Features

### 1. **Smart Target Detection**

Automatically identifies target type:
- Domains (example.com)
- Subdomains (subdomain.example.com)
- IPv4 addresses (192.168.1.1)
- IPv6 addresses
- CIDR ranges (192.168.0.0/24)
- URLs (https://example.com)
- Email addresses (user@example.com)
- Port targets (example.com:8080)

Each detection includes:
- Confidence score
- Normalized form
- Metadata (network mask, port, etc.)

### 2. **Scan Templates**

Predefined templates for common scan types:

| Template | Duration | Best For | Modules |
|----------|----------|----------|---------|
| **Quick** | 5 min | Health checks | DNS, HTTP, SSL, CVEs |
| **Thorough** | 15 min | Web apps | Subdomains, content discovery, web vulns |
| **Compliance** | 20 min | Compliance | Auth, crypto, data exposure, API testing |
| **Pentest** | 30+ min | Authorized testing | Exploitation, post-exploit, evidence |
| **Full Audit** | 60+ min | Complete audit | All modules |

### 3. **Progressive Disclosure**

User-friendly step-by-step workflow:
1. **Target** - What to scan (auto-detection)
2. **Template** - Which template (auto-recommended)
3. **Advanced** - Custom config (optional, JSON)
4. **Review** - Confirm before creating

### 4. **Real-Time Validation**

- Target validation as you type
- Template availability check
- Configuration validation
- Error feedback at each step

## API Endpoints

### Detect Target Type

```bash
POST /api/wizard/detect-target

Request:
{
  "target": "example.com"
}

Response:
{
  "target": "example.com",
  "type": "domain",
  "normalized": "example.com",
  "confidence": 0.95,
  "metadata": {"dot_count": 1}
}
```

### List Templates

```bash
GET /api/wizard/templates

Response:
[
  {
    "id": "quick",
    "name": "Quick Scan (5 min)",
    "description": "Fast surface-level scan...",
    "duration": "5 minutes",
    "modules_count": 4,
    "depth": "shallow"
  },
  ...
]
```

### Get Template Details

```bash
GET /api/wizard/templates/{template_name}

Response:
{
  "id": "thorough",
  "name": "Thorough Scan (15 min)",
  "description": "...",
  "enabled_modules": ["dns", "http", "ssl", ...],
  "depth": "medium",
  "timeout_minutes": 15,
  "parallelization": 3,
  "default_config": {...}
}
```

### Get Recommended Template

```bash
POST /api/wizard/recommend-template

Request:
{
  "target": "example.com"
}

Response:
{
  "target": "example.com",
  "target_type": "domain",
  "recommended_template": "thorough",
  "template_name": "Thorough Scan (15 min)",
  "reason": "Best for domain targets"
}
```

### Validate Wizard Input

```bash
POST /api/wizard/validate

Request:
{
  "target": "example.com",
  "template": "thorough",
  "custom_config": {"timeout": 20}
}

Response:
{
  "is_valid": true,
  "errors": {},
  "target_info": {...},
  "template_info": {...}
}
```

### Create Scan from Wizard

```bash
POST /api/wizard/create

Request:
{
  "target": "example.com",
  "template": "thorough",
  "custom_config": {"timeout": 20}
}

Response:
{
  "scan_id": "scan-12345",
  "target": "example.com",
  "template": "thorough",
  "scan_type": "security",
  "status": "queued",
  "config": {...}
}
```

### Batch Create Scans

```bash
POST /api/wizard/batch-create

Request:
{
  "targets": [
    "example.com",
    "test.com",
    "192.168.1.1"
  ],
  "template": "quick",
  "custom_config": {}
}

Response:
{
  "created": 3,
  "failed": 0,
  "scans": [
    {"scan_id": "scan-1", "target": "example.com", "status": "queued"},
    {"scan_id": "scan-2", "target": "test.com", "status": "queued"},
    {"scan_id": "scan-3", "target": "192.168.1.1", "status": "queued"}
  ],
  "failed_targets": []
}
```

## Frontend Component Usage

### Basic Usage

```jsx
import ScanWizard from './components/ScanWizard';

export default function App() {
  return <ScanWizard />;
}
```

### With Custom Integration

```jsx
import { useState } from 'react';
import ScanWizard from './components/ScanWizard';

export default function ScanPage() {
  const [createdScans, setCreatedScans] = useState([]);

  return (
    <div>
      <ScanWizard onScanCreated={(scan) => setCreatedScans([...createdScans, scan])} />
    </div>
  );
}
```

## Usage Examples

### Example 1: Scan a Domain

```
Step 1 - Target: "example.com"
  → Auto-detected as: domain
  → Confidence: 95%

Step 2 - Template: "Thorough" (auto-recommended)
  → 15 minutes
  → 7 modules
  → Medium depth

Step 3 - Advanced: Skip (use defaults)

Step 4 - Review & Create
  → Scan created!
  → Queued for processing
```

### Example 2: Scan a Network

```
Step 1 - Target: "192.168.0.0/24"
  → Auto-detected as: CIDR
  → Confidence: 100%

Step 2 - Template: "Quick" (recommended for network)
  → 5 minutes
  → 4 modules
  → Shallow depth

Step 3 - Advanced: Customize
{
  "aggressive": true,
  "parallel_threads": 10,
  "timeout": 30
}

Step 4 - Review & Create
  → Scan created!
```

### Example 3: Batch Scan Multiple Domains

Using batch endpoint:

```bash
curl -X POST https://api.scanner.com/api/wizard/batch-create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["domain1.com", "domain2.com", "domain3.com"],
    "template": "thorough"
  }'
```

Response:

```json
{
  "created": 3,
  "failed": 0,
  "scans": [
    {"scan_id": "scan-abc123", "target": "domain1.com", "status": "queued"},
    {"scan_id": "scan-def456", "target": "domain2.com", "status": "queued"},
    {"scan_id": "scan-ghi789", "target": "domain3.com", "status": "queued"}
  ]
}
```

## Configuration

### Template Configuration Files

Each template includes default configuration:

```python
# Quick Scan
{
  "scan_type": "security",
  "quick_scan": True,
  "check_ssl": True,
  "dns_enum": True,
  "http_test": True,
  "vuln_scan": "basic",
}

# Thorough Scan
{
  "scan_type": "security",
  "subdomain_enum": True,
  "content_discovery": True,
  "check_ssl": True,
  "web_testing": True,
  "vuln_scan": "standard",
  "crawl_depth": 2,
}

# Compliance Scan
{
  "scan_type": "compliance",
  "frameworks": ["owasp_top_10", "cwe", "pci_dss"],
  "authentication_testing": True,
  "crypto_analysis": True,
  "data_classification": True,
}
```

### Customization

Templates can be customized in `/api/wizard/create`:

```bash
curl -X POST https://api.scanner.com/api/wizard/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "template": "thorough",
    "custom_config": {
      "crawl_depth": 5,
      "timeout": 30,
      "aggressive": true
    }
  }'
```

## Target Type Detection

### Supported Formats

| Format | Example | Type | Confidence |
|--------|---------|------|------------|
| Domain | example.com | domain | 0.95 |
| Subdomain | api.example.com | subdomain | 0.95 |
| IPv4 | 192.168.1.1 | ipv4 | 1.0 |
| IPv6 | 2001:db8::1 | ipv6 | 1.0 |
| CIDR | 192.168.0.0/24 | cidr | 1.0 |
| URL | https://example.com | url | 1.0 |
| Email | user@example.com | email | 1.0 |
| Port | example.com:8080 | port | 0.9 |

### Detection Algorithm

```
1. Check URL format (http://, https://)
   → Extract domain, return as URL
2. Check IPv4 format
   → Return as IPv4
3. Check IPv6 format
   → Return as IPv6
4. Check CIDR format
   → Return as CIDR
5. Check Email format
   → Extract domain, return as EMAIL
6. Check Port format (IP:port)
   → Validate port range, return as PORT
7. Check Domain format
   → Count dots: 1+ = subdomain, else = domain
8. Unknown
   → Return with confidence 0
```

## Best Practices

### 1. Use Auto-Detection

Let the wizard detect the target type:

```javascript
// Good - Use detection
const response = await axios.post('/api/wizard/detect-target', {
  target: userInput
});

// Bad - Parse manually
const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(userInput);
```

### 2. Use Recommended Templates

```javascript
// Get recommendation
const rec = await axios.post('/api/wizard/recommend-template', {
  target: target
});
setSelectedTemplate(rec.recommended_template);
```

### 3. Validate Before Creating

```javascript
// Always validate
const validation = await axios.post('/api/wizard/validate', {
  target, template, custom_config
});

if (!validation.is_valid) {
  showErrors(validation.errors);
  return;
}

// Then create
createScan(target, template, custom_config);
```

### 4. Show Template Descriptions

Help users choose by showing what each template includes:

```javascript
// Get template details
const details = await axios.get(`/api/wizard/templates/${templateId}`);
showModules(details.enabled_modules);
```

## Performance

### Response Times

- Target Detection: ~50ms
- Template List: ~30ms
- Validation: ~200ms
- Scan Creation: ~500ms

### Optimization Tips

1. **Cache Templates** - List templates once on mount
2. **Debounce Detection** - Don't detect on every keystroke
3. **Parallel Requests** - Get templates while user types target
4. **Progressive UI** - Show detection results as they arrive

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| "Target cannot be empty" | No target entered | Require non-empty input |
| "Could not determine target type" | Unknown format | Show target format examples |
| "Invalid template" | Template doesn't exist | List valid templates |
| "Maximum 50 targets per batch" | Too many targets | Split into multiple batches |
| "Validation failed" | Server error | Check server logs |

### Example Error Handling

```javascript
try {
  const response = await axios.post('/api/wizard/create', {
    target, template, custom_config
  });
  navigateToScan(response.data.scan_id);
} catch (error) {
  const detail = error.response?.data?.detail;
  if (detail) {
    showError(detail);
  } else {
    showError('Failed to create scan. Please try again.');
  }
}
```

## Testing

### Manual Testing Checklist

- [ ] Detect various target types
- [ ] View all templates
- [ ] Navigate between steps
- [ ] Validate inputs
- [ ] Create scan successfully
- [ ] Handle validation errors
- [ ] Batch create multiple scans

### API Testing

```bash
# Test detection
curl -X POST http://localhost:8000/api/wizard/detect-target \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Test templates list
curl http://localhost:8000/api/wizard/templates

# Test creation
curl -X POST http://localhost:8000/api/wizard/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "example.com",
    "template": "quick"
  }'
```

## Related Files

- `modules/api/scan_wizard.py` - Core logic
- `modules/api/routes/wizard.py` - API endpoints
- `frontend/src/components/ScanWizard.jsx` - React component
- `frontend/src/styles/ScanWizard.css` - Styling

## See Also

- [Database Optimization (#42)](./DATABASE_OPTIMIZATION.md)
- [Rate Limiting (#43)](./RATE_LIMITING.md)
- [Scan API Documentation](./API.md)
