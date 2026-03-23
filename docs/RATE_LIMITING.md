# Rate Limiting & DDoS Protection (#43)

## Overview

Comprehensive API rate limiting system with Redis backend to prevent abuse, DoS attacks, and ensure fair resource allocation across users.

## Features

### 1. **Multi-Layer Rate Limiting**

#### Per-User Limits
- Protects against individual user abuse
- Identifier: User ID (if authenticated)
- Limits:
  - 60 requests/minute
  - 1000 requests/hour

#### Per-IP Limits
- Protects against anonymous attacks
- Identifier: Client IP address (if not authenticated)
- Same limits as per-user

#### Burst Protection
- Prevents rapid request spikes (DoS)
- Max 10 requests per 10 seconds
- Separate from rate limits

### 2. **Automatic Lockout**
- After 5 violations → 1 hour lockout
- Configurable via admin panel
- Automatic unlock after duration

### 3. **Admin Control Panel**
- View rate limit status
- List locked out users
- Unlock manually
- Update global configuration

## Configuration

### Default Limits

```python
requests_per_minute: int = 60       # Max requests per minute
requests_per_hour: int = 1000       # Max requests per hour
burst_limit: int = 10               # Max in 10 seconds
burst_window_seconds: int = 10      # Burst window duration
lockout_threshold: int = 5          # Violations before lockout
lockout_duration_seconds: int = 3600  # 1 hour lockout
```

### Environment Variables

```bash
REDIS_URL=redis://redis:6379  # Redis connection
```

## API Usage

### Automatic Rate Limiting

All API endpoints are automatically rate limited. When rate limit is exceeded:

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit-Minute: 60
X-RateLimit-Remaining-Minute: 0
X-RateLimit-Reset: 1679500860
X-RateLimit-Limit-Hour: 1000
X-RateLimit-Remaining-Hour: 850
Retry-After: 45

{
  "error": "rate_limit_exceeded",
  "message": "Too many requests",
  "reset_at": 1679500860,
  "remaining": {
    "minute": 0,
    "hour": 850
  }
}
```

### Response Headers

Every API response includes rate limit headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit-Minute` | Requests allowed per minute |
| `X-RateLimit-Remaining-Minute` | Requests remaining this minute |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |
| `X-RateLimit-Limit-Hour` | Requests allowed per hour |
| `X-RateLimit-Remaining-Hour` | Requests remaining this hour |
| `Retry-After` | Seconds to wait before retrying |

## Admin Endpoints

### Check Rate Limit Status

```bash
GET /admin/rate-limits/status/{identifier}

# Example
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/admin/rate-limits/status/user123"

# Response
{
  "identifier": "user123",
  "is_locked_out": false,
  "lockout_until": null,
  "requests_minute": 15,
  "requests_hour": 245,
  "violations": 0,
  "threshold": 5
}
```

### List Locked Out Identifiers

```bash
GET /admin/rate-limits/locked-out

# Response
{
  "count": 3,
  "identifiers": ["attacker1", "192.168.1.100", "user456"]
}
```

### Unlock an Identifier

```bash
POST /admin/rate-limits/unlock/{identifier}

# Example
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/admin/rate-limits/unlock/user123"

# Response
{
  "success": true,
  "message": "Unlocked user123"
}
```

### Get Current Configuration

```bash
GET /admin/rate-limits/config

# Response
{
  "requests_per_minute": 60,
  "requests_per_hour": 1000,
  "burst_limit": 10,
  "burst_window_seconds": 10,
  "lockout_threshold": 5,
  "lockout_duration_seconds": 3600
}
```

### Update Configuration

```bash
PUT /admin/rate-limits/config

curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests_per_minute": 100,
    "requests_per_hour": 2000
  }' \
  "http://localhost:8000/admin/rate-limits/config"

# Response
{
  "success": true,
  "config": {
    "requests_per_minute": 100,
    "requests_per_hour": 2000,
    "burst_limit": 10,
    "lockout_threshold": 5
  }
}
```

## How It Works

### 1. Request Arrives

```
Client → API Request
         ↓
   [RateLimitMiddleware]
         ↓
   Get identifier (User ID or IP)
         ↓
   Check Redis counters
```

### 2. Rate Limit Check

```
Check 1-minute counter
Check 1-hour counter
Check burst counter
Check lockout status
         ↓
   All OK? → Allow request (add to response headers)
   Limit exceeded? → Return 429 with retry information
   Locked out? → Return 429 with lockout expiration
```

### 3. Response Sent

```
Response headers include:
- X-RateLimit-Remaining-Minute
- X-RateLimit-Remaining-Hour
- X-RateLimit-Reset
- Retry-After
```

### 4. Violation Tracking

```
Each violation → Increment violation counter
Violations >= 5 → Apply 1-hour lockout
Auto-cleanup → Reset after window expires
```

## Examples

### Client Implementation

#### Python

```python
import requests
import time

def make_api_request(url, headers):
    """Make API request with automatic retry on rate limit."""
    response = requests.get(url, headers=headers)
    
    if response.status_code == 429:
        retry_after = int(response.headers.get("Retry-After", 60))
        print(f"Rate limited. Retrying in {retry_after}s...")
        time.sleep(retry_after)
        return make_api_request(url, headers)
    
    # Add rate limit info to response
    response.rate_limit = {
        "remaining_minute": response.headers.get("X-RateLimit-Remaining-Minute"),
        "remaining_hour": response.headers.get("X-RateLimit-Remaining-Hour"),
        "reset_at": response.headers.get("X-RateLimit-Reset"),
    }
    
    return response
```

#### JavaScript

```javascript
async function makeApiRequest(url, token) {
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` }
  });
  
  if (response.status === 429) {
    const retryAfter = parseInt(response.headers.get("Retry-After")) * 1000;
    console.log(`Rate limited. Retrying in ${retryAfter}ms...`);
    await new Promise(r => setTimeout(r, retryAfter));
    return makeApiRequest(url, token);
  }
  
  // Log rate limit status
  console.log({
    remaining_minute: response.headers.get("X-RateLimit-Remaining-Minute"),
    remaining_hour: response.headers.get("X-RateLimit-Remaining-Hour"),
    reset_at: new Date(response.headers.get("X-RateLimit-Reset") * 1000),
  });
  
  return response.json();
}
```

### Monitoring

Monitor rate limit violations:

```bash
# Check Redis for current state
redis-cli KEYS "ratelimit:*"

# Get specific user status
redis-cli HGETALL "ratelimit:user:user123:minute"

# Get all locked out users
redis-cli KEYS "ratelimit:lockout:*"

# Clear all rate limits (emergency only!)
redis-cli FLUSHDB
```

## Best Practices

### 1. Respect Rate Limits

Always check headers and implement exponential backoff:

```python
# Good: Respect retry-after
if response.status_code == 429:
    wait_time = int(response.headers.get("Retry-After", 60))
    time.sleep(wait_time)

# Bad: Ignore rate limits and spam requests
for i in range(1000):
    response = requests.get(url)  # Will get locked out!
```

### 2. Batch Requests

Combine multiple operations:

```python
# Bad: 50 individual requests → potential rate limit
for scan in scans:
    response = requests.post(f"/api/scans/{scan.id}/details")

# Good: Batch request
response = requests.post("/api/scans/batch/details", json={"scan_ids": scan_ids})
```

### 3. Cache Results

Reduce API load:

```python
# Cache scan results for 5 minutes
cache.set(f"scan:{scan_id}", scan_data, 300)

# Use cache if available
if cache.get(f"scan:{scan_id}"):
    return cache.get(f"scan:{scan_id}")
```

### 4. Use Pagination

Don't request huge datasets:

```python
# Bad: Fetch all scans
scans = requests.get("/api/scans").json()  # Could be millions

# Good: Paginate
scans = requests.get("/api/scans?skip=0&limit=20").json()
```

## Troubleshooting

### "Rate limit exceeded" error

**Cause:** You've made too many requests

**Solution:**
1. Check remaining requests: `X-RateLimit-Remaining-Minute`
2. Wait before retrying: Use `Retry-After` header
3. Reduce request frequency
4. Batch operations together

### Getting locked out

**Cause:** Multiple rate limit violations

**Solution:**
1. Contact admin to unlock: `/admin/rate-limits/unlock/{id}`
2. Wait 1 hour for automatic unlock
3. Check for request loops in your code

### Rate limits too strict

**For Admins:**
1. Update limits: `PUT /admin/rate-limits/config`
2. Increase `requests_per_minute` or `requests_per_hour`
3. Note: Changes apply immediately

## Performance Impact

- **Redis Operations:** ~5-10ms per request
- **Storage:** ~100 bytes per identifier per hour
- **Network:** Negligible (local Redis recommended)

## Security Considerations

### Protection Against

✅ API abuse (malicious actors)
✅ DoS attacks (resource exhaustion)
✅ Brute force attacks (auth endpoints)
✅ Scraping (excessive data harvesting)

### Not Protected Against

❌ DDoS at network level (needs WAF/CDN)
❌ Distributed attacks from many IPs (need IP blocking)
❌ Slowloris attacks (need connection pooling)

### For DDoS Protection

Use in combination with:
- Cloudflare / AWS Shield
- Web Application Firewall (WAF)
- IP-based blocking
- Network-level rate limiting

## Future Enhancements

1. **Per-Endpoint Limits** - Different limits for different endpoints
2. **Tiered Limits** - Different limits based on user plan/tier
3. **Dynamic Limits** - Auto-adjust based on system load
4. **Whitelist/Blacklist** - Bypass limits for trusted IPs
5. **Analytics Dashboard** - Visualize rate limit violations
6. **Webhook Alerts** - Notify on suspicious activity

## Related Files

- `modules/api/rate_limiter.py` - Core rate limiting logic
- `modules/api/rate_limit_middleware.py` - FastAPI middleware
- `modules/api/routes/rate_limits.py` - Admin endpoints
- `modules/api/main.py` - Integration with FastAPI app

## See Also

- [RFC 6585: Rate Limiting](https://tools.ietf.org/html/rfc6585)
- [API Rate Limiting Best Practices](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)
- [Redis Documentation](https://redis.io/docs/)
