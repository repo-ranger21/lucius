# Talon Vulnerability Management API

Comprehensive REST API for managing vulnerability data with ML-based threat scoring and multi-channel notifications.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
- [Request/Response Examples](#requestresponse-examples)
- [Error Handling](#error-handling)
- [Integration Guide](#integration-guide)

## Overview

The Vulnerability Management API provides:

- **CRUD Operations**: Create, read, update, and delete vulnerabilities
- **ML-Based Scoring**: Automatic threat score calculation (0-100)
- **Advanced Filtering**: Filter by severity, threat score, package, date range
- **Dashboard Statistics**: Comprehensive metrics and trends
- **Notifications**: Automatic alerts for high-severity vulnerabilities
- **CVE Integration**: Ready for external CVE database enrichment

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────┐
│    Flask-RESTX API Layer        │
│  (vulnerabilities.py)            │
│  - Route handling                │
│  - Input validation (Marshmallow)│
│  - Error handling                │
│  - Swagger documentation         │
└──────┬──────────────────────────┘
       │
       ▼
┌─────────────────────────────────┐
│   Business Logic Layer          │
│  (VulnerabilityService)          │
│  - Vulnerability CRUD            │
│  - Duplicate detection           │
│  - Threat scoring integration    │
│  - Notification triggering       │
└──────┬──────────────────────────┘
       │
       ├─────────────┬──────────────┐
       ▼             ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────────┐
│ Database │  │  Threat  │  │ Notification │
│  (SQLAlchemy)│ Scorer   │  │   Service    │
└──────────┘  └──────────┘  └──────────────┘
```

## Authentication

Currently uses a placeholder authentication decorator. To implement:

### Option 1: API Key Authentication

```python
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not validate_api_key(api_key):
            vulnerabilities_ns.abort(401, "Invalid API key")
        return f(*args, **kwargs)
    return decorated_function
```

### Option 2: JWT Token Authentication

```python
from flask_jwt_extended import jwt_required

# Replace @require_auth with @jwt_required()
```

## API Endpoints

### Vulnerability Collection

#### `GET /api/v1/vulnerabilities`

List vulnerabilities with advanced filtering.

**Query Parameters:**
- `severity` (string): Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
- `min_cvss` (float): Minimum CVSS score (0-10)
- `min_threat_score` (float): Minimum threat score (0-100)
- `package` (string): Filter by package name
- `search` (string): Search in CVE ID or description
- `start_date` (ISO 8601): Filter by publication start date
- `end_date` (ISO 8601): Filter by publication end date
- `limit` (int): Maximum results (1-500, default: 50)
- `offset` (int): Pagination offset (default: 0)

**Response:** 200 OK
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "cve_id": "CVE-2024-1234",
    "severity": "CRITICAL",
    "description": "Remote code execution vulnerability",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "threat_score": 92.5,
    "affected_packages": [...],
    "references": [...],
    "published_date": "2024-01-15T10:00:00Z",
    "created_at": "2024-01-15T10:05:00Z"
  }
]
```

#### `POST /api/v1/vulnerabilities` 🔒

Create a new vulnerability with automatic threat scoring.

**Requires:** Authentication

**Request Body:**
```json
{
  "cve_id": "CVE-2024-1234",
  "severity": "CRITICAL",
  "description": "Remote code execution vulnerability in XYZ library",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "affected_packages": [
    {
      "name": "xyz-lib",
      "version": "1.2.3",
      "ecosystem": "npm"
    }
  ],
  "references": [
    {
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
      "source": "NVD"
    }
  ],
  "published_date": "2024-01-15T10:00:00Z",
  "calculate_threat": true
}
```

**Response:** 201 Created
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "cve_id": "CVE-2024-1234",
  "threat_score": 92.5,
  ...
}
```

**Automatic Actions:**
- Calculates ML-based threat score
- Sends notifications if CRITICAL/HIGH severity
- Validates CVE format
- Checks for duplicates

### Single Vulnerability

#### `GET /api/v1/vulnerabilities/{id}`

Get vulnerability by UUID.

**Response:** 200 OK

#### `GET /api/v1/vulnerabilities/cve/{cve_id}`

Get vulnerability by CVE identifier (alternative endpoint).

**Example:** `/api/v1/vulnerabilities/cve/CVE-2024-1234`

#### `PUT /api/v1/vulnerabilities/{id}` 🔒

Update an existing vulnerability.

**Requires:** Authentication

**Request Body:**
```json
{
  "description": "Updated description",
  "severity": "HIGH",
  "cvss_score": 8.5,
  "recalculate_threat": true
}
```

**Response:** 200 OK

#### `DELETE /api/v1/vulnerabilities/{id}` 🔒

Soft delete a vulnerability.

**Requires:** Authentication

**Response:** 204 No Content

### Threat Scoring

#### `GET /api/v1/vulnerabilities/{id}/threat-score`

Get ML-based threat score with contributing factors.

**Response:** 200 OK
```json
{
  "cve_id": "CVE-2024-1234",
  "threat_score": 92.5,
  "factors": {
    "cvss_score": 0.98,
    "severity_weight": 1.0,
    "exploit_likelihood": 1.0,
    "age_factor": 0.95,
    "affected_scope": 0.6
  },
  "severity": "CRITICAL",
  "cvss_score": 9.8
}
```

#### `POST /api/v1/vulnerabilities/{id}/threat-score` 🔒

Recalculate and update threat score.

**Requires:** Authentication

### Analytics

#### `GET /api/v1/vulnerabilities/dashboard`

Get comprehensive dashboard statistics.

**Response:** 200 OK
```json
{
  "total_vulnerabilities": 1250,
  "severity_breakdown": {
    "CRITICAL": 45,
    "HIGH": 180,
    "MEDIUM": 650,
    "LOW": 350,
    "UNKNOWN": 25
  },
  "threat_score_distribution": {
    "min": 12.5,
    "max": 98.7,
    "avg": 52.3,
    "count_critical": 45,
    "count_high": 180,
    "count_medium": 650,
    "count_low": 350
  },
  "recent_vulnerabilities": [...],
  "high_threat_vulnerabilities": [...],
  "trends": {
    "daily_new_vulnerabilities": [
      {"date": "2024-01-08", "count": 12},
      {"date": "2024-01-09", "count": 8},
      ...
    ],
    "total_last_7_days": 67
  }
}
```

#### `GET /api/v1/vulnerabilities/stats`

Get lightweight statistics (faster than dashboard).

#### `GET /api/v1/vulnerabilities/high-threat`

Get high-threat vulnerabilities above threshold.

**Query Parameters:**
- `threshold` (float): Minimum threat score (default: 70.0)
- `limit` (int): Maximum results (default: 50)

#### `GET /api/v1/vulnerabilities/report`

Generate comprehensive report with filters.

**Query Parameters:**
- `severity_levels` (string): Comma-separated levels (e.g., "CRITICAL,HIGH")
- `min_threat_score` (float): Minimum threat score
- `start_date` (ISO 8601): Start date
- `end_date` (ISO 8601): End date

## Request/Response Examples

### Example 1: Create Critical Vulnerability

```bash
curl -X POST http://localhost:5000/api/v1/vulnerabilities \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "cve_id": "CVE-2024-5678",
    "severity": "CRITICAL",
    "description": "SQL injection in user authentication",
    "cvss_score": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "affected_packages": [
      {
        "name": "auth-service",
        "version": "2.1.0",
        "ecosystem": "pip"
      }
    ]
  }'
```

### Example 2: Search Vulnerabilities

```bash
# Search for Log4j vulnerabilities
curl "http://localhost:5000/api/v1/vulnerabilities?search=log4j&severity=CRITICAL&limit=10"

# Get vulnerabilities affecting specific package
curl "http://localhost:5000/api/v1/vulnerabilities?package=lodash&min_cvss=7.0"

# Get recent high-threat vulnerabilities
curl "http://localhost:5000/api/v1/vulnerabilities?min_threat_score=80&start_date=2024-01-01T00:00:00Z"
```

### Example 3: Update Vulnerability

```bash
curl -X PUT http://localhost:5000/api/v1/vulnerabilities/550e8400-e29b-41d4-a716-446655440000 \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "severity": "HIGH",
    "cvss_score": 8.5,
    "recalculate_threat": true
  }'
```

### Example 4: Get Dashboard

```bash
curl http://localhost:5000/api/v1/vulnerabilities/dashboard
```

## Error Handling

All endpoints follow consistent error response format:

### 400 Bad Request

```json
{
  "message": "Validation error: {'cve_id': ['Invalid CVE format']}"
}
```

### 401 Unauthorized

```json
{
  "message": "Unauthorized"
}
```

### 404 Not Found

```json
{
  "message": "Vulnerability 550e8400-e29b-41d4-a716-446655440000 not found"
}
```

### 409 Conflict

```json
{
  "message": "Vulnerability CVE-2024-1234 already exists"
}
```

### 500 Internal Server Error

```json
{
  "message": "Internal server error"
}
```

## Integration Guide

### Python Client Example

```python
import requests

class VulnerabilityClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }

    def create_vulnerability(self, vuln_data):
        """Create a new vulnerability."""
        response = requests.post(
            f"{self.base_url}/vulnerabilities",
            json=vuln_data,
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()

    def list_vulnerabilities(self, **filters):
        """List vulnerabilities with filters."""
        response = requests.get(
            f"{self.base_url}/vulnerabilities",
            params=filters
        )
        response.raise_for_status()
        return response.json()

    def get_dashboard(self):
        """Get dashboard statistics."""
        response = requests.get(f"{self.base_url}/vulnerabilities/dashboard")
        response.raise_for_status()
        return response.json()

# Usage
client = VulnerabilityClient("http://localhost:5000/api/v1", "your-api-key")

# Create vulnerability
vuln = client.create_vulnerability({
    "cve_id": "CVE-2024-9999",
    "severity": "HIGH",
    "description": "XSS vulnerability",
    "cvss_score": 7.5
})

# Search vulnerabilities
results = client.list_vulnerabilities(
    severity="CRITICAL",
    min_threat_score=80,
    limit=20
)

# Get dashboard
dashboard = client.get_dashboard()
print(f"Total vulnerabilities: {dashboard['total_vulnerabilities']}")
```

### JavaScript/TypeScript Client Example

```typescript
class VulnerabilityAPI {
  constructor(private baseURL: string, private apiKey: string) {}

  async createVulnerability(data: VulnerabilityData) {
    const response = await fetch(`${this.baseURL}/vulnerabilities`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey,
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`);
    }

    return response.json();
  }

  async listVulnerabilities(filters: VulnFilters = {}) {
    const params = new URLSearchParams(filters as any);
    const response = await fetch(
      `${this.baseURL}/vulnerabilities?${params}`
    );

    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`);
    }

    return response.json();
  }

  async getDashboard() {
    const response = await fetch(
      `${this.baseURL}/vulnerabilities/dashboard`
    );

    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`);
    }

    return response.json();
  }
}

// Usage
const api = new VulnerabilityAPI('http://localhost:5000/api/v1', 'your-api-key');

const vulns = await api.listVulnerabilities({
  severity: 'CRITICAL',
  min_threat_score: 80,
  limit: 20,
});
```

## Swagger Documentation

Interactive API documentation is available at:

```
http://localhost:5000/api/v1/docs
```

The Swagger UI provides:
- Complete API reference
- Request/response schemas
- Interactive testing
- Model definitions
- Authentication testing

## Best Practices

1. **Always validate CVE format**: Use regex `^CVE-\d{4}-\d{4,}$`
2. **Use pagination**: Set appropriate `limit` and `offset` for large datasets
3. **Enable threat calculation**: Set `calculate_threat: true` for new vulnerabilities
4. **Filter by threat score**: Prioritize remediation using `min_threat_score`
5. **Monitor dashboard**: Regularly check dashboard for trends
6. **Handle errors gracefully**: Implement retry logic for 5xx errors
7. **Cache dashboard data**: Dashboard queries are expensive, cache results
8. **Use CVE endpoint for lookups**: When you have CVE ID, use `/cve/{id}` endpoint

## Performance Considerations

- **Pagination**: Always use pagination for large result sets
- **Indexing**: CVE ID, severity, and threat_score are indexed
- **Caching**: Consider caching dashboard and stats endpoints
- **Async processing**: Threat scoring is synchronous; consider async for bulk operations
- **Connection pooling**: Configure appropriate database pool size

## Security Considerations

1. **Authentication**: Implement proper auth before production deployment
2. **Rate limiting**: Add rate limiting to prevent abuse
3. **Input validation**: All inputs are validated with Marshmallow schemas
4. **SQL injection**: Protected via SQLAlchemy ORM
5. **CORS**: Configure CORS appropriately for your frontend
6. **HTTPS**: Always use HTTPS in production
7. **API keys**: Rotate API keys regularly

## Support

For issues or questions:
- Check the Swagger documentation at `/api/v1/docs`
- Review error messages and logs
- Consult the codebase documentation
