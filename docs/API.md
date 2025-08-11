# API Documentation

**WAF-Rejected REST API and gRPC Interface Reference**

## REST API

### Health Check Endpoint

**GET `/health`**

Returns the current health status of the WAF service.

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime": "2h 30m 45s",
  "requests_processed": 15420,
  "threats_blocked": 234,
  "last_updated": "2025-08-10T14:30:00Z"
}
```

**Status Codes:**
- `200 OK` - Service is healthy
- `503 Service Unavailable` - Service is degraded

### Metrics Endpoint

**GET `/metrics`**

Returns Prometheus-format metrics for monitoring.

**Response:**
```
# HELP waf_requests_total Total number of requests processed
# TYPE waf_requests_total counter
waf_requests_total{status="allowed"} 15186
waf_requests_total{status="blocked"} 234

# HELP waf_request_duration_seconds Request processing duration
# TYPE waf_request_duration_seconds histogram
waf_request_duration_seconds_bucket{le="0.001"} 8234
waf_request_duration_seconds_bucket{le="0.005"} 14567
waf_request_duration_seconds_bucket{le="0.01"} 15123
waf_request_duration_seconds_bucket{le="+Inf"} 15420
```

### Configuration Reload

**POST `/admin/reload`**

Reloads the WAF configuration without restarting the service.

**Request Headers:**
- `Authorization: Bearer <admin_token>`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "config_path": "/etc/waf/config.toml"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration reloaded successfully",
  "timestamp": "2025-08-10T14:30:00Z"
}
```

### Security Events Query

**GET `/admin/events`**

Retrieves recent security events for analysis.

**Query Parameters:**
- `limit` - Number of events to return (default: 100, max: 1000)
- `since` - ISO 8601 timestamp to filter events
- `threat_type` - Filter by threat type (sql_injection, xss, geo_block, etc.)
- `severity` - Filter by severity (low, medium, high, critical)

**Response:**
```json
{
  "events": [
    {
      "id": "evt_abc123",
      "timestamp": "2025-08-10T14:29:45Z",
      "threat_type": "sql_injection",
      "severity": "high",
      "source_ip": "192.168.1.100",
      "target_path": "/api/users",
      "rule_id": "SQLI_001",
      "blocked": true,
      "details": {
        "pattern_matched": "union.*select",
        "payload": "' UNION SELECT * FROM users--",
        "user_agent": "Mozilla/5.0..."
      }
    }
  ],
  "total": 234,
  "has_more": true
}
```

## gRPC API

### Service Definition

```protobuf
syntax = "proto3";

package waf.v1;

service WAFService {
  // Stream security events in real-time
  rpc StreamSecurityEvents(StreamEventsRequest) returns (stream SecurityEvent);
  
  // Update security rules dynamically
  rpc UpdateRules(UpdateRulesRequest) returns (UpdateRulesResponse);
  
  // Get current WAF status
  rpc GetStatus(StatusRequest) returns (StatusResponse);
}

message SecurityEvent {
  string id = 1;
  int64 timestamp = 2;
  string threat_type = 3;
  string severity = 4;
  string source_ip = 5;
  string target_path = 6;
  string rule_id = 7;
  bool blocked = 8;
  map<string, string> metadata = 9;
}

message StreamEventsRequest {
  repeated string threat_types = 1;
  string min_severity = 2;
}

message UpdateRulesRequest {
  repeated SecurityRule rules = 1;
}

message SecurityRule {
  string id = 1;
  string pattern = 2;
  string action = 3;
  int32 priority = 4;
}
```

### Client Examples

#### Rust Client
```rust
use waf_proto::waf_service_client::WafServiceClient;
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = WafServiceClient::connect("http://localhost:9090").await?;
    
    let request = tonic::Request::new(StreamEventsRequest {
        threat_types: vec!["sql_injection".to_string(), "xss".to_string()],
        min_severity: "medium".to_string(),
    });
    
    let mut stream = client.stream_security_events(request).await?.into_inner();
    
    while let Some(event) = stream.message().await? {
        println!("Security Event: {} - {} from {}", 
            event.threat_type, event.severity, event.source_ip);
    }
    
    Ok(())
}
```

#### Python Client
```python
import grpc
import waf_pb2
import waf_pb2_grpc

def stream_events():
    channel = grpc.insecure_channel('localhost:9090')
    stub = waf_pb2_grpc.WAFServiceStub(channel)
    
    request = waf_pb2.StreamEventsRequest(
        threat_types=['sql_injection', 'xss'],
        min_severity='medium'
    )
    
    for event in stub.StreamSecurityEvents(request):
        print(f"Security Event: {event.threat_type} - {event.severity} from {event.source_ip}")

if __name__ == '__main__':
    stream_events()
```

## Authentication

### API Token Authentication

For admin endpoints, include the API token in the Authorization header:

```
Authorization: Bearer waf_token_abc123...
```

Configure the token in your config file:
```toml
[admin]
enabled = true
api_token = "waf_token_abc123def456ghi789"
bind_address = "127.0.0.1:9090"
```

### mTLS Authentication

For gRPC endpoints, configure mutual TLS:

```toml
[grpc]
bind_address = "0.0.0.0:9090"
tls_cert = "/path/to/server.crt"
tls_key = "/path/to/server.key"
client_ca = "/path/to/client-ca.crt"
```

## Error Handling

### HTTP Error Responses

All API endpoints return errors in a consistent format:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The request body contains invalid JSON",
    "details": {
      "field": "threat_type",
      "reason": "Unknown threat type: invalid_type"
    }
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Request format or parameters are invalid |
| `UNAUTHORIZED` | 401 | Missing or invalid API token |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Requested resource not found |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

### gRPC Error Handling

gRPC errors follow the standard gRPC status codes:

```rust
match response {
    Ok(response) => {
        // Handle successful response
    },
    Err(status) => {
        match status.code() {
            tonic::Code::Unauthenticated => {
                println!("Authentication failed");
            },
            tonic::Code::PermissionDenied => {
                println!("Insufficient permissions");
            },
            tonic::Code::NotFound => {
                println!("Resource not found");
            },
            _ => {
                println!("Error: {}", status.message());
            }
        }
    }
}
```

## Rate Limits

### API Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/health` | 100/min | Per IP |
| `/metrics` | 60/min | Per IP |
| `/admin/*` | 30/min | Per token |
| `gRPC StreamEvents` | 10 concurrent | Per connection |

### Headers

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1628610000
```

## Webhooks

### Security Event Webhooks

Configure webhooks to receive real-time security events:

```toml
[webhooks]
enabled = true

[[webhooks.endpoints]]
name = "security_team_slack"
url = "https://hooks.slack.com/services/..."
events = ["sql_injection", "xss"]
min_severity = "medium"
headers = { "Authorization" = "Bearer slack_token_123" }

[[webhooks.endpoints]]
name = "siem_integration"
url = "https://siem.company.com/api/events"
events = ["*"]
format = "cef"
```

### Webhook Payload Format

```json
{
  "webhook_id": "wh_123",
  "event_type": "security.threat_detected",
  "timestamp": "2025-08-10T14:30:00Z",
  "data": {
    "event_id": "evt_abc123",
    "threat_type": "sql_injection",
    "severity": "high",
    "source_ip": "192.168.1.100",
    "target_path": "/api/users",
    "blocked": true,
    "metadata": {
      "user_agent": "Mozilla/5.0...",
      "referer": "https://evil.com"
    }
  }
}
```

## SDK Examples

### JavaScript/TypeScript
```typescript
import { WAFClient } from '@waf-rejected/client';

const client = new WAFClient({
  baseURL: 'http://localhost:8080',
  apiToken: 'your-api-token'
});

// Get health status
const health = await client.getHealth();
console.log('WAF Status:', health.status);

// Stream security events
client.streamEvents(['sql_injection'], (event) => {
  console.log('Threat detected:', event);
});
```

### Go
```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/your-org/waf-rejected-go"
)

func main() {
    client := waf.NewClient(&waf.Config{
        BaseURL: "http://localhost:8080",
        APIToken: "your-api-token",
    })
    
    health, err := client.GetHealth(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("WAF Status: %s\n", health.Status)
}
```

This API documentation provides comprehensive coverage of all available endpoints, authentication methods, error handling, and client examples for integrating with WAF-Rejected.
