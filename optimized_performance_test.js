// k6 performance test for optimized WAF proxy
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  stages: [
    { duration: '10s', target: 50 },  // Ramp up
    { duration: '20s', target: 100 }, // Stay at 100 RPS
    { duration: '10s', target: 0 },   // Ramp down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<50'],  // 95% of requests under 50ms
    'http_req_failed': ['rate<0.1'],    // Less than 10% failures
  },
};

export default function() {
  const payload = JSON.stringify({
    message: 'optimized test payload',
    timestamp: Date.now(),
  });
  
  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };
  
  const response = http.post('http://localhost:8080/api/test', payload, params);
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 50ms': (r) => r.timings.duration < 50,
    'has WAF headers': (r) => r.headers['x-waf-version'] !== undefined,
  });
}
