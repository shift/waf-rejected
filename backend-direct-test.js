import http from 'k6/http';
import { check } from 'k6';

export default function () {
  // Test echo backend directly (without WAF proxy)
  const response = http.get('http://127.0.0.1:3000/api/health');
  
  console.log(`Response status: ${response.status}, time: ${response.timings.duration}ms`);
  
  check(response, {
    'status is not 5xx': (r) => r.status < 500,
    'response time < 5000ms': (r) => r.timings.duration < 5000,
    'response time < 1000ms': (r) => r.timings.duration < 1000,
    'got response': (r) => r.body.length > 0,
  });
}
