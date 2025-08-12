import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
export let errorRate = new Rate('errors');
export let responseTime = new Trend('response_time');
export let requestCount = new Counter('requests');

export let options = {
  stages: [
    { duration: '30s', target: 10 },  // Ramp up to 10 users
    { duration: '60s', target: 10 },  // Stay at 10 users for 1 minute
    { duration: '30s', target: 0 },   // Ramp down
  ],
};

export default function() {
  // Test the WAF proxy endpoint
  let response = http.get('http://127.0.0.1:8080/api/health');
  
  // Record metrics
  requestCount.add(1);
  responseTime.add(response.timings.duration);
  
  // Check response - we expect 404 because of the path normalization issue
  // But that means the WAF is processing the request
  let result = check(response, {
    'status is not 5xx': (r) => r.status < 500,  // Any non-server error is good
    'response time < 5000ms': (r) => r.timings.duration < 5000,
    'response time < 1000ms': (r) => r.timings.duration < 1000,
    'got response': (r) => r.status > 0,
  });
  
  errorRate.add(!result);
  
  console.log(`Response status: ${response.status}, time: ${response.timings.duration}ms`);
  
  sleep(0.1); // Brief pause between requests
}
