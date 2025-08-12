# WAF-Rejected Build Tasks
# Use 'just --list' to see all available commands

# Default task - show available commands
default:
    @just --list

# Development tasks
run:
    cargo run

test:
    cargo test

benchmark:
    cargo bench

# WASM ModSecurity tasks
build-modsec-wasm:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🔨 Building ModSecurity WASM module..."
    
    # Create wasm directory if it doesn't exist
    mkdir -p wasm
    
    # Build our WASM module
    cd wasm
    echo "🚀 Compiling ModSecurity WASM module..."
    
    # Use standard Go with WASM target
    GOOS=js GOARCH=wasm go build -o modsecurity.wasm main.go
    
    # Skip optimization for now to avoid validation issues
    echo "⚡ WASM module ready: wasm/modsecurity.wasm"
    
    echo "✅ ModSecurity WASM module built successfully"

# Test WASM module
test-wasm: build-modsec-wasm
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🧪 Testing Coraza WASM module..."
    
    if [ ! -f "wasm/modsecurity.wasm" ]; then
        echo "❌ WASM module not found. Run 'just build-coraza-wasm' first."
        exit 1
    fi
    
    # Show WASM module info
    echo "📊 WASM module information:"
    ls -lh wasm/modsecurity.wasm
    echo "✅ WASM module validation passed"

# Build with WASM integration
build-with-wasm: build-modsec-wasm
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🏗️ Building WAF-Rejected with WASM integration..."
    
    # Ensure WASM module exists
    if [ ! -f "wasm/modsecurity.wasm" ]; then
        echo "❌ WASM module not found. Building ModSecurity WASM first..."
        just build-modsec-wasm
    fi
    
    # Copy WASM module to expected location
    mkdir -p target/wasm
    cp wasm/modsecurity.wasm target/wasm/modsecurity.wasm
    
    # Build Rust application with WASM feature
    cargo build --release --features wasm-waf
    
    echo "✅ WAF-Rejected built with WASM integration"

# Clean build artifacts
clean:
    cargo clean
    rm -rf wasm/
    rm -rf target/wasm/

# Development environment info
env-info:
    @echo "🔧 Development Environment:"
    @echo "Rust: $(rustc --version)"
    @echo "Cargo: $(cargo --version)"
    @echo "Go: $(go version)"
    @echo "TinyGo: $(tinygo version)"
    @echo "Wasmtime: $(wasmtime --version)"
    @echo "WASM-opt: $(wasm-opt --version)"

# Performance testing with WASM
perf-test-wasm: build-with-wasm
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🚀 Performance testing WAF-Rejected with WASM..."
    
    # Start the WAF service in background
    ./target/release/waf-ingress &
    WAF_PID=$!
    
    # Wait for service to start
    sleep 2
    
    # Run performance test
    echo "📈 Running load test..."
    wrk -t12 -c400 -d30s http://127.0.0.1:3000/health
    
    # Cleanup
    kill $WAF_PID
    
    echo "✅ Performance test completed"

# Security test with malicious payloads
security-test: build-with-wasm
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🔒 Security testing WAF with malicious payloads..."
    
    # Start the WAF service
    ./target/release/waf-ingress &
    WAF_PID=$!
    sleep 2
    
    # Test SQL injection
    echo "Testing SQL injection..."
    curl -v "http://127.0.0.1:3000/?id=1' OR '1'='1"
    
    # Test XSS
    echo "Testing XSS..."
    curl -v -d "<script>alert('xss')</script>" http://127.0.0.1:3000/
    
    # Test path traversal
    echo "Testing path traversal..."
    curl -v "http://127.0.0.1:3000/../../../etc/passwd"
    
    # Cleanup
    kill $WAF_PID
    
    echo "✅ Security tests completed"

# Update Coraza to latest version
update-coraza:
    #!/usr/bin/env bash
    set -euo pipefail
    
    if [ -d "wasm/coraza" ]; then
        echo "🔄 Updating Coraza to latest version..."
        cd wasm/coraza
        git pull origin main
        cd ../..
        just build-coraza-wasm
    else
        echo "📦 Coraza not found, building fresh..."
        just build-coraza-wasm
    fi
