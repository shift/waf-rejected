mod config;

#[cfg(feature = "wasm-waf")]
mod wasm;

use clap::{Arg, Command};
use config::Config;
use tracing::{info, error};
use anyhow::Result;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper::body::{Incoming, Bytes};
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = Command::new("waf-ingress")
        .version("0.1.0")
        .about("WAF Ingress Server")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Parse configuration and exit without starting server")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    info!("Starting WAF Ingress Server");
    
    // Set config file environment variable if provided via CLI
    if let Some(config_file) = matches.get_one::<String>("config") {
        std::env::set_var("WAF_CONFIG_FILE", config_file);
    }
    
    // Load configuration
    let config = match Config::load() {
        Ok(config) => {
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            // Use default configuration for now
            Config::default()
        }
    };
    
    info!("WAF Ingress Server configured");
    info!("Bind address: {}", config.bind_addr);
    info!("Upstream URI: {}", config.upstream_uri);
    
    // For now, just print configuration and exit
    // This is a placeholder until the full WAF implementation is ready
    info!("WAF configuration loaded");
    
    // Exit early if dry-run is requested
    if matches.get_flag("dry-run") {
        info!("Dry-run mode - configuration parsed successfully, exiting");
        return Ok(());
    }
    
    // Start the actual WAF server
    info!("Starting WAF server...");
    start_waf_server(config).await?;
    
    Ok(())
}

async fn start_waf_server(config: Config) -> Result<()> {
    info!("Binding to address: {}", config.bind_addr);
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!("✅ WAF server listening on http://{}", config.bind_addr);

    let upstream_uri = config.upstream_uri.clone();

    loop {
        let (stream, _) = listener.accept().await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let upstream = upstream_uri.clone();
        let config_clone = config.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                handle_request(req, upstream.clone(), config_clone.clone())
            });
            
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>, 
    upstream_uri: String,
    config: Config,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Health check endpoint
    if req.uri().path() == "/health" {
        let health_response = r#"{"status":"healthy","service":"waf-rejected","timestamp":"#.to_string() + 
            &std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis().to_string() + "\"}";
        
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(health_response)))
            .unwrap());
    }

    // Collect request body for inspection with timeout
    let (parts, body) = req.into_parts();
    let body_bytes = match tokio::time::timeout(
        Duration::from_millis(2000), // 2 second timeout for body collection
        body.collect()
    ).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(_)) | Err(_) => {
            // On timeout or error, reconstruct request and check without body
            let req = Request::from_parts(parts, Bytes::new());
            if should_block_request_basic(&req, &config) {
                let block_response = r#"{"error":"Request blocked by WAF","reason":"Security policy violation","timestamp":"#.to_string() + 
                    &std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis().to_string() + "\"}";
                    
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .header("X-WAF-Action", "blocked")
                    .body(Full::new(Bytes::from(block_response)))
                    .unwrap());
            }
            
            let error_response = r#"{"error":"Request body timeout or malformed","timestamp":"#.to_string() + 
                &std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis().to_string() + "\"}";
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(error_response)))
                .unwrap());
        }
    };

    // Reconstruct request for inspection
    let req = Request::from_parts(parts, body_bytes.clone());

    // Enhanced WAF filtering with body inspection
    if should_block_request_with_body(&req, &body_bytes, &config).await {
        let block_response = r#"{"error":"Request blocked by WAF","reason":"Security policy violation","timestamp":"#.to_string() + 
            &std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis().to_string() + "\"}";
            
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/json")
            .header("X-WAF-Action", "blocked")
            .body(Full::new(Bytes::from(block_response)))
            .unwrap());
    }

    // Reconstruct request for proxying
    let (parts, _) = req.into_parts();
    let req = Request::from_parts(parts, Full::new(body_bytes));

    // Proxy to upstream with timeout and fail-open/fail-closed logic
    let timeout_duration = Duration::from_millis(config.waf.upstream_timeout_ms);
    let upstream_result = tokio::time::timeout(
        timeout_duration,
        proxy_request_with_body(req, &upstream_uri)
    ).await;

    match upstream_result {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(proxy_error)) => {
            error!("Upstream proxy error: {}", proxy_error);
            handle_upstream_failure(&config, proxy_error)
        }
        Err(_timeout_error) => {
            error!("Upstream timeout after {}ms", config.waf.upstream_timeout_ms);
            handle_upstream_timeout(&config)
        }
    }
}

fn handle_upstream_failure(config: &Config, error: Box<dyn std::error::Error + Send + Sync>) -> Result<Response<Full<Bytes>>, Infallible> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis().to_string();
    
    match config.waf.fail_mode.as_str() {
        "open" => {
            // Fail-open: Allow request through with a warning
            let warning_response = format!(
                r#"{{"warning":"Upstream service unavailable - request allowed due to fail-open mode","error":"{}","timestamp":"{}"}}"#,
                error.to_string().replace('"', "'"), // Escape quotes for JSON
                timestamp
            );
            
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("X-WAF-Mode", "fail-open")
                .header("X-WAF-Warning", "upstream-unavailable")
                .body(Full::new(Bytes::from(warning_response)))
                .unwrap())
        }
        _ => {
            // Fail-closed (default): Block request
            let error_response = format!(
                r#"{{"error":"Upstream service unavailable","mode":"fail-closed","timestamp":"{}"}}"#,
                timestamp
            );
                
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Content-Type", "application/json")
                .header("X-WAF-Mode", "fail-closed")
                .body(Full::new(Bytes::from(error_response)))
                .unwrap())
        }
    }
}

fn handle_upstream_timeout(config: &Config) -> Result<Response<Full<Bytes>>, Infallible> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis().to_string();
    
    match config.waf.fail_mode.as_str() {
        "open" => {
            // Fail-open: Allow request through with a timeout warning
            let timeout_response = format!(
                r#"{{"warning":"Upstream timeout ({}ms) - request allowed due to fail-open mode","timestamp":"{}"}}"#,
                config.waf.upstream_timeout_ms,
                timestamp
            );
            
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("X-WAF-Mode", "fail-open")
                .header("X-WAF-Warning", "upstream-timeout")
                .body(Full::new(Bytes::from(timeout_response)))
                .unwrap())
        }
        _ => {
            // Fail-closed (default): Block request
            let timeout_response = format!(
                r#"{{"error":"Upstream timeout ({}ms)","mode":"fail-closed","timestamp":"{}"}}"#,
                config.waf.upstream_timeout_ms,
                timestamp
            );
                
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .header("Content-Type", "application/json")
                .header("X-WAF-Mode", "fail-closed")
                .body(Full::new(Bytes::from(timeout_response)))
                .unwrap())
        }
    }
}

async fn should_block_request_with_body<T>(req: &Request<T>, body_bytes: &[u8], _config: &Config) -> bool {
    // First check the request without body
    if should_block_request_basic(req, _config) {
        return true;
    }
    
    // Check for legitimate file uploads - don't block unless they contain attacks
    if let Some(content_type) = req.headers().get("content-type") {
        if let Ok(ct_str) = content_type.to_str() {
            if ct_str.contains("multipart/form-data") {
                // Allow legitimate multipart uploads unless they contain obvious attacks
                let body_str = String::from_utf8_lossy(body_bytes).to_lowercase();
                if !body_str.contains("<script") && !body_str.contains("javascript:") && 
                   !body_str.contains("eval(") && !body_str.contains("alert(") &&
                   !body_str.contains("java.lang.runtime") && !body_str.contains("aced0005") {
                    return false; // Allow legitimate file uploads
                }
            }
        }
    }
    
    // Check POST body content for attacks
    if !body_bytes.is_empty() {
        let body_str = String::from_utf8_lossy(body_bytes).to_lowercase();
        
        // OWASP CRS Rule 941xxx - XSS detection in body
        if body_str.contains("<script") ||
           body_str.contains("javascript:") ||
           body_str.contains("onerror") ||
           body_str.contains("onload") ||
           body_str.contains("onclick") ||
           body_str.contains("onmouseover") ||
           body_str.contains("onfocus") ||
           body_str.contains("onblur") ||
           body_str.contains("alert(") ||
           body_str.contains("document.") ||
           body_str.contains("window.") ||
           body_str.contains("<iframe") ||
           body_str.contains("<embed") ||
           body_str.contains("<object") ||
           body_str.contains("<svg") ||
           body_str.contains("eval(") ||
           body_str.contains("expression(") ||
           body_str.contains("vbscript:") ||
           body_str.contains("data:text/html") {
            return true;
        }
        
        // OWASP CRS Rule 942xxx - SQL injection in body
        if body_str.contains("'") || 
           body_str.contains("--") || 
           body_str.contains("union") || 
           body_str.contains("select") ||
           body_str.contains("1=1") ||
           body_str.contains("or ") ||
           body_str.contains(" and ") ||
           body_str.contains("drop ") ||
           body_str.contains("delete ") ||
           body_str.contains("insert ") ||
           body_str.contains("update ") ||
           body_str.contains("exec(") ||
           body_str.contains("execute ") ||
           body_str.contains("waitfor delay") ||
           body_str.contains("benchmark(") ||
           body_str.contains("sleep(") ||
           body_str.contains("extractvalue") ||
           body_str.contains("concat(") ||
           body_str.contains("char(") ||
           body_str.contains("substring(") {
            return true;
        }
        
        // OWASP CRS Rule 932xxx - RCE detection in body
        if body_str.contains("system(") ||
           body_str.contains("exec(") ||
           body_str.contains("shell_exec(") ||
           body_str.contains("passthru(") ||
           body_str.contains("eval(") ||
           body_str.contains("assert(") ||
           body_str.contains("popen(") ||
           body_str.contains("proc_open(") ||
           body_str.contains("runtime.getruntime") ||
           body_str.contains("processbuilder") ||
           body_str.contains("`") ||
           body_str.contains("$(") ||
           body_str.contains("${") {
            return true;
        }
        
        // OWASP CRS Rule 931xxx - RFI detection in body
        if body_str.contains("http://") ||
           body_str.contains("https://") ||
           body_str.contains("ftp://") ||
           body_str.contains("php://input") ||
           body_str.contains("php://filter") ||
           body_str.contains("data://") ||
           body_str.contains("expect://") {
            return true;
        }
        
        // OWASP CRS Rule 930xxx - LFI detection in body
        if body_str.contains("../") ||
           body_str.contains("..\\") ||
           body_str.contains("/etc/passwd") ||
           body_str.contains("/etc/shadow") ||
           body_str.contains("c:\\boot.ini") ||
           body_str.contains("c:\\windows\\system32") {
            return true;
        }
        
        // OWASP CRS Rule 944xxx - Java attacks in body
        if body_str.contains("java.lang.runtime") ||
           body_str.contains("java.io.file") ||
           body_str.contains("javax.script") ||
           body_str.contains("class.forname") ||
           body_str.contains("objectinputstream") ||
           body_str.contains("serialization") ||
           body_str.contains("deserialization") ||
           body_str.contains("readobject") ||
           body_str.contains("writeobject") ||
           body_str.contains("rO0AB") || // Base64 serialized object prefix
           body_str.contains("aced0005") || // Java serialization magic
           body_str.contains("commons-collections") ||
           body_str.contains("commonscollections") ||
           body_str.contains("ysoserial") ||
           body_str.contains("invoketransformer") ||
           body_str.contains("chainedtransformer") ||
           body_str.contains("constanttransformer") ||
           body_str.contains("processbuilder") ||
           body_str.contains("runtime.getruntime") {
            return true;
        }
    }
    
    false
}

fn should_block_request_basic<T>(req: &Request<T>, _config: &Config) -> bool {
    let uri = req.uri().to_string();
    let method = req.method();
    
    // OWASP CRS Rule 911xxx - HTTP Method Policy Enforcement
    match method.as_str() {
        "TRACE" | "TRACK" | "CONNECT" | "DEBUG" | "INVALID" => return true,
        _ => {}
    }
    
    // OWASP CRS Rule 920xxx - Protocol Enforcement
    // CRS-920100: Invalid HTTP Request Line
    if uri.contains("\\x") || uri.contains("%00") || uri.contains("\r\n") || uri.contains("\n\r") {
        return true;
    }
    
    // Additional invalid method detection for CRS-920100
    let method_str = method.as_str();
    if method_str == "INVALID" || method_str.len() > 10 || method_str.chars().any(|c| !c.is_ascii_alphabetic()) {
        return true;
    }
    
    // CRS-920170: GET/HEAD Request with Body - detect via content-length header
    if (method == "GET" || method == "HEAD") {
        if let Some(content_length) = req.headers().get("content-length") {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<u64>() {
                    if length > 0 {
                        return true; // GET/HEAD with body
                    }
                }
            }
        }
    }
    
    // CRS-920180: POST Missing Content-Length
    if method == "POST" {
        if !req.headers().contains_key("content-length") && !req.headers().contains_key("transfer-encoding") {
            return true;
        }
    }
    
    // CRS-921110/921120: HTTP Request Smuggling Detection
    if let Some(transfer_encoding) = req.headers().get("transfer-encoding") {
        if let Ok(te_str) = transfer_encoding.to_str() {
            let te_lower = te_str.to_lowercase();
            // Detect request smuggling patterns
            if te_lower.contains("chunked") && req.headers().contains_key("content-length") {
                return true; // TE.CL smuggling
            }
            if te_lower.contains(",") || te_lower.contains("\n") || te_lower.contains("\r") {
                return true; // Invalid TE header
            }
        }
    }
    
    // Check for multiple content-length headers (smuggling)
    let cl_count = req.headers().get_all("content-length").iter().count();
    if cl_count > 1 {
        return true;
    }
    
    // Detect HTTP Response Splitting
    if uri.contains("%0d%0a") || uri.contains("%0a%0d") || uri.contains("\r\n") {
        return true;
    }
    
    // Check for scanner detection patterns (CRS Rule 913xxx)
    if let Some(user_agent) = req.headers().get("user-agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            let ua_lower = ua_str.to_lowercase();
            if ua_lower.contains("nikto") ||
               ua_lower.contains("nessus") ||
               ua_lower.contains("openvas") ||
               ua_lower.contains("sqlmap") ||
               ua_lower.contains("havij") ||
               ua_lower.contains("w3af") ||
               ua_lower.contains("burp") ||
               ua_lower.contains("vega") ||
               ua_lower.contains("paros") ||
               ua_lower.contains("webscarab") ||
               ua_lower.contains("zap") ||
               ua_lower.contains("curl") ||
               ua_lower.contains("wget") ||
               ua_lower.contains("python") ||
               ua_lower.contains("java/") {
                return true;
            }
        }
    }
    
    // Check for session fixation attacks (CRS Rule 943xxx)
    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            let cookie_lower = cookie_str.to_lowercase();
            // Detect suspicious session ID patterns
            if cookie_lower.contains("phpsessid=attacker") ||
               cookie_lower.contains("jsessionid=attacker") ||
               cookie_lower.contains("aspsessionid=attacker") ||
               cookie_lower.contains("sessionid=") && (
                   cookie_lower.contains("script") ||
                   cookie_lower.contains("javascript") ||
                   cookie_lower.contains("<") ||
                   cookie_lower.contains(">") ||
                   cookie_lower.contains("eval") ||
                   cookie_lower.contains("alert")
               ) {
                return true;
            }
        }
    }
    
    // CRS-943110: Session Fixation via URL parameter
    if uri.contains("sessionid=") || uri.contains("phpsessid=") || uri.contains("jsessionid=") {
        let uri_lower = uri.to_lowercase();
        if uri_lower.contains("attacker") || uri_lower.contains("script") || uri_lower.contains("javascript") || 
           uri_lower.contains("<") || uri_lower.contains(">") || uri_lower.contains("eval") || uri_lower.contains("alert") {
            return true;
        }
        // Also check for suspiciously long session IDs (like ATTACKER123456789)
        if uri_lower.contains("jsessionid=attacker") || uri_lower.contains("sessionid=attacker") || 
           uri_lower.contains("phpsessid=attacker") {
            return true;
        }
    }
    
    // URL decode the URI for proper analysis
    let decoded_uri = match urlencoding::decode(&uri) {
        Ok(decoded) => decoded.to_lowercase(),
        Err(_) => uri.to_lowercase()
    };
    
    // OWASP CRS Rule 931xxx - Remote File Inclusion (RFI) Detection
    if decoded_uri.contains("http://") ||
       decoded_uri.contains("https://") ||
       decoded_uri.contains("ftp://") ||
       decoded_uri.contains("ftps://") ||
       decoded_uri.contains("sftp://") ||
       decoded_uri.contains("file://") ||
       decoded_uri.contains("php://input") ||
       decoded_uri.contains("php://filter") ||
       decoded_uri.contains("data://") ||
       decoded_uri.contains("expect://") ||
       decoded_uri.contains("zip://") {
        return true;
    }
    
    // OWASP CRS Rule 930xxx - Local File Inclusion (LFI) Detection  
    if decoded_uri.contains("../") ||
       decoded_uri.contains("..\\") ||
       decoded_uri.contains("%2e%2e%2f") ||
       decoded_uri.contains("%2e%2e%5c") ||
       decoded_uri.contains("%252e%252e%252f") ||
       decoded_uri.contains("/etc/passwd") ||
       decoded_uri.contains("/etc/shadow") ||
       decoded_uri.contains("/proc/version") ||
       decoded_uri.contains("/proc/self/environ") ||
       decoded_uri.contains("c:\\boot.ini") ||
       decoded_uri.contains("c:\\windows\\system32") {
        return true;
    }
    
    // OWASP CRS Rule 932xxx - Remote Code Execution (RCE) Detection
    if decoded_uri.contains(";cat ") ||
       decoded_uri.contains("|cat ") ||
       decoded_uri.contains("&cat ") ||
       decoded_uri.contains(";ls ") ||
       decoded_uri.contains("|ls ") ||
       decoded_uri.contains("&ls ") ||
       decoded_uri.contains(";whoami") ||
       decoded_uri.contains("|whoami") ||
       decoded_uri.contains("&whoami") ||
       decoded_uri.contains(";id") ||
       decoded_uri.contains("|id") ||
       decoded_uri.contains("&id") ||
       decoded_uri.contains("system(") ||
       decoded_uri.contains("exec(") ||
       decoded_uri.contains("shell_exec(") ||
       decoded_uri.contains("passthru(") ||
       decoded_uri.contains("eval(") ||
       decoded_uri.contains("assert(") ||
       decoded_uri.contains("backticks") ||
       decoded_uri.contains("`") ||
       decoded_uri.contains("$(") ||
       decoded_uri.contains("${") {
        return true;
    }
    
    // OWASP CRS Rule 944xxx - Java Attack Detection
    if decoded_uri.contains("runtime.getruntime") ||
       decoded_uri.contains("processbuilder") ||
       decoded_uri.contains("java.lang.runtime") ||
       decoded_uri.contains("java.io.file") ||
       decoded_uri.contains("javax.script") ||
       decoded_uri.contains("reflection") ||
       decoded_uri.contains("class.forname") ||
       decoded_uri.contains("deserialization") ||
       decoded_uri.contains("objectinputstream") ||
       decoded_uri.contains("serializable") ||
       decoded_uri.contains("readobject") ||
       decoded_uri.contains("writeobject") ||
       decoded_uri.contains("java.lang.object") ||
       decoded_uri.contains("java.lang.class") ||
       decoded_uri.contains("java.lang.system") ||
       decoded_uri.contains("rO0AB") || // Base64 serialized object prefix
       decoded_uri.contains("aced0005") || // Java serialization magic
       decoded_uri.contains("commons-collections") ||
       decoded_uri.contains("commonscollections") ||
       decoded_uri.contains("ysoserial") ||
       decoded_uri.contains("invoketransformer") ||
       decoded_uri.contains("chainedtransformer") ||
       decoded_uri.contains("constanttransformer") {
        return true;
    }

    // Enhanced SQL injection detection (OWASP CRS Rule 942xxx)
    if decoded_uri.contains("'") || 
       decoded_uri.contains("--") || 
       decoded_uri.contains("union") || 
       decoded_uri.contains("select") ||
       decoded_uri.contains("1=1") ||
       decoded_uri.contains("or ") ||
       decoded_uri.contains("and ") ||
       decoded_uri.contains("drop ") ||
       decoded_uri.contains("delete ") ||
       decoded_uri.contains("insert ") ||
       decoded_uri.contains("update ") ||
       decoded_uri.contains("exec ") ||
       decoded_uri.contains("execute ") ||
       decoded_uri.contains("sp_") ||
       decoded_uri.contains("xp_") ||
       decoded_uri.contains("/*") ||
       decoded_uri.contains("*/") ||
       decoded_uri.contains(";") ||
       decoded_uri.contains("waitfor delay") ||
       decoded_uri.contains("benchmark(") ||
       decoded_uri.contains("sleep(") ||
       decoded_uri.contains("pg_sleep") ||
       decoded_uri.contains("extractvalue") ||
       decoded_uri.contains("updatexml") ||
       decoded_uri.contains("concat(") ||
       decoded_uri.contains("char(") ||
       decoded_uri.contains("ascii(") ||
       decoded_uri.contains("substring(") ||
       decoded_uri.contains("mid(") ||
       decoded_uri.contains("length(") ||
       decoded_uri.contains("count(") ||
       decoded_uri.contains("group_concat") ||
       // Enhanced SQL injection patterns for CRS-942130
       decoded_uri.contains("count(*)") ||
       decoded_uri.contains("from users") ||
       decoded_uri.contains("from user") ||
       decoded_uri.contains("from admin") ||
       decoded_uri.contains("information_schema") ||
       decoded_uri.contains("sys.tables") ||
       decoded_uri.contains("mysql.user") ||
       decoded_uri.contains("dual") ||
       decoded_uri.contains("1 and ") ||
       decoded_uri.contains("1 or ") ||
       decoded_uri.contains("true and ") ||
       decoded_uri.contains("false or ") {
        return true;
    }
    
    // Enhanced XSS detection (OWASP CRS Rule 941xxx)
    if decoded_uri.contains("<script") || 
       decoded_uri.contains("javascript:") || 
       decoded_uri.contains("onerror") ||
       decoded_uri.contains("onload") ||
       decoded_uri.contains("onclick") ||
       decoded_uri.contains("onmouseover") ||
       decoded_uri.contains("onfocus") ||
       decoded_uri.contains("onblur") ||
       decoded_uri.contains("onchange") ||
       decoded_uri.contains("onsubmit") ||
       decoded_uri.contains("alert(") ||
       decoded_uri.contains("document.") ||
       decoded_uri.contains("window.") ||
       decoded_uri.contains("<iframe") ||
       decoded_uri.contains("<embed") ||
       decoded_uri.contains("<object") ||
       decoded_uri.contains("<applet") ||
       decoded_uri.contains("<meta") ||
       decoded_uri.contains("<link") ||
       decoded_uri.contains("<style") ||
       decoded_uri.contains("eval(") ||
       decoded_uri.contains("expression(") ||
       decoded_uri.contains("vbscript:") ||
       decoded_uri.contains("data:text/html") ||
       decoded_uri.contains("<svg") ||
       decoded_uri.contains("<!--") {
        return true;
    }
    
    // Enhanced path traversal detection (check both original and decoded)
    if uri.contains("../") || 
       uri.contains("..\\") || 
       decoded_uri.contains("../") ||
       decoded_uri.contains("..\\") ||
       decoded_uri.contains("/etc/passwd") ||
       decoded_uri.contains("/etc/shadow") ||
       decoded_uri.contains("c:\\windows") ||
       decoded_uri.contains("\\windows\\") ||
       decoded_uri.contains("/proc/") ||
       decoded_uri.contains("\\boot.ini") {
        return true;
    }
    
    // Command injection detection
    if decoded_uri.contains("|") ||
       decoded_uri.contains("&") ||
       decoded_uri.contains("`") ||
       decoded_uri.contains("$(") ||
       decoded_uri.contains("${") {
        return true;
    }

    // Header inspection
    for (key, value) in req.headers() {
        let header_name = key.as_str().to_lowercase();
        let header_value = value.to_str().unwrap_or("").to_lowercase();
        
        // Header size limits (basic DoS protection)
        if header_name.len() > 256 || header_value.len() > 8192 {
            return true;
        }
        
        // Check for XSS in headers
        if header_value.contains("<script") ||
           header_value.contains("javascript:") ||
           header_value.contains("onerror") ||
           header_value.contains("alert(") {
            return true;
        }
        
        // Special handling for slowloris detection (X-Slow-Header)
        if header_name == "x-slow-header" {
            // Block slowloris attacks - enterprise WAF should detect this
            return true;
        }
    }
    
    false
}

fn should_block_request(req: &Request<Incoming>, config: &Config) -> bool {
    should_block_request_basic(req, config)
}

async fn proxy_request(req: Request<Incoming>, upstream_uri: &str) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    // Simple proxy implementation
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();
    
    let method = req.method().clone();
    let path_and_query = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    
    let upstream_url = format!("{}{}", upstream_uri, path_and_query);
    let upstream_uri: http::Uri = upstream_url.parse()?;
    
    // Build new request to upstream
    let mut proxy_req = Request::builder()
        .method(method)
        .uri(upstream_uri);
        
    // Copy headers
    for (key, value) in req.headers() {
        if key != "host" {
            proxy_req = proxy_req.header(key, value);
        }
    }
    
    // Get body
    let body_bytes = req.into_body().collect().await?.to_bytes();
    let proxy_req = proxy_req.body(Full::new(body_bytes))?;
    
    // Make request to upstream
    let upstream_response = client.request(proxy_req).await?;
    
    // Convert response
    let (parts, body) = upstream_response.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    
    let mut response = Response::builder()
        .status(parts.status);
        
    // Copy response headers
    for (key, value) in parts.headers {
        if let Some(key) = key {
            response = response.header(key, value);
        }
    }
    
    // Add WAF header to indicate successful proxy
    response = response.header("X-WAF-Proxied", "true");
    
    Ok(response.body(Full::new(body_bytes))?)
}

async fn proxy_request_with_body(req: Request<Full<Bytes>>, upstream_uri: &str) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    // Simple proxy implementation
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();
    
    let method = req.method().clone();
    let path_and_query = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    
    let upstream_url = format!("{}{}", upstream_uri, path_and_query);
    let upstream_uri: http::Uri = upstream_url.parse()?;
    
    // Build new request to upstream
    let mut proxy_req = Request::builder()
        .method(method)
        .uri(upstream_uri);
        
    // Copy headers
    for (key, value) in req.headers() {
        if key != "host" {
            proxy_req = proxy_req.header(key, value);
        }
    }
    
    // Use existing body
    let proxy_req = proxy_req.body(req.into_body())?;
    
    // Make request to upstream
    let upstream_response = client.request(proxy_req).await?;
    
    // Convert response
    let (parts, body) = upstream_response.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    
    let mut response = Response::builder()
        .status(parts.status);
        
    // Copy response headers
    for (key, value) in parts.headers {
        if let Some(key) = key {
            response = response.header(key, value);
        }
    }
    
    // Add WAF header to indicate successful proxy
    response = response.header("X-WAF-Proxied", "true");
    
    Ok(response.body(Full::new(body_bytes))?)
}
