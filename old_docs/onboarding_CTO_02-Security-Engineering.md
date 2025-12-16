# Chapter 2: Security Engineering Deep Dive

## 🛡️ Security Engineering Philosophy

WAF-Rejected implements a **defense-in-depth security model** with multiple layers of protection, advanced threat detection, and comprehensive logging, designed to protect against the evolving landscape of web application attacks.

### Security Design Principles

#### 1. **Zero Trust Architecture**
- **Never Trust, Always Verify**: Every request undergoes security validation
- **Least Privilege**: Minimal access rights for all system components
- **Continuous Validation**: Real-time security posture assessment
- **Assume Breach**: Design for compromise and implement containment

#### 2. **Proactive Threat Detection**
- **Signature-Based Detection**: Known attack pattern matching
- **Behavioral Analysis**: Anomaly detection for unknown threats  
- **Machine Learning Integration**: Adaptive threat recognition
- **Threat Intelligence**: Integration with external threat feeds

#### 3. **Comprehensive Logging**
- **Security Event Logging**: All security decisions logged
- **Audit Trail**: Complete audit trail for compliance
- **Real-time Analysis**: Immediate threat detection and response
- **Forensic Capability**: Detailed event reconstruction

## 🔍 Threat Detection Engine

### ModSecurity Integration

#### **OWASP Core Rule Set (CRS)**
```rust
// ModSecurity engine configuration
pub struct ModSecurityConfig {
    pub rules_directory: PathBuf,
    pub anomaly_threshold: u32,
    pub paranoia_level: u8,
    pub rule_engine: RuleEngine,
    pub request_body_limit: usize,
    pub response_body_limit: usize,
}

pub enum RuleEngine {
    DetectionOnly,  // Log only, don't block
    RejectBlocked, // Block requests that match rules
    ProcessAll,    // Full processing with blocking
}
```

#### **Attack Vector Detection**
1. **SQL Injection (SQLi)**
   - Union-based attacks
   - Boolean-based blind SQLi
   - Time-based blind SQLi
   - Error-based SQLi
   - NoSQL injection patterns

2. **Cross-Site Scripting (XSS)**
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS
   - mXSS (mutation XSS)
   - JavaScript event handler injection

3. **Remote Code Execution (RCE)**
   - Command injection
   - Code injection
   - Server-side template injection
   - Expression language injection
   - File upload exploitation

4. **Local File Inclusion (LFI)**
   - Directory traversal
   - Path manipulation
   - Null byte injection
   - Double encoding
   - Unicode encoding

5. **Remote File Inclusion (RFI)**
   - HTTP/HTTPS inclusion
   - FTP inclusion
   - Data URI schemes
   - Wrapper exploitation

### WASM Rule Engine

#### **Custom Rule Development**
```rust
// WASM rule interface
pub trait WasmRule {
    fn analyze_request(&self, request: &HttpRequest) -> SecurityDecision;
    fn analyze_response(&self, response: &HttpResponse) -> SecurityDecision;
    fn get_rule_metadata(&self) -> RuleMetadata;
}

pub struct SecurityDecision {
    pub action: SecurityAction,
    pub confidence: f32,
    pub threat_type: ThreatType,
    pub explanation: String,
}

pub enum SecurityAction {
    Allow,
    Block,
    Monitor,
    Challenge,
    Throttle(Duration),
}
```

#### **Advanced Detection Capabilities**
- **Behavioral Analysis**: User behavior pattern analysis
- **Machine Learning Models**: Feature extraction for ML-based detection
- **Protocol Analysis**: HTTP protocol violation detection
- **Content Analysis**: Deep content inspection and validation
- **Session Management**: Session hijacking and fixation detection

### Geographic Risk Assessment

#### **IP Geolocation Analysis**
```rust
pub struct GeographicAnalyzer {
    maxmind_reader: maxminddb::Reader<Vec<u8>>,
    risk_configuration: GeographicRiskConfig,
}

pub struct GeographicInfo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub risk_score: f32,
}

pub struct GeographicRiskConfig {
    pub blocked_countries: HashSet<String>,
    pub high_risk_countries: HashSet<String>,
    pub allowed_countries: Option<HashSet<String>>,
    pub tor_detection: bool,
    pub proxy_detection: bool,
    pub vpn_detection: bool,
}
```

#### **Risk Scoring Algorithm**
1. **Country Risk**: Base risk score per country (0.0-1.0)
2. **Network Risk**: ASN and organization reputation
3. **Infrastructure Risk**: Hosting providers, VPS, cloud providers
4. **Anonymization Risk**: Tor, VPN, proxy detection
5. **Historical Risk**: Past attack patterns from IP ranges

## 🔄 Rate Limiting & Traffic Management

### Distributed Rate Limiting

#### **Redis-Based Rate Limiting**
```rust
pub struct RateLimiter {
    redis_client: redis::Client,
    rules: Vec<RateRule>,
}

pub struct RateRule {
    pub name: String,
    pub pattern: Regex,
    pub limit: u32,
    pub window: Duration,
    pub burst: u32,
    pub key_strategy: KeyStrategy,
}

pub enum KeyStrategy {
    PerIP,
    PerUser,
    PerSession,
    PerEndpoint,
    Composite(Vec<String>),
}
```

#### **Rate Limiting Algorithms**
1. **Token Bucket**: Burst handling with sustained rate
2. **Leaky Bucket**: Smooth traffic shaping
3. **Fixed Window**: Simple per-period limits
4. **Sliding Window**: More accurate rate enforcement
5. **Adaptive Rate Limiting**: Dynamic adjustment based on load

### Traffic Analysis

#### **Request Pattern Analysis**
```rust
pub struct TrafficAnalyzer {
    pub request_patterns: LruCache<String, RequestPattern>,
    pub anomaly_detector: AnomalyDetector,
    pub baseline_metrics: BaselineMetrics,
}

pub struct RequestPattern {
    pub frequency: f64,
    pub size_distribution: Vec<u64>,
    pub endpoint_distribution: HashMap<String, u32>,
    pub user_agent_patterns: Vec<String>,
    pub timing_patterns: Vec<Duration>,
}
```

#### **Anomaly Detection**
- **Statistical Analysis**: Standard deviation-based anomaly detection
- **Time Series Analysis**: Seasonal and trend analysis
- **Clustering**: Request clustering for pattern identification
- **Machine Learning**: Unsupervised learning for anomaly detection

## 🔐 Content Security & Validation

### Request Validation

#### **Input Validation Framework**
```rust
pub struct RequestValidator {
    pub content_type_validators: HashMap<String, Box<dyn ContentValidator>>,
    pub encoding_detectors: Vec<Box<dyn EncodingDetector>>,
    pub size_limits: SizeLimits,
}

pub trait ContentValidator {
    fn validate(&self, content: &[u8]) -> ValidationResult;
    fn sanitize(&self, content: &[u8]) -> Vec<u8>;
}

pub struct ValidationResult {
    pub is_valid: bool,
    pub violations: Vec<ValidationViolation>,
    pub risk_score: f32,
}
```

#### **Content Type Analysis**
1. **JSON Validation**: Schema validation, injection detection
2. **XML Validation**: XXE detection, entity validation
3. **Form Data**: Parameter pollution, encoding attacks
4. **Multipart Data**: File upload security, MIME type validation
5. **Binary Content**: Malware detection, file type validation

### Response Security

#### **Response Analysis**
```rust
pub struct ResponseAnalyzer {
    pub data_leak_detectors: Vec<Box<dyn DataLeakDetector>>,
    pub content_scanners: Vec<Box<dyn ContentScanner>>,
}

pub trait DataLeakDetector {
    fn scan_response(&self, response: &HttpResponse) -> Vec<DataLeak>;
}

pub struct DataLeak {
    pub data_type: DataType,
    pub confidence: f32,
    pub location: String,
    pub sample: String,
}

pub enum DataType {
    CreditCard,
    SocialSecurityNumber,
    EmailAddress,
    PhoneNumber,
    IPAddress,
    ApiKey,
    Password,
    Custom(String),
}
```

#### **Data Loss Prevention (DLP)**
- **PII Detection**: Personally identifiable information scanning
- **Financial Data**: Credit card, banking information detection
- **API Keys**: Credential and token detection
- **Custom Patterns**: Configurable sensitive data patterns

## 📊 Security Event Processing

### Event Generation & Classification

#### **Security Event Structure**
```rust
pub struct SecurityEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub event_type: SecurityEventType,
    pub source: EventSource,
    pub request_info: RequestInfo,
    pub detection_info: DetectionInfo,
    pub mitigation: MitigationAction,
    pub context: HashMap<String, Value>,
}

pub enum Severity {
    Critical,  // Immediate action required
    High,      // Urgent attention needed
    Medium,    // Important but not urgent
    Low,       // Informational
    Info,      // General information
}

pub enum SecurityEventType {
    AttackDetected,
    AnomalyDetected,
    PolicyViolation,
    AccessDenied,
    RateLimitExceeded,
    DataLeakDetected,
    SystemAlert,
}
```

#### **Event Correlation Engine**
```rust
pub struct EventCorrelator {
    pub correlation_rules: Vec<CorrelationRule>,
    pub event_store: EventStore,
    pub alert_manager: AlertManager,
}

pub struct CorrelationRule {
    pub name: String,
    pub conditions: Vec<Condition>,
    pub time_window: Duration,
    pub threshold: u32,
    pub action: CorrelationAction,
}
```

### Real-Time Analysis

#### **Stream Processing**
- **Event Streaming**: Real-time event processing pipeline
- **Pattern Matching**: Complex event pattern recognition
- **Aggregation**: Event aggregation and summarization
- **Enrichment**: Event enrichment with threat intelligence

#### **Threat Intelligence Integration**
```rust
pub struct ThreatIntelligence {
    pub ip_reputation: IpReputationService,
    pub domain_reputation: DomainReputationService,
    pub malware_signatures: MalwareSignatureService,
    pub threat_feeds: Vec<Box<dyn ThreatFeed>>,
}

pub trait ThreatFeed {
    fn get_threat_info(&self, indicator: &str) -> Option<ThreatInfo>;
    fn is_malicious(&self, indicator: &str) -> bool;
    fn get_reputation_score(&self, indicator: &str) -> f32;
}
```

## 🔄 Security Operations

### Incident Response

#### **Automated Response Actions**
```rust
pub enum ResponseAction {
    Block {
        duration: Option<Duration>,
        scope: BlockScope,
    },
    Challenge {
        challenge_type: ChallengeType,
        difficulty: u8,
    },
    Throttle {
        rate_limit: u32,
        duration: Duration,
    },
    Monitor {
        enhanced_logging: bool,
        alert_threshold: u32,
    },
    Redirect {
        target_url: String,
        preserve_query: bool,
    },
}

pub enum BlockScope {
    IP,
    Subnet,
    ASN,
    Country,
    UserAgent,
    Session,
}
```

#### **Incident Classification**
1. **Severity Assessment**: Automated severity classification
2. **Impact Analysis**: Business impact assessment
3. **Response Prioritization**: Resource allocation based on severity
4. **Escalation Rules**: Automatic escalation for critical incidents

### Compliance & Reporting

#### **Compliance Frameworks**
- **PCI DSS**: Payment card industry compliance
- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act
- **SOC 2**: Service Organization Control 2
- **ISO 27001**: Information security management
- **NIST Cybersecurity Framework**: Risk management framework

#### **Audit Trail**
```rust
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub action: AuditAction,
    pub resource: String,
    pub outcome: AuditOutcome,
    pub details: HashMap<String, Value>,
    pub source_ip: IpAddr,
    pub user_agent: Option<String>,
}

pub enum AuditAction {
    ConfigurationChange,
    RuleUpdate,
    PolicyModification,
    UserAccess,
    SystemAccess,
    DataAccess,
    Export,
}
```

## 🔧 Security Configuration

### Rule Management

#### **Rule Configuration**
```toml
[security.rules]
enabled = ["owasp-crs", "custom-rules", "geo-blocking"]

[security.rules.owasp-crs]
path = "/etc/waf/rules/owasp"
paranoia_level = 2
anomaly_threshold = 5
sampling_percentage = 100

[security.rules.custom-rules]
path = "/etc/waf/rules/custom"
wasm_rules = ["bot-detection.wasm", "fraud-detection.wasm"]
reload_interval = "5m"

[security.geo-blocking]
blocked_countries = ["XX", "YY"]
high_risk_countries = ["ZZ"]
tor_blocking = true
proxy_detection = true
```

#### **Dynamic Rule Updates**
- **Hot Reloading**: Rule updates without service restart
- **A/B Testing**: Rule effectiveness testing
- **Gradual Rollout**: Phased rule deployment
- **Rollback Capability**: Quick rule rollback on issues

### Security Policies

#### **Policy Framework**
```rust
pub struct SecurityPolicy {
    pub name: String,
    pub version: String,
    pub rules: Vec<PolicyRule>,
    pub exceptions: Vec<PolicyException>,
    pub enforcement_mode: EnforcementMode,
}

pub struct PolicyRule {
    pub condition: PolicyCondition,
    pub action: PolicyAction,
    pub priority: u32,
}

pub enum EnforcementMode {
    Monitor,    // Log violations only
    Enforce,    // Block violations
    Learning,   // Build baseline
}
```

---

**Security Engineering prepared for CTO onboarding**  
**Document Classification**: Technical - Security Sensitive  
**Next Chapter**: [Platform Engineering & DevOps](03-Platform-Engineering.md)
