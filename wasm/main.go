//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"syscall/js"
)

// WAFEngine represents the WebAssembly interface to ModSecurity-style rules
type WAFEngine struct {
	rules []SecurityRule
}

// SecurityRule represents a single security rule
type SecurityRule struct {
	ID          int    `json:"id"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`
	Severity    string `json:"severity"`
	Tags        []string `json:"tags"`
	compiledRegex *regexp.Regexp
}

// SecurityDecision represents the result of WAF evaluation
type SecurityDecision struct {
	Action       string            `json:"action"`
	Blocked      bool              `json:"blocked"`
	Score        int               `json:"score"`
	Messages     []string          `json:"messages"`
	Headers      map[string]string `json:"headers"`
	TriggeredRules []int           `json:"triggered_rules"`
}

// RequestContext represents the HTTP request data for evaluation
type RequestContext struct {
	Method      string            `json:"method"`
	URI         string            `json:"uri"`
	Protocol    string            `json:"protocol"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ClientIP    string            `json:"client_ip"`
	UserAgent   string            `json:"user_agent"`
	ContentType string            `json:"content_type"`
	QueryParams string            `json:"query_params"`
}

var engine *WAFEngine

// Default security rules (simplified ModSecurity-style)
func getDefaultRules() []SecurityRule {
	rules := []SecurityRule{
		{
			ID:          1001,
			Description: "SQL Injection Detection",
			Pattern:     `(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|vbscript|onload|onerror|alert)\s*[\(\=]`,
			Action:      "block",
			Severity:    "critical",
			Tags:        []string{"attack-sqli", "OWASP_CRS"},
		},
		{
			ID:          1002,
			Description: "XSS Attack Detection",
			Pattern:     `(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onmouseover=|<iframe|<object|<embed)`,
			Action:      "block",
			Severity:    "critical",
			Tags:        []string{"attack-xss", "OWASP_CRS"},
		},
		{
			ID:          1003,
			Description: "Path Traversal Detection",
			Pattern:     `(\.\./|\.\.\%2f|\.\.\%5c|%2e%2e%2f|%2e%2e%5c)`,
			Action:      "block",
			Severity:    "critical",
			Tags:        []string{"attack-lfi", "path-traversal"},
		},
		{
			ID:          1004,
			Description: "Command Injection Detection",
			Pattern:     `(?i)(;|\||&|`+"`"+`|\$\(|%0a|%0d|nc\s|netcat|wget|curl|ping|nslookup|whoami|id\s)`,
			Action:      "block",
			Severity:    "critical",
			Tags:        []string{"attack-rce", "command-injection"},
		},
		{
			ID:          1005,
			Description: "HTTP Method Validation",
			Pattern:     `^(?!GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH).*$`,
			Action:      "block",
			Severity:    "error",
			Tags:        []string{"protocol-violation"},
		},
		{
			ID:          1006,
			Description: "Suspicious User-Agent",
			Pattern:     `(?i)(sqlmap|nmap|nikto|burp|owasp|zap|w3af|scanner|bot|crawler|python|curl|wget)`,
			Action:      "block",
			Severity:    "warning",
			Tags:        []string{"scanner-detection", "reputation-scanner"},
		},
		{
			ID:          1007,
			Description: "Large Request Body",
			Pattern:     ``,  // This will be handled specially in the code
			Action:      "block",
			Severity:    "warning",
			Tags:        []string{"dos-protection"},
		},
	}

	// Compile regex patterns
	for i := range rules {
		if rules[i].Pattern != "" {
			compiled, err := regexp.Compile(rules[i].Pattern)
			if err != nil {
				fmt.Printf("Failed to compile regex for rule %d: %v\n", rules[i].ID, err)
				continue
			}
			rules[i].compiledRegex = compiled
		}
	}

	return rules
}

// Initialize the WAF engine
func initializeWAF(this js.Value, args []js.Value) interface{} {
	engine = &WAFEngine{
		rules: getDefaultRules(),
	}
	
	return js.ValueOf(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("WAF engine initialized with %d rules", len(engine.rules)),
		"rules_loaded": len(engine.rules),
	})
}

// Process HTTP request through security rules
func processRequest(this js.Value, args []js.Value) interface{} {
	if engine == nil {
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "WAF engine not initialized",
		})
	}

	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "Request context required",
		})
	}

	// Parse request context from JSON
	requestJSON := args[0].String()
	var ctx RequestContext
	if err := json.Unmarshal([]byte(requestJSON), &ctx); err != nil {
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to parse request context: %v", err),
		})
	}

	// Evaluate request against rules
	decision := evaluateRequest(&ctx)
	
	result, _ := json.Marshal(decision)
	return js.ValueOf(map[string]interface{}{
		"success":  true,
		"decision": string(result),
	})
}

// Evaluate request against all security rules
func evaluateRequest(ctx *RequestContext) SecurityDecision {
	decision := SecurityDecision{
		Action:         "allow",
		Blocked:        false,
		Score:          0,
		Messages:       []string{},
		Headers:        map[string]string{"X-WAF-Status": "passed"},
		TriggeredRules: []int{},
	}

	// Combine all request data for pattern matching
	requestData := []string{
		ctx.URI,
		ctx.Body,
		ctx.UserAgent,
		ctx.QueryParams,
		ctx.Method,
	}
	
	// Add all header values
	for _, value := range ctx.Headers {
		requestData = append(requestData, value)
	}

	// Note: allData could be used for more complex pattern matching in the future
	_ = strings.Join(requestData, " ")

	for _, rule := range engine.rules {
		// Special handling for specific rules
		if rule.ID == 1007 { // Large request body
			if len(ctx.Body) > 1048576 { // 1MB limit
				decision = triggerRule(decision, rule, "Request body too large")
				continue
			}
		}

		if rule.ID == 1005 { // HTTP method validation
			if rule.compiledRegex != nil && rule.compiledRegex.MatchString(ctx.Method) {
				decision = triggerRule(decision, rule, fmt.Sprintf("Invalid HTTP method: %s", ctx.Method))
				continue
			}
		}

		// Pattern-based rule evaluation
		if rule.compiledRegex != nil {
			// Check URI
			if rule.compiledRegex.MatchString(ctx.URI) {
				decision = triggerRule(decision, rule, fmt.Sprintf("Pattern matched in URI: %s", ctx.URI))
				continue
			}
			
			// Check body
			if ctx.Body != "" && rule.compiledRegex.MatchString(ctx.Body) {
				decision = triggerRule(decision, rule, "Pattern matched in request body")
				continue
			}
			
			// Check User-Agent
			if rule.compiledRegex.MatchString(ctx.UserAgent) {
				decision = triggerRule(decision, rule, fmt.Sprintf("Pattern matched in User-Agent: %s", ctx.UserAgent))
				continue
			}
			
			// Check all headers
			for name, value := range ctx.Headers {
				if rule.compiledRegex.MatchString(value) {
					decision = triggerRule(decision, rule, fmt.Sprintf("Pattern matched in header %s", name))
					break
				}
			}
			
			// Check query parameters
			if ctx.QueryParams != "" && rule.compiledRegex.MatchString(ctx.QueryParams) {
				decision = triggerRule(decision, rule, "Pattern matched in query parameters")
				continue
			}
		}
	}

	// Set overall block decision based on any triggered critical rules
	if decision.Score > 0 {
		decision.Blocked = true
		decision.Action = "block"
		decision.Headers["X-WAF-Status"] = "blocked"
		decision.Headers["X-WAF-Score"] = fmt.Sprintf("%d", decision.Score)
	}

	return decision
}

// Trigger a security rule
func triggerRule(decision SecurityDecision, rule SecurityRule, message string) SecurityDecision {
	decision.TriggeredRules = append(decision.TriggeredRules, rule.ID)
	decision.Messages = append(decision.Messages, fmt.Sprintf("Rule %d (%s): %s", rule.ID, rule.Description, message))
	
	// Add score based on severity
	switch rule.Severity {
	case "critical":
		decision.Score += 5
	case "error":
		decision.Score += 4
	case "warning":
		decision.Score += 3
	case "notice":
		decision.Score += 2
	default:
		decision.Score += 1
	}
	
	return decision
}

// Get WAF engine status and statistics
func getEngineStatus(this js.Value, args []js.Value) interface{} {
	if engine == nil {
		return js.ValueOf(map[string]interface{}{
			"initialized": false,
			"error":       "WAF engine not initialized",
		})
	}

	return js.ValueOf(map[string]interface{}{
		"initialized": true,
		"engine":      "Simplified ModSecurity Rules Engine",
		"version":     "1.0.0",
		"rules_count": len(engine.rules),
		"ready":       true,
	})
}

// Add a new security rule
func addRule(this js.Value, args []js.Value) interface{} {
	if engine == nil {
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "WAF engine not initialized",
		})
	}

	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "Rule definition required",
		})
	}

	ruleJSON := args[0].String()
	var rule SecurityRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to parse rule: %v", err),
		})
	}

	// Compile regex if pattern provided
	if rule.Pattern != "" {
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return js.ValueOf(map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Invalid regex pattern: %v", err),
			})
		}
		rule.compiledRegex = compiled
	}

	engine.rules = append(engine.rules, rule)

	return js.ValueOf(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Rule %d added successfully", rule.ID),
		"rules_count": len(engine.rules),
	})
}

// Get all rules
func getRules(this js.Value, args []js.Value) interface{} {
	if engine == nil {
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "WAF engine not initialized",
		})
	}

	// Create rules without compiled regex for JSON serialization
	safeRules := make([]SecurityRule, len(engine.rules))
	for i, rule := range engine.rules {
		safeRules[i] = SecurityRule{
			ID:          rule.ID,
			Description: rule.Description,
			Pattern:     rule.Pattern,
			Action:      rule.Action,
			Severity:    rule.Severity,
			Tags:        rule.Tags,
		}
	}

	rulesJSON, _ := json.Marshal(safeRules)
	return js.ValueOf(map[string]interface{}{
		"success": true,
		"rules":   string(rulesJSON),
		"count":   len(engine.rules),
	})
}

func main() {
	// Make functions available to JavaScript
	js.Global().Set("initializeWAF", js.FuncOf(initializeWAF))
	js.Global().Set("processRequest", js.FuncOf(processRequest))
	js.Global().Set("getEngineStatus", js.FuncOf(getEngineStatus))
	js.Global().Set("addRule", js.FuncOf(addRule))
	js.Global().Set("getRules", js.FuncOf(getRules))

	fmt.Println("Simplified ModSecurity WASM module loaded successfully")
	
	// Keep the module alive
	select {}
}
