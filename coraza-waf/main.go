package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

//go:embed ui.html
var uiHTML []byte

type RuleGroupConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	OWASPTop10  string `json:"owasp_top10"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Directives  string `json:"directives"`
}

type BlockedIPDetail struct {
	IP            string   `json:"ip"`
	Threshold     string   `json:"threshold"`
	Reasoning     string   `json:"reasoning"`
	AttackVector  string   `json:"attack_vector"`
	SamplePayload string   `json:"sample_payload"`
	TopPaths      []string `json:"top_paths"`
	Country       string   `json:"country"`
	City          string   `json:"city"`
	CountryISO    string   `json:"country_iso"`
	IOCReputation string   `json:"ioc_reputation"`
	BlockedAt     string   `json:"blocked_at"`
}

type TempRateLimitInfo struct {
	IP              string `json:"ip"`
	LimitedAt       string `json:"limited_at"`
	LiftAt          string `json:"lift_at"`
	CooldownSeconds int    `json:"cooldown_seconds"`
	RequestCount15m int    `json:"request_count_15m"`
	Reason          string `json:"reason"`
}

type WAFConfig struct {
	EngineMode           string              `json:"engine_mode"`        // "On", "DetectionOnly", "Off"
	ParanoiaLevel        int                 `json:"paranoia_level"`     // 1..4
	EnableFullCRS        bool                `json:"enable_full_crs"`    // Include full @owasp_crs/*.conf
	BlockedIPs           []string            `json:"blocked_ips"`        // IP/CIDR blocklist
	AllowedIPs           []string            `json:"allowed_ips"`        // IP/CIDR allowlist
	RuleGroups           []RuleGroupConfig   `json:"rule_groups"`        // Toggleable OWASP Top 10 rule groups
	CustomSecRules       string              `json:"custom_sec_rules"`   // User-defined native SecLang rules
	BlockedIPDetails     []BlockedIPDetail   `json:"blocked_ip_details,omitempty"` // Enriched threat metadata for blocked IPs
	TempRateLimits       []TempRateLimitInfo `json:"temp_rate_limits,omitempty"`
	RateLimitMaxRequests int                 `json:"rate_limit_max_requests,omitempty"`
	RateLimitWindowMin   int                 `json:"rate_limit_window_min,omitempty"`
	RateLimitCooldownMin int                 `json:"rate_limit_cooldown_min,omitempty"`
	UpdatedAt            string              `json:"updated_at"`
}

type ClientRateLimiter struct {
	mu          sync.Mutex
	maxRequests int
	window      time.Duration
	cooldown    time.Duration
	requests    map[string][]time.Time
	cooldowns   map[string]time.Time
	limitedAt   map[string]time.Time
	counts      map[string]int
}

func newClientRateLimiter(maxReqs int, win, cool time.Duration) *ClientRateLimiter {
	return &ClientRateLimiter{
		maxRequests: maxReqs,
		window:      win,
		cooldown:    cool,
		requests:    make(map[string][]time.Time),
		cooldowns:   make(map[string]time.Time),
		limitedAt:   make(map[string]time.Time),
		counts:      make(map[string]int),
	}
}

func (rl *ClientRateLimiter) CheckAndRecord(ip string) (bool, int, string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UTC()

	// 1. Check if currently in cooldown
	if liftAt, ok := rl.cooldowns[ip]; ok {
		if now.Before(liftAt) {
			remSec := int(liftAt.Sub(now).Seconds()) + 1
			return true, remSec, fmt.Sprintf("Rate limit cooldown active (exceeded %d requests in %v). Auto-lifts in %ds.", rl.maxRequests, rl.window, remSec)
		}
		// Expired cooldown: automatically lift
		delete(rl.cooldowns, ip)
		delete(rl.limitedAt, ip)
		delete(rl.counts, ip)
		delete(rl.requests, ip)
	}

	// 2. Filter requests within sliding window
	cutoff := now.Add(-rl.window)
	reqs := rl.requests[ip]
	valid := reqs[:0]
	for _, t := range reqs {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	rl.requests[ip] = valid

	// 3. Exceeded threshold (> 50 req in 15m)
	if len(valid) > rl.maxRequests {
		liftAt := now.Add(rl.cooldown)
		rl.cooldowns[ip] = liftAt
		rl.limitedAt[ip] = now
		rl.counts[ip] = len(valid)
		remSec := int(rl.cooldown.Seconds())
		return true, remSec, fmt.Sprintf("Exceeded rate limit (%d requests in %v baseline). Temporary %v cooldown applied.", len(valid), rl.window, rl.cooldown)
	}

	return false, 0, ""
}

func (rl *ClientRateLimiter) Lift(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.cooldowns, ip)
	delete(rl.limitedAt, ip)
	delete(rl.counts, ip)
	delete(rl.requests, ip)
}

func (rl *ClientRateLimiter) GetActiveLimits() []TempRateLimitInfo {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UTC()
	var list []TempRateLimitInfo
	for ip, liftAt := range rl.cooldowns {
		if now.Before(liftAt) {
			remSec := int(liftAt.Sub(now).Seconds())
			list = append(list, TempRateLimitInfo{
				IP:              ip,
				LimitedAt:       rl.limitedAt[ip].Format(time.RFC3339),
				LiftAt:          liftAt.Format(time.RFC3339),
				CooldownSeconds: remSec,
				RequestCount15m: rl.counts[ip],
				Reason:          fmt.Sprintf("Rate limit exceeded (%d req/15m). Temporary 5-minute cool-down active (%ds remaining).", rl.counts[ip], remSec),
			})
		}
	}
	return list
}

func (rl *ClientRateLimiter) SyncExternalLimits(limits []TempRateLimitInfo) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UTC()
	for _, lim := range limits {
		if lim.IP == "" {
			continue
		}
		if liftAt, err := time.Parse(time.RFC3339, lim.LiftAt); err == nil {
			if now.Before(liftAt) {
				rl.cooldowns[lim.IP] = liftAt
				if limAt, err2 := time.Parse(time.RFC3339, lim.LimitedAt); err2 == nil {
					rl.limitedAt[lim.IP] = limAt
				} else {
					rl.limitedAt[lim.IP] = now
				}
				rl.counts[lim.IP] = lim.RequestCount15m
			}
		}
	}
}

type WAFAuditEvent struct {
	Timestamp     string   `json:"@timestamp"`
	App           string   `json:"app"`
	Shipper       string   `json:"shipper"`
	Engine        string   `json:"engine"`
	TransactionID string   `json:"transaction_id"`
	Action        string   `json:"action"` // "blocked", "detected", "allowed", "rate_limited"
	Interrupted   bool     `json:"interrupted"`
	Status        int      `json:"status"`
	ClientIP      string   `json:"client_ip"`
	RequestMethod string   `json:"request_method"`
	RequestURI    string   `json:"request_uri"`
	Host          string   `json:"host"`
	UserAgent     string   `json:"user_agent"`
	RuleID        int      `json:"rule_id,omitempty"`
	RuleIDs       []int    `json:"rule_ids,omitempty"`
	RuleMsg       string   `json:"rule_msg,omitempty"`
	OWASPCategory string   `json:"owasp_category"`
	OWASPTop10    string   `json:"owasp_top10"`
	Severity      string   `json:"severity"`
	MatchedData   string   `json:"matched_data,omitempty"`
	LatencyMs     float64  `json:"latency_ms"`
}

type WAFStats struct {
	TotalRequests   uint64 `json:"total_requests"`
	BlockedRequests uint64 `json:"blocked_requests"`
	DetectedEvents  uint64 `json:"detected_events"`
	AllowedRequests uint64 `json:"allowed_requests"`
	LastReloadTime  string `json:"last_reload_time"`
}

var (
	activeWAF      atomic.Pointer[coraza.WAF]
	currentConfig  WAFConfig
	configMu       sync.RWMutex
	logMu          sync.Mutex
	recentEvents   []WAFAuditEvent
	recentEventsMu sync.RWMutex
	rateLimiter    = newClientRateLimiter(50, 15*time.Minute, 5*time.Minute)

	totalReqs    atomic.Uint64
	blockedReqs  atomic.Uint64
	detectedReqs atomic.Uint64
	allowedReqs  atomic.Uint64
	lastReload   string

	dataDir      = getEnv("WAF_DATA_DIR", "/data")
	auditLogPath = getEnv("WAF_AUDIT_LOG", "/var/log/waf/audit.log")
	upstreamURL  = getEnv("UPSTREAM_URL", "http://web-frontend-service.default.svc.cluster.local:80")
)

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func defaultRuleGroups() []RuleGroupConfig {
	return []RuleGroupConfig{
		{
			ID:          "RG-913",
			Name:        "OWASP CRS 913: Scanner & Bot Detection",
			Category:    "Scanner / Bot Detection",
			OWASPTop10:  "A05:2021-Security Misconfiguration",
			Description: "Blocks automated vulnerability scanners, web crawlers, and offensive recon tools (sqlmap, nikto, nuclei, nmap, masscan, dirbuster, gobuster, wfuzz, acunetix, metasploit).",
			Enabled:     true,
			Directives: `SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:sqlmap|nikto|nmap|masscan|nessus|acunetix|nuclei|dirbuster|gobuster|wfuzz|zgrab|hydra|metasploit|burpsuite|havij|openvas|commix|wpscan)" "id:913100,phase:1,deny,status:403,log,msg:'OWASP CRS 913: Security Scanner User-Agent Detected',tag:'OWASP_CRS/SCANNER_DETECTION',tag:'A05:2021-Security_Misconfiguration',severity:'CRITICAL'"
SecRule &REQUEST_HEADERS:User-Agent "@eq 0" "id:913101,phase:1,pass,log,msg:'OWASP CRS 913: Missing User-Agent Header',tag:'OWASP_CRS/SCANNER_DETECTION',severity:'WARNING'"`,
		},
		{
			ID:          "RG-920",
			Name:        "OWASP CRS 920: Protocol Enforcement & Malformed HTTP",
			Category:    "Protocol Violation",
			OWASPTop10:  "A04:2021-Insecure Design",
			Description: "Blocks null-byte injection (%00), invalid HTTP methods (TRACE, TRACK, CONNECT), and protocol evasion anomalies.",
			Enabled:     true,
			Directives: `SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY "@validateByteRange 1-255" "id:920270,phase:2,deny,status:403,log,msg:'OWASP CRS 920: Null Byte (%00) Injection Detected',tag:'OWASP_CRS/PROTOCOL_VIOLATION',tag:'A04:2021-Insecure_Design',severity:'CRITICAL'"
SecRule REQUEST_METHOD "@rx ^(?:TRACE|TRACK|CONNECT|DEBUG)$" "id:920100,phase:1,deny,status:403,log,msg:'OWASP CRS 920: Disallowed HTTP Method',tag:'OWASP_CRS/PROTOCOL_VIOLATION',tag:'A04:2021-Insecure_Design',severity:'ERROR'"`,
		},
		{
			ID:          "RG-930",
			Name:        "OWASP CRS 930: Local File Inclusion (LFI) & Path Traversal",
			Category:    "Path Traversal / LFI",
			OWASPTop10:  "A01:2021-Broken Access Control",
			Description: "Blocks directory traversal (../, ..\\, %2e%2e) and sensitive OS/Kubernetes file access (/etc/passwd, /etc/shadow, /proc/self, .env, .git, kubernetes serviceaccount tokens).",
			Enabled:     true,
			Directives: `SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx (?i)(?:(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)|(?:/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/|/var/run/secrets/kubernetes\.io|/\.(?:env|git|aws|ssh)|wp-config\.php|web\.config))" "id:930100,phase:2,deny,status:403,log,msg:'OWASP CRS 930: Path Traversal or Sensitive File Access Attempt',tag:'OWASP_CRS/LFI',tag:'A01:2021-Broken_Access_Control',severity:'CRITICAL'"`,
		},
		{
			ID:          "RG-931",
			Name:        "OWASP CRS 931: Server-Side Request Forgery (SSRF) & RFI",
			Category:    "SSRF / RFI",
			OWASPTop10:  "A10:2021-SSRF",
			Description: "Blocks SSRF probes targeting cloud metadata (169.254.169.254), internal Kubernetes services (.svc.cluster.local, 10.96.0.1), localhost, and dangerous URI schemes (file://, gopher://, dict://).",
			Enabled:     true,
			Directives: `SecRule ARGS|REQUEST_BODY "@rx (?i)(?:(?:file|gopher|dict|ldap|tftp)://|https?://(?:169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.96\.0\.1|[^\s/]*\.svc\.cluster\.local|opensearch\.logging|prometheus-server))" "id:931100,phase:2,deny,status:403,log,msg:'OWASP CRS 931: SSRF or Internal Cluster Metadata Probe Detected',tag:'OWASP_CRS/SSRF',tag:'A10:2021-SSRF',severity:'CRITICAL'"`,
		},
		{
			ID:          "RG-932",
			Name:        "OWASP CRS 932: Remote Code Execution (RCE) & Command Injection",
			Category:    "Remote Code Execution (RCE)",
			OWASPTop10:  "A03:2021-Injection",
			Description: "Blocks OS command injection, shell pipelines, reverse shells (/bin/sh, /bin/bash, nc -e, curl/wget pipe, $(...), backticks, cmd.exe, powershell).",
			Enabled:     true,
			Directives: `SecRule ARGS|REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer "@rx (?i)(?:(?:/bin/(?:sh|bash|zsh|dash)|/usr/bin/(?:id|whoami|uname|nc|wget|curl)|cmd\.exe|powershell(?:\.exe)?)|(?:[;&|]\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\b)|\$\([^)]+\))" "id:932100,phase:2,deny,status:403,log,msg:'OWASP CRS 932: OS Command Injection / RCE Payload Detected',tag:'OWASP_CRS/RCE',tag:'A03:2021-Injection',severity:'CRITICAL'"`,
		},
		{
			ID:          "RG-941",
			Name:        "OWASP CRS 941: Cross-Site Scripting (XSS) & Libinjection XSS",
			Category:    "Cross-Site Scripting (XSS)",
			OWASPTop10:  "A03:2021-Injection",
			Description: "Uses native Coraza @detectXSS (libinjection) plus regex signatures for <script>, javascript: URIs, DOM event handlers (onerror, onload, onmouseover), and cookie theft.",
			Enabled:     true,
			Directives: `SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_BODY "@detectXSS" "id:941100,phase:2,deny,status:403,log,msg:'OWASP CRS 941: XSS Attack Detected via libinjection',tag:'OWASP_CRS/XSS',tag:'A03:2021-Injection',severity:'CRITICAL'"
SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_BODY "@rx (?i)(?:<\s*script\b|javascript\s*:|on(?:error|load|click|mouseover|focus|submit|toggle)\s*=|<\s*(?:iframe|svg|object|embed|img)\b[^>]*(?:src|onload|onerror)\s*=|document\.(?:cookie|domain|write)|alert\s*\()" "id:941110,phase:2,deny,status:403,log,msg:'OWASP CRS 941: Cross-Site Scripting (XSS) Vector Detected',tag:'OWASP_CRS/XSS',tag:'A03:2021-Injection',severity:'CRITICAL'"`,
		},
		{
			ID:          "RG-942",
			Name:        "OWASP CRS 942: SQL Injection (SQLi) & Libinjection SQLi",
			Category:    "SQL Injection (SQLi)",
			OWASPTop10:  "A03:2021-Injection",
			Description: "Uses native Coraza @detectSQLi (libinjection) plus signatures for UNION SELECT, boolean tautologies (OR 1=1), time-based blind SQLi (SLEEP, BENCHMARK, WAITFOR), and schema enumeration.",
			Enabled:     true,
			Directives: `SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_BODY "@detectSQLi" "id:942100,phase:2,deny,status:403,log,msg:'OWASP CRS 942: SQL Injection Attack Detected via libinjection',tag:'OWASP_CRS/SQLI',tag:'A03:2021-Injection',severity:'CRITICAL'"
SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_BODY "@rx (?i)(?:union\s+(?:all\s+)?select\b|(?:'|\"|\b)(?:or|and)\s+(?:'?\d+'?\s*=\s*'?\d+'?|true|1=1)|(?:sleep|benchmark)\s*\(\s*\d+|waitfor\s+delay\s+'|information_schema\.|xp_cmdshell|;\s*(?:drop|alter|truncate|delete\s+from)\s+table)" "id:942110,phase:2,deny,status:403,log,msg:'OWASP CRS 942: SQL Injection Payload Detected',tag:'OWASP_CRS/SQLI',tag:'A03:2021-Injection',severity:'CRITICAL'"`,
		},
		{
			ID:          "RG-943",
			Name:        "OWASP CRS 943: Session Fixation & Authentication Bypass",
			Category:    "Session Fixation / Auth Attack",
			OWASPTop10:  "A07:2021-Identification and Authentication Failures",
			Description: "Blocks session fixation attempts (PHPSESSID, JSESSIONID, ASPSESSIONID in query/referrers) and privilege escalation parameter tampering.",
			Enabled:     true,
			Directives: `SecRule ARGS_NAMES "@rx (?i)^(?:phpsessid|jsessionid|aspsessionid|cfid|cftoken)$" "id:943100,phase:2,deny,status:403,log,msg:'OWASP CRS 943: Session Fixation Attempt via URL Parameter',tag:'OWASP_CRS/SESSION_FIXATION',tag:'A07:2021-Auth_Failures',severity:'ERROR'"`,
		},
		{
			ID:          "RG-944",
			Name:        "OWASP CRS 944: Log4Shell, Deserialization, Prototype Pollution & SSTI",
			Category:    "Log4Shell / Injection / Deserialization",
			OWASPTop10:  "A08:2021-Software and Data Integrity Failures",
			Description: "Blocks Log4j JNDI lookups (${jndi:ldap:...}), Node.js Prototype Pollution (__proto__, constructor.prototype), Server-Side Template Injection ({{7*7}}), and XXE (<!ENTITY).",
			Enabled:     true,
			Directives: `SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|REQUEST_HEADERS:X-Forwarded-For "@rx (?i)(?:\$\{\s*(?:jndi|lower|upper|env|sys|date)\s*:|__proto__|constructor\s*\.\s*prototype|<!ENTITY\s+|<!DOCTYPE\s+[^\[]+\[)" "id:944100,phase:2,deny,status:403,log,msg:'OWASP CRS 944: Log4Shell JNDI, XXE, or Prototype Pollution Attack',tag:'OWASP_CRS/INJECTION_GENERIC',tag:'A08:2021-Integrity_Failures',severity:'CRITICAL'"`,
		},
		{
			ID:          "RG-950",
			Name:        "OWASP CRS 950: Known Bad Inputs, Exploit Scanners & Webshells",
			Category:    "Known Bad Inputs / Exploit Probe",
			OWASPTop10:  "A06:2021-Vulnerable and Outdated Components",
			Description: "Blocks automated exploit probes against common admin paths (/phpmyadmin, /wp-admin, /wp-login.php, /vendor/phpunit, /actuator/env, /cgi-bin/, webshells c99.php/r57.php).",
			Enabled:     true,
			Directives: `SecRule REQUEST_URI "@rx (?i)(?:/phpmyadmin|/pma|/myadmin|/wp-admin|/wp-login\.php|/xmlrpc\.php|/vendor/phpunit|/actuator/(?:env|heapdump|gateway)|/cgi-bin/|/(?:c99|r57|b374k|wso|alfa)\.php|/boaform/|/GponForm/)" "id:950100,phase:1,deny,status:403,log,msg:'OWASP CRS 950: Known Exploit Path or Webshell Probe Blocked',tag:'OWASP_CRS/KNOWN_BAD_INPUTS',tag:'A06:2021-Vulnerable_Components',severity:'ERROR'"`,
		},
	}
}

func defaultConfig() WAFConfig {
	return WAFConfig{
		EngineMode:           "On",
		ParanoiaLevel:        1,
		EnableFullCRS:        false,
		BlockedIPs:           []string{},
		AllowedIPs:           []string{},
		RuleGroups:           defaultRuleGroups(),
		RateLimitMaxRequests: 50,
		RateLimitWindowMin:   15,
		RateLimitCooldownMin: 5,
		CustomSecRules: `# Custom Native Coraza SecLang Rules for example.com
# Example: Block specific custom header or path
SecRule REQUEST_HEADERS:X-Attack-Test "@streq blockme" "id:100001,phase:1,deny,status:403,log,msg:'Custom SecRule 100001: Blocked X-Attack-Test Header',tag:'CUSTOM_WAF_RULE',severity:'ERROR'"
`,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func isPrivateOrInternalIP(ipStr string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func isProtectedUserIP(ipStr string) bool {
	return strings.HasPrefix(strings.TrimSpace(ipStr), "172.59.")
}

func buildFullSecLangDirectives(cfg WAFConfig) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("SecRuleEngine %s\n", cfg.EngineMode))
	b.WriteString("SecRequestBodyAccess On\n")
	b.WriteString("SecRequestBodyLimit 13107200\n")
	b.WriteString("SecRequestBodyNoFilesLimit 131072\n")
	b.WriteString("SecResponseBodyAccess Off\n")
	b.WriteString(fmt.Sprintf("SecAction \"id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d\"\n", cfg.ParanoiaLevel, cfg.ParanoiaLevel))

	// 1. IP Allowlist
	if len(cfg.AllowedIPs) > 0 {
		clean := []string{}
		for _, ip := range cfg.AllowedIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				clean = append(clean, ip)
			}
		}
		if len(clean) > 0 {
			b.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:100010,phase:1,allow,nolog,msg:'IP Allowlist Match'\"\n", strings.Join(clean, ",")))
		}
	}

	// 2. IP Blocklist (Rule 100020: ONLY for verified malicious exploit payload attackers)
	if len(cfg.BlockedIPs) > 0 {
		clean := []string{}
		for _, ip := range cfg.BlockedIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" && !isPrivateOrInternalIP(ip) && !isProtectedUserIP(ip) {
				clean = append(clean, ip)
			}
		}
		if len(clean) > 0 {
			b.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:100020,phase:1,deny,status:403,log,msg:'Coraza IP Blocklist: Malicious Exploit Payload Detected',tag:'IP_BLOCKLIST',severity:'CRITICAL'\"\n", strings.Join(clean, ",")))
		}
	}

	// 3. Toggleable OWASP Top 10 Rule Groups
	for _, rg := range cfg.RuleGroups {
		if rg.Enabled && strings.TrimSpace(rg.Directives) != "" {
			b.WriteString(fmt.Sprintf("\n# --- %s (%s) ---\n", rg.ID, rg.Name))
			b.WriteString(rg.Directives + "\n")
		}
	}

	// 4. Custom SecRules from UI
	if strings.TrimSpace(cfg.CustomSecRules) != "" {
		b.WriteString("\n# --- Custom User SecRules ---\n")
		b.WriteString(cfg.CustomSecRules + "\n")
	}

	// 5. Optional Full Embedded OWASP CRS v4
	if cfg.EnableFullCRS {
		b.WriteString("\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n")
	}

	return b.String()
}

func compileWAF(cfg WAFConfig) (coraza.WAF, error) {
	directives := buildFullSecLangDirectives(cfg)
	wafCfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives)
	return coraza.NewWAF(wafCfg)
}

func loadOrInitConfig() error {
	_ = os.MkdirAll(dataDir, 0755)
	_ = os.MkdirAll(filepath.Dir(auditLogPath), 0755)
	cfgFile := filepath.Join(dataDir, "waf-config.json")

	var cfg WAFConfig
	if raw, err := os.ReadFile(cfgFile); err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			cfg = defaultConfig()
		}
	} else {
		cfg = defaultConfig()
	}

	if cfg.RateLimitMaxRequests <= 0 {
		cfg.RateLimitMaxRequests = 50
	}
	if cfg.RateLimitWindowMin <= 0 {
		cfg.RateLimitWindowMin = 15
	}
	if cfg.RateLimitCooldownMin <= 0 {
		cfg.RateLimitCooldownMin = 5
	}
	if len(cfg.TempRateLimits) > 0 {
		rateLimiter.SyncExternalLimits(cfg.TempRateLimits)
	}

	// Sanitize any blocked IPs
	var cleanBlocked []string
	for _, ip := range cfg.BlockedIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" && !isPrivateOrInternalIP(ip) && !isProtectedUserIP(ip) {
			cleanBlocked = append(cleanBlocked, ip)
		}
	}
	cfg.BlockedIPs = cleanBlocked

	w, err := compileWAF(cfg)
	if err != nil {
		return err
	}
	activeWAF.Store(&w)
	configMu.Lock()
	currentConfig = cfg
	lastReload = time.Now().UTC().Format(time.RFC3339)
	configMu.Unlock()
	saveConfigToDisk(cfg)
	return nil
}

func saveConfigToDisk(cfg WAFConfig) {
	cfgFile := filepath.Join(dataDir, "waf-config.json")
	if b, err := json.MarshalIndent(cfg, "", "  "); err == nil {
		_ = os.WriteFile(cfgFile, b, 0644)
	}
	rulesFile := filepath.Join(dataDir, "active-coraza.conf")
	_ = os.WriteFile(rulesFile, []byte(buildFullSecLangDirectives(cfg)), 0644)
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func categorizeRule(ruleID int, tags []string, msg string) (string, string, string) {
	switch {
	case ruleID == 100030:
		return "Rate Limit Exceeded (HTTP 429)", "A04:2021-Insecure Design", "MEDIUM"
	case ruleID == 100020:
		return "IP Blocklist (Malicious Exploit)", "A01:2021-Broken Access Control", "CRITICAL"
	case ruleID >= 913000 && ruleID < 914000:
		return "Scanner / Bot Detection", "A05:2021-Security Misconfiguration", "HIGH"
	case ruleID >= 920000 && ruleID < 922000:
		return "Protocol Violation", "A04:2021-Insecure Design", "HIGH"
	case ruleID >= 930000 && ruleID < 931000:
		return "Path Traversal / LFI", "A01:2021-Broken Access Control", "CRITICAL"
	case ruleID >= 931000 && ruleID < 932000:
		return "SSRF / RFI", "A10:2021-SSRF", "CRITICAL"
	case ruleID >= 932000 && ruleID < 933000:
		return "Remote Code Execution (RCE)", "A03:2021-Injection", "CRITICAL"
	case ruleID >= 941000 && ruleID < 942000:
		return "Cross-Site Scripting (XSS)", "A03:2021-Injection", "CRITICAL"
	case ruleID >= 942000 && ruleID < 943000:
		return "SQL Injection (SQLi)", "A03:2021-Injection", "CRITICAL"
	case ruleID >= 943000 && ruleID < 944000:
		return "Session Fixation / Auth Attack", "A07:2021-Identification and Authentication Failures", "HIGH"
	case ruleID >= 944000 && ruleID < 945000:
		return "Log4Shell / Injection / Deserialization", "A08:2021-Software and Data Integrity Failures", "CRITICAL"
	case ruleID >= 950000 && ruleID < 960000:
		return "Known Bad Inputs / Exploit Probe", "A06:2021-Vulnerable and Outdated Components", "HIGH"
	default:
		return "Custom Coraza SecRule", "OWASP-WAF-Rule", "HIGH"
	}
}

func recordAuditEvent(ev WAFAuditEvent) {
	// Keep last 100 security events in memory for UI
	if ev.Action != "allowed" {
		recentEventsMu.Lock()
		recentEvents = append([]WAFAuditEvent{ev}, recentEvents...)
		if len(recentEvents) > 100 {
			recentEvents = recentEvents[:100]
		}
		recentEventsMu.Unlock()
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(auditLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
	}
}

func evaluateRequest(waf coraza.WAF, r *http.Request, clientIP string) (types.Transaction, *types.Interruption, []byte, error) {
	tx := waf.NewTransaction()
	tx.ProcessConnection(clientIP, 0, "", 80)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return tx, it, nil, nil
	}

	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if len(bodyBytes) > 0 {
			if it, _, err := tx.WriteRequestBody(bodyBytes); err != nil || it != nil {
				return tx, it, bodyBytes, err
			}
		}
	}
	it, err := tx.ProcessRequestBody()
	return tx, it, bodyBytes, err
}

func extractMatchedRules(tx types.Transaction) (int, []int, string, string, string, string, string) {
	var primaryID int
	var ruleIDs []int
	var primaryMsg string
	var matchedData string
	cat := "Clean Traffic"
	top10 := "None"
	sev := "NONE"

	for _, mr := range tx.MatchedRules() {
		id := mr.Rule().ID()
		if id == 900000 || id == 100010 {
			continue
		}
		ruleIDs = append(ruleIDs, id)
		if primaryID == 0 {
			primaryID = id
			primaryMsg = mr.Message()
			matchedData = mr.Data()
			if matchedData == "" {
				for _, md := range mr.MatchedDatas() {
					if md.Value() != "" {
						matchedData = fmt.Sprintf("%s=%s", md.Key(), md.Value())
						break
					}
				}
			}
			cat, top10, sev = categorizeRule(id, nil, primaryMsg)
		}
	}
	return primaryID, ruleIDs, primaryMsg, matchedData, cat, top10, sev
}

func main() {
	if err := loadOrInitConfig(); err != nil {
		log.Fatalf("Failed to initialize Coraza WAF: %v", err)
	}

	target, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("Invalid upstream URL %s: %v", upstreamURL, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)

	// 1. Public WAF Reverse Proxy Server (:80)
	wafMux := http.NewServeMux()
	wafMux.HandleFunc("/waf-healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","waf":"coraza-v3"}`))
	})
	wafMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		totalReqs.Add(1)
		clientIP := extractClientIP(r)

		// 1. Rate Limiting check (HTTP 429) for non-internal traffic
		// Baseline window: 15 minutes, threshold: >50 req/15m, cooldown: 5 minutes auto-lifted
		if !isPrivateOrInternalIP(clientIP) {
			isAllowlisted := false
			configMu.RLock()
			for _, aip := range currentConfig.AllowedIPs {
				if strings.TrimSpace(aip) == clientIP {
					isAllowlisted = true
					break
				}
			}
			configMu.RUnlock()

			if !isAllowlisted {
				limited, retryAfter, reason := rateLimiter.CheckAndRecord(clientIP)
				if limited {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
					w.Header().Set("X-WAF-Engine", "Coraza-v3")
					w.Header().Set("X-WAF-Rule-ID", "100030")
					w.WriteHeader(http.StatusTooManyRequests)
					resp := map[string]interface{}{
						"error":               "Too Many Requests - Rate Limit Exceeded",
						"status":              429,
						"rule_id":             100030,
						"rule_message":        reason,
						"retry_after_seconds": retryAfter,
						"threshold":           "50 requests per 15-minute baseline window",
						"cooldown_duration":   "5 minutes (auto-lifted)",
					}
					_ = json.NewEncoder(w).Encode(resp)
					recordAuditEvent(WAFAuditEvent{
						Timestamp:     time.Now().UTC().Format(time.RFC3339),
						App:           "coraza-waf",
						Shipper:       "sidecar",
						Engine:        "Coraza WAF v3 (Rate Limiter)",
						TransactionID: fmt.Sprintf("rl-%d", time.Now().UnixNano()),
						Action:        "rate_limited",
						Interrupted:   true,
						Status:        http.StatusTooManyRequests,
						ClientIP:      clientIP,
						RequestMethod: r.Method,
						RequestURI:    r.URL.RequestURI(),
						Host:          r.Host,
						UserAgent:     r.UserAgent(),
						RuleID:        100030,
						RuleIDs:       []int{100030},
						RuleMsg:       reason,
						OWASPCategory: "Rate Limit Exceeded (HTTP 429)",
						OWASPTop10:    "A04:2021-Insecure Design",
						Severity:      "MEDIUM",
						MatchedData:   fmt.Sprintf("ClientIP=%s; RetryAfter=%ds", clientIP, retryAfter),
						LatencyMs:     float64(time.Since(start).Microseconds()) / 1000.0,
					})
					return
				}
			}
		}

		wafPtr := activeWAF.Load()
		if wafPtr == nil {
			proxy.ServeHTTP(w, r)
			return
		}

		tx, it, _, _ := evaluateRequest(*wafPtr, r, clientIP)
		defer func() {
			tx.ProcessLogging()
			_ = tx.Close()
		}()

		primaryID, ruleIDs, primaryMsg, matchedData, cat, top10, sev := extractMatchedRules(tx)
		interrupted := it != nil
		status := http.StatusOK
		action := "allowed"

		if interrupted {
			status = http.StatusForbidden
			action = "blocked"
			blockedReqs.Add(1)
			if primaryID == 0 {
				primaryID = it.RuleID
				primaryMsg = "Blocked by Coraza WAF SecRule"
				cat, top10, sev = categorizeRule(primaryID, nil, primaryMsg)
			}
		} else if len(ruleIDs) > 0 {
			action = "detected"
			detectedReqs.Add(1)
		} else {
			allowedReqs.Add(1)
		}

		ev := WAFAuditEvent{
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			App:           "coraza-waf",
			Shipper:       "sidecar",
			Engine:        "Coraza WAF v3 (OWASP CRS)",
			TransactionID: tx.ID(),
			Action:        action,
			Interrupted:   interrupted,
			Status:        status,
			ClientIP:      clientIP,
			RequestMethod: r.Method,
			RequestURI:    r.URL.RequestURI(),
			Host:          r.Host,
			UserAgent:     r.UserAgent(),
			RuleID:        primaryID,
			RuleIDs:       ruleIDs,
			RuleMsg:       primaryMsg,
			OWASPCategory: cat,
			OWASPTop10:    top10,
			Severity:      sev,
			MatchedData:   matchedData,
			LatencyMs:     float64(time.Since(start).Microseconds()) / 1000.0,
		}
		recordAuditEvent(ev)

		if interrupted {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-WAF-Engine", "Coraza-v3")
			w.Header().Set("X-WAF-Transaction-ID", tx.ID())
			w.Header().Set("X-WAF-Rule-ID", fmt.Sprintf("%d", primaryID))
			w.WriteHeader(http.StatusForbidden)
			resp := map[string]interface{}{
				"error":          "Request Blocked by Coraza Web Application Firewall (WAF)",
				"status":         403,
				"transaction_id": tx.ID(),
				"rule_id":        primaryID,
				"rule_message":   primaryMsg,
				"owasp_category": cat,
				"owasp_top_10":   top10,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		w.Header().Set("X-WAF-Engine", "Coraza-v3")
		proxy.ServeHTTP(w, r)
	})

	// 2. Native Coraza WAF Management Console & SecLang Playground Server (:8080)
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(uiHTML)
	})
	adminMux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		configMu.RLock()
		cfg := currentConfig
		reloadTs := lastReload
		configMu.RUnlock()

		cfg.TempRateLimits = rateLimiter.GetActiveLimits()

		recentEventsMu.RLock()
		evs := make([]WAFAuditEvent, len(recentEvents))
		copy(evs, recentEvents)
		recentEventsMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"config":           cfg,
			"compiled_seclang": buildFullSecLangDirectives(cfg),
			"stats": WAFStats{
				TotalRequests:   totalReqs.Load(),
				BlockedRequests: blockedReqs.Load(),
				DetectedEvents:  detectedReqs.Load(),
				AllowedRequests: allowedReqs.Load(),
				LastReloadTime:  reloadTs,
			},
			"recent_events": evs,
		})
	})
	adminMux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var newCfg WAFConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
			return
		}
		newCfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

		// Sanitize BlockedIPs: remove private and protected user IPs
		var cleanBlocked []string
		for _, ip := range newCfg.BlockedIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" && !isPrivateOrInternalIP(ip) && !isProtectedUserIP(ip) {
				cleanBlocked = append(cleanBlocked, ip)
			}
		}
		newCfg.BlockedIPs = cleanBlocked

		// Sync external temporary rate limits
		if len(newCfg.TempRateLimits) > 0 {
			rateLimiter.SyncExternalLimits(newCfg.TempRateLimits)
		}

		// Validate & Compile with native Coraza v3 compiler
		newWAF, err := compileWAF(newCfg)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Coraza SecLang Compiler Error: %v", err),
			})
			return
		}

		activeWAF.Store(&newWAF)
		configMu.Lock()
		currentConfig = newCfg
		lastReload = newCfg.UpdatedAt
		configMu.Unlock()
		saveConfigToDisk(newCfg)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":           "reloaded",
			"message":          "Coraza v3 SecLang rules validated and hot-reloaded with zero downtime.",
			"updated_at":       newCfg.UpdatedAt,
			"compiled_seclang": buildFullSecLangDirectives(newCfg),
		})
	})
	adminMux.HandleFunc("/api/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ip := strings.TrimSpace(req.IP)
		if ip != "" {
			rateLimiter.Lift(ip)
			configMu.Lock()
			var newBlocked []string
			for _, b := range currentConfig.BlockedIPs {
				if b != ip {
					newBlocked = append(newBlocked, b)
				}
			}
			currentConfig.BlockedIPs = newBlocked
			var newDetails []BlockedIPDetail
			for _, d := range currentConfig.BlockedIPDetails {
				if d.IP != ip {
					newDetails = append(newDetails, d)
				}
			}
			currentConfig.BlockedIPDetails = newDetails
			currentConfig.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			newWAF, err := compileWAF(currentConfig)
			if err == nil {
				activeWAF.Store(&newWAF)
				lastReload = currentConfig.UpdatedAt
				saveConfigToDisk(currentConfig)
			}
			configMu.Unlock()
			log.Printf("[WAF API] Successfully unblocked client IP %s and lifted rate-limit cooldown", ip)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "unblocked",
			"ip":      ip,
			"message": fmt.Sprintf("Client IP %s unblocked and rate-limit cooldown lifted.", ip),
		})
	})
	adminMux.HandleFunc("/api/simulate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var reqSpec struct {
			Method     string            `json:"method"`
			URI        string            `json:"uri"`
			ClientIP   string            `json:"client_ip"`
			UserAgent  string            `json:"user_agent"`
			Headers    map[string]string `json:"headers"`
			Body       string            `json:"body"`
			LogToAudit bool              `json:"log_to_audit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqSpec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if reqSpec.Method == "" {
			reqSpec.Method = "GET"
		}
		if reqSpec.URI == "" {
			reqSpec.URI = "/"
		}
		if reqSpec.ClientIP == "" {
			reqSpec.ClientIP = "198.51.100.42"
		}
		if reqSpec.UserAgent == "" {
			reqSpec.UserAgent = "Mozilla/5.0 (Coraza-Playground-Simulator)"
		}

		simReq, err := http.NewRequest(reqSpec.Method, "http://example.com"+reqSpec.URI, strings.NewReader(reqSpec.Body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		simReq.Header.Set("User-Agent", reqSpec.UserAgent)
		for k, v := range reqSpec.Headers {
			simReq.Header.Set(k, v)
		}

		wafPtr := activeWAF.Load()
		tx, it, _, _ := evaluateRequest(*wafPtr, simReq, reqSpec.ClientIP)
		defer func() {
			tx.ProcessLogging()
			_ = tx.Close()
		}()

		primaryID, ruleIDs, primaryMsg, matchedData, cat, top10, sev := extractMatchedRules(tx)
		interrupted := it != nil
		action := "allowed"
		status := 200
		if interrupted {
			action = "blocked"
			status = 403
		} else if len(ruleIDs) > 0 {
			action = "detected"
		}

		type matchedRuleDetail struct {
			ID      int    `json:"id"`
			Message string `json:"message"`
			Data    string `json:"data"`
			File    string `json:"file"`
		}
		var details []matchedRuleDetail
		for _, mr := range tx.MatchedRules() {
			if mr.Rule().ID() == 900000 || mr.Rule().ID() == 100010 {
				continue
			}
			details = append(details, matchedRuleDetail{
				ID:      mr.Rule().ID(),
				Message: mr.Message(),
				Data:    mr.Data(),
				File:    mr.Rule().File(),
			})
		}

		if reqSpec.LogToAudit {
			totalReqs.Add(1)
			if interrupted {
				blockedReqs.Add(1)
			} else if len(ruleIDs) > 0 {
				detectedReqs.Add(1)
			} else {
				allowedReqs.Add(1)
			}
			recordAuditEvent(WAFAuditEvent{
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
				App:           "coraza-waf",
				Shipper:       "sidecar",
				Engine:        "Coraza WAF v3 (OWASP CRS)",
				TransactionID: tx.ID(),
				Action:        action,
				Interrupted:   interrupted,
				Status:        status,
				ClientIP:      reqSpec.ClientIP,
				RequestMethod: reqSpec.Method,
				RequestURI:    reqSpec.URI,
				Host:          "example.com",
				UserAgent:     reqSpec.UserAgent,
				RuleID:        primaryID,
				RuleIDs:       ruleIDs,
				RuleMsg:       primaryMsg,
				OWASPCategory: cat,
				OWASPTop10:    top10,
				Severity:      sev,
				MatchedData:   matchedData,
				LatencyMs:     0.5,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"transaction_id": tx.ID(),
			"action":         action,
			"interrupted":    interrupted,
			"status":         status,
			"primary_rule":   primaryID,
			"primary_msg":    primaryMsg,
			"owasp_category": cat,
			"owasp_top10":    top10,
			"severity":       sev,
			"matched_data":   matchedData,
			"matched_rules":  details,
		})
	})

	go func() {
		log.Printf("[Coraza WAF UI] Listening on :8080 (Management Console & Native SecLang Playground)")
		if err := http.ListenAndServe(":8080", adminMux); err != nil {
			log.Fatalf("Admin UI server failed: %v", err)
		}
	}()

	log.Printf("[Coraza WAF Proxy] Listening on :80 -> upstream %s", upstreamURL)
	if err := http.ListenAndServe(":80", wafMux); err != nil {
		log.Fatalf("WAF Proxy server failed: %v", err)
	}
}
