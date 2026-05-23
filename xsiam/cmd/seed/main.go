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

const tenantID = "t-super"

func ptr[T any](v T) *T { return &v }

func truncate(ctx context.Context, database arangodb.Database, cols ...string) {
	for _, col := range cols {
		c, err := database.Collection(ctx, col)
		if err != nil {
			continue
		}
		if err := c.Truncate(ctx); err != nil {
			fmt.Printf("warn truncate %s: %v\n", col, err)
		} else {
			fmt.Printf("truncated %s\n", col)
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
	)

	tenantRepo := repository.NewTenantRepo(database)
	userRepo   := repository.NewUserRepo(database)
	rbacRepo   := repository.NewRBACRoleRepo(database)
	alertRepo  := repository.NewAlertRepo(database)
	incRepo    := repository.NewIncidentRepo(database)
	assetRepo  := repository.NewAssetRepo(database)
	vulnRepo   := repository.NewVulnerabilityRepo(database)
	iocRepo    := repository.NewIocRepo(database)
	feedRepo   := repository.NewIntelFeedRepo(database)
	deviceRepo := repository.NewDeviceRepo(database)
	ruleRepo   := repository.NewDetectionRuleRepo(database)
	pbRepo     := repository.NewPlaybookRepo(database)
	actionRepo := repository.NewActionRepo(database)

	now := time.Now()

	// ── 1. Tenant ──────────────────────────────────────────────────────────
	superTenant := &model.Tenant{
		TenantID: tenantID, TenantCode: "SUPER", Name: "Acme Security SOC",
		Tier: model.TenantTierSuper, IsEnabled: true,
		Settings: model.TenantSettings{LogRetentionDays: 90, MaxUsers: 9999, AllowCustomRules: true},
	}
	must("tenant", tenantRepo.Create(ctx, superTenant))

	// ── 2. Users ───────────────────────────────────────────────────────────
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
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

	// Retrieve incident keys for action linking
	incidentKeys := make([]string, len(incSpecs))
	{
		aql := `FOR doc IN incidents FILTER doc.tenant_id == @tid SORT doc.created_at ASC RETURN doc._key`
		cur, err := database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: map[string]any{"tid": tenantID}})
		if err == nil {
			defer cur.Close()
			j := 0
			for cur.HasMore() && j < len(incidentKeys) {
				var k string
				if _, e := cur.ReadDocument(ctx, &k); e == nil {
					incidentKeys[j] = k
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

	// Summary
	_ = ruleKeys
	fmt.Printf("\n✓ seed complete\n")
	fmt.Printf("  assets=%d vulns=%d iocs=%d feeds=%d rules=%d alerts=%d incidents=%d devices=%d playbooks=%d actions=%d\n",
		len(assetSpecs), len(vulnSpecs), len(iocSpecs), len(feedSpecs),
		len(ruleSpecs), len(alertSpecs), len(incSpecs),
		len(deviceSpecs), len(pbSpecs), len(actionSpecs))
}
