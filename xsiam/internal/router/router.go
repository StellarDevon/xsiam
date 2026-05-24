package router

import (
	"io/fs"
	"net/http"
	"time"
	"xsiam/internal/domain/alert"
	"xsiam/internal/domain/asset"
	authdomain "xsiam/internal/domain/auth"
	copilotdomain "xsiam/internal/domain/copilot"
	"xsiam/internal/domain/dashboard"
	"xsiam/internal/domain/device"
	endpointdomain "xsiam/internal/domain/endpoint"
	etldomain "xsiam/internal/domain/etl"
	"xsiam/internal/domain/identity"
	"xsiam/internal/ingest"
	"xsiam/internal/domain/incident"
	networkdomain "xsiam/internal/domain/network"
	"xsiam/internal/domain/query"
	"xsiam/internal/domain/report"
	"xsiam/internal/domain/response"
	"xsiam/internal/domain/threat"
	"xsiam/internal/middleware"
	"xsiam/internal/svc/audit"
	"xsiam/internal/svc/auth"
	"xsiam/internal/svc/notify"
	"xsiam/internal/svc/rbac"
	"xsiam/pkg/svcclient"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)


// Handlers aggregates all domain handlers for the web-facing engine.
type Handlers struct {
	Dashboard     *dashboard.Handler
	Alert         *alert.Handler
	Incident      *incident.Handler
	Causality     *incident.CausalityHandler
	SmartScore    *incident.SmartScoreHandler
	Asset         *asset.Handler
	Vulnerability *asset.VulnHandler
	IOC           *threat.IocHandler
	IntelFeed     *threat.FeedHandler
	DetectionRule *threat.RuleHandler
	Action        *response.ActionHandler
	Playbook      *response.PlaybookHandler
	Device        *device.Handler
	Policy        *device.PolicyHandler
	DataSource    *device.DataSourceHandler
	IdentityRisk  *identity.RiskHandler
	Exposure      *identity.ExposureHandler
	Report        *report.Handler
	Auth          *authdomain.Handler
	User          *authdomain.UserHandler
	Tenant        *authdomain.TenantHandler
	RBAC          *authdomain.RBACHandler
	LogEntry      *query.Handler
	ETLRule       *etldomain.Handler
	ThreatIntel   *threat.ThreatIntelHandler
	Copilot       *copilotdomain.Handler
	Privilege     *identity.PrivilegeHandler
	Audit         *audit.Handler
	Notify        *notify.PublicHandler
	Network       *networkdomain.Handler
	Endpoint      *endpointdomain.Handler
}

// InternalHandlers aggregates handlers for the internal-only engine.
type InternalHandlers struct {
	AlertWebhook *authdomain.InternalHandler
	AgentEvent   *device.AgentEventInternalHandler
	AgentLog     *ingest.Handler
	Auth         *auth.Handler
	RBAC         *rbac.Handler
	Notify       *notify.Handler
	Audit        *audit.Handler
}

// NewWebEngine builds the user-facing HTTP engine on WebPort.
// Serves: login, protected business APIs, React SPA.
func NewWebEngine(h Handlers, svcClient svcclient.Caller, jwtSecret string, log *zap.Logger, staticFiles fs.FS) *gin.Engine {
	r := gin.New()
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.Use(middleware.Recovery(log))
	r.Use(middleware.Logger(log))
	r.Use(middleware.RequestID())

	// Public health check
	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "3.0.0",
		})
	})

	// Public auth
	r.POST("/api/auth/login", h.Auth.Login)

	// Protected API
	api := r.Group("/api")
	api.Use(middleware.JWTAuth(jwtSecret))
	api.Use(middleware.TenantContext())
	{
		api.GET("/dashboard/stats", h.Dashboard.Stats)

		alerts := api.Group("/alerts")
		{
			alerts.GET("", h.Alert.List)
			alerts.POST("", h.Alert.Create)
			alerts.GET("/stats", h.Alert.Stats)
			alerts.POST("/bulk", h.Alert.Bulk)
			alerts.GET("/:id", h.Alert.Get)
			alerts.PATCH("/:id", h.Alert.Update)
			alerts.POST("/:id/link_incident", h.Alert.LinkIncident)
			alerts.GET("/:id/summary", h.Alert.Summary)
		}

		incidents := api.Group("/incidents")
		{
			incidents.GET("", h.Incident.List)
			incidents.POST("", h.Incident.Create)
			incidents.GET("/sla_stats", h.Incident.SLAStats)
			incidents.GET("/export", h.Incident.Export)
			incidents.POST("/bulk", h.Incident.Bulk)
			incidents.POST("/bulk_correlate", h.Causality.BulkCorrelate)
			incidents.GET("/:id", h.Incident.Get)
			incidents.PATCH("/:id", h.Incident.Update)
			incidents.DELETE("/:id", h.Incident.Delete)
			incidents.GET("/:id/alerts", h.Incident.ListAlerts)
			incidents.GET("/:id/timeline", h.Incident.GetTimeline)
			incidents.POST("/:id/notes", h.Incident.AddNote)
			incidents.POST("/:id/merge", h.Incident.Merge)
			incidents.GET("/:id/summary", h.Incident.Summary)
			incidents.POST("/:id/sla_recalc", h.Incident.SLARecalc)
			incidents.GET("/:id/graph", h.Causality.GetGraph)
			incidents.GET("/:id/smart_score", h.SmartScore.Get)
			incidents.POST("/:id/smart_score/recalc", h.SmartScore.Recalc)
		}

		assets := api.Group("/assets")
		{
			assets.GET("", h.Asset.List)
			assets.GET("/stats", h.Asset.Stats)
			assets.POST("", h.Asset.Create)
			assets.POST("/bulk", h.Asset.Bulk)
			assets.GET("/export", h.Asset.Export)
			assets.GET("/:id", h.Asset.Get)
			assets.PATCH("/:id", h.Asset.Update)
			assets.DELETE("/:id", h.Asset.Delete)
		}

		vulns := api.Group("/vulnerabilities")
		{
			vulns.GET("", h.Vulnerability.List)
			vulns.POST("", h.Vulnerability.Create)
			vulns.GET("/stats", h.Vulnerability.Stats)
			vulns.POST("/bulk", h.Vulnerability.Bulk)
			vulns.GET("/export", h.Vulnerability.Export)
			vulns.GET("/:id", h.Vulnerability.Get)
			vulns.PATCH("/:id", h.Vulnerability.Update)
			vulns.DELETE("/:id", h.Vulnerability.Delete)
		}

		iocs := api.Group("/iocs")
		{
			iocs.GET("", h.IOC.List)
			iocs.POST("", h.IOC.Create)
			iocs.POST("/bulk", h.IOC.BulkImport)
			iocs.GET("/search", h.IOC.Search)
			// Static sub-paths must come before /:id to avoid routing conflict.
			iocs.GET("/hunt", h.IOC.Hunt)
			iocs.GET("/:id", h.IOC.Get)
			iocs.PATCH("/:id", h.IOC.Update)
			iocs.DELETE("/:id", h.IOC.Delete)
		}

		feeds := api.Group("/intel_feeds")
		{
			feeds.GET("", h.IntelFeed.List)
			feeds.POST("", h.IntelFeed.Create)
			// Static sub-paths must come before /:id to avoid routing conflict.
			feeds.POST("/bulk_sync", h.IntelFeed.BulkSync)
			feeds.GET("/:id", h.IntelFeed.Get)
			feeds.PATCH("/:id", h.IntelFeed.Update)
			feeds.DELETE("/:id", h.IntelFeed.Delete)
			feeds.POST("/:id/sync", h.IntelFeed.Sync)
		}

		actions := api.Group("/actions")
		{
			actions.GET("", h.Action.List)
			actions.POST("", h.Action.Create)
			actions.GET("/:id", h.Action.Get)
			actions.PATCH("/:id", h.Action.Update)
			actions.POST("/:id/execute", h.Action.Execute)
		}

		logs := api.Group("/logs")
		{
			logs.GET("/query", h.LogEntry.Query)
			logs.GET("/datasets", h.LogEntry.Datasets)
		}

		// ETL pipeline rule management
		if h.ETLRule != nil {
			etlRules := api.Group("/etl/rules")
			{
				etlRules.GET("", h.ETLRule.List)
				etlRules.POST("", h.ETLRule.Create)
				etlRules.GET("/stats", h.ETLRule.Stats)
				etlRules.GET("/export", h.ETLRule.Export)
				etlRules.POST("/import", h.ETLRule.Import)
				etlRules.GET("/:id", h.ETLRule.Get)
				etlRules.PATCH("/:id", h.ETLRule.Update)
				etlRules.PATCH("/:id/toggle", h.ETLRule.Toggle)
				etlRules.DELETE("/:id", h.ETLRule.Delete)
				etlRules.POST("/:id/test", h.ETLRule.Test)
			}
		}

		devices := api.Group("/devices")
		{
			devices.GET("", h.Device.ListAgents)
			// Static sub-paths must be before /:id to avoid routing conflict
			devices.GET("/liveness", h.Device.Liveness)
			devices.POST("/liveness", h.Device.Liveness)
			devices.GET("/online-count", h.Device.OnlineCount)
			devices.POST("/enrollment_token", h.Device.GenerateToken)
			devices.GET("/:id", h.Device.GetAgent)
			devices.PATCH("/:id", h.Device.UpdateAgent)
			devices.POST("/:id/upgrade", h.Device.UpgradeAgent)
			devices.DELETE("/:id", h.Device.UninstallAgent)
			devices.POST("/:id/heartbeat", h.Device.Heartbeat)
			devices.POST("/:id/execute", h.Device.Execute)
		}

		policies := api.Group("/agent_policies")
		{
			policies.GET("", h.Policy.List)
			policies.POST("", h.Policy.Create)
			policies.PATCH("/:id", h.Policy.Update)
			policies.DELETE("/:id", h.Policy.Delete)
		}

		ds := api.Group("/datasources")
		{
			ds.GET("", h.DataSource.List)
			ds.POST("", h.DataSource.Create)
			ds.PATCH("/:id", h.DataSource.Update)
			ds.DELETE("/:id", h.DataSource.Delete)
		}

		playbooks := api.Group("/playbooks")
		{
			playbooks.GET("", h.Playbook.List)
			playbooks.POST("", h.Playbook.Create)
			playbooks.GET("/:id", h.Playbook.Get)
			playbooks.PATCH("/:id", h.Playbook.Update)
			playbooks.DELETE("/:id", h.Playbook.Delete)
			playbooks.POST("/:id/execute", h.Playbook.Execute)
			playbooks.GET("/:id/executions", h.Playbook.GetExecutions)
		}

		reports := api.Group("/reports")
		{
			reports.GET("", h.Report.List)
			reports.POST("", h.Report.Create)
			reports.GET("/stats", h.Report.Stats)
			reports.GET("/:id", h.Report.Get)
			reports.DELETE("/:id", h.Report.Delete)
			reports.POST("/:id/schedule", h.Report.Schedule)
			reports.GET("/:id/download", h.Report.Download)
		}

		users := api.Group("/users")
		{
			users.GET("", h.User.List)
			users.POST("", h.User.Create)
			users.GET("/me", h.User.Me)
			users.GET("/me/profile", h.User.GetProfile)
			users.PATCH("/me/profile", h.User.UpdateProfile)
			users.POST("/bulk", h.User.Bulk)
			users.GET("/:id", h.User.Get)
			users.PATCH("/:id", h.User.Update)
			users.DELETE("/:id", h.User.Delete)
			users.POST("/:id/change_password", h.User.ChangePassword)
		}

		rules := api.Group("/detection_rules")
		{
			rules.GET("", h.DetectionRule.List)
			rules.POST("", h.DetectionRule.Create)
			// Static sub-paths must come before /:id to avoid routing conflict
			rules.GET("/mitre_coverage", h.DetectionRule.MitreCoverage)
			rules.POST("/bulk", h.DetectionRule.BulkToggle)
			rules.GET("/:id", h.DetectionRule.Get)
			rules.PATCH("/:id", h.DetectionRule.Update)
			rules.DELETE("/:id", h.DetectionRule.Delete)
			rules.POST("/:id/status", h.DetectionRule.TransitionStatus)
			rules.GET("/:id/test_replay", h.DetectionRule.TestReplay)
			rules.POST("/:id/test", h.DetectionRule.Test)
			rules.GET("/:id/hit_stats", h.DetectionRule.HitStats)
		}

		itdr := api.Group("/identity_risks")
		{
			itdr.GET("", h.IdentityRisk.List)
			itdr.GET("/:user_id", h.IdentityRisk.Get)
			itdr.POST("/:user_id/signal", h.IdentityRisk.AddSignal)
		}

		// Active identity sessions (alias endpoint for ITDR frontend)
		api.GET("/identity_sessions", h.IdentityRisk.Sessions)

		exposure := api.Group("/exposure_scores")
		{
			exposure.GET("", h.Exposure.List)
			exposure.POST("/bulk", h.Exposure.BulkUpdate)
			exposure.POST("/recalc", h.Exposure.RecalcAll)
			exposure.PATCH("/:id", h.Exposure.Update)
		}

		tenants := api.Group("/tenants")
		tenants.Use(middleware.RequireSuperTenant())
		{
			tenants.GET("", h.Tenant.List)
			tenants.POST("", h.Tenant.Create)
			tenants.GET("/:id", h.Tenant.Get)
			tenants.PATCH("/:id", h.Tenant.Update)
			tenants.DELETE("/:id", h.Tenant.Delete)
		}

		rbacGroup := api.Group("/rbac/roles")
		{
			rbacGroup.GET("", h.RBAC.List)
			rbacGroup.POST("", h.RBAC.Create)
			rbacGroup.PATCH("/:id", h.RBAC.Update)
			rbacGroup.DELETE("/:id", h.RBAC.Delete)
			rbacGroup.POST("/:id/members", h.RBAC.AddMember)
			rbacGroup.DELETE("/:id/members/:user_id", h.RBAC.RemoveMember)
		}

		// Threat intel aggregation views
		if h.ThreatIntel != nil {
			ti := api.Group("/threat_intel")
			{
				ti.GET("/rules",    h.ThreatIntel.Rules)
				ti.GET("/samples",  h.ThreatIntel.Samples)
				ti.GET("/reports",  h.ThreatIntel.Reports)
				ti.GET("/sessions", h.ThreatIntel.Sessions)
			}
		}

		// Extended dashboard stats
		api.GET("/dashboard/extended_stats", h.Dashboard.ExtendedStats)

		// DataSource stats
		api.GET("/datasources/stats", h.DataSource.Stats)

		// AI Copilot
		if h.Copilot != nil {
			api.POST("/copilot/chat", h.Copilot.Chat)
			api.POST("/copilot/nl2xql", h.Copilot.NL2XQL)
		}

		// Privilege restrictions (ITDR)
		if h.Privilege != nil {
			priv := api.Group("/privilege_restrictions")
			{
				priv.GET("",         h.Privilege.List)
				priv.POST("",        h.Privilege.Create)
				priv.PUT("/release", h.Privilege.Release)
				priv.GET("/stats",   h.Privilege.Stats)
				priv.DELETE("/:id",  h.Privilege.Delete)
			}
		}

		// Audit logs (admin UI — tenant-scoped via JWT)
		if h.Audit != nil {
			api.GET("/audit/logs", h.Audit.WebList)
		}

		// Notify test (admin) — send a test notification on any configured channel
		if h.Notify != nil {
			api.POST("/notify/test", h.Notify.Test)
		}

		// Network Security — traffic, DNS, asset inventory, network detection rules
		if h.Network != nil {
			api.GET("/network/stats", h.Network.Stats)
			api.GET("/network/traffic/timeline", h.Network.TrafficTimeline)

			netConns := api.Group("/network/connections")
			{
				netConns.GET("", h.Network.ListConnections)
				netConns.POST("/block", h.Network.BlockConnection)
			}

			netDNS := api.Group("/network/dns")
			{
				netDNS.GET("", h.Network.ListDNS)
				netDNS.POST("/blocklist", h.Network.AddDNSBlocklist)
			}

			netRules := api.Group("/network/detection_rules")
			{
				netRules.GET("", h.Network.ListNetworkRules)
				netRules.PATCH("/:id", h.Network.UpdateNetworkRule)
			}

			netAlerts := api.Group("/network/alerts")
			{
				netAlerts.GET("", h.Network.ListNetworkAlerts)
				netAlerts.PATCH("/:id", h.Network.UpdateNetworkAlert)
			}

			api.GET("/network/devices", h.Network.ListNetworkDevices)
		}

		// Endpoint Security — overview stats, isolation management
		if h.Endpoint != nil {
			api.GET("/endpoint/stats", h.Endpoint.Stats)

			endpointIso := api.Group("/endpoint/isolated")
			{
				endpointIso.GET("", h.Endpoint.ListIsolated)
				endpointIso.POST("", h.Endpoint.IsolateEndpoint)
				endpointIso.PUT("/:id/release", h.Endpoint.ReleaseIsolation)
			}
		}
	}

	// SPA static assets + fallback
	if staticFiles != nil {
		distFS, _ := fs.Sub(staticFiles, "dist")
		httpFS := http.FS(distFS)
		fileServer := http.StripPrefix("/", http.FileServer(httpFS))
		serveIndex := func(c *gin.Context) {
			data, err := fs.ReadFile(distFS, "index.html")
			if err != nil {
				c.Status(http.StatusNotFound)
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
		}
		r.GET("/", serveIndex)
		r.GET("/favicon.svg", func(c *gin.Context) { fileServer.ServeHTTP(c.Writer, c.Request) })
		r.GET("/icons.svg", func(c *gin.Context) { fileServer.ServeHTTP(c.Writer, c.Request) })
		r.GET("/assets/*filepath", func(c *gin.Context) { fileServer.ServeHTTP(c.Writer, c.Request) })
		r.NoRoute(serveIndex)
	}

	return r
}

// NewInternalEngine builds the internal-only HTTP engine on InternalPort.
// Not reachable from outside; handles: svc callbacks, datalake alert webhook.
func NewInternalEngine(h InternalHandlers) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	// Auth / RBAC / Notify / Audit — called by internal services via localclient,
	// exposed here for any out-of-process tooling (e.g. CLI, migration scripts).
	r.POST("/auth/login", h.Auth.Login)
	r.POST("/auth/refresh", h.Auth.Refresh)
	r.POST("/auth/verify", h.Auth.Verify)
	r.POST("/rbac/check", h.RBAC.Check)
	r.POST("/notify/send", h.Notify.Send)
	r.POST("/audit/record", h.Audit.Record)
	r.GET("/audit/logs", h.Audit.List)

	// Datalake alert webhook (ngx saved_search callback)
	r.POST("/alerts/ingest", h.AlertWebhook.CreateFromRule)

	// Agent lifecycle events from fluent-bit / endpoint agents
	// POST /internal/agent/event  {"agent_id":"…","event":"connect|disconnect|heartbeat",…}
	r.POST("/internal/agent/event", h.AgentEvent.Handle)

	// XLOG binary log batch from fluent-bit out_xsiam_log plugin
	// POST /internal/agent/log   Content-Type: application/x-xlog
	// Frame: XLOG TLV header + zstd-compressed TSV body
	if h.AgentLog != nil {
		r.POST("/internal/agent/log", h.AgentLog.Handle)
	}

	return r
}
