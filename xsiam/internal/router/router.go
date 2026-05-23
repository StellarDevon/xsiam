package router

import (
	"io/fs"
	"net/http"
	"xsiam/internal/domain/alert"
	"xsiam/internal/domain/asset"
	authdomain "xsiam/internal/domain/auth"
	"xsiam/internal/domain/dashboard"
	"xsiam/internal/domain/device"
	"xsiam/internal/domain/identity"
	"xsiam/internal/domain/incident"
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
}

// InternalHandlers aggregates handlers for the internal-only engine.
type InternalHandlers struct {
	AlertWebhook *authdomain.InternalHandler
	AgentEvent   *device.AgentEventInternalHandler
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
			alerts.GET("/:id", h.Alert.Get)
			alerts.PATCH("/:id", h.Alert.Update)
			alerts.POST("/:id/link_incident", h.Alert.LinkIncident)
			alerts.POST("/bulk", h.Alert.Bulk)
		}

		incidents := api.Group("/incidents")
		{
			incidents.GET("", h.Incident.List)
			incidents.POST("", h.Incident.Create)
			incidents.GET("/:id", h.Incident.Get)
			incidents.PATCH("/:id", h.Incident.Update)
			incidents.DELETE("/:id", h.Incident.Delete)
			incidents.GET("/:id/alerts", h.Incident.ListAlerts)
			incidents.GET("/:id/timeline", h.Incident.GetTimeline)
			incidents.POST("/:id/notes", h.Incident.AddNote)
			incidents.POST("/:id/merge", h.Incident.Merge)
			incidents.POST("/bulk", h.Incident.Bulk)
			incidents.GET("/:id/graph", h.Causality.GetGraph)
			incidents.GET("/:id/smart_score", h.SmartScore.Get)
			incidents.POST("/:id/smart_score/recalc", h.SmartScore.Recalc)
		}

		assets := api.Group("/assets")
		{
			assets.GET("", h.Asset.List)
			assets.GET("/stats", h.Asset.Stats)
			assets.POST("", h.Asset.Create)
			assets.GET("/:id", h.Asset.Get)
			assets.PATCH("/:id", h.Asset.Update)
			assets.DELETE("/:id", h.Asset.Delete)
		}

		vulns := api.Group("/vulnerabilities")
		{
			vulns.GET("", h.Vulnerability.List)
			vulns.POST("", h.Vulnerability.Create)
			vulns.GET("/:id", h.Vulnerability.Get)
			vulns.PATCH("/:id", h.Vulnerability.Update)
			vulns.DELETE("/:id", h.Vulnerability.Delete)
			vulns.GET("/stats", h.Vulnerability.Stats)
		}

		iocs := api.Group("/iocs")
		{
			iocs.GET("", h.IOC.List)
			iocs.POST("", h.IOC.Create)
			iocs.POST("/bulk", h.IOC.BulkImport)
			iocs.GET("/search", h.IOC.Search)
			iocs.GET("/:id", h.IOC.Get)
			iocs.PATCH("/:id", h.IOC.Update)
			iocs.DELETE("/:id", h.IOC.Delete)
		}

		feeds := api.Group("/intel_feeds")
		{
			feeds.GET("", h.IntelFeed.List)
			feeds.POST("", h.IntelFeed.Create)
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

		devices := api.Group("/devices")
		{
			devices.GET("", h.Device.ListAgents)
			// liveness: must be before /:id to avoid conflict
			devices.GET("/liveness", h.Device.Liveness)
			devices.POST("/liveness", h.Device.Liveness)
			devices.POST("/enrollment_token", h.Device.GenerateToken)
			devices.GET("/:id", h.Device.GetAgent)
			devices.PATCH("/:id", h.Device.UpdateAgent)
			devices.POST("/:id/upgrade", h.Device.UpgradeAgent)
			devices.DELETE("/:id", h.Device.UninstallAgent)
			// fluent-bit heartbeat webhook (no JWT, IP-whitelisted in production)
			devices.POST("/:id/heartbeat", h.Device.Heartbeat)
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
		}

		reports := api.Group("/reports")
		{
			reports.GET("", h.Report.List)
			reports.POST("", h.Report.Create)
			reports.GET("/:id", h.Report.Get)
			reports.DELETE("/:id", h.Report.Delete)
		}

		users := api.Group("/users")
		{
			users.GET("", h.User.List)
			users.POST("", h.User.Create)
			users.GET("/:id", h.User.Get)
			users.PATCH("/:id", h.User.Update)
			users.DELETE("/:id", h.User.Delete)
			users.POST("/:id/change_password", h.User.ChangePassword)
		}

		rules := api.Group("/detection_rules")
		{
			rules.GET("", h.DetectionRule.List)
			rules.POST("", h.DetectionRule.Create)
			rules.GET("/:id", h.DetectionRule.Get)
			rules.PATCH("/:id", h.DetectionRule.Update)
			rules.DELETE("/:id", h.DetectionRule.Delete)
			rules.POST("/:id/status", h.DetectionRule.TransitionStatus)
			rules.GET("/:id/test_replay", h.DetectionRule.TestReplay)
			rules.GET("/mitre_coverage", h.DetectionRule.MitreCoverage)
		}

		itdr := api.Group("/identity_risks")
		{
			itdr.GET("", h.IdentityRisk.List)
			itdr.GET("/:user_id", h.IdentityRisk.Get)
			itdr.POST("/:user_id/signal", h.IdentityRisk.AddSignal)
		}

		exposure := api.Group("/exposure_scores")
		{
			exposure.GET("", h.Exposure.List)
			exposure.PATCH("/:id", h.Exposure.Update)
			exposure.POST("/recalc", h.Exposure.RecalcAll)
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

	return r
}
