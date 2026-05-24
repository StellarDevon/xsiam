// xsiam is the all-in-one binary: web API + UI on :18080, internal services on :18090.
//
// :18080 — user-facing: login, business APIs, React SPA
// :18090 — internal-only: auth/RBAC/notify/audit svc endpoints + datalake alert webhook
//
// Usage:
//
//	xsiam
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	xsiamroot "xsiam"
	"xsiam/config"
	"xsiam/db"
	"xsiam/internal/cache"
	"xsiam/internal/cron"
	"xsiam/pkg/statscache"
	"xsiam/internal/datalake"
	alertdomain "xsiam/internal/domain/alert"
	assetdomain "xsiam/internal/domain/asset"
	authdomain "xsiam/internal/domain/auth"
	copilotdomain "xsiam/internal/domain/copilot"
	"xsiam/internal/domain/dashboard"
	devicedomain "xsiam/internal/domain/device"
	endpointdomain "xsiam/internal/domain/endpoint"
	identitydomain "xsiam/internal/domain/identity"
	incidentdomain "xsiam/internal/domain/incident"
	etldomain "xsiam/internal/domain/etl"
	networkdomain "xsiam/internal/domain/network"
	querydomain "xsiam/internal/domain/query"
	reportdomain "xsiam/internal/domain/report"
	responsedomain "xsiam/internal/domain/response"
	threatdomain "xsiam/internal/domain/threat"
	"xsiam/internal/etl"
	"xsiam/internal/ingest"
	"xsiam/internal/presence"
	"xsiam/internal/repository"
	"xsiam/internal/router"
	"xsiam/internal/svc/audit"
	"xsiam/internal/svc/auth"
	"xsiam/internal/svc/notify"
	"xsiam/internal/svc/rbac"
	"xsiam/pkg/localclient"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	log, _ := zap.NewProduction()
	defer log.Sync()

	cfg := config.Load()

	if cfg.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	// ── Database ───────────────────────────────────────────────────────────
	arangoClient, err := db.Connect(cfg.ArangoDB.Endpoints, cfg.ArangoDB.Username, cfg.ArangoDB.Password)
	if err != nil {
		log.Fatal("failed to connect to ArangoDB", zap.Error(err))
	}
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	arangoDB, err := db.Database(bgCtx, arangoClient, cfg.ArangoDB.Database)
	if err != nil {
		log.Fatal("failed to open database", zap.Error(err))
	}
	log.Info("arangodb connected", zap.String("db", cfg.ArangoDB.Database))

	// ── Cache ──────────────────────────────────────────────────────────────
	store, err := cache.New()
	if err != nil {
		log.Fatal("failed to create cache", zap.Error(err))
	}
	defer store.Close()
	_ = store

	// ── Shared repositories ────────────────────────────────────────────────
	auditRepo := repository.NewAuditLogRepo(arangoDB)
	userRepo := repository.NewUserRepo(arangoDB)
	rbacRepo := repository.NewRBACRoleRepo(arangoDB)
	tenantRepo := repository.NewTenantRepo(arangoDB)
	identityRiskRepo := repository.NewIdentityRiskRepo(arangoDB)
	privRepo := repository.NewPrivilegeRestrictionRepo(arangoDB)
	exposureRepo := repository.NewExposureScoreRepo(arangoDB)
	reportRepo := repository.NewReportRepo(arangoDB)
	ruleRepoShared := repository.NewDetectionRuleRepo(arangoDB)

	// ── Svc services (auth / RBAC / notify / audit) ────────────────────────
	authSvc := auth.New(cfg.Auth.JWTSecret, cfg.Auth.TokenExpireHr, userRepo)
	rbacSvc := rbac.New(rbacRepo)
	notifySvc := notify.New(cfg.Notify)
	auditSvc := audit.New(auditRepo)

	// ── In-process caller ─────────────────────────────────────────────────
	caller := localclient.New(authSvc, rbacSvc, notifySvc, auditSvc)

	// ── Stubs ──────────────────────────────────────────────────────────────
	execClient := responsedomain.NewExecutionClient(cfg.Stub.Execution)
	agentCtrl := devicedomain.NewAgentController(cfg.Stub.ETL)
	feedPuller := threatdomain.NewFeedPuller(cfg.Stub.ETL)
	aiEngine := incidentdomain.NewAIEngine(cfg.Stub.AIEngine)

	// ── DataLake ───────────────────────────────────────────────────────────
	var lakeClient datalake.QueryClient
	var lakeWriter *datalake.Client
	if cfg.DataLake.Enabled {
		lakeWriter = datalake.New(cfg.DataLake.QueryURL, cfg.DataLake.HECURL, cfg.DataLake.HECToken)
		lakeClient = lakeWriter
	} else {
		lakeClient = &datalake.DataLakeStub{}
	}

	// ── Domain repos ───────────────────────────────────────────────────────
	alertRepo := alertdomain.NewRepo(arangoDB)
	incidentRepo := incidentdomain.NewRepo(arangoDB)
	graphRepo := incidentdomain.NewCausalityRepo(arangoDB)
	assetRepo := assetdomain.NewRepo(arangoDB)
	vulnRepo := assetdomain.NewVulnRepo(arangoDB)
	iocRepo := threatdomain.NewIocRepo(arangoDB)
	feedRepo := threatdomain.NewFeedRepo(arangoDB)
	domainRuleRepo := threatdomain.NewRuleRepo(arangoDB)
	actionRepo := responsedomain.NewActionRepo(arangoDB)
	pbRepo := responsedomain.NewPlaybookRepo(arangoDB)
	devRepo := devicedomain.NewRepo(arangoDB)
	policyRepo := devicedomain.NewPolicyRepo(arangoDB)
	dsRepo := devicedomain.NewDataSourceRepo(arangoDB)
	networkRepo := repository.NewNetworkRepo(arangoDB)
	endpointRepo := repository.NewEndpointRepo(arangoDB)

	alertRepo.EnsureIndexes(bgCtx)

	// ── Domain services ────────────────────────────────────────────────────
	causalitySvc := incidentdomain.NewCausalityService(graphRepo, alertRepo, incidentRepo, assetRepo)
	pool := incidentdomain.NewCorrelationPool(causalitySvc)
	defer pool.Shutdown()

	alertSvc := alertdomain.NewService(alertRepo, incidentRepo, auditRepo, pool)
	incidentSvc := incidentdomain.NewService(incidentRepo, alertRepo, auditRepo)
	webhookDispatcher := incidentdomain.NewWebhookDispatcher(cfg.Webhook.Endpoints, cfg.Webhook.Secret, log)
	incidentdomain.InjectDispatcher(incidentSvc, webhookDispatcher)
	assetSvc := assetdomain.NewService(assetRepo, auditRepo)
	vulnSvc := assetdomain.NewVulnService(vulnRepo, auditRepo)
	iocSvc := threatdomain.NewIocService(iocRepo, auditRepo)
	feedSvc := threatdomain.NewFeedService(feedRepo, feedPuller, auditRepo)
	ruleSvc := threatdomain.NewRuleService(domainRuleRepo, lakeClient, lakeWriter, auditRepo, cfg)
	actionSvc := responsedomain.NewActionService(actionRepo, execClient, auditRepo)
	pbSvc := responsedomain.NewPlaybookService(pbRepo, execClient, auditRepo)

	// ── Redis: presence registry + stats cache ────────────────────────────
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       0,
	})
	presenceReg := presence.New(rdb)
	statsCache := statscache.New(rdb)

	devSvc := devicedomain.NewService(devRepo, policyRepo, dsRepo, agentCtrl, auditRepo, statsCache)
	if err := presenceReg.Ping(bgCtx); err != nil {
		log.Warn("redis not available — presence/statscache degraded", zap.Error(err))
		// Non-fatal: liveness queries will return empty; stats always computed live
	} else {
		log.Info("redis connected", zap.String("addr", cfg.RedisAddr))
		// Start presence GC sweep every 15 seconds
		presenceGC := presence.NewGC(presenceReg, devRepo, log)
		presenceGC.StartLoop(bgCtx, 15*time.Second)
	}

	dashSvc := dashboard.NewService(
		repository.NewAlertRepo(arangoDB),
		repository.NewIncidentRepo(arangoDB),
		repository.NewAssetRepo(arangoDB),
		repository.NewVulnerabilityRepo(arangoDB),
		ruleRepoShared,
		repository.NewIocRepo(arangoDB),
		identityRiskRepo,
		reportRepo,
		statsCache,
	)
	reportSvc := reportdomain.NewService(reportRepo, dashSvc)
	authConsoleSvc := authdomain.NewAuthService(caller, userRepo)
	userSvc := authdomain.NewUserService(userRepo)
	tenantSvc := authdomain.NewTenantService(tenantRepo)
	rbacConsoleSvc := authdomain.NewRBACService(rbacRepo)
	smartScoreSvc := incidentdomain.NewSmartScoreService(incidentRepo, alertRepo, aiEngine)
	identityRiskSvc := identitydomain.NewRiskService(identityRiskRepo, privRepo)
	exposureSvc := identitydomain.NewExposureService(
		exposureRepo,
		repository.NewVulnerabilityRepo(arangoDB),
		repository.NewAssetRepo(arangoDB),
	)
	logSvc := querydomain.NewServiceWithRepo(lakeClient, arangoDB)

	networkSvc := networkdomain.NewService(networkRepo, statsCache)
	endpointSvc := endpointdomain.NewService(endpointRepo, repository.NewAlertRepo(arangoDB), statsCache)

	_ = identityRiskSvc.Restore(bgCtx)
	identityRiskSvc.StartFlusher(bgCtx)

	// ── Cron ──────────────────────────────────────────────────────────────
	mgr := cron.New(bgCtx, log)
	registerCronTasks(mgr, log, alertRepo, ruleSvc, causalitySvc, smartScoreSvc, exposureSvc, reportSvc)
	registerStatsCronTasks(mgr, log, tenantRepo, dashSvc, networkSvc, endpointSvc, devSvc, statsCache)
	mgr.Start()
	log.Info("cron started")

	// ── ETL pipeline ─────────────────────────────────────────────────────────
	// The pipeline hot-reloads rules from ArangoDB every 60s.
	// When cfg.Stub.ETL is true the pipeline starts empty (no rules loaded).
	// Either way the Pipeline object is always non-nil so ingest can call Process().
	var etlPipeline *etl.Pipeline
	{
		// Optional GeoIP database (disabled when path is empty).
		var geoipDB *etl.GeoIPDB
		if cfg.GeoIP.CityDBPath != "" {
			var gErr error
			geoipDB, gErr = etl.OpenGeoIPDB(cfg.GeoIP.CityDBPath, cfg.GeoIP.ASNDBPath)
			if gErr != nil {
				log.Warn("geoip db open failed — lookup_geoip actions will no-op", zap.Error(gErr))
				geoipDB = nil
			} else {
				log.Info("geoip db loaded", zap.String("city_db", cfg.GeoIP.CityDBPath))
			}
		}

		etlDedup := etl.NewDeduplicator()
		etlLua := etl.NewLuaEngine()

		etlRuleRepo := repository.NewETLRuleRepo(arangoDB)
		etlExecutor := etl.NewActionExecutor(
			repository.NewAssetRepo(arangoDB),
			repository.NewIocRepo(arangoDB),
			geoipDB,
			etlDedup,
			etlLua,
			log,
		)
		etlPipeline = etl.NewPipeline(etlExecutor)
		if !cfg.Stub.ETL {
			engine := etl.NewRuleEngine(etlRuleRepo, etlPipeline, "t-super", log)
			if err := engine.LoadRules(bgCtx); err != nil {
				log.Warn("etl rule initial load failed (empty rule set active)", zap.Error(err))
			}
			engine.StartHotReload(bgCtx)
		}
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	// ── Web server :18080 ─────────────────────────────────────────────────
	webHandlers := router.Handlers{
		Dashboard:     dashboard.NewHandler(dashSvc),
		Alert:         alertdomain.NewHandler(alertSvc),
		Incident:      incidentdomain.NewHandler(incidentSvc),
		Causality:     incidentdomain.NewCausalityHandler(causalitySvc),
		SmartScore:    incidentdomain.NewSmartScoreHandler(smartScoreSvc),
		Asset:         assetdomain.NewHandler(assetSvc),
		Vulnerability: assetdomain.NewVulnHandler(vulnSvc),
		IOC:           threatdomain.NewIocHandler(iocSvc),
		IntelFeed:     threatdomain.NewFeedHandler(feedSvc),
		DetectionRule: threatdomain.NewRuleHandler(ruleSvc),
		Action:        responsedomain.NewActionHandler(actionSvc),
		Playbook:      responsedomain.NewPlaybookHandler(pbSvc),
		Device:        devicedomain.NewHandler(devSvc, presenceReg),
		Policy:        devicedomain.NewPolicyHandler(devSvc),
		DataSource:    devicedomain.NewDataSourceHandler(devSvc),
		IdentityRisk:  identitydomain.NewRiskHandler(identityRiskSvc),
		Exposure:      identitydomain.NewExposureHandler(exposureSvc),
		Report:        reportdomain.NewHandler(reportSvc),
		Auth:          authdomain.NewHandler(authConsoleSvc),
		User:          authdomain.NewUserHandlerWithProfile(userSvc, repository.NewUserProfileRepo(arangoDB)),
		Tenant:        authdomain.NewTenantHandler(tenantSvc),
		RBAC:          authdomain.NewRBACHandler(rbacConsoleSvc),
		LogEntry:      querydomain.NewHandler(logSvc),
		ETLRule:       etldomain.NewHandler(etldomain.NewService(repository.NewETLRuleRepo(arangoDB), etlPipeline)),
		ThreatIntel:   threatdomain.NewThreatIntelHandler(domainRuleRepo, iocRepo, reportRepo),
		Copilot:       copilotdomain.NewHandler(copilotdomain.NewService(cfg.CopilotAPIKey, alertRepo, incidentRepo, iocRepo)),
		Privilege:     identitydomain.NewPrivilegeHandler(privRepo),
		Audit:         audit.NewHandler(auditSvc),
		Notify:        notify.NewPublicHandler(notifySvc),
		Network:       networkdomain.NewHandler(networkSvc),
		Endpoint:      endpointdomain.NewHandler(endpointSvc),
	}
	webEngine := router.NewWebEngine(webHandlers, caller, cfg.Auth.JWTSecret, log, xsiamroot.StaticFiles)
	webSrv := &http.Server{Addr: ":" + cfg.WebPort, Handler: webEngine}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("web server starting", zap.String("port", cfg.WebPort))
		if err := webSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("web server error", zap.Error(err))
		}
	}()
	go func() {
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = webSrv.Shutdown(ctx)
	}()

	// ── Ingest handler (XLOG binary frames from fluent-bit / agents) ──────
	// Data flow per event:
	//   1. raw event  → ngx HEC  index "raw_<tag>"          (if lakeWriter != nil)
	//   2. etl.Pipeline.Process() → transformed entry
	//   3. ETL entry  → ngx HEC  index <rule.Output.NgxIndex> (if lakeWriter != nil)
	//   4. ETL entry  → ArangoDB log_entries                  (if rule.Output.WriteArango)
	// When no rule matches: raw event → ngx + ArangoDB (default).
	var ingestHandler *ingest.Handler
	{
		logEntryRepo := repository.NewLogEntryRepo(arangoDB)
		// Pass lakeWriter as the ngx client (nil when DataLake is disabled —
		// all events fall back to ArangoDB-only in that case).
		h, err := ingest.NewHandler(etlPipeline, lakeWriter, logEntryRepo, "t-super", log)
		if err != nil {
			log.Fatal("failed to create ingest handler", zap.Error(err))
		}
		ingestHandler = h
	}

	// ── Internal server :18090 ────────────────────────────────────────────
	internalHandlers := router.InternalHandlers{
		AlertWebhook: authdomain.NewInternalHandler(alertSvc),
		AgentEvent:   devicedomain.NewAgentEventInternalHandler(devSvc, presenceReg, log),
		AgentLog:     ingestHandler,
		Auth:         auth.NewHandler(authSvc),
		RBAC:         rbac.NewHandler(rbacSvc),
		Notify:       notify.NewHandler(notifySvc),
		Audit:        audit.NewHandler(auditSvc),
	}
	internalEngine := router.NewInternalEngine(internalHandlers)
	internalSrv := &http.Server{Addr: ":" + cfg.InternalPort, Handler: internalEngine}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("internal server starting", zap.String("port", cfg.InternalPort))
		if err := internalSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("internal server error", zap.Error(err))
		}
	}()
	go func() {
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = internalSrv.Shutdown(ctx)
	}()

	fmt.Printf("\n  xsiam running — web=:%s  internal=:%s\n\n", cfg.WebPort, cfg.InternalPort)
	log.Info("xsiam started", zap.String("web", cfg.WebPort), zap.String("internal", cfg.InternalPort))

	<-quit
	log.Info("xsiam shutting down…")
	mgr.Shutdown()
	bgCancel()
	wg.Wait()
	log.Info("xsiam stopped")
}

func registerCronTasks(
	mgr *cron.Manager,
	log *zap.Logger,
	alertRepo *alertdomain.Repo,
	ruleSvc *threatdomain.RuleService,
	causalitySvc *incidentdomain.CausalityService,
	smartScoreSvc *incidentdomain.SmartScoreService,
	exposureSvc *identitydomain.ExposureService,
	reportSvc *reportdomain.Service,
) {
	_ = mgr.RegisterCron("0 */5 * * * *", cron.Task{
		Name: "alert_correlation_sweep",
		Fn: func(ctx context.Context) {
			now := time.Now()
			from := now.Add(-5 * time.Minute)
			recentAlerts, _ := alertRepo.FindByTimeRange(ctx, from, now)
			p := incidentdomain.NewCorrelationPool(causalitySvc)
			for _, a := range recentAlerts {
				p.Submit(a.AlertID)
			}
			time.Sleep(30 * time.Second)
			p.Shutdown()
		},
	})

	_ = mgr.RegisterCron("0 0 * * * *", cron.Task{
		Name: "smart_score_evict_expired",
		Fn: func(_ context.Context) {
			smartScoreSvc.EvictExpired()
		},
	})

	_ = mgr.RegisterCron("0 0 */6 * * *", cron.Task{
		Name: "exposure_recalc_all",
		Fn: func(ctx context.Context) {
			_ = exposureSvc.RecalcAll(ctx, "")
		},
	})

	_ = mgr.RegisterCron("0 0 2 * * *", cron.Task{
		Name: "archive_cold_alerts",
		Fn:   func(_ context.Context) {},
	})

	_ = mgr.RegisterCron("0 */15 * * * *", cron.Task{
		Name: "detection_rule_sync",
		Fn: func(ctx context.Context) {
			rules, _, _ := ruleSvc.List(ctx, repository.DetectionRuleListFilter{
				Status:   "active",
				PageSize: 1000,
				Page:     1,
			})
			for _, rule := range rules {
				log.Debug("rule sync check", zap.String("rule", rule.Name))
			}
		},
	})

	_ = mgr.RegisterCron("0 */10 * * * *", cron.Task{
		Name: "report_process_pending",
		Fn: func(ctx context.Context) {
			_ = reportSvc.ProcessPending(ctx, "")
		},
	})

	_ = mgr.RegisterCron("0 30 1 * * *", cron.Task{
		Name: "smart_score_recalc_nightly",
		Fn: func(ctx context.Context) {
			_ = smartScoreSvc.RecalcForTenant(ctx, "t-super")
		},
	})
}

// registerStatsCronTasks registers per-tenant stats precomputation jobs.
// These populate the Redis stats cache so dashboards read from cache, not
// from live AQL queries, under normal operating conditions.
func registerStatsCronTasks(
	mgr *cron.Manager,
	log *zap.Logger,
	tenantRepo *repository.TenantRepo,
	dashSvc *dashboard.Service,
	networkSvc *networkdomain.Service,
	endpointSvc *endpointdomain.Service,
	devSvc *devicedomain.Service,
	_ *statscache.Client,
) {
	// Helper: iterate all tenant IDs from the tenant repo.
	allTenants := func(ctx context.Context) []string {
		tenants, _, _ := tenantRepo.List(ctx, 1, 1000)
		ids := make([]string, 0, len(tenants))
		for _, t := range tenants {
			ids = append(ids, t.TenantID)
		}
		return ids
	}

	// Dashboard stats — refresh every 5 minutes.
	_ = mgr.RegisterCron("0 */5 * * * *", cron.Task{
		Name: "stats_precompute_dashboard",
		Fn: func(ctx context.Context) {
			for _, tid := range allTenants(ctx) {
				if _, err := dashSvc.GetStats(ctx, tid); err != nil {
					log.Warn("dashboard stats precompute failed",
						zap.String("tenant", tid), zap.Error(err))
				}
			}
		},
	})

	// Network stats — refresh every 15 minutes.
	_ = mgr.RegisterCron("0 */15 * * * *", cron.Task{
		Name: "stats_precompute_network",
		Fn: func(ctx context.Context) {
			for _, tid := range allTenants(ctx) {
				networkSvc.InvalidateStatsCache(ctx, tid)
				if _, err := networkSvc.Stats(ctx, tid); err != nil {
					log.Warn("network stats precompute failed",
						zap.String("tenant", tid), zap.Error(err))
				}
			}
		},
	})

	// Endpoint stats — refresh every 15 minutes.
	_ = mgr.RegisterCron("0 */15 * * * *", cron.Task{
		Name: "stats_precompute_endpoint",
		Fn: func(ctx context.Context) {
			for _, tid := range allTenants(ctx) {
				if _, err := endpointSvc.Stats(ctx, tid); err != nil {
					log.Warn("endpoint stats precompute failed",
						zap.String("tenant", tid), zap.Error(err))
				}
			}
		},
	})

	// Datasource stats — refresh every 30 minutes.
	_ = mgr.RegisterCron("0 */30 * * * *", cron.Task{
		Name: "stats_precompute_datasource",
		Fn: func(ctx context.Context) {
			for _, tid := range allTenants(ctx) {
				if _, err := devSvc.GetDataSourceStats(ctx, tid); err != nil {
					log.Warn("datasource stats precompute failed",
						zap.String("tenant", tid), zap.Error(err))
				}
			}
		},
	})
}
